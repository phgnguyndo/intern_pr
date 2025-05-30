"""Infostealer logs parser."""
from argparse import Namespace
from io import BytesIO
from pathlib import Path
from zipfile import ZipFile

from py7zr import SevenZipFile
from rarfile import RarFile, BadRarFile, NotRarFile
from verboselogs import VerboseLogger

from stealer_parser.helpers import dump_to_file, init_logger, parse_options
from stealer_parser.models import ArchiveWrapper, Leak
from stealer_parser.processing import process_archive
import os
import time
import queue
import sys
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from dotenv import load_dotenv
from zipfile import BadZipFile
import threading

# Load .env file
load_dotenv()

def read_archive(
    buffer: BytesIO, filename: str, password: str | None
) -> ArchiveWrapper:
    """Open logs archive and returns a reader object."""
    archive: RarFile | ZipFile | SevenZipFile
    match Path(filename).suffix:
        case ".rar":
            archive = RarFile(buffer)
        case ".zip":
            archive = ZipFile(buffer)
        case ".7z":
            archive = SevenZipFile(buffer, password=password)
        case other_ext:
            raise NotImplementedError(f"{other_ext} not handled.")
    return ArchiveWrapper(archive, filename=filename, password=password)

def process_archive_file(filename: str, outfile: str, password: str | None, verbose: int) -> None:
    logger: VerboseLogger = init_logger(name="StealerParser", verbosity_level=verbose)
    archive: ArchiveWrapper | None = None
    try:
        leak = Leak(filename=filename)
        logger.debug(f"Processing {filename}, output to {outfile}, verbosity={verbose}, password={password}")
        with open(filename, "rb") as file_handle:
            buffer = BytesIO(file_handle.read())
            try:
                archive = read_archive(buffer, filename, password)
                logger.debug(f"Archive opened: {filename}, files: {archive.namelist()}")
            except BadRarFile as rar_err:
                logger.error(f"RAR file error for {filename}: {rar_err}")
                raise
            process_archive(logger, leak, archive)
        dump_to_file(logger, outfile, leak)
    except BadRarFile:
        raise
    except (
        FileNotFoundError,
        NotImplementedError,
        OSError,
        PermissionError,
    ) as err:
        logger.error(f"Failed reading {filename}: {err}")
        raise
    except RuntimeError as err:
        logger.error(f"Failed parsing {filename}: {err}")
        raise
    except Exception as err:
        logger.error(f"Unexpected error processing {filename}: {err}")
        raise
    finally:
        if archive:
            archive.close()

# def main_auto(filename: str, outfile: str, verbose: int = 0) -> None:
#     password = os.getenv("ZIP_PASSWORD")  # Load password from .env
#     process_archive_file(filename, outfile, password, verbose)

def main() -> None:
    """Program's entrypoint for manual mode."""
    args: Namespace = parse_options("Parse infostealer logs archives.")
    process_archive_file(args.filename, args.outfile, args.password, args.verbose)

def main_auto(filename: str, outfile: str, verbose: int = 0) -> None:
    """Program's entrypoint for auto mode."""
    process_archive_file(filename, outfile, None, verbose)  # No password in auto mode

class ZipFileHandler(FileSystemEventHandler):
    def __init__(self, zip_queue, output_dir, verbosity=0):
        self.zip_queue = zip_queue
        self.output_dir = output_dir
        self.verbosity = verbosity
        self.file_status = {}  # {path: last_modified_time}
        self.stable_time = 5  # Thời gian không thay đổi (giây)
        self.max_files = 5  # Giới hạn số file xử lý đồng thời
        self.lock = threading.Lock()
        self._start_checker()

    def _start_checker(self):
        def check_files():
            while True:
                with self.lock:
                    current_time = time.time()
                    to_remove = []
                    for path, last_modified in list(self.file_status.items()):
                        if current_time - last_modified < self.stable_time:
                            continue
                        if not os.path.exists(path) or os.path.getsize(path) == 0:
                            logger = init_logger(name="StealerParser", verbosity_level=self.verbosity)
                            logger.error(f"File {path} not ready or empty")
                            to_remove.append(path)
                            continue
                        try:
                            with open(path, "rb") as file_handle:
                                buffer = BytesIO(file_handle.read())
                                if path.endswith('.rar'):
                                    RarFile(buffer)
                                elif path.endswith('.zip'):
                                    ZipFile(buffer)
                                elif path.endswith('.7z'):
                                    SevenZipFile(buffer, password=None)
                            logger = init_logger(name="StealerParser", verbosity_level=self.verbosity)
                            logger.debug(f"File {path} is complete and valid")
                            if len(self.zip_queue.queue) < self.max_files:
                                logger.info(f"New archive detected: {path}")
                                self.zip_queue.put(path)
                                to_remove.append(path)
                            else:
                                logger.debug(f"Queue full, delaying {path}")
                        except (BadRarFile, NotRarFile, BadZipFile, Exception) as err:
                            logger = init_logger(name="StealerParser", verbosity_level=self.verbosity)
                            logger.error(f"File {path} invalid: {err}")
                            to_remove.append(path)
                    for path in to_remove:
                        self.file_status.pop(path, None)
                time.sleep(1)
        threading.Thread(target=check_files, daemon=True).start()

    def on_modified(self, event):
        if event.is_directory:
            return
        if event.src_path.endswith(('.zip', '.rar', '.7z')):
            logger = init_logger(name="StealerParser", verbosity_level=self.verbosity)
            logger.debug(f"File modified: {event.src_path}")
            with self.lock:
                self.file_status[event.src_path] = time.time()

def process_zip_queue(zip_queue, output_dir, verbosity=0):
    logger = init_logger(name="StealerParser", verbosity_level=verbosity)
    while True:
        try:
            filename = zip_queue.get(block=True, timeout=1)
            output_filename = os.path.join(
                output_dir,
                f"{os.path.splitext(os.path.basename(filename))[0]}.json"
            )
            logger.info(f"Running equivalent command: stealer_parser -o {output_filename} {filename}")
            logger.info(f"Processing: {filename}")
            success = False
            try:
                main_auto(filename, output_filename, verbosity)
                success = True
            except Exception as err:
                logger.error(f"Failed processing {filename}: {err}")
            if success:
                logger.info(f"Successfully processed '{filename}' to '{output_filename}'")
            zip_queue.task_done()
        except queue.Empty:
            time.sleep(1)

def monitor_zip_directory(zip_dir=None, output_dir=None, verbosity=0):
    zip_dir = zip_dir or os.getenv("ZIP_DIR")
    output_dir = output_dir or os.getenv("JSON_DIR")
    if not zip_dir or not output_dir:
        raise ValueError("ZIP_DIR and JSON_DIR must be set in .env")
    if not os.path.exists(zip_dir):
        raise FileNotFoundError(f"Directory {zip_dir} does not exist")
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    zip_queue = queue.Queue()
    event_handler = ZipFileHandler(zip_queue, output_dir, verbosity)
    observer = Observer()
    observer.schedule(event_handler, zip_dir, recursive=False)
    observer.start()
    logger = init_logger(name="StealerParser", verbosity_level=verbosity)
    logger.info(f"Monitoring directory {zip_dir} for new archives...")
    try:
        process_zip_queue(zip_queue, output_dir, verbosity)
    except KeyboardInterrupt:
        observer.stop()
        logger.info("Monitoring stopped")
    observer.join()

if __name__ == "__main__":
    if len(sys.argv) > 1:
        main()  # Chạy chế độ thủ công
    else:
        verbosity = 1  # Bật log chi tiết để debug
        try:
            monitor_zip_directory(verbosity=verbosity)
        except (ValueError, FileNotFoundError) as err:
            print(f"Error: {err}")
            sys.exit(1)