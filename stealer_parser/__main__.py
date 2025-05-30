from .main import main, monitor_zip_directory
import sys
from dotenv import load_dotenv
load_dotenv()
if __name__ == "__main__":
    if len(sys.argv) > 1:
        main()
    else:
        verbosity = 1
        try:
            monitor_zip_directory(verbosity=verbosity)
        except (ValueError, FileNotFoundError) as err:
            print(f"Error: {err}")
            exit(1)