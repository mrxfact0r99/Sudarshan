import sys
import os

sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

from edr.server_gui import main

if __name__ == "__main__":
    main()
