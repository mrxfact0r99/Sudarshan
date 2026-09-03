import sys
import os
from Scripts.gui import main

sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

sys.dont_write_bytecode = True

if __name__ == "__main__":
    main()
