import json
import os
import time

STATUS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".agent_status.json")


def write_status(**fields):

    fields["updated_at"] = time.time()
    try:
        with open(STATUS_PATH, "w", encoding="utf-8") as f:
            json.dump(fields, f)
    except OSError:
        pass


def read_status():
    try:
        with open(STATUS_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None
