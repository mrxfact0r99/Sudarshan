"""
Sudarshan EDR - shared status file.

The protected background agent (installed via deploy/install_agent.py as a
Windows Service / systemd unit) writes its current state here every few
seconds. edr/agent_gui.py polls this file to show a live view to
whoever is logged into the endpoint - no privilege needed to read it, and
reading/displaying it has no effect on the protected process at all.

This is intentionally a plain JSON file, not a socket/pipe: keeps the
viewer decoupled from the agent's process lifetime, so opening or closing
the viewer can never accidentally affect collection.
"""

import json
import os
import time

STATUS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".agent_status.json")


def write_status(**fields):
    """Best-effort - a failure here should never crash the actual agent.

    Writes STATUS_PATH in place (truncate + write) instead of the more
    common tmp-file-then-os.replace() pattern. os.replace()/MoveFileEx
    needs DELETE access on the destination file on Windows, and once
    deploy/edr_self_protect_windows.py locks this folder down (see its
    docstring) a standard user - which is exactly the account the
    no-admin agent runs as - no longer has DELETE there. Writing in
    place only needs data-write access, which is still granted, so the
    protected agent can keep updating its own status file. This is a
    little less atomic than the tmp+replace pattern (a reader could in
    theory see a half-written file), but agent_gui.py's read_status()
    already tolerates a bad/partial read by returning None.
    """
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
