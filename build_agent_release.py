#!/usr/bin/env python3
"""
Sudarshan EDR - Agent-only release builder.

Copies ONLY the files an endpoint agent needs into dist/Sudarshan_EDR_Agent/
and zips it up. None of the server code (edr/server.py, edr/server_gui.py,
dashboard templates, report generator, or the server's SQLite data) is
included - so this is what you hand to a machine that should only ever run
the agent, never see server internals.

Run:
    python3 build_agent_release.py

Output:
    dist/Sudarshan_EDR_Agent/           <- folder, ready to run
    dist/Sudarshan_EDR_Agent.zip        <- same thing, zipped
"""

import os
import shutil
import zipfile

ROOT = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = os.path.join(ROOT, "dist", "Sudarshan_EDR_Agent")

# Every path here is relative to the project root. Files not listed
# (edr/server.py, edr/server_gui.py, edr/templates/, edr/server_data/,
# Scripts/report/, main.py, main_gui.py, edr_server_gui.py, start_server.py,
# .git/, README.md) are intentionally left out of the agent release.
AGENT_FILES = [
    "edr/__init__.py",
    "edr/agent.py",
    "edr/agent_gui.py",
    "edr/agent_status.py",
    "edr/config.py",
    "edr_agent_gui.py",
    "Scripts/__init__.py",
    "Scripts/common.py",
    "Scripts/collectors/__init__.py",
    "Scripts/collectors/processes.py",
    "Scripts/collectors/networks.py",
    "Scripts/collectors/usb.py",
    "Scripts/collectors/history.py",
    "Scripts/collectors/logs.py",
    "Scripts/collectors/recycle.py",
    "Scripts/collectors/clipboard.py",
    "Scripts/collectors/commands.py",
    "Scripts/collectors/execution.py",
    # deploy/install_agent.py --mode user (default): no admin/root needed
    # to install at all - protects the folder from deletion and the
    # running agent process from End Task using deploy/edr_self_protect_windows.py.
    # deploy/install_agent.py --mode service: real OS-enforced "only
    # admin/root can end task" - installs as a Windows Service
    # (LocalSystem, elevated install) or systemd unit (root, sudo
    # install). See each file's own docstring.
    "deploy/install_agent.py",
    "deploy/install_windows.py",
    "deploy/install_linux.py",
    "deploy/edr_self_protect_windows.py",
    "deploy/edr_self_protect_linux.py",
    "deploy/edr_service_windows.py",
    "deploy/edr-agent.service",
]

# pywin32 is only needed for the Windows-service install path; the
# environment marker keeps `pip install -r requirements.txt` working
# unchanged on Linux.
AGENT_REQUIREMENTS = "psutil>=5.9\nrequests>=2.31\npywin32>=306; platform_system=='Windows'\n"

AGENT_README = """\
Sudarshan EDR - Agent
======================

This folder contains ONLY the endpoint agent - no server code, no
dashboard, no other agents' data. Run it on a machine you own or are
explicitly authorized to monitor (see edr/config.py). This folder can be
extracted and installed entirely as a normal (non-admin) user - see below.

Setup:
    pip install -r requirements.txt

RECOMMENDED - one command, always the strongest available protection,
no flags/choices to make:

    Windows (elevated / "Run as administrator" prompt - required,
    creating any Windows Service needs it):
        python deploy\\install_windows.py --server http://SERVER_IP:8443 --token THE_TOKEN

    Linux (sudo - required):
        sudo python3 deploy/install_linux.py --server http://SERVER_IP:8443 --token THE_TOKEN

Each of these does everything in one shot:
  - Installs the agent as a real OS service (Windows Service running as
    LocalSystem / systemd unit running as root) so a standard user's
    Task Manager "End Task", `taskkill`, or `kill`/`kill -9` all fail
    with Access is denied / Operation not permitted - only an actual
    admin (Windows) or root (Linux) session can stop it.
  - Locks the install FOLDER itself against deletion/tampering by a
    standard user too - not just the running process.
  - The dashboard's Start/Stop/Terminate buttons work immediately
    (gated by the dashboard login, separate from OS-level protection).
  - Every completed collection cycle auto-generates a PDF report on
    the server.

ALTERNATIVE - Windows only, no admin needed to INSTALL (only to later
stop it or delete the folder):
    python deploy\\install_agent.py --mode user --server http://SERVER_IP:8443 --token THE_TOKEN
See deploy/edr_self_protect_windows.py for exactly how that works.

See the agent's status any time (no admin/root needed):
    python edr_agent_gui.py
This opens a plain, read-only window - agent id, connection state,
whether collection is on/off, last cycle result. Close it normally with
the window's [X] whenever you like; it only reads a status file, so
closing it does NOT stop the background agent. Reopen it any time to
check again.

Quick manual test instead (no protection, no install - just for checking
the agent talks to the server before installing it for real; needs the
token as an env var since deploy/install_agent.py hasn't written
edr/instance_config.json yet at this point):
    export SUDARSHAN_ENROLL_TOKEN="the-token-the-server-owner-gave-you"
    (Windows: set SUDARSHAN_ENROLL_TOKEN=the-token-the-server-owner-gave-you)
    python3 -m edr.agent --server http://SERVER_IP:8443 --once
"""


def main():
    if os.path.isdir(OUT_DIR):
        shutil.rmtree(OUT_DIR)
    os.makedirs(OUT_DIR)

    for rel_path in AGENT_FILES:
        src = os.path.join(ROOT, rel_path)
        dst = os.path.join(OUT_DIR, rel_path)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        if not os.path.isfile(src):
            print(f"  ! skipping missing file: {rel_path}")
            continue
        shutil.copy2(src, dst)

    with open(os.path.join(OUT_DIR, "requirements.txt"), "w") as f:
        f.write(AGENT_REQUIREMENTS)
    with open(os.path.join(OUT_DIR, "README.md"), "w") as f:
        f.write(AGENT_README)

    zip_path = os.path.join(ROOT, "dist", "Sudarshan_EDR_Agent")
    shutil.make_archive(zip_path, "zip", root_dir=os.path.dirname(OUT_DIR), base_dir="Sudarshan_EDR_Agent")

    print(f"Agent-only release built:")
    print(f"  Folder → {OUT_DIR}")
    print(f"  Zip    → {zip_path}.zip")
    print(f"  Files included: {len(AGENT_FILES) + 2}")


if __name__ == "__main__":
    main()
