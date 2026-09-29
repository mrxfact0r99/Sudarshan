import os
import shutil
import zipfile

ROOT = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = os.path.join(ROOT, "dist", "Sudarshan_EDR_Agent")


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
    "deploy/install_agent.py",
    "deploy/install_windows.py",
    "deploy/install_linux.py",
    "deploy/edr_self_protect_windows.py",
    "deploy/edr_self_protect_linux.py",
    "deploy/edr_service_windows.py",
    "deploy/edr-agent.service",
]


AGENT_REQUIREMENTS = "psutil>=5.9\nrequests>=2.31\npywin32>=306; platform_system=='Windows'\n"

AGENT_README = """\
Sudarshan EDR - Agent
======================

This folder contains ONLY the endpoint agent - no server code, no
dashboard, no other agents' data. Run it on a machine you own or are
explicitly authorized to monitor (see edr/config.py). This folder can be
extracted and installed entirely as a normal (non-admin) user - see below.

Setup:
    pip3 install -r requirements.txt

RECOMMENDED - one command, always the strongest available protection,
no flags/choices to make:

    Windows (elevated / "Run as administrator" prompt - required,
    creating any Windows Service needs it):
        python3 deploy\\install_windows.py --server http://SERVER_IP:8443 --token THE_TOKEN

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
