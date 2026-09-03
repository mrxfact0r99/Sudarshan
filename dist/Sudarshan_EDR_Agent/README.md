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
        python deploy\install_windows.py --server http://SERVER_IP:8443 --token THE_TOKEN

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
    python deploy\install_agent.py --mode user --server http://SERVER_IP:8443 --token THE_TOKEN
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
