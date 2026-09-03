#!/usr/bin/env python3
"""
Sudarshan EDR - Windows one-command installer.

No --mode flag, no choices to make. This always installs the STRONGEST
protection available on Windows in a single command:
  - A real Windows Service ('SudarshanEDRAgent') running as LocalSystem.
  - The service object's own ACL hardened to SYSTEM + Administrators
    only (not just Stop - Query/Read too).
  - The install folder locked so a standard user gets "Access is
    denied" trying to delete or modify anything in it.

This calls the exact same, already-tested functions that
deploy/install_agent.py --mode service uses (write_instance_config,
install_windows_service_mode) - nothing is reimplemented here, so
there's no separate code path that could drift or introduce a new bug.

MUST be run from an elevated ("Run as administrator") Command Prompt or
PowerShell - creating any Windows Service is itself an OS-level
admin-only action, so there is no admin-free way to do this. If you
specifically want the no-admin-install alternative (folder+process
lock via DACL, still ends up admin-only to actually stop), use
`python deploy\\install_agent.py --mode user ...` instead - that path
is unchanged and still available.

Usage (elevated prompt):
    python deploy\\install_windows.py --server http://SERVER_IP:8443 --token THE_TOKEN

After this finishes:
  - Dashboard Start/Stop toggles collection on/off; the endpoint stays
    Online either way.
  - Dashboard Terminate shuts the service down completely (gated by the
    dashboard login) - and separately, no standard Windows user/Task
    Manager/`taskkill`/`net stop` can touch it either; only an elevated
    admin session can (Services console, or `net stop SudarshanEDRAgent`
    run elevated).
  - Every completed collection cycle auto-generates a PDF report on the
    server; re-running the installer later (e.g. to point at a new
    server) is safe and just re-enrolls cleanly.
"""

import argparse
import os
import platform
import sys

if platform.system() != "Windows":
    print("This installer is Windows-only. On Linux, use:")
    print("  sudo python3 deploy/install_linux.py --server ... --token ...")
    sys.exit(1)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import install_agent as shared  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--server", required=True, help="EDR server URL, e.g. http://192.168.1.50:8443")
    parser.add_argument("--token", required=True, help="Enrollment token given to you by the server owner")
    args = parser.parse_args()

    if not shared._is_elevated_windows():
        print("! This needs an elevated ('Run as administrator') Command Prompt or PowerShell.")
        print("  Right-click Command Prompt / PowerShell -> 'Run as administrator', then re-run:")
        print(f"    python deploy\\install_windows.py --server {args.server} --token {args.token}")
        sys.exit(1)

    shared.write_instance_config(args.server, args.token)
    shared.install_windows_service_mode()


if __name__ == "__main__":
    main()
