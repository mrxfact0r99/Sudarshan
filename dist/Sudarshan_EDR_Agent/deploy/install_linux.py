#!/usr/bin/env python3
"""
Sudarshan EDR - Linux one-command installer.

No mode flag - Linux only ever has this one path (there is no Linux
equivalent of Windows' no-admin DACL self-lock trick; see
deploy/install_agent.py's module docstring for why). One command does
everything:
  - Installs + enables 'edr-agent' as a systemd unit running as root
    (deploy/edr-agent.service). A normal user's kill/kill -9/killall
    against it returns "Operation not permitted" - the kernel itself
    blocks it (same-UID or root/CAP_KILL only for signal delivery).
  - Locks the install folder down to root-only write/delete access
    (deploy/edr_self_protect_linux.py: chown root:root + strip
    group/other write, recursively) - a standard user gets "Permission
    denied" trying to delete, rename, or edit anything in it, including
    .agent_id or the collector scripts.

This calls the exact same, already-tested functions that
deploy/install_agent.py uses on Linux (write_instance_config,
install_linux) - nothing is reimplemented here.

MUST be run with sudo / as root.

Usage:
    sudo python3 deploy/install_linux.py --server http://SERVER_IP:8443 --token THE_TOKEN

After this finishes:
  - Dashboard Start/Stop toggles collection on/off; the endpoint stays
    Online either way.
  - Dashboard Terminate shuts the agent down completely (gated by the
    dashboard login) - and separately, no non-root user can `kill` the
    process or delete/tamper with the install folder either; only root
    (sudo systemctl stop edr-agent) can.
  - Every completed collection cycle auto-generates a PDF report on the
    server; re-running this installer later (e.g. to point at a new
    server) is safe and just re-enrolls cleanly.
"""

import argparse
import os
import platform
import sys

if platform.system() == "Windows":
    print("This installer is Linux-only. On Windows, use (elevated prompt):")
    print("  python deploy\\install_windows.py --server ... --token ...")
    sys.exit(1)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import install_agent as shared  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--server", required=True, help="EDR server URL, e.g. http://192.168.1.50:8443")
    parser.add_argument("--token", required=True, help="Enrollment token given to you by the server owner")
    args = parser.parse_args()

    if not shared._is_root_linux():
        print("! Please re-run this with sudo:")
        print(f"    sudo python3 deploy/install_linux.py --server {args.server} --token {args.token}")
        sys.exit(1)

    shared.write_instance_config(args.server, args.token)
    shared.install_linux()


if __name__ == "__main__":
    main()
