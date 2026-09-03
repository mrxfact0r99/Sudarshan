#!/usr/bin/env python3
"""
Sudarshan EDR - Agent installer.

Two ways to deploy the agent release for real (not just a quick manual
test), controlled by --mode:

  --mode user (DEFAULT on Windows, no admin/elevation needed at all):
      - Locks the extracted agent folder against deletion by a standard
        user (deploy/edr_self_protect_windows.py: protect_folder()).
      - Registers a per-user Scheduled Task (no admin needed to create
        a task that runs at YOUR OWN logon with your own privileges)
        so the agent starts automatically.
      - The agent process, once running, locks its OWN process DACL
        (protect_current_process(), called from edr/agent.py at
        startup) so a standard user's Task Manager "End Task" /
        `taskkill` fails with "Access is denied" - only an actually
        elevated admin session can still stop it.
      This is the recommended default: extracting the folder and
      installing it never prompts a normal user for admin rights; the
      ONLY thing that ends up admin-only is ending the running task /
      deleting the folder.

  --mode service (Windows: elevated "Run as administrator" required;
                  Linux: this is the only mode, always root/sudo):
      - Windows: installs+starts a real Windows Service running as
        LocalSystem - the strongest protection available, but Windows
        itself requires an elevated session to create any service, so
        this mode can never be admin-free; use --mode user instead if
        that matters more to you than this mode's extra strength.
      - Linux: installs+enables a systemd unit running as root. There
        is no Linux equivalent of --mode user's process self-DACL
        trick: on Linux, a process's own (non-root) owner can ALWAYS
        signal/kill their own processes - the kernel does not offer an
        opt-out for same-uid delivery the way Windows' DACL model does
        for same-user handles. So on Linux, "only root can end task" is
        only achievable by actually running the agent as a different
        (root) account, which is unavoidably an admin-only step.

Only install this on a machine you own or are explicitly authorized to
monitor - see edr/config.py.

Usage:
    Windows (no admin needed - default):
        python deploy\\install_agent.py --server http://192.168.1.50:8443 --token THE_TOKEN

    Windows (elevated prompt, strongest/LocalSystem protection):
        python deploy\\install_agent.py --mode service --server http://192.168.1.50:8443 --token THE_TOKEN

    Linux (sudo, always required):
        sudo python3 deploy/install_agent.py --server http://192.168.1.50:8443 --token THE_TOKEN
"""

import argparse
import json
import os
import platform
import subprocess
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INSTANCE_CONFIG_PATH = os.path.join(PROJECT_ROOT, "edr", "instance_config.json")
SERVICE_UNIT_SRC = os.path.join(PROJECT_ROOT, "deploy", "edr-agent.service")
SERVICE_UNIT_DST = "/etc/systemd/system/edr-agent.service"
IS_WINDOWS = platform.system() == "Windows"

sys.path.insert(0, os.path.join(PROJECT_ROOT, "deploy"))
import edr_self_protect_windows as self_protect  # noqa: E402
import edr_self_protect_linux as self_protect_linux  # noqa: E402


def _is_elevated_windows():
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def _is_root_linux():
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def write_instance_config(server, token):
    with open(INSTANCE_CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump({"server_url": server, "enroll_token": token}, f, indent=2)
    print(f"Wrote {INSTANCE_CONFIG_PATH}")


def _harden_service_acl():
    """Explicitly lock down the SERVICE OBJECT's own ACL (separate from the
    process's ACL) so only SYSTEM and Administrators have ANY rights over
    it - not just Stop, but Start/PauseContinue/UserDefinedControl and even
    Query/Read. Windows' own default ACL already denies Stop to standard
    users, but it still grants them read/query rights; this removes that
    too and makes the restriction explicit rather than relying on the
    platform default. Run this only after 'install' has created the
    service, and only from an elevated prompt (enforced by the caller).
    SY = LocalSystem, BA = Built-in Administrators. No ACE for any other
    SID means everyone else is implicitly denied all rights.
    """
    sddl = (
        "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)"
        "(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)"
    )
    print("-> sc sdset SudarshanEDRAgent (restricting service ACL to SYSTEM + Administrators)")
    result = subprocess.run(["sc", "sdset", "SudarshanEDRAgent", sddl])
    if result.returncode != 0:
        print(f"! Warning: could not harden the service ACL (exit {result.returncode}). "
              "The service is still LocalSystem-protected against Task Manager/kill, "
              "but 'sc stop' by a non-admin may still be reachable at the SCM level "
              "(Windows' own default there already denies Stop to standard users).")


def install_windows_user_mode(server, token):
    """No admin/elevation required at any step. See this file's module
    docstring and deploy/edr_self_protect_windows.py for exactly how
    'no admin to install, but admin to end task / delete the folder'
    is achieved without a Windows Service."""
    if self_protect.is_elevated():
        print("(Running elevated is fine too - this mode just doesn't require it.)")

    print(f"-> protecting install folder against deletion: {PROJECT_ROOT}")
    folder_ok = self_protect.protect_folder(PROJECT_ROOT)

    agent_script = os.path.join(PROJECT_ROOT, "edr", "agent.py")
    print("-> registering per-user logon task (no admin needed)")
    task_ok = self_protect.register_logon_task(
        agent_script, f'--server "{server}"', task_name="SudarshanEDRAgent"
    )

    print()
    if folder_ok:
        print("Folder protection: ON - a standard user can no longer delete")
        print(f"  {PROJECT_ROOT}\n  or anything inside it (Access is denied).")
    else:
        print("! Folder protection could not be applied (see warnings above) -")
        print("  the agent will still run, just without that hardening.")

    if task_ok:
        print("\nAuto-start: ON - 'SudarshanEDRAgent' now runs at every logon for")
        print("this user, and has just been started for this session too.")
        print("Process protection (Task Manager End Task requires admin) is")
        print("applied by the agent itself a few seconds after each start -")
        print("see edr/agent.py's call to protect_current_process().")
    else:
        print("\n! Auto-start task could not be registered (see warnings above).")
        print("  You can still start the agent manually any time:")
        print(f'  python "{agent_script}" --server "{server}"')

    print(
        "\nWant the strongest protection instead (real LocalSystem Windows\n"
        "Service, at the cost of needing an elevated prompt to install it)?\n"
        "  python deploy\\install_agent.py --mode service --server ... --token ...\n"
    )


def install_windows_service_mode():
    if not _is_elevated_windows():
        print("! --mode service needs an elevated ('Run as administrator') prompt.")
        print("  (Or drop --mode service to install without admin rights instead.)")
        sys.exit(1)

    try:
        import win32serviceutil  # noqa: F401
    except ImportError:
        print("! pywin32 is required. Install it first:  pip install pywin32")
        sys.exit(1)

    service_script = os.path.join(PROJECT_ROOT, "deploy", "edr_service_windows.py")
    for cmd in ("install", "start"):
        print(f"-> {service_script} {cmd}")
        result = subprocess.run([sys.executable, service_script, cmd])
        if result.returncode != 0:
            print(f"! Service {cmd} step failed (exit {result.returncode}).")
            sys.exit(result.returncode)

    _harden_service_acl()
    self_protect.protect_folder(PROJECT_ROOT)

    print(
        "\nDone. 'SudarshanEDRAgent' is now running as a LocalSystem service.\n"
        "A standard user cannot End Task it from Task Manager - only an\n"
        "administrator session can (Services console, or:\n"
        "  net stop SudarshanEDRAgent   <- must be run elevated).\n"
    )


def install_linux():
    if not _is_root_linux():
        print("! Please re-run this with sudo:  sudo python3 deploy/install_agent.py ...")
        sys.exit(1)

    with open(SERVICE_UNIT_SRC, "r", encoding="utf-8") as f:
        unit_text = f.read()

    # Point the unit at wherever this release actually lives and at the
    # interpreter currently running this installer, rather than the
    # placeholder path baked into the template.
    unit_text = unit_text.replace("/opt/sudarshan-edr", PROJECT_ROOT)
    unit_text = unit_text.replace(
        "ExecStart=/usr/bin/python3 -m edr.agent --server http://ServerIP:8443",
        f"ExecStart={sys.executable} -m edr.agent",
    )

    with open(SERVICE_UNIT_DST, "w", encoding="utf-8") as f:
        f.write(unit_text)
    print(f"Wrote {SERVICE_UNIT_DST}")

    for cmd in (["systemctl", "daemon-reload"], ["systemctl", "enable", "--now", "edr-agent"]):
        print(f"-> {' '.join(cmd)}")
        result = subprocess.run(cmd)
        if result.returncode != 0:
            print(f"! {' '.join(cmd)} failed (exit {result.returncode}).")
            sys.exit(result.returncode)

    # Protect the install folder itself, not just the running process -
    # otherwise a standard user could `rm -rf` PROJECT_ROOT, edit the
    # collector scripts, or delete .agent_id even though they can't kill
    # the (root-owned) service. See deploy/edr_self_protect_linux.py.
    print(f"-> protecting install folder against deletion/tampering: {PROJECT_ROOT}")
    folder_ok = self_protect_linux.protect_folder(PROJECT_ROOT)

    print(
        "\nDone. 'edr-agent' is now running as root via systemd.\n"
        "A normal user's `kill`/`kill -9 <pid>` on it returns "
        "'Operation not permitted' - only root/sudo can stop it:\n"
        "  sudo systemctl stop edr-agent\n"
    )
    if folder_ok:
        print(
            f"Folder protection: ON - a standard user can no longer delete, rename,\n"
            f"or modify {PROJECT_ROOT}\nor anything inside it (Permission denied)."
        )
    else:
        print("! Folder protection could not be applied (see warnings above) -")
        print("  the agent will still run, just without that hardening.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", required=True, help="EDR server URL, e.g. http://192.168.1.50:8443")
    parser.add_argument("--token", required=True, help="Enrollment token given to you by the server owner")
    parser.add_argument(
        "--mode", choices=["user", "service"], default="user",
        help="Windows: 'user' (default, no admin needed) or 'service' "
             "(elevated, real LocalSystem Windows Service). Linux always "
             "uses the root/systemd path regardless of this flag.",
    )
    args = parser.parse_args()

    write_instance_config(args.server, args.token)

    if IS_WINDOWS:
        if args.mode == "service":
            install_windows_service_mode()
        else:
            install_windows_user_mode(args.server, args.token)
    else:
        install_linux()


if __name__ == "__main__":
    main()
