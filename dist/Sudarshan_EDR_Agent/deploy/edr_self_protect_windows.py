"""
Sudarshan EDR - Windows self-protection (no admin needed to install).

This is a DIFFERENT protection path from deploy/edr_service_windows.py.
That file gets "only admin can end task" from the OS by running the agent
as LocalSystem - which is strong, but installing a Windows Service is
itself an admin-only action, so a standard user can never set that path
up on their own.

This file gets a similar "only admin can end task" result WITHOUT ever
requiring elevation, using two facts about Windows that don't need admin
rights, only the rights an object's owner already has by default:

  1. A process's creator is its owner and can rewrite that process
     object's own DACL (WRITE_DAC is part of the default rights an
     owner gets - see MSDN "process security and access rights"). So a
     normal, non-elevated process CAN restrict who is allowed to open
     a handle to itself with PROCESS_TERMINATE, at the moment it starts.
  2. The person who extracts/creates a folder owns it, and an owner can
     set that folder's own ACL too, without being an admin.

What protect_current_process() actually does:
    Rewrites the running process's DACL so that:
      - LocalSystem and (the real, elevated) Administrators token can
        still do anything to it (ALLOW ACEs placed first).
      - Everyone else (Everyone / any standard-user token, INCLUDING a
        non-elevated admin's filtered token under UAC) is explicitly
        DENIED PROCESS_TERMINATE, PROCESS_SUSPEND_RESUME, WRITE_DAC and
        WRITE_OWNER - so they can't kill it, suspend it, or undo this
        protection by rewriting the DACL again.
      - Everyone still keeps harmless rights (query info, synchronize)
        so Task Manager can still list/see it, dashboards can still
        check it's alive, etc. - it just can't be ended.
    Net effect: Task Manager "End Task" / `taskkill` from a standard
    user (or a non-elevated admin) fails with "Access is denied". An
    ACTUALLY elevated ("Run as administrator") session can still end
    it, because Windows lets a full/elevated token with SeDebugPrivilege
    bypass object DACLs entirely - which is exactly the admin-only
    behaviour that's wanted here.

What protect_folder() actually does:
    Uses icacls (shipped with every Windows install, no admin needed to
    run it against a folder you own) to:
      - Break inheritance so nothing above this folder can quietly
        re-grant rights inside it.
      - DENY Delete + Delete-subfolders-and-files to Everyone,
        recursively - so a standard user (even the same user who
        extracted/installed it) gets "Access is denied" trying to
        delete the folder, any file in it, or the folder itself, from
        Explorer, `del`, `rmdir /s`, PowerShell, etc.
      - Explicitly (re)grant Administrators and SYSTEM Full Control,
        recursively, so an elevated session (or the real service path)
        can still manage/uninstall it.
      - Still allow Everyone to read/write/execute the files that are
        already there and add new ones (the running agent needs to
        keep updating its own status/log/id files) - just not delete
        them. See edr/agent_status.py's docstring for why write_status()
        writes in place instead of via a delete-requiring rename.

Note on protect_folder() and elevated admins: icacls stores new explicit
Deny ACEs ahead of explicit Allow ACEs in the folder's DACL (its normal
canonical ordering), and access checks stop at the first ACE that
resolves a given bit. That means even an elevated admin's request to
DELETE hits the Deny-Everyone(DE,DC) ACE before it would reach their own
Allow-Administrators(F) ACE for that same bit, so a direct delete still
fails for them too. It's not a bug - it's what makes this "admin-only,
and deliberate" rather than "admin-only by an accident of ordering":
WRITE_DAC is a separate bit that the Deny ACE never covers, so an
elevated admin still keeps the right to edit the ACL itself. In
practice that means an elevated admin removes the block in one extra,
explicit step before deleting (unprotect_folder(), or the admin's own
`icacls FOLDER /remove:d "*S-1-1-0"`), rather than deleting directly by
accident - this is the same two-step pattern real antivirus/EDR
products use for their own install folders.

Neither function needs pywin32 for protect_folder() (pure subprocess +
icacls). protect_current_process() needs pywin32 (already a listed
agent dependency on Windows - see requirements.txt). Both are best
effort: any failure is caught, logged, and does NOT stop the agent from
running - a machine where this happens to fail still gets a working,
just less tamper-resistant, agent.

This module only does anything on Windows; importing/calling it on
Linux/macOS is a harmless no-op (see deploy/install_agent.py's
install_linux(), which uses the real root-owned systemd path instead,
since Linux has no exact equivalent of a self-owned DACL rewrite - see
its own note below).
"""

import ctypes
import os
import platform
import subprocess
import sys

IS_WINDOWS = platform.system() == "Windows"


def _log(msg):
    print(f"[edr_self_protect] {msg}")


def protect_current_process():
    """Best-effort: lock this running process's DACL so a standard user
    (incl. a non-elevated admin) cannot End Task / suspend / re-DACL it,
    while SYSTEM and a genuinely elevated Administrator still can.

    Returns True if the protection was applied, False otherwise (never
    raises - callers should treat this purely as a hardening step, not
    something the agent's own startup should depend on).
    """
    if not IS_WINDOWS:
        return False

    try:
        import win32api
        import win32con
        import win32security
    except ImportError:
        _log("pywin32 not installed - skipping process self-protection "
             "(agent still runs, just without this hardening). "
             "Install with: pip install pywin32")
        return False

    try:
        # Access-right bits not always exposed as win32con constants on
        # older pywin32 builds - fall back to the documented raw values.
        PROCESS_TERMINATE = getattr(win32con, "PROCESS_TERMINATE", 0x0001)
        PROCESS_SUSPEND_RESUME = getattr(win32con, "PROCESS_SUSPEND_RESUME", 0x0800)
        PROCESS_QUERY_INFORMATION = getattr(win32con, "PROCESS_QUERY_INFORMATION", 0x0400)
        PROCESS_QUERY_LIMITED_INFORMATION = getattr(win32con, "PROCESS_QUERY_LIMITED_INFORMATION", 0x1000)
        SYNCHRONIZE = getattr(win32con, "SYNCHRONIZE", 0x00100000)
        READ_CONTROL = getattr(win32con, "READ_CONTROL", 0x00020000)
        WRITE_DAC = getattr(win32con, "WRITE_DAC", 0x00040000)
        WRITE_OWNER = getattr(win32con, "WRITE_OWNER", 0x00080000)
        PROCESS_ALL_ACCESS = getattr(win32con, "PROCESS_ALL_ACCESS", 0x1FFFFF)

        h_process = win32api.GetCurrentProcess()

        system_sid = win32security.CreateWellKnownSid(win32security.WinLocalSystemSid, None)
        admins_sid = win32security.CreateWellKnownSid(win32security.WinBuiltinAdministratorsSid, None)
        everyone_sid = win32security.CreateWellKnownSid(win32security.WinWorldSid, None)

        dacl = win32security.ACL()
        # Order matters: Windows access checks walk the ACL top to
        # bottom and stop granting/denying per requested bit as soon as
        # a matching ACE is hit. Putting the specific SYSTEM/Admins
        # ALLOW-everything ACEs first means those two trustees get
        # PROCESS_ALL_ACCESS granted before the later blanket Everyone
        # DENY is ever reached - even though Administrators is also
        # technically a member of Everyone.
        dacl.AddAccessAllowedAce(win32security.ACL_REVISION, PROCESS_ALL_ACCESS, system_sid)
        dacl.AddAccessAllowedAce(win32security.ACL_REVISION, PROCESS_ALL_ACCESS, admins_sid)

        deny_mask = PROCESS_TERMINATE | PROCESS_SUSPEND_RESUME | WRITE_DAC | WRITE_OWNER
        dacl.AddAccessDeniedAce(win32security.ACL_REVISION, deny_mask, everyone_sid)

        allow_mask = PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE | READ_CONTROL
        dacl.AddAccessAllowedAce(win32security.ACL_REVISION, allow_mask, everyone_sid)

        sd = win32security.SECURITY_DESCRIPTOR()
        sd.SetSecurityDescriptorDacl(1, dacl, 0)

        win32security.SetKernelObjectSecurity(h_process, win32security.DACL_SECURITY_INFORMATION, sd)
        _log("process self-protection applied - a standard user's End Task/"
             "kill will now fail with Access is denied; an elevated admin "
             "session can still stop it.")
        return True
    except Exception as e:
        _log(f"could not apply process self-protection ({e}) - agent still "
             f"runs normally, just without this hardening.")
        return False


def protect_folder(folder_path):
    """Best-effort: lock down folder_path (recursively) via icacls so a
    standard user (including the same user who installed it) cannot
    delete it or anything inside it, while Administrators/SYSTEM keep
    full control. Safe to call without admin rights as long as the
    caller owns folder_path (true right after extracting/installing it
    as that same user).

    Returns True if applied, False otherwise (never raises).
    """
    if not IS_WINDOWS:
        return False
    if not os.path.isdir(folder_path):
        _log(f"skip folder protection - not a directory: {folder_path}")
        return False

    # Well-known SIDs so this works regardless of machine locale:
    #   S-1-1-0     Everyone
    #   S-1-5-32-544 BUILTIN\Administrators
    #   S-1-5-18    LocalSystem
    everyone = "*S-1-1-0"
    admins = "*S-1-5-32-544"
    system = "*S-1-5-18"

    commands = [
        # Stop inheriting permissions from the parent folder (e.g. the
        # user's normal Downloads/Desktop ACL), so nothing above this
        # folder can quietly re-grant delete rights inside it.
        ["icacls", folder_path, "/inheritance:d"],
        # Full control for Administrators and SYSTEM, recursively -
        # this is what lets an elevated session (or the service/root
        # deploy path) still manage or uninstall the folder.
        ["icacls", folder_path, "/grant:r", f"{admins}:(OI)(CI)F", "/T", "/C"],
        ["icacls", folder_path, "/grant:r", f"{system}:(OI)(CI)F", "/T", "/C"],
        # Explicit DENY of Delete (D) on every file/subfolder, plus
        # deny Delete-subfolders-and-files (DC, i.e. delete-child) at
        # the container level - NTFS lets a delete succeed via EITHER
        # right, so both must be denied or a standard user could still
        # remove things one way even with the other blocked.
        ["icacls", folder_path, "/deny", f"{everyone}:(OI)(CI)(DE,DC)", "/T", "/C"],
        # Everyone still keeps read/write/execute/add-new-file rights,
        # just not delete - the running agent (same standard user) still
        # needs to update its own status/log/.agent_id files in place.
        ["icacls", folder_path, "/grant", f"{everyone}:(OI)(CI)(RX,W,AD)", "/T", "/C"],
    ]

    for cmd in commands:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            _log(f"'{' '.join(cmd)}' failed (exit {result.returncode}): "
                 f"{result.stderr.strip() or result.stdout.strip()}")
            return False

    _log(f"folder protection applied to {folder_path} - a standard user "
         f"can no longer delete this folder or its contents; only "
         f"Administrators/SYSTEM can.")
    return True


def unprotect_folder(folder_path):
    """Undo protect_folder(): remove the Everyone deny-delete ACE and the
    inheritance break, so the folder can be deleted/uninstalled normally
    again. Needs to be run from an elevated ('Run as administrator')
    session - a standard user's token never gets WRITE_DAC on this
    folder in the first place (see protect_folder()'s docstring), so
    they cannot call this to undo their own restriction; that's the
    point. Useful for legitimately uninstalling the agent, or for your
    own testing during project demo/viva.
    """
    if not IS_WINDOWS:
        return False
    if not os.path.isdir(folder_path):
        return False

    commands = [
        ["icacls", folder_path, "/remove:d", "*S-1-1-0", "/T", "/C"],
        ["icacls", folder_path, "/inheritance:e"],
    ]
    for cmd in commands:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            _log(f"'{' '.join(cmd)}' failed (exit {result.returncode}): "
                 f"{result.stderr.strip() or result.stdout.strip()}. "
                 f"Are you running this elevated?")
            return False

    _log(f"folder protection removed from {folder_path} - it can be "
         f"deleted normally again.")
    return True


def register_logon_task(script_path, args, task_name="SudarshanEDRAgent"):
    """Register a per-user Scheduled Task that runs `script_path` with
    `args` at this user's logon, using /RL LIMITED (standard, non-
    elevated run level) so creating it does NOT require admin rights -
    unlike a Windows Service, a task that runs at your own logon with
    your own (non-elevated) privileges is something any standard user
    can schedule for themselves.

    This is what makes the agent start automatically without needing
    the extracted folder to be run manually every time, while still
    keeping the whole install admin-free. Actual "can't be ended by a
    standard user" protection comes from protect_current_process(),
    called by the agent itself right after it starts - not from this
    task registration.
    """
    if not IS_WINDOWS:
        return False

    python_exe = sys.executable
    tr = f'"{python_exe}" "{script_path}" {args}'.strip()

    cmd = [
        "schtasks", "/create", "/tn", task_name,
        "/tr", tr,
        "/sc", "onlogon",
        "/rl", "limited",
        "/f",  # overwrite if it already exists (e.g. re-running the installer)
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        _log(f"could not register logon task (exit {result.returncode}): "
             f"{result.stderr.strip() or result.stdout.strip()}")
        return False

    _log(f"logon task '{task_name}' registered (runs at your next logon, "
         f"no admin needed). Starting it now for this session too...")
    subprocess.run(["schtasks", "/run", "/tn", task_name], capture_output=True, text=True)
    return True


def is_elevated():
    """True if the CURRENT process already has an elevated/admin token.
    Used by install_agent.py only to decide which message to print -
    never to gate the no-admin install path, which must work either way.
    """
    if not IS_WINDOWS:
        return False
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


if __name__ == "__main__":
    # Small standalone CLI, handy for testing/demoing this file on its
    # own (e.g. for a project viva) without running the full installer.
    #   python deploy\edr_self_protect_windows.py protect-folder .
    #   python deploy\edr_self_protect_windows.py unprotect-folder .   (run elevated)
    #   python deploy\edr_self_protect_windows.py protect-process       (protects THIS process; Ctrl+C to exit, or End Task it elevated to prove the point)
    import argparse
    import time

    parser = argparse.ArgumentParser(description="Sudarshan EDR self-protection - standalone test CLI")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p1 = sub.add_parser("protect-folder")
    p1.add_argument("path")
    p2 = sub.add_parser("unprotect-folder")
    p2.add_argument("path")
    sub.add_parser("protect-process")
    ns = parser.parse_args()

    if ns.cmd == "protect-folder":
        protect_folder(os.path.abspath(ns.path))
    elif ns.cmd == "unprotect-folder":
        unprotect_folder(os.path.abspath(ns.path))
    elif ns.cmd == "protect-process":
        protect_current_process()
        print(f"PID {os.getpid()} protected. Try Task Manager 'End Task' on it as a "
              f"standard user (should fail), then again from an elevated Task "
              f"Manager (should succeed). Sleeping - Ctrl+C here to exit normally.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
