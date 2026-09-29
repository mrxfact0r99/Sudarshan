import ctypes
import os
import platform
import subprocess
import sys

IS_WINDOWS = platform.system() == "Windows"


def _log(msg):
    print(f"[edr_self_protect] {msg}")


def protect_current_process():

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

    if not IS_WINDOWS:
        return False
    if not os.path.isdir(folder_path):
        _log(f"skip folder protection - not a directory: {folder_path}")
        return False

    everyone = "*S-1-1-0"
    admins = "*S-1-5-32-544"
    system = "*S-1-5-18"

    commands = [
 
        ["icacls", folder_path, "/inheritance:d"],

        ["icacls", folder_path, "/grant:r", f"{admins}:(OI)(CI)F", "/T", "/C"],
        ["icacls", folder_path, "/grant:r", f"{system}:(OI)(CI)F", "/T", "/C"],

        ["icacls", folder_path, "/deny", f"{everyone}:(OI)(CI)(DE,DC)", "/T", "/C"],

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

    if not IS_WINDOWS:
        return False

    python_exe = sys.executable
    tr = f'"{python_exe}" "{script_path}" {args}'.strip()

    cmd = [
        "schtasks", "/create", "/tn", task_name,
        "/tr", tr,
        "/sc", "onlogon",
        "/rl", "limited",
        "/f", 
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

    if not IS_WINDOWS:
        return False
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


if __name__ == "__main__":

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
