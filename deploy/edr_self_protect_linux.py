"""
Sudarshan EDR - Linux folder self-protection.

This is the Linux counterpart to deploy/edr_self_protect_windows.py's
protect_folder()/unprotect_folder(). Linux has no equivalent of a
process's own self-owned DACL rewrite (see install_agent.py's module
docstring for why "only root can end task" is achieved differently -
via systemd running the agent as root, so the kernel's own kill(2) UID
check blocks a standard user's signal), but the INSTALL FOLDER itself
still needs the same "a standard user can't delete/tamper with it"
protection that Windows gets from protect_folder(). Without this, a
standard user could `rm -rf` the install folder, edit the collector
scripts, or delete .agent_id / instance_config.json even though they
can't kill the running (root-owned) process.

How protect_folder() works:
    On Linux/POSIX, deleting, renaming, or creating an entry inside a
    directory is governed by WRITE permission on that DIRECTORY (not by
    who owns the individual file inside it) - see `man 2 unlink`. So:
      1. chown -R root:root <folder>   - the standard/non-root user who
         extracted the release no longer OWNS any of it.
      2. chmod so group/other lose write access on every directory
         (removes their ability to add/remove/rename entries) AND on
         every file (removes their ability to overwrite file content),
         while keeping read (+execute on directories, and on files that
         were already executable) so the files can still be read and
         run normally.
    Net effect: a standard user gets "Permission denied" on
    `rm`, `rm -rf`, editing, or renaming anything in the folder. Root
    (and the systemd service, which runs as root - see edr-agent.service)
    can still do anything to it, same as the Windows Administrators/
    SYSTEM carve-out in protect_folder() there.

This must be run as root (systemd install is already root-only - see
install_agent.py's _is_root_linux() check, called right before this).
Best-effort: any failure is caught, logged, and does NOT stop the agent
install from finishing - a folder where this happens to fail still gets
a working, just less tamper-resistant, agent (identical philosophy to
the Windows module).
"""

import os
import stat
import subprocess


def _log(msg):
    print(f"[edr_self_protect_linux] {msg}")


def _is_root():
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def protect_folder(folder_path):
    """Lock an install folder down to root-only write/delete access.

    Returns True if applied, False otherwise (never raises).
    """
    if not os.path.isdir(folder_path):
        _log(f"skip folder protection - not a directory: {folder_path}")
        return False
    if not _is_root():
        _log("skip folder protection - must be run as root (use sudo).")
        return False

    try:
        # 1. Ownership: root:root, so the extracting user no longer owns
        #    any file/dir here and can't rely on owner-write permission.
        result = subprocess.run(["chown", "-R", "root:root", folder_path],
                                 capture_output=True, text=True)
        if result.returncode != 0:
            _log(f"chown failed: {result.stderr.strip()}")
            return False

        # 2. Permissions: walk the tree and strip group/other WRITE bits
        #    everywhere (directories AND files), while preserving whatever
        #    read/execute bits already existed (so scripts stay runnable
        #    and files stay readable) - and preserving OWNER (root) write
        #    so root/the systemd service can still update .agent_id,
        #    .agent_status.json, instance_config.json, logs, etc.
        for dirpath, dirnames, filenames in os.walk(folder_path):
            for name in dirnames + filenames:
                path = os.path.join(dirpath, name)
                try:
                    current = stat.S_IMODE(os.lstat(path).st_mode)
                    new_mode = current & ~(stat.S_IWGRP | stat.S_IWOTH)
                    os.chmod(path, new_mode)
                except OSError as e:
                    _log(f"chmod failed on {path}: {e}")
                    return False
        root_mode = stat.S_IMODE(os.lstat(folder_path).st_mode)
        os.chmod(folder_path, root_mode & ~(stat.S_IWGRP | stat.S_IWOTH))

    except Exception as e:
        _log(f"folder protection failed: {e}")
        return False

    _log(f"folder protection applied to {folder_path} - a standard user can "
         f"no longer delete, rename, or modify this folder or anything "
         f"inside it (Permission denied); only root can.")
    return True


def unprotect_folder(folder_path):
    """Undo protect_folder(): hand the folder back to a normal, writable
    state (owner-writable by root, but that's the point of un-protecting -
    typically used right before a legitimate uninstall/reinstall). Must
    be run as root, same as protect_folder().
    """
    if not os.path.isdir(folder_path):
        return False
    if not _is_root():
        _log("skip - must be run as root (use sudo).")
        return False

    try:
        result = subprocess.run(["chmod", "-R", "u+rwX,go+rwX", folder_path],
                                 capture_output=True, text=True)
        if result.returncode != 0:
            _log(f"chmod failed: {result.stderr.strip()}")
            return False
    except Exception as e:
        _log(f"unprotect failed: {e}")
        return False

    _log(f"folder protection removed from {folder_path} - it can be "
         f"deleted/modified normally again.")
    return True


if __name__ == "__main__":
    # Standalone test CLI, mirrors edr_self_protect_windows.py's:
    #   sudo python3 deploy/edr_self_protect_linux.py protect-folder .
    #   sudo python3 deploy/edr_self_protect_linux.py unprotect-folder .
    import argparse

    parser = argparse.ArgumentParser(description="Sudarshan EDR Linux self-protection - standalone test CLI")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p1 = sub.add_parser("protect-folder")
    p1.add_argument("path")
    p2 = sub.add_parser("unprotect-folder")
    p2.add_argument("path")
    ns = parser.parse_args()

    if ns.cmd == "protect-folder":
        protect_folder(os.path.abspath(ns.path))
    elif ns.cmd == "unprotect-folder":
        unprotect_folder(os.path.abspath(ns.path))
