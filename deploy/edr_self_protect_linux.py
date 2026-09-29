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
    if not os.path.isdir(folder_path):
        _log(f"skip folder protection - not a directory: {folder_path}")
        return False
    if not _is_root():
        _log("skip folder protection - must be run as root (use sudo).")
        return False

    try:

        result = subprocess.run(["chown", "-R", "root:root", folder_path],
                                 capture_output=True, text=True)
        if result.returncode != 0:
            _log(f"chown failed: {result.stderr.strip()}")
            return False

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
