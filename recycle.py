import os
import sys
import json
import struct
import platform
import configparser
import urllib.parse
from datetime import datetime, timedelta

EVIDENCE_DIR = "Evidences"


def detect_os():
    system = platform.system()
    if system == "Windows":
        return "Windows"
    elif system == "Linux":
        return "Linux"
    elif system == "Darwin":
        return "macOS"
    return f"Unknown ({system})"


def filetime_to_datetime(ft):
    """Convert a Windows FILETIME (100-ns intervals since 1601-01-01) to datetime."""
    if not ft or ft <= 0:
        return None
    try:
        return datetime(1601, 1, 1) + timedelta(microseconds=ft / 10)
    except (OverflowError, OSError):
        return None


def parse_index_file(path):
    """Parse a Windows $I metadata file (supports legacy and Win10+ formats)."""
    with open(path, "rb") as f:
        data = f.read()

    if len(data) < 24:
        return {"error": "File too short to be a valid $I record"}

    version = struct.unpack("<q", data[0:8])[0]
    file_size = struct.unpack("<q", data[8:16])[0]
    deleted_raw = struct.unpack("<q", data[16:24])[0]
    deleted_time = filetime_to_datetime(deleted_raw)

    try:
        if version == 1:
            name_bytes = data[24:]
            original_name = name_bytes.decode("utf-16-le", errors="replace").split("\x00")[0]
        else:
            name_len = struct.unpack("<i", data[24:28])[0]
            name_bytes = data[28:28 + name_len * 2]
            original_name = name_bytes.decode("utf-16-le", errors="replace").rstrip("\x00")
    except Exception as e:
        return {
            "version": version,
            "file_size": file_size,
            "deleted_time": deleted_time.isoformat() if deleted_time else None,
            "original_name": None,
            "parse_warning": f"Could not decode file name: {e}",
        }

    return {
        "version": version,
        "file_size": file_size,
        "deleted_time": deleted_time.isoformat() if deleted_time else None,
        "original_name": original_name,
    }


def collect_windows_recycle_bin():
    entries = []
    system_drive = os.environ.get("SystemDrive", "C:")
    root = f"{system_drive}\\$Recycle.Bin"

    if not os.path.isdir(root):
        return {"error": f"Recycle Bin root not found or inaccessible: {root}"}

    try:
        sid_dirs = os.listdir(root)
    except PermissionError:
        return {"error": f"Permission denied listing {root}. Run as Administrator."}

    for sid in sid_dirs:
        sid_path = os.path.join(root, sid)
        if not os.path.isdir(sid_path):
            continue

        try:
            files = os.listdir(sid_path)
        except PermissionError:
            entries.append({
                "sid": sid,
                "error": "Permission denied (likely another user's bin). Run as Administrator.",
            })
            continue

        for fname in files:
            if not fname.startswith("$I"):
                continue

            info_path = os.path.join(sid_path, fname)
            data_fname = "$R" + fname[2:]
            data_path = os.path.join(sid_path, data_fname)

            try:
                parsed = parse_index_file(info_path)
            except (PermissionError, FileNotFoundError) as e:
                parsed = {"error": str(e)}

            entries.append({
                "sid": sid,
                "index_file": info_path,
                "data_file": data_path if os.path.exists(data_path) else None,
                "data_file_recoverable": os.path.exists(data_path),
                **parsed,
            })

    return entries


def parse_trashinfo(path):
    config = configparser.ConfigParser(interpolation=None)
    try:
        config.read(path, encoding="utf-8")
        section = config["Trash Info"]
        original_path = urllib.parse.unquote(section.get("Path", ""))
        deletion_date = section.get("DeletionDate", None)
        return {"original_path": original_path, "deletion_date": deletion_date}
    except (configparser.Error, KeyError) as e:
        return {"error": f"Could not parse trashinfo: {e}"}


def collect_trash_dir(trash_root, label):
    entries = []
    info_dir = os.path.join(trash_root, "info")
    files_dir = os.path.join(trash_root, "files")

    if not os.path.isdir(info_dir):
        return entries

    try:
        info_files = os.listdir(info_dir)
    except PermissionError:
        return [{"trash_root": trash_root, "error": "Permission denied"}]

    for fname in info_files:
        if not fname.endswith(".trashinfo"):
            continue
        base_name = fname[: -len(".trashinfo")]
        info_path = os.path.join(info_dir, fname)
        parsed = parse_trashinfo(info_path)

        data_path = os.path.join(files_dir, base_name)
        exists = os.path.exists(data_path)
        size = None
        if exists:
            try:
                size = (
                    os.path.getsize(data_path)
                    if os.path.isfile(data_path)
                    else None
                )
            except OSError:
                size = None

        entries.append({
            "trash_source": label,
            "info_file": info_path,
            "data_file": data_path if exists else None,
            "data_file_recoverable": exists,
            "file_size": size,
            **parsed,
        })

    return entries


def collect_linux_trash():
    entries = []

    xdg_data_home = os.environ.get("XDG_DATA_HOME", os.path.expanduser("~/.local/share"))
    home_trash = os.path.join(xdg_data_home, "Trash")
    entries.extend(collect_trash_dir(home_trash, "home"))

    uid = os.getuid() if hasattr(os, "getuid") else None
    mount_points = ["/media", "/mnt", "/run/media"]
    for mount_base in mount_points:
        if not os.path.isdir(mount_base):
            continue
        try:
            for entry in os.listdir(mount_base):
                candidate_base = os.path.join(mount_base, entry)
                if not os.path.isdir(candidate_base):
                    continue
                for sub in [candidate_base] + [
                    os.path.join(candidate_base, s)
                    for s in os.listdir(candidate_base)
                    if os.path.isdir(os.path.join(candidate_base, s))
                ]:
                    trash_dir = os.path.join(sub, f".Trash-{uid}") if uid is not None else None
                    if trash_dir and os.path.isdir(trash_dir):
                        entries.extend(collect_trash_dir(trash_dir, f"volume:{sub}"))
        except (PermissionError, FileNotFoundError):
            continue

    return entries


def collect_recycle_bin(os_name):
    if os_name == "Windows":
        return collect_windows_recycle_bin()
    elif os_name == "Linux":
        return collect_linux_trash()
    else:
        raise SystemExit(
            f"Unsupported OS for recycle bin collection: {os_name}. "
            "This script currently supports Windows and Linux only."
        )


def ensure_evidence_dir():
    os.makedirs(EVIDENCE_DIR, exist_ok=True)


def save_evidence(entries, os_name):
    ensure_evidence_dir()
    fname = os.path.join(EVIDENCE_DIR, "recycle_bin.json")

    if isinstance(entries, dict) and "error" in entries:
        total = 0
    else:
        total = len(entries)

    payload = {
        "generated_at": datetime.now().isoformat(),
        "detected_os": os_name,
        "hostname": platform.node(),
        "total_deleted_items": total,
        "items": entries,
    }

    with open(fname, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False, default=str)

    return fname


def main():
    os_name = detect_os()
    print(f"[*] Detected OS: {os_name}")
    print("[*] Collecting recycle bin / trash evidence...")

    entries = collect_recycle_bin(os_name)

    if isinstance(entries, dict) and "error" in entries:
        print(f"[!] {entries['error']}")
    else:
        recoverable = sum(1 for e in entries if e.get("data_file_recoverable"))
        errors = sum(1 for e in entries if "error" in e)
        print(f"[*] Found {len(entries)} deleted item record(s).")
        print(f"[*] {recoverable} still have recoverable data on disk.")
        if errors:
            print(f"[!] {errors} record(s) had errors (see JSON for details).")

    fname = save_evidence(entries, os_name)
    print(f"[+] Evidence saved to: {fname}")


if __name__ == "__main__":
    main()