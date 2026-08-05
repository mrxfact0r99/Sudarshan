import os
import sys
import re
import json
import struct
import platform
from pathlib import Path
from datetime import datetime, timedelta

try:
    from ..common import detect_os
except ImportError:
    sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
    from common import detect_os

try:
    import winreg
except ImportError:
    winreg = None




def filetime_to_datetime(ft):
    if not ft or ft <= 0:
        return None
    try:
        return datetime(1601, 1, 1) + timedelta(microseconds=ft / 10)
    except (OverflowError, OSError):
        return None


def stat_times(path):
    try:
        st = os.stat(path)
        return {
            "accessed": datetime.fromtimestamp(st.st_atime).isoformat(),
            "modified": datetime.fromtimestamp(st.st_mtime).isoformat(),
            "size": st.st_size,
        }
    except OSError as e:
        return {"error": str(e)}


def safe_read_lines(path):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.readlines()



def parse_bash_history(path):
    entries = []
    lines = safe_read_lines(path)
    pending_ts = None

    for line in lines:
        line = line.rstrip("\n")
        if not line:
            continue
        m = re.match(r"^#(\d{9,10})$", line.strip())
        if m:
            pending_ts = datetime.fromtimestamp(int(m.group(1))).isoformat()
            continue
        entries.append({"command": line, "timestamp": pending_ts})
        pending_ts = None

    return entries


def parse_zsh_history(path):
    entries = []
    lines = safe_read_lines(path)

    for line in lines:
        line = line.rstrip("\n")
        if not line:
            continue
        m = re.match(r"^: (\d+):(\d+);(.*)$", line)
        if m:
            ts = datetime.fromtimestamp(int(m.group(1))).isoformat()
            entries.append({"command": m.group(3), "timestamp": ts})
        else:
            entries.append({"command": line, "timestamp": None})

    return entries


def parse_fish_history(path):
    entries = []
    lines = safe_read_lines(path)
    current_cmd = None

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("- cmd:"):
            if current_cmd is not None:
                entries.append(current_cmd)
            current_cmd = {"command": stripped[len("- cmd:"):].strip(), "timestamp": None}
        elif stripped.startswith("when:") and current_cmd is not None:
            try:
                epoch = int(stripped[len("when:"):].strip())
                current_cmd["timestamp"] = datetime.fromtimestamp(epoch).isoformat()
            except ValueError:
                pass

    if current_cmd is not None:
        entries.append(current_cmd)

    return entries


def parse_plain_history(path):
    entries = []
    for line in safe_read_lines(path):
        line = line.rstrip("\n")
        if not line:
            continue
        entries.append({"command": line, "timestamp": None})
    return entries


LINUX_HISTORY_FILES = [
    (".bash_history", "bash", parse_bash_history),
    (".zsh_history", "zsh", parse_zsh_history),
    (".local/share/fish/fish_history", "fish", parse_fish_history),
    (".python_history", "python", parse_plain_history),
    (".mysql_history", "mysql", parse_plain_history),
    (".psql_history", "psql", parse_plain_history),
    (".rediscli_history", "redis-cli", parse_plain_history),
    (".sqlite_history", "sqlite3", parse_plain_history),
    (".node_repl_history", "node", parse_plain_history),
]


def collect_history_for_home(home_dir, username):
    entries = []
    for rel_path, tool, parser in LINUX_HISTORY_FILES:
        full_path = os.path.join(home_dir, rel_path)
        if not os.path.isfile(full_path):
            continue
        try:
            commands = parser(full_path)
        except (PermissionError, OSError) as e:
            entries.append({
                "user": username,
                "shell_or_tool": tool,
                "history_file": full_path,
                "error": str(e),
            })
            continue

        entries.append({
            "user": username,
            "shell_or_tool": tool,
            "history_file": full_path,
            "file_times": stat_times(full_path),
            "command_count": len(commands),
            "commands": commands,
        })

    return entries


def collect_linux_command_history():
    entries = []

    current_home = os.path.expanduser("~")
    current_user = os.environ.get("USER") or os.environ.get("LOGNAME") or os.path.basename(current_home)
    entries.extend(collect_history_for_home(current_home, current_user))

    if current_home != "/root" and os.path.isdir("/root"):
        entries.extend(collect_history_for_home("/root", "root"))


    if os.path.isdir("/home"):
        try:
            for entry in os.listdir("/home"):
                candidate = os.path.join("/home", entry)
                if candidate == current_home or not os.path.isdir(candidate):
                    continue
                entries.extend(collect_history_for_home(candidate, entry))
        except PermissionError:
            pass

    return entries


def collect_powershell_history_for_profile(appdata_roaming, username):
    """PSReadLine persists command history to a plain-text file shared by
    Windows PowerShell 5.x and PowerShell 7.x (same host name, ConsoleHost)."""
    history_path = os.path.join(
        appdata_roaming, "Microsoft", "Windows", "PowerShell", "PSReadLine", "ConsoleHost_history.txt"
    )

    if not os.path.isfile(history_path):
        return None

    try:
        commands = parse_plain_history(history_path)
    except (PermissionError, OSError) as e:
        return {
            "user": username,
            "shell_or_tool": "powershell (PSReadLine)",
            "history_file": history_path,
            "error": str(e),
        }

    return {
        "user": username,
        "shell_or_tool": "powershell (PSReadLine)",
        "history_file": history_path,
        "file_times": stat_times(history_path),
        "command_count": len(commands),
        "commands": commands,
    }


def collect_windows_powershell_history():
    entries = []

    appdata = os.environ.get("APPDATA")
    current_user = os.environ.get("USERNAME", "unknown")
    if appdata:
        result = collect_powershell_history_for_profile(appdata, current_user)
        if result:
            entries.append(result)

    system_drive = os.environ.get("SystemDrive", "C:")
    users_root = f"{system_drive}\\Users"
    if os.path.isdir(users_root):
        try:
            profiles = os.listdir(users_root)
        except PermissionError:
            profiles = []

        for profile in profiles:
            if profile == current_user:
                continue
            roaming = os.path.join(users_root, profile, "AppData", "Roaming")
            if not os.path.isdir(roaming):
                continue
            try:
                result = collect_powershell_history_for_profile(roaming, profile)
                if result:
                    entries.append(result)
            except PermissionError:
                entries.append({
                    "user": profile,
                    "shell_or_tool": "powershell (PSReadLine)",
                    "error": "Permission denied",
                })

    return entries


def _read_registry_values(hive, subkey):
    if winreg is None:
        return
    try:
        with winreg.OpenKey(hive, subkey) as key:
            i = 0
            while True:
                try:
                    name, data, vtype = winreg.EnumValue(key, i)
                    yield name, data, vtype
                    i += 1
                except OSError:
                    break
    except FileNotFoundError:
        return
    except PermissionError:
        return


def collect_windows_runmru():

    if winreg is None:
        return {"error": "winreg module unavailable (not running on Windows)"}

    base = r"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
    entries = []
    order = None

    for name, data, vtype in _read_registry_values(winreg.HKEY_CURRENT_USER, base):
        if name == "MRUList":
            order = data
            continue
        # RunMRU values end with a literal "\1" suffix marking the slot as
        # most-recently-used; rstrip() strips a *set* of characters, not a
        # substring, so it was mangling any path that happened to end in
        # digits or backslashes (e.g. "...\Users\test1" -> "...\Users\test").
        if isinstance(data, str) and data.endswith("\\1"):
            value = data[:-2]
        else:
            value = data
        entries.append({
            "artifact": "run_mru",
            "slot": name,
            "command": value,
        })

    if order:
        entries.append({"artifact": "run_mru_order", "mru_order": order})

    return entries if entries else {"error": "RunMRU key empty or not found"}


def collect_windows_typed_paths():

    if winreg is None:
        return {"error": "winreg module unavailable (not running on Windows)"}

    base = r"Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths"
    entries = [
        {"artifact": "typed_path", "slot": name, "value": data}
        for name, data, vtype in _read_registry_values(winreg.HKEY_CURRENT_USER, base)
    ]
    return entries if entries else {"error": "TypedPaths key empty or not found"}


def collect_windows_command_history():
    return {
        "powershell_history": collect_windows_powershell_history(),
        "run_mru": collect_windows_runmru(),
        "typed_paths": collect_windows_typed_paths(),
    }


def collect_command_history(os_name):
    if os_name == "Windows":
        return collect_windows_command_history()
    elif os_name == "Linux":
        return {"shell_histories": collect_linux_command_history()}
    else:
        raise SystemExit(
            f"Unsupported OS for command history collection: {os_name}. "
            "This script currently supports Windows and Linux only."
        )


def _count_commands(section):
    if isinstance(section, dict) and "error" in section:
        return 0
    if isinstance(section, list):
        total = 0
        for item in section:
            if isinstance(item, dict) and "command_count" in item:
                total += item["command_count"]
            elif isinstance(item, dict):
                total += 1
        return total
    return 0


def save_evidence(results, os_name):
    project_root = Path(__file__).resolve().parent.parent.parent
    evidence_dir = project_root / "Evidences"
    evidence_dir.mkdir(exist_ok=True)

    file_path = evidence_dir / "command_history.json"

    totals = {k: _count_commands(v) for k, v in results.items()}

    payload = {
        "generated_at": datetime.now().isoformat(),
        "detected_os": os_name,
        "hostname": platform.node(),
        "totals_by_source": totals,
        "artifacts": results,
    }

    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False, default=str)

    return str(file_path)


def main():
    os_name = detect_os()
    print(f"[*] Detected OS: {os_name}")
    print("[*] Collecting command history evidence...")

    results = collect_command_history(os_name)

    for source_name, section in results.items():
        if isinstance(section, dict) and "error" in section:
            print(f"[!] {source_name}: {section['error']}")
        else:
            count = _count_commands(section)
            print(f"[*] {source_name}: {count} command(s) recovered")

    fname = save_evidence(results, os_name)
    print(f"[+] Evidence saved to: {fname}")


if __name__ == "__main__":
    main()