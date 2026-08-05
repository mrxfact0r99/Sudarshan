import os
import sys
import csv
import json
import struct
import platform
import subprocess
import io
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

try:
    import psutil
except ImportError:
    psutil = None



def filetime_to_datetime(ft):
    if not ft or ft <= 0:
        return None
    try:
        return datetime(1601, 1, 1) + timedelta(microseconds=ft / 10)
    except (OverflowError, OSError):
        return None


def run_command(args, timeout=30):
    try:
        result = subprocess.run(
            args, capture_output=True, text=True, timeout=timeout, check=False
        )
        if result.returncode != 0 and not result.stdout:
            return None, (result.stderr or f"Command exited with code {result.returncode}").strip()
        return result.stdout, None
    except FileNotFoundError:
        return None, f"Command not found: {args[0]}"
    except subprocess.TimeoutExpired:
        return None, f"Command timed out: {' '.join(args)}"
    except Exception as e:
        return None, str(e)


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



WINDOWS_SYSTEM_ACCOUNTS = {
    "nt authority\\system",
    "nt authority\\local service",
    "nt authority\\network service",
}

WINDOWS_SYSTEM_PATH_MARKERS = (
    "\\windows\\system32",
    "\\windows\\syswow64",
    "\\windows\\winsxs",
    "\\windows\\immersivecontrolpanel",
    "\\windows\\servicing",
    "\\programdata\\microsoft\\windows defender",
    "\\windows\\",  
)

WINDOWS_NOISE_NAMES = {
    "system", "system idle process", "registry", "smss.exe", "csrss.exe",
    "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe", "lsaiso.exe",
    "svchost.exe", "dwm.exe", "sihost.exe", "ctfmon.exe", "fontdrvhost.exe",
    "runtimebroker.exe", "searchindexer.exe", "searchapp.exe", "taskhostw.exe",
    "dllhost.exe", "applicationframehost.exe", "shellexperiencehost.exe",
    "textinputhost.exe", "conhost.exe", "wmiprvse.exe", "spoolsv.exe",
    "audiodg.exe", "nissrv.exe", "msmpeng.exe", "smartscreen.exe",
    "securityhealthservice.exe", "wudfhost.exe", "wlanext.exe",
}

WINDOWS_CHILD_CMDLINE_MARKERS = ("--type=", "--utility-sub-type=")


def is_genuine_windows_process(entry):
    name = (entry.get("name") or "").strip().lower()
    exe_path = (entry.get("executable_path") or "").strip().lower()
    username = (entry.get("username") or "").strip().lower()
    cmdline = (entry.get("command_line") or "").lower()

    if not name or not exe_path:
        return False

    if username in WINDOWS_SYSTEM_ACCOUNTS or not username:
        return False

    if any(marker in exe_path for marker in WINDOWS_SYSTEM_PATH_MARKERS):
        return False

    if name in WINDOWS_NOISE_NAMES:
        return False

    if any(marker in cmdline for marker in WINDOWS_CHILD_CMDLINE_MARKERS):
        return False

    return True


LINUX_SYSTEM_PATH_MARKERS = (
    "/usr/lib/", "/usr/libexec/", "/usr/sbin/", "/lib/systemd/",
    "/usr/lib/systemd/", "/snap/core", "/init",
)

LINUX_NOISE_NAMES = {
    "systemd", "kthreadd", "kworker", "ksoftirqd", "migration", "rcu_sched",
    "rcu_gp", "watchdog", "cron", "dbus-daemon", "dbus-broker", "sshd",
    "networkd-dispatcher", "polkitd", "udisksd", "accounts-daemon",
    "systemd-journald", "systemd-logind", "systemd-udevd", "systemd-resolved",
    "systemd-timesyncd", "gdm3", "gdm-session-worker", "Xorg", "wpa_supplicant",
}


def is_genuine_linux_process(entry):
    name = (entry.get("name") or "").strip().lower()
    exe_path = (entry.get("executable_path") or "").strip().lower()
    username = (entry.get("username") or "").strip().lower()

    if not name or not exe_path:
        return False

    if username in {"root", "daemon", "systemd-network", "systemd-resolve", "messagebus"} or not username:
        return False

    if any(marker in exe_path for marker in LINUX_SYSTEM_PATH_MARKERS):
        return False

    if name in LINUX_NOISE_NAMES or name.startswith("kworker"):
        return False

    return True


def collect_windows_processes():
    if psutil is not None:
        entries = []
        for proc in psutil.process_iter(
            ["pid", "ppid", "name", "exe", "cmdline", "username", "create_time"]
        ):
            try:
                info = proc.info
                entries.append({
                    "pid": info.get("pid"),
                    "parent_pid": info.get("ppid"),
                    "name": info.get("name"),
                    "executable_path": info.get("exe"),
                    "command_line": " ".join(info.get("cmdline") or []),
                    "username": info.get("username"),
                    "start_time": datetime.fromtimestamp(info["create_time"]).isoformat()
                    if info.get("create_time") else None,
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return [e for e in entries if is_genuine_windows_process(e)]

    stdout, err = run_command(["tasklist", "/v", "/fo", "csv"])
    if err:
        return {"error": f"psutil not installed and tasklist failed: {err}"}

    entries = []
    reader = csv.DictReader(io.StringIO(stdout))
    for row in reader:
        name = (row.get("Image Name") or "").strip()
        username = (row.get("User Name") or "").strip()
        if not name or name.lower() in WINDOWS_NOISE_NAMES:
            continue
        if not username or username.lower() in WINDOWS_SYSTEM_ACCOUNTS:
            continue
        entries.append({
            "name": name,
            "pid": row.get("PID"),
            "username": row.get("User Name"),
            "session": row.get("Session Name"),
            "memory_usage": row.get("Mem Usage"),
            "status": row.get("Status"),
            "window_title": row.get("Window Title"),
            "note": "Install psutil for executable path, command line, and start time.",
        })
    return entries



def collect_windows_prefetch():
    windir = os.environ.get("SystemRoot", "C:\\Windows")
    pf_dir = os.path.join(windir, "Prefetch")

    if not os.path.isdir(pf_dir):
        return {"error": f"Prefetch folder not found or inaccessible: {pf_dir}"}

    try:
        files = os.listdir(pf_dir)
    except PermissionError:
        return {"error": f"Permission denied listing {pf_dir}. Run as Administrator."}

    entries = []
    for fname in files:
        if not fname.lower().endswith(".pf"):
            continue
        full_path = os.path.join(pf_dir, fname)
        base = fname[:-3]
        parts = base.rsplit("-", 1)
        program_name = parts[0] if parts else base
        name_hash = parts[1] if len(parts) == 2 else None

        entries.append({
            "program_name": program_name,
            "name_hash": name_hash,
            "prefetch_file": full_path,
            "file_times": stat_times(full_path),
            "note": "Run count/last-run timestamps require decompressing the PF "
                    "payload; only filename metadata and file timestamps are captured.",
        })

    return entries


def collect_windows_shimcache_raw():

    if winreg is None:
        return {"error": "winreg module unavailable (not running on Windows)"}

    base = r"SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base) as key:
            _, _, last_write_ft = winreg.QueryInfoKey(key)
            last_write = filetime_to_datetime(last_write_ft)
            try:
                data, vtype = winreg.QueryValueEx(key, "AppCompatCache")
                raw_size = len(data) if isinstance(data, (bytes, bytearray)) else None
            except FileNotFoundError:
                raw_size = None
    except FileNotFoundError:
        return {"error": "AppCompatCache key not found (requires Administrator privileges)"}
    except PermissionError:
        return {"error": "Permission denied reading AppCompatCache. Run as Administrator."}

    return {
        "registry_key": base,
        "key_last_write_time": last_write.isoformat() if last_write else None,
        "raw_value_size_bytes": raw_size,
        "note": "Raw capture only. Decode with a ShimCache/AppCompatCache parser "
                "(e.g. Eric Zimmerman's AppCompatCacheParser) for entry-level detail.",
    }



def collect_windows_scheduled_tasks():
    stdout, err = run_command(["schtasks", "/query", "/fo", "csv", "/v"])
    if err:
        return {"error": err}

    entries = []
    reader = csv.DictReader(io.StringIO(stdout))
    for row in reader:
        if not row.get("TaskName"):
            continue
        entries.append({
            "task_name": row.get("TaskName"),
            "status": row.get("Status"),
            "last_run_time": row.get("Last Run Time"),
            "next_run_time": row.get("Next Run Time"),
            "task_to_run": row.get("Task To Run"),
            "run_as_user": row.get("Run As User"),
        })

    return entries


def collect_windows_services():
    if winreg is None:
        return {"error": "winreg module unavailable (not running on Windows)"}

    base = r"SYSTEM\CurrentControlSet\Services"
    entries = []
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base) as root:
            i = 0
            while True:
                try:
                    service_name = winreg.EnumKey(root, i)
                except OSError:
                    break
                i += 1
                try:
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, f"{base}\\{service_name}") as svc_key:
                        def _get(name):
                            try:
                                return winreg.QueryValueEx(svc_key, name)[0]
                            except FileNotFoundError:
                                return None

                        image_path = _get("ImagePath")
                        if not image_path:
                            continue
                        entries.append({
                            "service_name": service_name,
                            "display_name": _get("DisplayName"),
                            "image_path": image_path,
                            "start_type": _get("Start"),
                            "type": _get("Type"),
                        })
                except PermissionError:
                    continue
    except PermissionError:
        return {"error": "Permission denied reading Services key. Run as Administrator."}

    return entries


def collect_windows_executed_programs():
    return {
        "running_processes": collect_windows_processes(),
        "prefetch": collect_windows_prefetch(),
        "shimcache_raw": collect_windows_shimcache_raw(),
        "scheduled_tasks": collect_windows_scheduled_tasks(),
        "services": collect_windows_services(),
    }


def collect_linux_processes():
    if psutil is not None:
        entries = []
        for proc in psutil.process_iter(
            ["pid", "ppid", "name", "exe", "cmdline", "username", "create_time"]
        ):
            try:
                info = proc.info
                entries.append({
                    "pid": info.get("pid"),
                    "parent_pid": info.get("ppid"),
                    "name": info.get("name"),
                    "executable_path": info.get("exe"),
                    "command_line": " ".join(info.get("cmdline") or []),
                    "username": info.get("username"),
                    "start_time": datetime.fromtimestamp(info["create_time"]).isoformat()
                    if info.get("create_time") else None,
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return [e for e in entries if is_genuine_linux_process(e)]

    entries = []
    for pid_str in os.listdir("/proc"):
        if not pid_str.isdigit():
            continue
        pid_dir = f"/proc/{pid_str}"
        try:
            with open(f"{pid_dir}/comm", "r") as f:
                name = f.read().strip()
        except OSError:
            continue

        try:
            exe = os.readlink(f"{pid_dir}/exe")
        except OSError:
            exe = None

        try:
            with open(f"{pid_dir}/cmdline", "rb") as f:
                cmdline = f.read().replace(b"\x00", b" ").strip().decode(errors="replace")
        except OSError:
            cmdline = None

        try:
            st = os.stat(pid_dir)
            start_time = datetime.fromtimestamp(st.st_ctime).isoformat()
        except OSError:
            start_time = None

        entry = {
            "pid": int(pid_str),
            "name": name,
            "executable_path": exe,
            "command_line": cmdline,
            "start_time": start_time,
            "note": "install psutil for parent pid, username, and precise start time",
        }
        if is_genuine_linux_process({**entry, "username": ""}):
            entries.append(entry)

    return entries


def collect_linux_cron_jobs():
    entries = []

    system_cron_paths = ["/etc/crontab"]
    if os.path.isdir("/etc/cron.d"):
        system_cron_paths += [
            os.path.join("/etc/cron.d", f) for f in os.listdir("/etc/cron.d")
        ]

    for path in system_cron_paths:
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                lines = [l.rstrip("\n") for l in f if l.strip() and not l.strip().startswith("#")]
        except OSError as e:
            entries.append({"source": path, "error": str(e)})
            continue
        entries.append({"source": path, "scope": "system", "entries": lines})

    spool_dir = "/var/spool/cron/crontabs"
    if os.path.isdir(spool_dir):
        try:
            for user in os.listdir(spool_dir):
                path = os.path.join(spool_dir, user)
                try:
                    with open(path, "r", encoding="utf-8", errors="replace") as f:
                        lines = [l.rstrip("\n") for l in f if l.strip() and not l.strip().startswith("#")]
                    entries.append({"source": path, "scope": f"user:{user}", "entries": lines})
                except (OSError, PermissionError) as e:
                    entries.append({"source": path, "scope": f"user:{user}", "error": str(e)})
        except PermissionError:
            entries.append({"source": spool_dir, "error": "Permission denied listing user crontabs"})


    stdout, err = run_command(["crontab", "-l"])
    if stdout:
        lines = [l.rstrip("\n") for l in stdout.splitlines() if l.strip() and not l.strip().startswith("#")]
        entries.append({"source": "crontab -l", "scope": "current_user", "entries": lines})

    return entries


def collect_linux_systemd_timers():
    stdout, err = run_command(["systemctl", "list-timers", "--all", "--no-pager"])
    if err:
        return {"error": err}

    entries = []
    lines = stdout.splitlines()
    for line in lines[1:]:  
        stripped = line.strip()
        if not stripped or stripped.startswith("*") or "timers listed" in stripped:
            continue
        entries.append({"raw_line": stripped})

    return entries


def collect_linux_auditd_execve():

    log_path = "/var/log/audit/audit.log"
    if not os.path.isfile(log_path):
        return {"error": f"auditd log not found: {log_path} (auditd may not be installed/running)"}

    entries = []
    try:
        with open(log_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if "type=EXECVE" in line or ("type=SYSCALL" in line and "syscall=59" in line):
                    entries.append({"raw_line": line.strip()})
    except PermissionError:
        return {"error": f"Permission denied reading {log_path}. Requires root."}
    except OSError as e:
        return {"error": str(e)}

    return entries


def collect_linux_executed_programs():
    return {
        "running_processes": collect_linux_processes(),
        "cron_jobs": collect_linux_cron_jobs(),
        "systemd_timers": collect_linux_systemd_timers(),
        "auditd_execve": collect_linux_auditd_execve(),
    }


def collect_executed_programs(os_name):
    if os_name == "Windows":
        return collect_windows_executed_programs()
    elif os_name == "Linux":
        return collect_linux_executed_programs()
    else:
        raise SystemExit(
            f"Unsupported OS for executed program collection: {os_name}. "
            "This script currently supports Windows and Linux only."
        )


def _count_items(section):
    if isinstance(section, dict) and "error" in section:
        return 0
    if isinstance(section, list):
        return len(section)
    return 0


def save_evidence(results, os_name):
    project_root = Path(__file__).resolve().parent.parent.parent
    evidence_dir = project_root / "Evidences"
    evidence_dir.mkdir(exist_ok=True)

    file_path = evidence_dir / "executed_programs.json"

    totals = {k: _count_items(v) for k, v in results.items()}

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
    print("[*] Collecting executed program evidence...")

    if psutil is None:
        print("[!] psutil not installed -- process details will be limited. "
              "Run: pip install psutil")

    results = collect_executed_programs(os_name)

    for source_name, section in results.items():
        if isinstance(section, dict) and "error" in section:
            print(f"[!] {source_name}: {section['error']}")
        else:
            print(f"[*] {source_name}: {_count_items(section)} record(s)")

    fname = save_evidence(results, os_name)
    print(f"[+] Evidence saved to: {fname}")


if __name__ == "__main__":
    main()