import os
import json
import platform
from datetime import datetime

try:
    import psutil
except ImportError:
    raise SystemExit(
        "psutil not installed. Run: pip install psutil"
    )

EVIDENCE_DIR = "Evidences"

FIELDS = [
    "pid", "ppid", "name", "exe", "cmdline", "status", "username",
    "create_time", "cpu_percent", "cpu_times", "memory_info",
    "memory_percent", "num_threads", "nice", "cwd", "open_files",
    "connections", "num_fds",
]


def safe_get(proc, attr):
    """Call proc.<attr>() or return a friendly error string instead of crashing."""
    try:
        value = getattr(proc, attr)()
        return serialize(value)
    except psutil.AccessDenied:
        return "Access Denied"
    except psutil.NoSuchProcess:
        return "Process ended before it could be read"
    except NotImplementedError:
        return "Not supported on this OS"
    except Exception as e:
        return f"Error: {e}"


def serialize(value):
    """Convert psutil named-tuples / lists of them into plain JSON-friendly data."""
    if isinstance(value, list):
        return [serialize(v) for v in value]
    if hasattr(value, "_asdict"):
        return value._asdict()
    if isinstance(value, (int, float, str, bool)) or value is None:
        return value
    return str(value)


def collect_processes():
    processes = []
    for proc in psutil.process_iter():
        entry = {}
        for field in FIELDS:
            if field == "create_time":
                entry["create_time"] = safe_get(proc, "create_time")
                try:
                    ts = proc.create_time()
                    entry["create_time_readable"] = datetime.fromtimestamp(ts).isoformat()
                except Exception:
                    entry["create_time_readable"] = None
            elif field == "connections":
                if hasattr(proc, "net_connections"):
                    entry["connections"] = safe_get(proc, "net_connections")
                else:
                    entry["connections"] = safe_get(proc, "connections")
            elif field in ("cmdline", "open_files"):
                entry[field] = safe_get(proc, field)
            elif field == "num_fds":
                if hasattr(proc, "num_fds"):
                    entry["num_fds"] = safe_get(proc, "num_fds")
                else:
                    entry["num_fds"] = "Not supported on this OS"
            else:
                entry[field] = safe_get(proc, field)
        processes.append(entry)
    return processes


def ensure_evidence_dir():
    os.makedirs(EVIDENCE_DIR, exist_ok=True)


def save_evidence(processes, os_name):
    ensure_evidence_dir()
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = os.path.join(EVIDENCE_DIR, f"current_processes.json")

    payload = {
        "generated_at": datetime.now().isoformat(),
        "detected_os": os_name,
        "os_raw": platform.system(),
        "os_version": platform.version(),
        "hostname": platform.node(),
        "total_processes": len(processes),
        "processes": processes,
    }

    with open(fname, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False, default=str)

    return fname


def detect_os():
    """Detect the OS and return a clean, human-readable name."""
    system = platform.system()
    if system == "Windows":
        os_name = "Windows"
    elif system == "Linux":
        os_name = "Linux"
    elif system == "Darwin":
        os_name = "macOS"
    else:
        os_name = f"Unknown ({system})" 
    return os_name


def main():
    os_name = detect_os()
    print(f"[*] Detected OS: {os_name}")
    print("[*] Collecting details of all currently running processes...")

    processes = collect_processes()
    print(f"[*] Found {len(processes)} running processes.")

    fname = save_evidence(processes, os_name)
    print(f"[+] Evidence saved to: {fname}")


if __name__ == "__main__":
    main()