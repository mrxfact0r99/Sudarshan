import os
import json
import platform
from datetime import datetime

try:
    import psutil
except ImportError:
    raise SystemExit("psutil not installed. Run: pip3 install psutil")

from ..common import EVIDENCE_DIR, detect_os, ensure_evidence_dir


def get_process_name(pid):
    """Look up process name safely for a given PID."""
    if pid is None:
        return None
    try:
        return psutil.Process(pid).name()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return "Unknown/Access Denied"


def collect_connections():
    connections = []

    try:
        raw_conns = psutil.net_connections(kind="inet")  
    except psutil.AccessDenied:
        raise SystemExit(
            "Access denied reading connections. Run as Administrator (Windows) "
            "or with sudo (Linux/macOS) for full results."
        )

    for c in raw_conns:
        entry = {
            "fd": c.fd,
            "family": str(c.family),
            "type": str(c.type),
            "local_address": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else None,
            "remote_address": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else None,
            "status": c.status,
            "pid": c.pid,
            "process_name": get_process_name(c.pid),
        }
        connections.append(entry)

    return connections


def save_evidence(connections, os_name):
    ensure_evidence_dir()
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = os.path.join(EVIDENCE_DIR, f"network_connections.json")

    payload = {
        "generated_at": datetime.now().isoformat(),
        "detected_os": os_name,
        "hostname": platform.node(),
        "total_connections": len(connections),
        "connections": connections,
    }

    with open(fname, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False, default=str)

    return fname


def main():
    os_name = detect_os()
    print(f"[*] Detected OS: {os_name}")
    print("[*] Collecting current network connections...")

    connections = collect_connections()
    print(f"[*] Found {len(connections)} connections.")

    fname = save_evidence(connections, os_name)
    print(f"[+] Evidence saved to: {fname}")


if __name__ == "__main__":
    main()