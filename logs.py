import os
import json
import platform
import subprocess
from datetime import datetime

EVIDENCE_DIR = "Evidences"
MAX_EVENTS = 1000


def detect_os():
    system = platform.system()
    if system == "Windows":
        return "Windows"
    elif system == "Linux":
        return "Linux"
    elif system == "Darwin":
        return "macOS"
    return f"Unknown ({system})"


def collect_windows_logs(max_events=MAX_EVENTS):
    logs = {}
    log_names = ["System", "Application", "Security"]

    for log_name in log_names:
        try:
            ps_cmd = [
                "powershell",
                "-NoProfile",
                "-Command",
                (
                    f"Get-WinEvent -LogName {log_name} -MaxEvents {max_events} "
                    "-ErrorAction Stop | "
                    "Select-Object TimeCreated, Id, LevelDisplayName, "
                    "ProviderName, Message | ConvertTo-Json -Depth 4"
                ),
            ]
            result = subprocess.run(
                ps_cmd, capture_output=True, text=True, timeout=90
            )

            if result.returncode != 0:
                logs[log_name] = {
                    "error": result.stderr.strip()
                    or f"Could not read {log_name} log "
                    "(Security log usually requires Administrator)."
                }
                continue

            raw = result.stdout.strip()
            if not raw:
                logs[log_name] = []
                continue

            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                parsed = [parsed]
            logs[log_name] = parsed

        except json.JSONDecodeError:
            logs[log_name] = {"error": "Failed to parse PowerShell JSON output"}
        except subprocess.TimeoutExpired:
            logs[log_name] = {"error": "Timed out reading log"}
        except Exception as e:
            logs[log_name] = {"error": str(e)}

    return logs

def collect_linux_logs(max_events=MAX_EVENTS):
    logs = {}

    try:
        result = subprocess.run(
            ["journalctl", "-o", "json", "-n", str(max_events), "--no-pager"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode == 0 and result.stdout.strip():
            entries = []
            for line in result.stdout.strip().splitlines():
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
            logs["journalctl"] = entries
        else:
            logs["journalctl"] = {
                "error": result.stderr.strip()
                or "journalctl returned no data (try sudo for full access)."
            }
    except FileNotFoundError:
        logs["journalctl"] = {"error": "journalctl not found on this system"}
    except subprocess.TimeoutExpired:
        logs["journalctl"] = {"error": "Timed out reading journal"}
    except Exception as e:
        logs["journalctl"] = {"error": str(e)}

    log_files = {
        "syslog": "/var/log/syslog",
        "auth_log": "/var/log/auth.log",
        "messages": "/var/log/messages",
        "secure": "/var/log/secure",
        "kern_log": "/var/log/kern.log",
    }
    file_logs = {}
    for name, path in log_files.items():
        if os.path.exists(path):
            try:
                with open(path, "r", errors="replace") as f:
                    lines = f.readlines()[-max_events:]
                file_logs[name] = [line.rstrip("\n") for line in lines]
            except PermissionError:
                file_logs[name] = {
                    "error": f"Permission denied reading {path}. Try sudo."
                }
            except Exception as e:
                file_logs[name] = {"error": str(e)}
    if file_logs:
        logs["log_files"] = file_logs

    return logs


def collect_logs(os_name):
    if os_name == "Windows":
        return collect_windows_logs()
    elif os_name == "Linux":
        return collect_linux_logs()
    else:
        raise SystemExit(
            f"Unsupported OS for log collection: {os_name}. "
            "This script currently supports Windows and Linux only."
        )


def ensure_evidence_dir():
    os.makedirs(EVIDENCE_DIR, exist_ok=True)


def save_evidence(logs, os_name):
    ensure_evidence_dir()
    fname = os.path.join(EVIDENCE_DIR, "system_logs.json")

    payload = {
        "generated_at": datetime.now().isoformat(),
        "detected_os": os_name,
        "hostname": platform.node(),
        "max_events_per_source": MAX_EVENTS,
        "logs": logs,
    }

    with open(fname, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False, default=str)

    return fname


def main():
    os_name = detect_os()
    print(f"[*] Detected OS: {os_name}")
    print("[*] Collecting system logs...")

    logs = collect_logs(os_name)

    for source, data in logs.items():
        if isinstance(data, dict) and "error" in data:
            print(f"[!] {source}: {data['error']}")
        elif isinstance(data, list):
            print(f"[*] {source}: {len(data)} entries")
        elif isinstance(data, dict):
            for sub, sub_data in data.items():
                if isinstance(sub_data, dict) and "error" in sub_data:
                    print(f"[!] {source}/{sub}: {sub_data['error']}")
                else:
                    print(f"[*] {source}/{sub}: {len(sub_data)} lines")

    fname = save_evidence(logs, os_name)
    print(f"[+] Evidence saved to: {fname}")


if __name__ == "__main__":
    main()