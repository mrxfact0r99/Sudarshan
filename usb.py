import platform
import subprocess
import json
import os
import re
from datetime import datetime, timedelta

MINUTES_BACK = 24 * 60  
EVIDENCE_DIR = "Evidences"


def ensure_evidence_dir():
    os.makedirs(EVIDENCE_DIR, exist_ok=True)


def is_admin():
    try:
        if platform.system() == "Windows":
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        return os.geteuid() == 0
    except Exception:
        return False


def save_evidence(payload, os_name):
    ensure_evidence_dir()
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = os.path.join(EVIDENCE_DIR, f"usb_login_events.json")
    with open(fname, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False, default=str)
    return fname


def collect_windows_usb(minutes_back):
    events = []
    note = None
    start_time = datetime.utcnow() - timedelta(minutes=minutes_back)
    time_str = start_time.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    xpath = (
        f"*[System[(EventID=2003 or EventID=2010 or EventID=400 or EventID=410) "
        f"and TimeCreated[@SystemTime>='{time_str}']]]"
    )
    cmd = ["wevtutil", "qe", "System", f"/q:{xpath}", "/f:text", "/rd:true"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if result.returncode != 0 or not result.stdout.strip():
            note = "No USB events found in this window, or insufficient permissions."
        else:
            events = parse_windows_text_events(result.stdout)
    except FileNotFoundError:
        note = "wevtutil not found - not a Windows system."
    except Exception as e:
        note = f"Error reading USB events: {e}"
    return events, note


def collect_windows_logins(minutes_back):
    events = []
    note = None
    start_time = datetime.utcnow() - timedelta(minutes=minutes_back)
    time_str = start_time.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    xpath = (
        f"*[System[(EventID=4624 or EventID=4625 or EventID=4634 or EventID=4647) "
        f"and TimeCreated[@SystemTime>='{time_str}']]]"
    )
    cmd = ["wevtutil", "qe", "Security", f"/q:{xpath}", "/f:text", "/rd:true"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if result.returncode != 0 or not result.stdout.strip():
            note = (
                "No login events found. Ensure 'Audit Logon Events' is enabled:\n"
                '  auditpol /set /subcategory:"Logon" /success:enable /failure:enable\n'
                "and run this script as Administrator."
            )
        else:
            events = parse_windows_text_events(result.stdout)
    except FileNotFoundError:
        note = "wevtutil not found - not a Windows system."
    except Exception as e:
        note = f"Error reading login events: {e}"
    return events, note


def parse_windows_text_events(raw_text):
    entries = []
    blocks = raw_text.split("Event[")
    for block in blocks[1:]:
        entry = {}
        m_date = re.search(r"Date:\s*(.+)", block)
        m_id = re.search(r"Event ID:\s*(\S+)", block)
        m_user = re.search(r"Account Name:\s*(.+)", block)
        m_desc = re.search(r"Description:\s*\n(.+)", block)
        if m_date:
            entry["time"] = m_date.group(1).strip()
        if m_id:
            entry["event_id"] = m_id.group(1).strip()
        if m_user:
            entry["account"] = m_user.group(1).strip()
        if m_desc:
            entry["description"] = m_desc.group(1).strip()[:300]
        if entry:
            entries.append(entry)
    return entries


def collect_linux_usb(minutes_back):
    events = []
    note = None
    since = f"-{minutes_back}min"
    cmd = ["journalctl", "-k", "--since", since, "--no-pager", "-o", "short-iso"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if result.returncode != 0:
            note = "Could not read kernel log via journalctl. Try running with sudo."
        else:
            lines = [l for l in result.stdout.splitlines() if "usb" in l.lower()]
            events = [{"raw": l} for l in lines]
            if not events:
                note = "No USB-related kernel messages found in this window."
    except FileNotFoundError:
        try:
            result = subprocess.run(["dmesg"], capture_output=True, text=True, timeout=30)
            lines = [l for l in result.stdout.splitlines() if "usb" in l.lower()]
            events = [{"raw": l} for l in lines]
            if not events:
                note = "No USB-related messages found in dmesg."
        except Exception as e:
            note = f"Neither journalctl nor dmesg available: {e}"
    except Exception as e:
        note = f"Error reading USB events: {e}"
    return events, note


def collect_linux_logins(minutes_back):
    events = []
    note = None

    try:
        result = subprocess.run(["last", "-F"], capture_output=True, text=True, timeout=30)
        if result.returncode == 0 and result.stdout.strip():
            for line in result.stdout.splitlines():
                if line.strip() and not line.startswith("wtmp begins"):
                    events.append({"source": "last(wtmp)", "raw": line.strip()})
    except FileNotFoundError:
        pass
    except Exception as e:
        note = f"Error running 'last': {e}"

    try:
        since = f"-{minutes_back}min"
        cmd = ["journalctl", "-u", "systemd-logind", "--since", since,
               "--no-pager", "-o", "short-iso"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if line.strip():
                    events.append({"source": "systemd-logind", "raw": line.strip()})
    except FileNotFoundError:
        pass
    except Exception:
        pass

    if not events and note is None:
        note = (
            "No login events found. Try running with sudo, or check "
            "/var/log/auth.log directly (Debian/Ubuntu)."
        )
    return events, note


def collect_macos_usb(minutes_back):
    events = []
    note = None
    cmd = [
        "log", "show", "--last", f"{minutes_back}m",
        "--predicate", 'eventMessage contains "USB" or eventMessage contains "IOUSBHost"',
        "--style", "compact"
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
        if result.returncode != 0:
            note = "Could not read unified log. Run with sudo."
        else:
            lines = [l for l in result.stdout.splitlines() if l.strip()]
            events = [{"raw": l} for l in lines]
            if not events:
                note = "No USB-related entries found in this window."
    except FileNotFoundError:
        note = "'log' command not found - this does not look like macOS."
    except Exception as e:
        note = f"Error reading USB events: {e}"
    return events, note


def collect_macos_logins(minutes_back):
    events = []
    note = None
    cmd = [
        "log", "show", "--last", f"{minutes_back}m",
        "--predicate", 'eventMessage contains "loginwindow" or process == "loginwindow"',
        "--style", "compact"
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
        if result.returncode != 0:
            note = "Could not read unified log. Run with sudo."
        else:
            lines = [l for l in result.stdout.splitlines() if l.strip()]
            events = [{"raw": l} for l in lines]
            if not events:
                note = "No login-related entries found in this window."
    except FileNotFoundError:
        note = "'log' command not found - this does not look like macOS."
    except Exception as e:
        note = f"Error reading login events: {e}"
    return events, note


def detect_os():
    system = platform.system()
    if system == "Windows":
        return "Windows"
    elif system == "Linux":
        return "Linux"
    elif system == "Darwin":
        return "macOS"
    return f"Unknown ({system})"


def main():
    os_name = detect_os()
    print(f"[*] Detected OS: {os_name}")
    print(f"[*] Looking back: {MINUTES_BACK} minutes ({MINUTES_BACK // 60} hours)")

    if not is_admin():
        print("[!] Warning: not running as admin/root - results may be incomplete.")

    if os_name == "Windows":
        usb_events, usb_note = collect_windows_usb(MINUTES_BACK)
        login_events, login_note = collect_windows_logins(MINUTES_BACK)
    elif os_name == "Linux":
        usb_events, usb_note = collect_linux_usb(MINUTES_BACK)
        login_events, login_note = collect_linux_logins(MINUTES_BACK)
    elif os_name == "macOS":
        usb_events, usb_note = collect_macos_usb(MINUTES_BACK)
        login_events, login_note = collect_macos_logins(MINUTES_BACK)
    else:
        usb_events, usb_note = [], f"Unsupported OS: {os_name}"
        login_events, login_note = [], f"Unsupported OS: {os_name}"

    payload = {
        "generated_at": datetime.now().isoformat(),
        "detected_os": os_name,
        "hostname": platform.node(),
        "ran_as_admin": is_admin(),
        "window_minutes": MINUTES_BACK,
        "usb_events": {
            "count": len(usb_events),
            "events": usb_events,
            "note": usb_note,
        },
        "login_events": {
            "count": len(login_events),
            "events": login_events,
            "note": login_note,
        },
    }

    fname = save_evidence(payload, os_name)

    print(f"[*] USB events found: {len(usb_events)}")
    if usb_note:
        print(f"[i] USB note: {usb_note}")
    print(f"[*] Login events found: {len(login_events)}")
    if login_note:
        print(f"[i] Login note: {login_note}")
    print(f"[+] Evidence saved to: {fname}")


if __name__ == "__main__":
    main()

    