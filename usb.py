import platform
import subprocess
import json
import os
import re
from datetime import datetime, timedelta

MINUTES_BACK = 24 * 60
EVIDENCE_DIR = "Evidences"

# If True, the script will turn on SACL-based read/write auditing on any
# removable drive it finds, so that FUTURE file reads and writes on that
# drive get logged (Security log event 4663). This can NOT see reads that
# already happened before you enabled it -- Windows does not log reads by
# default, and there is no way to recover that retroactively. Writes are
# recovered separately (and retroactively) via the USN Journal, no setup
# needed. Auditing reads is also noisy (one event per file access), so it's
# opt-in via this flag.
ENABLE_READ_WRITE_AUDIT = True


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
    fname = os.path.join(EVIDENCE_DIR, "usb_login_events.json")
    with open(fname, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False, default=str)
    return fname


# ---------------------------------------------------------------------------
# Windows
# ---------------------------------------------------------------------------

def run_powershell(script, timeout=90):
    """Run a PowerShell command and return the CompletedProcess, or None if
    powershell.exe isn't available (i.e. not Windows)."""
    try:
        return subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, timeout=timeout
        )
    except FileNotFoundError:
        return None
    except Exception:
        return None


def collect_windows_usb(minutes_back):
    """
    USB connect/install events live in the
    'Microsoft-Windows-DriverFrameworks-UserMode/Operational' log, NOT in
    'System' -- so the previous version was querying a log that never had
    these events in it, which is why it always returned 0 results.

    This also adds a registry-based fallback (HKLM\\SYSTEM\\CurrentControlSet\\
    Enum\\USBSTOR) which lists every USB storage device that has ever been
    plugged into this machine. It has no timestamp, but it works even without
    admin rights and even if the event log rolled over / was cleared.
    """
    events = []
    note = None

    ps_script = f"""
    $ErrorActionPreference = 'SilentlyContinue'
    Get-WinEvent -FilterHashtable @{{
        LogName='Microsoft-Windows-DriverFrameworks-UserMode/Operational'
        StartTime=(Get-Date).AddMinutes(-{minutes_back})
    }} 2>$null | Select-Object TimeCreated, Id, LevelDisplayName, Message | ConvertTo-Json -Depth 3
    """
    result = run_powershell(ps_script)

    if result is None:
        note = "PowerShell not found - this does not look like Windows."
    else:
        raw = result.stdout.strip()
        if raw:
            try:
                data = json.loads(raw)
                if isinstance(data, dict):
                    data = [data]
                for item in data:
                    events.append({
                        "time": item.get("TimeCreated"),
                        "event_id": item.get("Id"),
                        "level": item.get("LevelDisplayName"),
                        "description": (item.get("Message") or "")[:300],
                    })
            except json.JSONDecodeError:
                note = "Could not parse DriverFrameworks-UserMode log output."

    if not events and note is None:
        note = ("No device-install events found in this window. This can "
                 "happen if the log rolled over, or if the device was "
                 "already installed before and Windows only logs first-time "
                 "installs. See 'usbstor_history' below for the full list of "
                 "USB storage devices ever connected to this machine.")

    usb_history = collect_usb_registry_history()

    return events, note, usb_history


def collect_usb_registry_history():
    """Enumerate every USB mass-storage device that has ever been connected,
    from the registry. Works without admin rights, no time window (registry
    doesn't store a per-plug timestamp, only the last driver-install info)."""
    devices = []
    try:
        import winreg
    except ImportError:
        return devices

    base = r"SYSTEM\CurrentControlSet\Enum\USBSTOR"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base) as key:
            i = 0
            while True:
                try:
                    device_class = winreg.EnumKey(key, i)  # e.g. Disk&Ven_Kingston&Prod_DataTraveler...
                except OSError:
                    break
                i += 1
                try:
                    with winreg.OpenKey(key, device_class) as class_key:
                        j = 0
                        while True:
                            try:
                                serial = winreg.EnumKey(class_key, j)
                            except OSError:
                                break
                            j += 1
                            friendly_name = device_class
                            try:
                                with winreg.OpenKey(class_key, serial) as inst_key:
                                    try:
                                        friendly_name = winreg.QueryValueEx(inst_key, "FriendlyName")[0]
                                    except FileNotFoundError:
                                        pass
                            except OSError:
                                pass
                            devices.append({
                                "device_class": device_class,
                                "serial_number": serial,
                                "friendly_name": friendly_name,
                            })
                except OSError:
                    continue
    except FileNotFoundError:
        pass
    except Exception:
        pass
    return devices


def get_removable_drives():
    """Return drive letters (e.g. ['D:']) for currently connected removable
    (USB) drives."""
    drives = []
    ps_script = (
        "Get-CimInstance Win32_LogicalDisk -Filter \"DriveType=2\" "
        "| Select-Object DeviceID | ConvertTo-Json"
    )
    result = run_powershell(ps_script, timeout=30)
    if result is None:
        return drives
    raw = result.stdout.strip()
    if not raw:
        return drives
    try:
        data = json.loads(raw)
        if isinstance(data, dict):
            data = [data]
        for item in data:
            dev = item.get("DeviceID")
            if dev:
                drives.append(dev)
    except json.JSONDecodeError:
        pass
    return drives


USN_REASON_FLAGS = [
    (0x00000001, "Data overwritten"),
    (0x00000002, "Data extended (written/appended)"),
    (0x00000004, "Data truncated"),
    (0x00000010, "Named data stream overwritten"),
    (0x00000020, "Named data stream extended"),
    (0x00000040, "Named data stream truncated"),
    (0x00000100, "File/dir created"),
    (0x00000200, "File/dir deleted"),
    (0x00000400, "Extended attributes changed"),
    (0x00000800, "Security/ACL changed"),
    (0x00001000, "Renamed (old name)"),
    (0x00002000, "Renamed (new name)"),
    (0x00008000, "Basic info changed (timestamps/attributes)"),
    (0x00020000, "Compression state changed"),
    (0x00040000, "Encryption changed"),
    (0x00100000, "Reparse point changed"),
    (0x00200000, "Alternate data stream changed"),
    (0x80000000, "File/dir closed"),
]


def decode_usn_reason(reason_field):
    """USN 'Reason' comes back either as a hex string (e.g. '0x00000102')
    or already as comma-separated flag names depending on Windows/PowerShell
    version. Handle both."""
    if reason_field is None:
        return []
    text = str(reason_field).strip()
    if text.lower().startswith("0x"):
        try:
            value = int(text, 16)
        except ValueError:
            return [text]
        return [label for bit, label in USN_REASON_FLAGS if value & bit]
    # Already human-readable (comma separated), just split it.
    return [p.strip() for p in text.split(",") if p.strip()]


def collect_usb_write_operations(minutes_back):
    """
    Retroactive write/create/delete/rename history for connected removable
    drives, read from the NTFS USN Journal (enabled by default, no setup
    required). This does NOT capture reads -- the journal only tracks
    changes, never plain reads.
    """
    events = []
    note = None

    if not is_admin():
        return events, ("Reading the USN Journal requires Administrator "
                         "privileges. Re-run as Administrator to see file "
                         "write/create/delete history for the USB drive.")

    drives = get_removable_drives()
    if not drives:
        return events, ("No removable drive currently connected. Plug the "
                         "USB device in before running the script to see "
                         "file activity on it.")

    cutoff = datetime.now() - timedelta(minutes=minutes_back)

    for drive in drives:
        # Make sure a journal exists (harmless no-op if it already does).
        subprocess.run(["fsutil", "usn", "createjournal", "m=1000", "a=100", drive],
                        capture_output=True, text=True, timeout=15)

        try:
            result = subprocess.run(
                ["fsutil", "usn", "readjournal", drive, "csv"],
                capture_output=True, text=True, timeout=90
            )
        except Exception as e:
            note = f"Error reading USN journal on {drive}: {e}"
            continue

        if result.returncode != 0 or not result.stdout.strip():
            if note is None:
                note = (f"Could not read USN journal on {drive} "
                         f"(empty or unsupported on this drive/filesystem).")
            continue

        lines = [l for l in result.stdout.splitlines() if l.strip()]
        if len(lines) <= 1:
            continue

        header = [h.strip().strip('"') for h in lines[0].split(",")]

        def col(row, name):
            try:
                idx = header.index(name)
                return row[idx].strip().strip('"')
            except (ValueError, IndexError):
                return None

        for line in lines[1:]:
            row = line.split(",")
            timestamp_raw = col(row, "Time Stamp") or col(row, "TimeStamp")
            filename = col(row, "File name") or col(row, "FileName")
            reason = col(row, "Reason")

            ts = None
            if timestamp_raw:
                for fmt in ("%m/%d/%Y %H:%M:%S", "%m/%d/%Y %I:%M:%S %p"):
                    try:
                        ts = datetime.strptime(timestamp_raw, fmt)
                        break
                    except ValueError:
                        continue

            if ts is not None and ts < cutoff:
                continue

            events.append({
                "drive": drive,
                "time": timestamp_raw,
                "file_name": filename,
                "operations": decode_usn_reason(reason),
            })

    if not events and note is None:
        note = "No write/create/delete/rename activity found on connected removable drives in this window."

    return events, note


def enable_read_write_auditing(drives):
    """
    One-time setup so that FUTURE reads and writes on the given drives get
    logged as Security log event 4663. Cannot see anything that happened
    before this runs. Requires admin.
    """
    if not drives:
        return None
    if not is_admin():
        return "Enabling read/write auditing requires Administrator privileges."

    subprocess.run(
        ["auditpol", "/set", "/subcategory:File System", "/success:enable", "/failure:enable"],
        capture_output=True, text=True, timeout=15
    )

    for drive in drives:
        path = drive + "\\"
        ps_script = f"""
        $ErrorActionPreference = 'SilentlyContinue'
        $path = '{path}'
        $acl = Get-Acl -Path $path -Audit
        $rule = New-Object System.Security.AccessControl.FileSystemAuditRule(
            'Everyone', 'ReadData,WriteData', 'ContainerInherit,ObjectInherit', 'None', 'Success')
        $acl.AddAuditRule($rule)
        Set-Acl -Path $path -AclObject $acl -Audit
        """
        run_powershell(ps_script, timeout=30)

    return None


def collect_read_write_audit_events(minutes_back, drives):
    """
    Query event 4663 ('An attempt was made to access an object') from the
    Security log and split out Read vs Write based on the Accesses field.
    Only shows activity from AFTER auditing was enabled (see
    enable_read_write_auditing). Requires admin.
    """
    events = []
    note = None

    if not is_admin():
        return events, "Reading the Security log requires Administrator privileges."
    if not drives:
        return events, "No removable drive connected - nothing to audit."

    ps_script = f"""
    $ErrorActionPreference = 'SilentlyContinue'
    Get-WinEvent -FilterHashtable @{{
        LogName='Security'
        Id=4663
        StartTime=(Get-Date).AddMinutes(-{minutes_back})
    }} 2>$null | Select-Object TimeCreated, Message | ConvertTo-Json -Depth 3
    """
    result = run_powershell(ps_script, timeout=90)
    if result is None:
        return events, "PowerShell not found - this does not look like Windows."

    raw = result.stdout.strip()
    if not raw:
        return events, ("No read/write access events found yet. Auditing only "
                         "covers activity from the moment it was enabled this "
                         "run onward - access the drive, then re-run.")

    try:
        data = json.loads(raw)
        if isinstance(data, dict):
            data = [data]
    except json.JSONDecodeError:
        return events, "Could not parse Security log output."

    for item in data:
        msg = item.get("Message") or ""
        if not any(d.rstrip(":") in msg for d in drives):
            continue
        path_match = re.search(r"Object Name:\s*(.+)", msg)
        access_match = re.search(r"Accesses:\s*\n?\s*(.+)", msg)
        accesses = access_match.group(1).strip() if access_match else ""
        op = []
        if "ReadData" in accesses or "Read Data" in accesses:
            op.append("Read")
        if "WriteData" in accesses or "Write Data" in accesses:
            op.append("Write")
        if not op:
            continue
        events.append({
            "time": item.get("TimeCreated"),
            "file_name": path_match.group(1).strip() if path_match else None,
            "operations": op,
        })

    if not events and note is None:
        note = "No matching read/write events for the connected drive(s) in this window yet."

    return events, note


def collect_windows_logins(minutes_back):
    """
    Login events (4624/4625/4634/4647) live in the Security log, which
    Windows locks down to Administrators/SYSTEM by design -- a standard user
    process will always get 0 results here, no matter how the query is
    written. There is no way around this other than running elevated.

    Note: enabling audit policy only affects LOGONS THAT HAPPEN AFTER you
    enable it. It cannot retroactively produce events for past logins.
    """
    events = []
    note = None

    if not is_admin():
        return events, ("Security log requires Administrator privileges. "
                         "Right-click PowerShell/CMD -> 'Run as Administrator', "
                         "then re-run this script.")

    # Make sure logon auditing is on going forward (safe to re-run).
    try:
        subprocess.run(
            ["auditpol", "/set", "/subcategory:Logon", "/success:enable", "/failure:enable"],
            capture_output=True, text=True, timeout=15
        )
    except Exception:
        pass

    ps_script = f"""
    $ErrorActionPreference = 'SilentlyContinue'
    Get-WinEvent -FilterHashtable @{{
        LogName='Security'
        Id=4624,4625,4634,4647
        StartTime=(Get-Date).AddMinutes(-{minutes_back})
    }} 2>$null | Select-Object TimeCreated, Id, Message | ConvertTo-Json -Depth 3
    """
    result = run_powershell(ps_script)

    if result is None:
        note = "PowerShell not found - this does not look like Windows."
    else:
        raw = result.stdout.strip()
        if raw:
            try:
                data = json.loads(raw)
                if isinstance(data, dict):
                    data = [data]
                for item in data:
                    msg = item.get("Message") or ""
                    account_match = re.search(r"Account Name:\s*(.+)", msg)
                    events.append({
                        "time": item.get("TimeCreated"),
                        "event_id": item.get("Id"),
                        "account": account_match.group(1).strip() if account_match else None,
                        "description": msg[:300],
                    })
            except json.JSONDecodeError:
                note = "Could not parse Security log output."

    if not events and note is None:
        note = ("No login events found in this window. Auditing has just been "
                 "(re)enabled for future logons -- if this is a fresh enable, "
                 "log out/in once and re-run to see results.")

    return events, note


# ---------------------------------------------------------------------------
# Linux
# ---------------------------------------------------------------------------

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
        note = ("No login events found. Try running with sudo, or check "
                "/var/log/auth.log directly (Debian/Ubuntu).")
    return events, note


# ---------------------------------------------------------------------------
# macOS
# ---------------------------------------------------------------------------

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

    admin = is_admin()
    if not admin:
        print("[!] Warning: not running as admin/root - login events (and possibly "
              "some USB events) will be incomplete or empty. Re-run elevated for "
              "full results.")

    usb_history = []
    write_events, write_note = [], None
    audit_events, audit_note = [], None
    if os_name == "Windows":
        usb_events, usb_note, usb_history = collect_windows_usb(MINUTES_BACK)
        login_events, login_note = collect_windows_logins(MINUTES_BACK)

        write_events, write_note = collect_usb_write_operations(MINUTES_BACK)

        drives = get_removable_drives()
        if ENABLE_READ_WRITE_AUDIT and drives:
            audit_err = enable_read_write_auditing(drives)
            if audit_err:
                audit_note = audit_err
            else:
                audit_events, audit_note = collect_read_write_audit_events(MINUTES_BACK, drives)
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
        "ran_as_admin": admin,
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
    if os_name == "Windows":
        payload["usbstor_history"] = {
            "count": len(usb_history),
            "devices": usb_history,
            "note": "Full list of USB storage devices ever connected (from registry, no timestamp).",
        }
        payload["file_operations"] = {
            "writes_creates_deletes_renames": {
                "count": len(write_events),
                "events": write_events,
                "note": write_note,
                "source": "NTFS USN Journal - retroactive, no setup required.",
            },
            "read_write_audit": {
                "count": len(audit_events),
                "events": audit_events,
                "note": audit_note,
                "source": ("Security log event 4663 via SACL auditing - only "
                            "covers activity from when auditing was enabled "
                            "onward, cannot see past reads."),
                "enabled": ENABLE_READ_WRITE_AUDIT,
            },
        }

    fname = save_evidence(payload, os_name)

    print(f"[*] USB events found: {len(usb_events)}")
    if usb_note:
        print(f"[i] USB note: {usb_note}")
    if os_name == "Windows":
        print(f"[*] USB storage devices in registry history: {len(usb_history)}")
        print(f"[*] Write/create/delete/rename events found: {len(write_events)}")
        if write_note:
            print(f"[i] Write history note: {write_note}")
        print(f"[*] Read/write audit events found: {len(audit_events)}")
        if audit_note:
            print(f"[i] Read/write audit note: {audit_note}")
    print(f"[*] Login events found: {len(login_events)}")
    if login_note:
        print(f"[i] Login note: {login_note}")
    print(f"[+] Evidence saved to: {fname}")


if __name__ == "__main__":
    main()