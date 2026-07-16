import glob
import hashlib
import ipaddress
import json
import os
import re
import sys
import urllib.parse
from datetime import datetime, timezone

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
)
from reportlab.lib.enums import TA_CENTER


SUSPICIOUS_KEYWORDS = [
    "mimikatz", "psexec", "ncat", "netcat", "meterpreter",
    "cobaltstrike", "beacon", "empire", "bloodhound", "sharphound",
    "invoke-expression", "iex(", "-enc ", "-encodedcommand",
    "downloadstring", "downloadfile", "frombase64string",
    "certutil -urlcache", "certutil -decode", "bitsadmin",
    "rundll32.exe javascript", "regsvr32 /u /s /i:http",
    "wmic process call create", "reverse shell",
]

SUSPICIOUS_PATH_FRAGMENTS = [
    "\\temp\\", "/tmp/", "\\appdata\\local\\temp", "\\public\\",
    "\\programdata\\", "/dev/shm/", "\\users\\public\\downloads",
    "/var/tmp/",
]

COMMONLY_SPOOFED_NAMES = {
    "svchost.exe", "explorer.exe", "lsass.exe", "csrss.exe",
    "winlogon.exe", "services.exe", "smss.exe", "spoolsv.exe",
}

REMOTE_ACCESS_TOOLS = {
    "anydesk.exe", "teamviewer.exe", "chromeremotedesktop.exe",
    "ammyy.exe", "logmein.exe", "splashtop.exe", "ultraviewer.exe",
    "supremo.exe", "vnc.exe", "tightvnc.exe", "realvnc.exe",
}

HIGH_RISK_PORTS = {4444, 4445, 1337, 31337, 8081, 6666, 6667, 12345, 54321}
WELL_KNOWN_LOW_RISK_PORTS = {80, 443, 53, 123, 25, 110, 143, 993, 995, 22, 21}

PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("64:ff9b::/96"),
]

FAMILY_MAP = {"2": "IPv4", "10": "IPv6", "23": "IPv6", "30": "IPv6"}
TYPE_MAP = {"1": "TCP", "2": "UDP"}

# Windows logon type reference (only used if login_events carry a logon_type field)
RISKY_LOGON_TYPES = {10: "RemoteInteractive (RDP)", 3: "Network"}
FAILED_LOGON_EVENT_IDS = {"4625"}

# Windows Event Log IDs that commonly warrant closer review during triage.
SUSPICIOUS_EVENT_IDS = {
    "1102": ("High", "Audit log was cleared - a common anti-forensic action"),
    "104": ("High", "Event log (System/Application) was cleared"),
    "4720": ("Medium", "A user account was created"),
    "4726": ("Medium", "A user account was deleted"),
    "4732": ("Medium", "A member was added to a security-enabled local group"),
    "4728": ("Medium", "A member was added to a security-enabled global group"),
    "4756": ("Medium", "A member was added to a security-enabled universal group"),
    "4698": ("Medium", "A scheduled task was created"),
    "4699": ("Low", "A scheduled task was deleted"),
    "7045": ("Medium", "A new service was installed"),
    "4697": ("Medium", "A service was installed (Security log)"),
    "4625": ("Medium", "A failed logon attempt was recorded"),
    "4648": ("Medium", "A logon was attempted using explicit credentials"),
    "4672": ("Low", "Special privileges were assigned to a new logon"),
    "7040": ("Low", "A service's start type was changed"),
    "1116": ("High", "Antivirus/Defender detected malware"),
    "1117": ("Medium", "Antivirus/Defender took action on detected malware"),
    "5001": ("Medium", "Antivirus/Defender real-time protection was disabled/changed"),
}

# Message/provider keywords worth flagging even without a matching event ID above.
SUSPICIOUS_EVENT_MESSAGE_KEYWORDS = SUSPICIOUS_KEYWORDS + [
    "windows defender", "real-time protection", "audit log was cleared",
    "log was cleared", "shadow copy", "vssadmin", "wevtutil",
]

# Keywords in browser history (URL or page title) that commonly indicate
# reconnaissance, evasion, or acquisition of offensive tooling. This is a
# coarse triage heuristic, not proof of intent - plenty of legitimate research
# (including forensics work itself) will touch some of these terms.
SUSPICIOUS_BROWSER_KEYWORDS = [
    "mimikatz", "metasploit", "meterpreter", "cobalt strike", "empire c2",
    "bloodhound", "sharphound", "psexec", "netcat", "ncat",
    "clear event log", "clear windows event log", "wevtutil cl",
    "disable windows defender", "bypass antivirus", "bypass edr",
    "keygen", "crack license", "warez", "torrent",
    "how to wipe forensic", "anti-forensic", "delete usb history",
    "delete browser history tool", "vpn no logs", "tor browser download",
    "pastebin.com/raw", "dark web market","murder","porn"
]

SEARCH_ENGINE_QUERY_PARAMS = {
    "google.": "q",
    "bing.com": "q",
    "duckduckgo.com": "q",
    "yahoo.com": "p",
    "search.yahoo.com": "p",
    "baidu.com": "wd",
    "yandex.": "text",
    "ask.com": "q",
    "startpage.com": "query",
}

RANK = {"High": 3, "Medium": 2, "Low": 1, "Info": 0, "Clean": -1}

SEVERITY_COLOR = {
    "High": colors.HexColor("#B00020"),
    "Medium": colors.HexColor("#B8860B"),
    "Low": colors.HexColor("#2F6F4E"),
    "Info": colors.HexColor("#3B5F8A"),
    "Clean": colors.HexColor("#6B7280"),
}


# ---------------------------------------------------------------------------
# Evidence file discovery
# ---------------------------------------------------------------------------

def find_evidence_dir():
    here = os.path.dirname(os.path.abspath(__file__)) if "__file__" in globals() else os.getcwd()
    for base in (os.getcwd(), here):
        for name in ("Evidence", "Evidences", "evidence", "evidences"):
            candidate = os.path.join(base, name)
            if os.path.isdir(candidate):
                return candidate
    return os.getcwd()


def find_evidence_file(evidence_dir, keywords):
    candidates = []
    try:
        entries = os.listdir(evidence_dir)
    except OSError:
        entries = []
    for fname in entries:
        if fname.lower().endswith(".json") and any(k in fname.lower() for k in keywords):
            candidates.append(os.path.join(evidence_dir, fname))
    if not candidates:
        return None
    candidates.sort(key=os.path.getmtime, reverse=True)
    return candidates[0]


# ---------------------------------------------------------------------------
# Loading helpers
# ---------------------------------------------------------------------------

def sha256_of_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


LIST_KEYS = ("processes", "process_list", "network", "networks",
             "connections", "data", "results", "items", "records")


def load_json_with_meta(path):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        data = json.load(f)

    if isinstance(data, list):
        return {}, data

    if isinstance(data, dict):
        for key in LIST_KEYS:
            if key in data and isinstance(data[key], list):
                meta = {k: v for k, v in data.items() if k != key}
                return meta, data[key]
        if all(isinstance(v, dict) for v in data.values()) and data:
            return {}, list(data.values())

    raise ValueError(f"Could not find a list of records in {path}")


def load_usb_login_json(path):
    """This file has a distinct shape: {..., usb_events: {count, events, note},
    login_events: {count, events, note}}. Return (meta, usb_events, usb_note,
    login_events, login_note)."""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        data = json.load(f)

    meta = {k: v for k, v in data.items() if k not in ("usb_events", "login_events")}
    usb_block = data.get("usb_events", {}) or {}
    login_block = data.get("login_events", {}) or {}
    return (
        meta,
        usb_block.get("events", []) or [],
        usb_block.get("note", ""),
        login_block.get("events", []) or [],
        login_block.get("note", ""),
    )


def load_eventlog_json(path):
    """Shape: {..., logs: {"System": [...], "Application": [...], "Security": [...]}}.
    Returns (meta, {channel_name: [raw_records]})."""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        data = json.load(f)

    meta = {k: v for k, v in data.items() if k != "logs"}
    logs_block = data.get("logs", {}) or {}
    channels = {}
    for channel, entries in logs_block.items():
        if isinstance(entries, list):
            channels[channel] = entries
    return meta, channels


def load_browser_json(path):
    """Shape: {..., browsers: {"Chrome (Profile 1)": {source_path, history_count,
    history: [...]}}}. Returns (meta, {browser_name: {source_path, history: [...]}})."""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        data = json.load(f)

    meta = {k: v for k, v in data.items() if k != "browsers"}
    browsers_block = data.get("browsers", {}) or {}
    browsers = {}
    for name, info in browsers_block.items():
        if not isinstance(info, dict):
            continue
        browsers[name] = {
            "source_path": info.get("source_path", ""),
            "history_count": info.get("history_count", len(info.get("history", []) or [])),
            "history": info.get("history", []) or [],
        }
    return meta, browsers


def first_present(rec, keys, default=""):
    for k in keys:
        if k in rec and rec[k] not in (None, ""):
            return rec[k]
    return default


def stringify_cmdline(raw):
    if isinstance(raw, list):
        return " ".join(str(x) for x in raw)
    if raw in (None, "Access Denied"):
        return ""
    return str(raw)


def split_addr_port(addr_str):
    if not addr_str:
        return "", ""
    if ":" not in addr_str:
        return addr_str, ""
    ip_part, _, port_part = addr_str.rpartition(":")
    return ip_part, port_part


def is_private_or_reserved(addr):
    if not addr:
        return True
    try:
        ip = ipaddress.ip_address(addr.split("%")[0])
        return any(ip in net for net in PRIVATE_NETS)
    except ValueError:
        return True


def parse_dotnet_date(raw):
    """Parse timestamps shaped like '/Date(1784193031572)/' (ms since epoch, UTC).
    Falls back to returning the original string unchanged if it doesn't match."""
    if not raw:
        return ""
    s = str(raw)
    m = re.match(r"^/Date\((-?\d+)\)/$", s.strip())
    if not m:
        return s
    ms = int(m.group(1))
    try:
        dt = datetime.fromtimestamp(ms / 1000.0, tz=timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except (ValueError, OverflowError, OSError):
        return s


def extract_search_query(url):
    """If the URL looks like a search-engine results page, return the decoded
    query string; otherwise return None."""
    if not url:
        return None
    try:
        parsed = urllib.parse.urlparse(url)
    except ValueError:
        return None
    host = (parsed.netloc or "").lower()
    for domain_fragment, param in SEARCH_ENGINE_QUERY_PARAMS.items():
        if domain_fragment in host:
            qs = urllib.parse.parse_qs(parsed.query)
            values = qs.get(param)
            if values:
                return values[0]
    return None


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------

def normalize_process(rec, idx):
    raw_pid = rec.get("pid")
    pid_valid = isinstance(raw_pid, int) or (
        isinstance(raw_pid, str) and raw_pid.strip().lstrip("-").isdigit()
    )
    pid = str(raw_pid) if pid_valid else f"IDX-{idx}"

    raw_ppid = rec.get("ppid")
    ppid = str(raw_ppid) if isinstance(raw_ppid, int) else str(
        first_present(rec, ["ppid", "PPID", "parent_pid"], "?"))

    exe_raw = first_present(rec, ["exe", "path", "ExecutablePath"], "")
    access_denied = exe_raw == "Access Denied"
    path = "" if access_denied else exe_raw

    embedded_conns = []

    connections = rec.get("connections", [])

    if isinstance(connections, str):
        connections = []

    for c in connections:
        if not isinstance(c, dict):
            continue

        laddr = c.get("laddr") or []
        raddr = c.get("raddr") or []

        embedded_conns.append({
            "laddr": laddr[0] if len(laddr) > 0 else "",
            "lport": str(laddr[1]) if len(laddr) > 1 else "",
            "raddr": raddr[0] if len(raddr) > 0 else "",
            "rport": str(raddr[1]) if len(raddr) > 1 else "",
            "state": c.get("status", ""),
        })

    return {
        "pid": pid,
        "pid_valid": pid_valid,
        "ppid": ppid,
        "name": str(first_present(rec, ["name", "Name", "process_name"], "unknown")),
        "path": path,
        "access_denied": access_denied,
        "cmdline": stringify_cmdline(rec.get("cmdline")),
        "user": str(first_present(rec, ["username", "user", "owner"], "")),
        "start_time": str(first_present(rec, ["create_time_readable", "start_time"], "")),
        "status": str(first_present(rec, ["status", "state"], "")),
        "embedded_conns": embedded_conns,
        "_raw": rec,
    }


def normalize_connection(rec):
    local_ip, local_port = "", ""
    remote_ip, remote_port = "", ""

    if "local_address" in rec:
        local_ip, local_port = split_addr_port(rec.get("local_address") or "")
        remote_ip, remote_port = split_addr_port(rec.get("remote_address") or "")
    else:
        laddr = rec.get("laddr") or []
        raddr = rec.get("raddr") or []
        local_ip = laddr[0] if len(laddr) > 0 else str(first_present(rec, ["local_address"], ""))
        local_port = str(laddr[1]) if len(laddr) > 1 else str(first_present(rec, ["lport", "local_port"], ""))
        remote_ip = raddr[0] if len(raddr) > 0 else ""
        remote_port = str(raddr[1]) if len(raddr) > 1 else ""

    family = str(first_present(rec, ["family"], ""))
    ttype = str(first_present(rec, ["type"], ""))
    protocol = TYPE_MAP.get(ttype, ttype or "?")
    if family:
        protocol = f"{protocol}/{FAMILY_MAP.get(family, family)}"

    return {
        "pid": str(first_present(rec, ["pid", "owning_pid"], "?")),
        "program": str(first_present(rec, ["process_name", "program", "name"], "")),
        "protocol": protocol,
        "laddr": local_ip,
        "lport": local_port,
        "raddr": remote_ip,
        "rport": remote_port,
        "state": str(first_present(rec, ["status", "state"], "")),
        "_raw": rec,
    }


def normalize_usb_event(rec, idx):
    return {
        "id": f"USB-{idx}",
        "device": str(first_present(rec, ["friendly_name", "device_name", "name", "description"], "Unknown device")),
        "vendor_id": str(first_present(rec, ["vendor_id", "vid"], "")),
        "product_id": str(first_present(rec, ["product_id", "pid"], "")),
        "serial": str(first_present(rec, ["serial_number", "serial"], "")),
        "drive_letter": str(first_present(rec, ["drive_letter", "drive"], "")),
        "event_type": str(first_present(rec, ["event_type", "action", "type"], "")),
        "timestamp": str(first_present(rec, ["timestamp", "time", "connect_time", "datetime"], "")),
        "_raw": rec,
    }


def normalize_login_event(rec, idx):
    return {
        "id": f"LOGIN-{idx}",
        "username": str(first_present(rec, ["username", "user", "account"], "")),
        "event_id": str(first_present(rec, ["event_id", "eventid", "id"], "")),
        "logon_type": first_present(rec, ["logon_type", "logontype"], ""),
        "source": str(first_present(rec, ["source_ip", "workstation", "source"], "")),
        "success": first_present(rec, ["success", "status", "result"], ""),
        "timestamp": str(first_present(rec, ["timestamp", "time", "datetime"], "")),
        "_raw": rec,
    }


def normalize_event_log(rec, channel, idx):
    time_raw = first_present(rec, ["TimeCreated", "time_created", "timestamp"], "")
    return {
        "id": f"EVT-{channel}-{idx}",
        "channel": str(channel),
        "event_id": str(first_present(rec, ["Id", "EventID", "event_id"], "")),
        "level": str(first_present(rec, ["LevelDisplayName", "Level"], "")),
        "provider": str(first_present(rec, ["ProviderName", "Provider"], "")),
        "message": str(first_present(rec, ["Message", "message"], "")),
        "timestamp": parse_dotnet_date(time_raw),
        "_raw": rec,
    }


def normalize_browser_entry(rec, browser_name, idx):
    return {
        "id": f"WEB-{idx}",
        "browser": str(browser_name),
        "url": str(first_present(rec, ["url"], "")),
        "title": str(first_present(rec, ["title"], "")),
        "visit_count": first_present(rec, ["visit_count"], ""),
        "timestamp": str(first_present(rec, ["last_visit_time_iso", "last_visit_time"], "")),
        "_raw": rec,
    }


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

def analyze(processes, connections, usb_events, usb_note, login_events, login_note,
            event_logs=None, browser_entries=None):
    event_logs = event_logs or []
    browser_entries = browser_entries or []
    findings = []

    # --- Data-quality / collection-integrity findings ---
    invalid_pid_count = sum(1 for p in processes if not p["pid_valid"])
    if invalid_pid_count:
        findings.append({
            "severity": "Info", "target": "process",
            "category": "Data integrity - corrupted PID field",
            "detail": (
                f"{invalid_pid_count} of {len(processes)} process records contain a "
                f"non-numeric 'pid' value, indicating a bug in the collection script "
                f"(likely calling psutil's Process.pid as a method instead of reading "
                f"it as a property). PID-based correlation with the network export is "
                f"unreliable for these records; process-name correlation was used "
                f"instead, and synthetic IDs (IDX-n) were assigned for reference."
            ),
            "pid": "-",
        })

    access_denied_count = sum(1 for p in processes if p["access_denied"])
    if access_denied_count:
        findings.append({
            "severity": "Info", "target": "process",
            "category": "Data integrity - restricted process access",
            "detail": (
                f"{access_denied_count} process record(s) could not have their "
                f"executable path read (permission denied) - normal for some "
                f"protected system processes, but limits path verification for them."
            ),
            "pid": "-",
        })

    if not usb_events:
        findings.append({
            "severity": "Info", "target": "usb",
            "category": "Collection gap - no USB events captured",
            "detail": usb_note or "No USB events were present in the evidence file.",
            "pid": "-",
        })

    if not login_events:
        findings.append({
            "severity": "Info", "target": "login",
            "category": "Collection gap - no login events captured",
            "detail": (login_note or "No login events were present in the evidence file.") +
                      " This is a collection gap, not evidence that no logons occurred - "
                      "verify independently via the Windows Security event log or Sysmon "
                      "if login activity is in scope for this investigation.",
            "pid": "-",
        })

    flagged_names = set()

    # 1. Suspicious keywords
    for p in processes:
        haystack = " ".join([p["name"], p["path"], p["cmdline"]]).lower()
        for kw in SUSPICIOUS_KEYWORDS:
            if kw in haystack:
                findings.append({
                    "severity": "High", "target": "process",
                    "category": "Suspicious command / tool reference",
                    "detail": f"{p['name']} (pid {p['pid']}) matched keyword '{kw.strip()}' "
                              f"in its path or command line.",
                    "pid": p["pid"],
                })
                flagged_names.add(p["name"].lower())
                break

    # 2. Execution from suspicious / user-writable paths
    for p in processes:
        low_path = p["path"].lower()
        for frag in SUSPICIOUS_PATH_FRAGMENTS:
            if frag in low_path:
                findings.append({
                    "severity": "Medium", "target": "process",
                    "category": "Execution from non-standard directory",
                    "detail": f"{p['name']} (pid {p['pid']}) runs from a temp/user-writable "
                              f"location: {p['path']}",
                    "pid": p["pid"],
                })
                flagged_names.add(p["name"].lower())
                break

    # 3. Masquerading
    for p in processes:
        lname = p["name"].lower()
        if lname in COMMONLY_SPOOFED_NAMES and p["path"]:
            path_low = p["path"].lower()
            if "system32" not in path_low and "syswow64" not in path_low \
                    and "\\windows\\" not in path_low:
                findings.append({
                    "severity": "High", "target": "process",
                    "category": "Possible process masquerading",
                    "detail": f"{p['name']} (pid {p['pid']}) is named after a common system "
                              f"process but runs from: {p['path']}",
                    "pid": p["pid"],
                })
                flagged_names.add(p["name"].lower())

    # 4. Remote access tooling
    for p in processes:
        if p["name"].lower() in REMOTE_ACCESS_TOOLS:
            findings.append({
                "severity": "Medium", "target": "process",
                "category": "Remote access tool present",
                "detail": f"{p['name']} (pid {p['pid']}) is a remote-access/remote-support "
                          f"tool. Confirm whether its use on this host is authorized.",
                "pid": p["pid"],
            })

    # 5. External network connections
    for c in connections:
        raddr = c["raddr"]
        if raddr and not is_private_or_reserved(raddr):
            try:
                port_num = int(c["rport"])
            except ValueError:
                port_num = None
            severity = "Low" if port_num in WELL_KNOWN_LOW_RISK_PORTS else "Medium"
            findings.append({
                "severity": severity, "target": "connection",
                "category": "External network connection",
                "detail": f"{c['program']} (pid {c['pid']}) connected to external address "
                          f"{raddr}:{c['rport']} ({c['protocol']}, state={c['state']}).",
                "pid": c["pid"],
            })

    # 6. High-risk ports
    for c in connections:
        for port_field in (c["rport"], c["lport"]):
            try:
                if int(port_field) in HIGH_RISK_PORTS:
                    findings.append({
                        "severity": "High", "target": "connection",
                        "category": "Known high-risk port",
                        "detail": f"{c['program']} (pid {c['pid']}) uses port {port_field}, "
                                  f"commonly associated with backdoors/reverse shells.",
                        "pid": c["pid"],
                    })
            except ValueError:
                pass

    # 7. Network activity from an already-flagged process (name-based join)
    for c in connections:
        if c["program"].lower() in flagged_names and c["raddr"]:
            findings.append({
                "severity": "High", "target": "connection",
                "category": "Network activity from a previously flagged process",
                "detail": f"{c['program']} (pid {c['pid']}) - already flagged above for "
                          f"suspicious path/command-line indicators - has an active "
                          f"connection to {c['raddr']}:{c['rport']}.",
                "pid": c["pid"],
            })

    # 8. USB events - flag every connection event, escalate for unidentified devices
    for u in usb_events:
        has_id = bool(u["vendor_id"] or u["product_id"] or u["serial"])
        severity = "Low" if has_id else "Medium"
        detail = f"USB device event: {u['device']}"
        if u["drive_letter"]:
            detail += f" (mounted as {u['drive_letter']})"
        if not has_id:
            detail += " - no vendor/product/serial identifier captured, cannot verify device identity."
        if u["timestamp"]:
            detail += f" at {u['timestamp']}."
        findings.append({
            "severity": severity, "target": "usb",
            "category": "Removable storage / USB device activity",
            "detail": detail,
            "pid": u["id"],
        })

    # 9. Login events - failures, RDP/network logons, unrecognized sources
    failure_counter = {}
    for l in login_events:
        is_failure = str(l["event_id"]) in FAILED_LOGON_EVENT_IDS or \
            str(l["success"]).lower() in ("false", "failure", "0")
        logon_type = l["logon_type"]
        try:
            logon_type_int = int(logon_type)
        except (ValueError, TypeError):
            logon_type_int = None

        if is_failure:
            key = (l["username"], l["source"])
            failure_counter[key] = failure_counter.get(key, 0) + 1
            findings.append({
                "severity": "Medium", "target": "login",
                "category": "Failed logon attempt",
                "detail": f"Failed logon for '{l['username']}' from {l['source'] or 'unknown source'} "
                          f"at {l['timestamp']}.",
                "pid": l["id"],
            })
        elif logon_type_int in RISKY_LOGON_TYPES:
            findings.append({
                "severity": "Low", "target": "login",
                "category": "Remote/network logon",
                "detail": f"Logon type {logon_type_int} ({RISKY_LOGON_TYPES[logon_type_int]}) "
                          f"for '{l['username']}' from {l['source'] or 'unknown source'} "
                          f"at {l['timestamp']}.",
                "pid": l["id"],
            })

    for (username, source), count in failure_counter.items():
        if count >= 5:
            findings.append({
                "severity": "High", "target": "login",
                "category": "Possible brute-force logon attempts",
                "detail": f"{count} failed logon attempts for '{username}' from "
                          f"{source or 'unknown source'} within the collection window.",
                "pid": "-",
            })

    # 10. Windows Event Log entries - known-risky event IDs, error/critical levels,
    #     and keyword matches in the message text.
    if not event_logs:
        findings.append({
            "severity": "Info", "target": "eventlog",
            "category": "Collection gap - no Windows Event Log entries captured",
            "detail": "No Windows Event Log entries were present in the evidence file.",
            "pid": "-",
        })

    for e in event_logs:
        matched = False
        if e["event_id"] in SUSPICIOUS_EVENT_IDS:
            severity, reason = SUSPICIOUS_EVENT_IDS[e["event_id"]]
            findings.append({
                "severity": severity, "target": "eventlog",
                "category": f"Notable event ID {e['event_id']} ({e['channel']})",
                "detail": f"{reason}. Provider: {e['provider']}, at {e['timestamp']}.",
                "pid": e["id"],
            })
            matched = True

        haystack = f"{e['provider']} {e['message']}".lower()
        for kw in SUSPICIOUS_EVENT_MESSAGE_KEYWORDS:
            if kw in haystack:
                findings.append({
                    "severity": "High", "target": "eventlog",
                    "category": "Suspicious keyword in event log message",
                    "detail": f"Event ID {e['event_id']} ({e['channel']}, provider "
                              f"{e['provider']}) message matched '{kw.strip()}' at "
                              f"{e['timestamp']}.",
                    "pid": e["id"],
                })
                matched = True
                break

        if not matched and e["level"].lower() in ("error", "critical"):
            findings.append({
                "severity": "Low", "target": "eventlog",
                "category": f"{e['level']} level event ({e['channel']})",
                "detail": f"Event ID {e['event_id']} from provider {e['provider']} "
                          f"logged at {e['level']} level at {e['timestamp']}.",
                "pid": e["id"],
            })

    # 11. Browser history - keyword matches on URL/title.
    if not browser_entries:
        findings.append({
            "severity": "Info", "target": "browser",
            "category": "Collection gap - no browser history captured",
            "detail": "No browser history entries were present in the evidence file.",
            "pid": "-",
        })

    for b in browser_entries:
        haystack = f"{b['url']} {b['title']}".lower()
        for kw in SUSPICIOUS_BROWSER_KEYWORDS:
            if kw in haystack:
                findings.append({
                    "severity": "High", "target": "browser",
                    "category": "Suspicious browser history entry",
                    "detail": f"{b['browser']} history matched '{kw.strip()}' - "
                              f"\"{b['title']}\" ({b['url']}) last visited {b['timestamp']}.",
                    "pid": b["id"],
                })
                break

    return findings


def build_network_correlation(connections):
    corr = {}
    for c in connections:
        key = (c["pid"], c["program"])
        corr.setdefault(key, []).append(c)
    return corr


def build_risk_map(findings):
    """row-id -> highest severity, for High/Medium/Low findings only (Info excluded)."""
    m = {}
    for f in findings:
        sev = f["severity"]
        if sev not in ("High", "Medium", "Low"):
            continue
        rid = f["pid"]
        if rid in ("-", "?"):
            continue
        if rid not in m or RANK[sev] > RANK[m[rid]]:
            m[rid] = sev
    return m


def risk_label_cell(risk, cell_style):
    color = SEVERITY_COLOR.get(risk, SEVERITY_COLOR["Clean"])
    return Paragraph(f'<font color="{color.hexval()}"><b>{risk}</b></font>', cell_style)


# ---------------------------------------------------------------------------
# PDF generation
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {"High": 0, "Medium": 1, "Low": 2, "Info": 3}


def safe(text):
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def make_table(data, col_widths, header_bg=colors.HexColor("#1F2937")):
    t = Table(data, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), header_bg),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 7.5),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#B0B0B0")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F4F4F6")]),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    return t


def generate_pdf(output_path, case_name, examiner, evidence_source,
                  proc_path, net_path, usb_path,
                  proc_meta, net_meta, usb_meta,
                  processes, connections, usb_events, usb_note,
                  login_events, login_note, findings,
                  eventlog_path=None, eventlog_meta=None, event_logs=None,
                  browser_path=None, browser_meta=None, browsers=None,
                  browser_entries=None):

    eventlog_meta = eventlog_meta or {}
    event_logs = event_logs or []
    browser_meta = browser_meta or {}
    browsers = browsers or {}
    browser_entries = browser_entries or []

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("TitleBig", parent=styles["Title"], fontSize=23,
                                  alignment=TA_CENTER, textColor=colors.HexColor("#1F2937"))
    subtitle_style = ParagraphStyle("Subtitle", parent=styles["Normal"], fontSize=12,
                                     alignment=TA_CENTER, textColor=colors.HexColor("#555555"),
                                     spaceAfter=6)
    h1 = ParagraphStyle("H1", parent=styles["Heading1"], fontSize=15,
                         textColor=colors.HexColor("#1F2937"), spaceBefore=14, spaceAfter=8)
    h2 = ParagraphStyle("H2Generic", parent=styles["Heading2"], fontSize=11,
                         spaceBefore=6, spaceAfter=4)
    body = ParagraphStyle("Body", parent=styles["Normal"], fontSize=9.5, leading=13)
    small = ParagraphStyle("Small", parent=styles["Normal"], fontSize=8, leading=11,
                            textColor=colors.HexColor("#444444"))
    cell = ParagraphStyle("Cell", parent=styles["Normal"], fontSize=7.5, leading=9)

    doc = SimpleDocTemplate(
        output_path, pagesize=letter,
        leftMargin=0.6 * inch, rightMargin=0.6 * inch,
        topMargin=0.6 * inch, bottomMargin=0.6 * inch,
        title=f"Digital Forensics Report - {case_name}",
    )

    story = []
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    risk_map = build_risk_map(findings)

    # ---------------- Cover page ----------------
    story.append(Spacer(1, 1.0 * inch))
    story.append(Paragraph("Digital Forensics Analysis Report", title_style))
    story.append(Spacer(1, 0.12 * inch))
    story.append(Paragraph("Process, Network, USB/Login, Event Log &amp; Browser History Review", subtitle_style))
    story.append(Spacer(1, 0.4 * inch))

    hostname = (proc_meta.get("hostname") or net_meta.get("hostname") or usb_meta.get("hostname")
                or eventlog_meta.get("hostname") or browser_meta.get("hostname") or "Unknown")
    os_name = (proc_meta.get("detected_os") or net_meta.get("detected_os") or usb_meta.get("detected_os")
               or eventlog_meta.get("detected_os") or browser_meta.get("detected_os") or "Unknown")
    os_version = proc_meta.get("os_version", "")

    cover_data = [
        ["Case Name:", safe(case_name)],
        ["Examiner:", safe(examiner)],
        ["Evidence Source:", safe(evidence_source)],
        ["Host (from evidence):", safe(hostname)],
        ["OS (from evidence):", safe(f"{os_name} {os_version}".strip())],
        ["Report Generated:", now],
        ["Process Export Collected:", safe(proc_meta.get("generated_at", "Unknown"))],
        ["Network Export Collected:", safe(net_meta.get("generated_at", "Unknown"))],
        ["USB/Login Export Collected:", safe(usb_meta.get("generated_at", "Unknown")) if usb_path else "Not provided"],
        ["Event Log Export Collected:", safe(eventlog_meta.get("generated_at", "Unknown")) if eventlog_path else "Not provided"],
        ["Browser History Export Collected:", safe(browser_meta.get("generated_at", "Unknown")) if browser_path else "Not provided"],
        ["Evidence File 1 (Processes):", os.path.basename(proc_path)],
        ["  SHA-256:", sha256_of_file(proc_path)],
        ["Evidence File 2 (Network):", os.path.basename(net_path)],
        ["  SHA-256:", sha256_of_file(net_path)],
    ]
    if usb_path:
        cover_data += [
            ["Evidence File 3 (USB/Login):", os.path.basename(usb_path)],
            ["  SHA-256:", sha256_of_file(usb_path)],
        ]
    if eventlog_path:
        cover_data += [
            ["Evidence File 4 (Event Logs):", os.path.basename(eventlog_path)],
            ["  SHA-256:", sha256_of_file(eventlog_path)],
        ]
    if browser_path:
        cover_data += [
            ["Evidence File 5 (Browser History):", os.path.basename(browser_path)],
            ["  SHA-256:", sha256_of_file(browser_path)],
        ]
    cover_table = Table(cover_data, colWidths=[2.3 * inch, 4.0 * inch])
    cover_table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#333333")),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(cover_table)
    story.append(Spacer(1, 0.35 * inch))
    story.append(Paragraph(
        "This report was generated by an automated triage script that parses "
        "process, network-connection, USB/login, Windows Event Log, and browser "
        "history evidence, cross-references the data sets, and flags indicators "
        "that commonly warrant closer manual review. Automated flags and Risk "
        "ratings are investigative leads, not conclusions - every finding below "
        "should be independently verified by the examiner.",
        small))
    story.append(PageBreak())

    # ---------------- Executive summary ----------------
    story.append(Paragraph("1. Executive Summary", h1))
    sev_counts = {"High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for f in findings:
        sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1

    summary_tbl = make_table(
        [["Metric", "Count"],
         ["Total processes parsed", str(len(processes))],
         ["Total network connections parsed", str(len(connections))],
         ["Total USB events parsed", str(len(usb_events))],
         ["Total login events parsed", str(len(login_events))],
         ["Total Windows Event Log entries parsed", str(len(event_logs))],
         ["Total browser history entries parsed", str(len(browser_entries))],
         ["High severity findings", str(sev_counts.get("High", 0))],
         ["Medium severity findings", str(sev_counts.get("Medium", 0))],
         ["Low severity findings", str(sev_counts.get("Low", 0))],
         ["Informational (data-quality) notes", str(sev_counts.get("Info", 0))]],
        col_widths=[3.5 * inch, 2.8 * inch],
    )
    story.append(summary_tbl)
    story.append(Spacer(1, 0.2 * inch))
    story.append(Paragraph(
        f"The automated review produced {len(findings)} flagged item(s): "
        f"{sev_counts.get('High', 0)} high, {sev_counts.get('Medium', 0)} medium, "
        f"{sev_counts.get('Low', 0)} low, and {sev_counts.get('Info', 0)} informational "
        f"(data-quality) notes. Details for each are in Section 2.", body))

    high_findings = [f for f in findings if f["severity"] == "High"]
    if high_findings:
        story.append(Spacer(1, 0.15 * inch))
        story.append(Paragraph(
            f"<b>{len(high_findings)} High-severity item(s) - reviewed first:</b>", body))
        hi_rows = [["Category", "Ref.", "Detail"]]
        for f in high_findings:
            hi_rows.append([
                Paragraph(safe(f["category"]), cell),
                Paragraph(safe(f["pid"]), cell),
                Paragraph(safe(f["detail"]), cell),
            ])
        story.append(make_table(hi_rows, col_widths=[1.7 * inch, 0.6 * inch, 4.5 * inch],
                                 header_bg=colors.HexColor("#B00020")))
    story.append(PageBreak())

    # ---------------- Findings ----------------
    story.append(Paragraph("2. Flagged Findings", h1))
    if not findings:
        story.append(Paragraph("No automated findings to display.", body))
    else:
        findings_sorted = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f["severity"], 9))
        rows = [["Sev.", "Category", "Ref.", "Detail"]]
        for f in findings_sorted:
            rows.append([
                Paragraph(f'<font color="{SEVERITY_COLOR[f["severity"]].hexval()}"><b>{f["severity"]}</b></font>', cell),
                Paragraph(safe(f["category"]), cell),
                Paragraph(safe(f["pid"]), cell),
                Paragraph(safe(f["detail"]), cell),
            ])
        story.append(make_table(rows, col_widths=[0.45 * inch, 1.5 * inch, 0.5 * inch, 4.35 * inch]))
    story.append(PageBreak())

    # ---------------- Process inventory ----------------
    story.append(Paragraph("3. Process Inventory", h1))
    story.append(Paragraph(
        "Risk is the highest severity of any finding attached to that process (from "
        "Section 2). 'Clean' means no automated heuristic matched - not a guarantee "
        "the process is benign.", body))
    story.append(Spacer(1, 0.1 * inch))

    proc_rows = [["Risk", "PID", "PPID", "Name", "User", "Path", "Command Line"]]
    for p in processes:
        risk = risk_map.get(p["pid"], "Clean")
        proc_rows.append([
            risk_label_cell(risk, cell),
            Paragraph(safe(p["pid"]), cell),
            Paragraph(safe(p["ppid"]), cell),
            Paragraph(safe(p["name"]), cell),
            Paragraph(safe(p["user"]), cell),
            Paragraph(safe(p["path"] or ("(access denied)" if p["access_denied"] else "")), cell),
            Paragraph(safe(p["cmdline"])[:250], cell),
        ])
    story.append(make_table(
        proc_rows,
        col_widths=[0.55 * inch, 0.5 * inch, 0.4 * inch, 0.9 * inch, 0.6 * inch, 1.45 * inch, 1.85 * inch]
    ))
    story.append(PageBreak())

    # ---------------- Network inventory ----------------
    story.append(Paragraph("4. Network Connection Inventory", h1))
    story.append(Spacer(1, 0.1 * inch))

    net_rows = [["Risk", "PID", "Program", "Proto", "Local Addr:Port", "Remote Addr:Port", "State"]]
    for c in connections:
        risk = risk_map.get(c["pid"], "Clean")
        net_rows.append([
            risk_label_cell(risk, cell),
            Paragraph(safe(c["pid"]), cell),
            Paragraph(safe(c["program"]), cell),
            Paragraph(safe(c["protocol"]), cell),
            Paragraph(safe(f"{c['laddr']}:{c['lport']}" if c["laddr"] else ""), cell),
            Paragraph(safe(f"{c['raddr']}:{c['rport']}" if c["raddr"] else ""), cell),
            Paragraph(safe(c["state"]), cell),
        ])
    story.append(make_table(
        net_rows,
        col_widths=[0.55 * inch, 0.45 * inch, 0.95 * inch, 0.6 * inch, 1.55 * inch, 1.55 * inch, 0.6 * inch]
    ))
    story.append(PageBreak())

    # ---------------- USB / Login inventory ----------------
    story.append(Paragraph("5. USB &amp; Login Event Inventory", h1))
    if usb_path:
        window_min = usb_meta.get("window_minutes")
        ran_admin = usb_meta.get("ran_as_admin")
        story.append(Paragraph(
            f"Collection window: {window_min} minutes. Collected with administrator "
            f"privileges: {ran_admin}.", body))
    story.append(Spacer(1, 0.1 * inch))

    story.append(Paragraph("5.1 USB Device Events", h2))
    if not usb_events:
        story.append(Paragraph(
            f"No USB events recorded. {safe(usb_note) if usb_note else ''}", body))
    else:
        usb_rows = [["Risk", "Device", "Vendor:Product", "Serial", "Drive", "Event", "Timestamp"]]
        for u in usb_events:
            risk = risk_map.get(u["id"], "Clean")
            usb_rows.append([
                risk_label_cell(risk, cell),
                Paragraph(safe(u["device"]), cell),
                Paragraph(safe(f"{u['vendor_id']}:{u['product_id']}"), cell),
                Paragraph(safe(u["serial"]), cell),
                Paragraph(safe(u["drive_letter"]), cell),
                Paragraph(safe(u["event_type"]), cell),
                Paragraph(safe(u["timestamp"]), cell),
            ])
        story.append(make_table(
            usb_rows,
            col_widths=[0.55 * inch, 1.3 * inch, 0.9 * inch, 1.0 * inch, 0.5 * inch, 0.7 * inch, 1.35 * inch]
        ))
    story.append(Spacer(1, 0.15 * inch))

    story.append(Paragraph("5.2 Login Events", h2))
    if not login_events:
        story.append(Paragraph(
            f"No login events recorded. {safe(login_note) if login_note else ''}", body))
    else:
        login_rows = [["Risk", "User", "Event ID", "Logon Type", "Source", "Result", "Timestamp"]]
        for l in login_events:
            risk = risk_map.get(l["id"], "Clean")
            login_rows.append([
                risk_label_cell(risk, cell),
                Paragraph(safe(l["username"]), cell),
                Paragraph(safe(l["event_id"]), cell),
                Paragraph(safe(l["logon_type"]), cell),
                Paragraph(safe(l["source"]), cell),
                Paragraph(safe(l["success"]), cell),
                Paragraph(safe(l["timestamp"]), cell),
            ])
        story.append(make_table(
            login_rows,
            col_widths=[0.55 * inch, 0.9 * inch, 0.6 * inch, 0.8 * inch, 1.1 * inch, 0.7 * inch, 1.25 * inch]
        ))
    story.append(PageBreak())

    # ---------------- Windows Event Log inventory ----------------
    story.append(Paragraph("6. Windows Event Log Review", h1))
    if eventlog_path:
        max_per_source = eventlog_meta.get("max_events_per_source")
        if max_per_source:
            story.append(Paragraph(
                f"Up to {max_per_source} events were captured per log channel at "
                f"collection time; this is a bounded sample, not the full log.", body))
    story.append(Spacer(1, 0.1 * inch))

    if not event_logs:
        story.append(Paragraph("No Windows Event Log entries were present in the evidence file.", body))
    else:
        flagged_evt_ids = {f["pid"] for f in findings if f["target"] == "eventlog" and f["pid"] not in ("-", "?")}
        flagged_events = [e for e in event_logs if e["id"] in flagged_evt_ids]
        other_events = [e for e in event_logs if e["id"] not in flagged_evt_ids]

        story.append(Paragraph(
            f"6.1 Flagged Events ({len(flagged_events)} of {len(event_logs)}) - shown first", h2))
        if not flagged_events:
            story.append(Paragraph("No individual event log entries matched an automated heuristic.", body))
        else:
            evt_rows = [["Risk", "Channel", "Event ID", "Level", "Provider", "Timestamp", "Message"]]
            flagged_events_sorted = sorted(
                flagged_events,
                key=lambda e: RANK.get(risk_map.get(e["id"], "Clean"), -1),
                reverse=True,
            )
            for e in flagged_events_sorted:
                risk = risk_map.get(e["id"], "Clean")
                evt_rows.append([
                    risk_label_cell(risk, cell),
                    Paragraph(safe(e["channel"]), cell),
                    Paragraph(safe(e["event_id"]), cell),
                    Paragraph(safe(e["level"]), cell),
                    Paragraph(safe(e["provider"]), cell),
                    Paragraph(safe(e["timestamp"]), cell),
                    Paragraph(safe(e["message"])[:300], cell),
                ])
            story.append(make_table(
                evt_rows,
                col_widths=[0.5 * inch, 0.6 * inch, 0.5 * inch, 0.55 * inch, 1.1 * inch, 1.1 * inch, 2.05 * inch]
            ))
        story.append(Spacer(1, 0.15 * inch))

        story.append(Paragraph(f"6.2 All Other Parsed Events ({len(other_events)})", h2))
        if not other_events:
            story.append(Paragraph("No additional events to display.", body))
        else:
            evt_rows2 = [["Channel", "Event ID", "Level", "Provider", "Timestamp", "Message"]]
            for e in other_events:
                evt_rows2.append([
                    Paragraph(safe(e["channel"]), cell),
                    Paragraph(safe(e["event_id"]), cell),
                    Paragraph(safe(e["level"]), cell),
                    Paragraph(safe(e["provider"]), cell),
                    Paragraph(safe(e["timestamp"]), cell),
                    Paragraph(safe(e["message"])[:250], cell),
                ])
            story.append(make_table(
                evt_rows2,
                col_widths=[0.65 * inch, 0.55 * inch, 0.6 * inch, 1.2 * inch, 1.2 * inch, 2.2 * inch]
            ))
    story.append(PageBreak())

    # ---------------- Browser history ----------------
    story.append(Paragraph("7. Browser History Review", h1))
    if browsers:
        profile_lines = ", ".join(
            f"{name} ({info.get('history_count', len(info.get('history', [])))} entries, "
            f"source: {info.get('source_path', 'unknown')})"
            for name, info in browsers.items()
        )
        story.append(Paragraph(f"Profiles captured: {safe(profile_lines)}", body))
    story.append(Spacer(1, 0.1 * inch))

    if not browser_entries:
        story.append(Paragraph("No browser history entries were present in the evidence file.", body))
    else:
        search_rows_data = []
        for b in browser_entries:
            q = extract_search_query(b["url"])
            if q:
                search_rows_data.append((b, q))

        story.append(Paragraph(f"7.1 Search Engine Queries ({len(search_rows_data)})", h2))
        if not search_rows_data:
            story.append(Paragraph("No search-engine query strings were identified in the parsed URLs.", body))
        else:
            search_rows = [["Browser", "Query", "Visits", "Last Visited", "URL"]]
            for b, q in search_rows_data:
                search_rows.append([
                    Paragraph(safe(b["browser"]), cell),
                    Paragraph(safe(q), cell),
                    Paragraph(safe(b["visit_count"]), cell),
                    Paragraph(safe(b["timestamp"]), cell),
                    Paragraph(safe(b["url"])[:200], cell),
                ])
            story.append(make_table(
                search_rows,
                col_widths=[0.9 * inch, 1.9 * inch, 0.5 * inch, 1.1 * inch, 2.1 * inch]
            ))
        story.append(Spacer(1, 0.15 * inch))

        flagged_web_ids = {f["pid"] for f in findings if f["target"] == "browser" and f["pid"] not in ("-", "?")}
        flagged_entries = [b for b in browser_entries if b["id"] in flagged_web_ids]
        other_entries = [b for b in browser_entries if b["id"] not in flagged_web_ids]

        story.append(Paragraph(f"7.2 Flagged History Entries ({len(flagged_entries)})", h2))
        if not flagged_entries:
            story.append(Paragraph("No individual history entries matched an automated heuristic.", body))
        else:
            fw_rows = [["Risk", "Browser", "Title", "URL", "Visits", "Last Visited"]]
            for b in flagged_entries:
                risk = risk_map.get(b["id"], "Clean")
                fw_rows.append([
                    risk_label_cell(risk, cell),
                    Paragraph(safe(b["browser"]), cell),
                    Paragraph(safe(b["title"])[:120], cell),
                    Paragraph(safe(b["url"])[:200], cell),
                    Paragraph(safe(b["visit_count"]), cell),
                    Paragraph(safe(b["timestamp"]), cell),
                ])
            story.append(make_table(
                fw_rows,
                col_widths=[0.5 * inch, 0.8 * inch, 1.3 * inch, 2.1 * inch, 0.5 * inch, 1.1 * inch]
            ))
        story.append(Spacer(1, 0.15 * inch))

        story.append(Paragraph(
            f"7.3 Full Browsing History ({len(other_entries)} additional entries not flagged above)", h2))
        if not other_entries:
            story.append(Paragraph("No additional history entries to display.", body))
        else:
            hist_rows = [["Browser", "Title", "URL", "Visits", "Last Visited"]]
            for b in other_entries:
                hist_rows.append([
                    Paragraph(safe(b["browser"]), cell),
                    Paragraph(safe(b["title"])[:120], cell),
                    Paragraph(safe(b["url"])[:220], cell),
                    Paragraph(safe(b["visit_count"]), cell),
                    Paragraph(safe(b["timestamp"]), cell),
                ])
            story.append(make_table(
                hist_rows,
                col_widths=[0.8 * inch, 1.5 * inch, 2.6 * inch, 0.5 * inch, 1.1 * inch]
            ))
    story.append(PageBreak())

    # ---------------- Correlation view ----------------
    story.append(Paragraph("8. Process-to-Network Correlation", h1))
    story.append(Paragraph(
        "Grouped directly from the network-connection export, which carries its own "
        "reliable PID and process-name fields for each connection.", body))
    story.append(Spacer(1, 0.1 * inch))

    corr = build_network_correlation(connections)
    corr_rows = [["PID", "Program", "# Connections", "Remote Endpoints"]]
    for (pid, program), conns in sorted(corr.items(), key=lambda kv: -len(kv[1])):
        remotes = sorted(set(f"{c['raddr']}:{c['rport']}" for c in conns if c["raddr"]))
        remotes_str = ", ".join(remotes)[:400] if remotes else "(local/listen only)"
        corr_rows.append([
            Paragraph(safe(pid), cell),
            Paragraph(safe(program), cell),
            str(len(conns)),
            Paragraph(safe(remotes_str), cell),
        ])
    story.append(make_table(
        corr_rows,
        col_widths=[0.5 * inch, 1.3 * inch, 0.9 * inch, 3.6 * inch]
    ))
    story.append(PageBreak())

    # ---------------- Methodology ----------------
    story.append(Paragraph("9. Methodology &amp; Chain of Custody Notes", h1))
    story.append(Paragraph(
        "<b>Evidence handling:</b> Source files were read in place (no modification) and "
        "hashed with SHA-256 at the start of this analysis; hashes are recorded on the "
        "cover page for chain-of-custody purposes.", body))
    story.append(Spacer(1, 0.08 * inch))
    story.append(Paragraph(
        "<b>Normalization:</b> Records from all evidence files were mapped onto a common "
        "schema to tolerate differing key names/shapes between exports.", body))
    story.append(Spacer(1, 0.08 * inch))
    story.append(Paragraph(
        "<b>PID correlation caveat:</b> Where the process export's 'pid' field is "
        "corrupted (see Section 2), this report falls back to process-name based "
        "correlation, which is weaker and can be ambiguous when multiple processes "
        "share a name.", body))
    story.append(Spacer(1, 0.08 * inch))
    story.append(Paragraph(
        "<b>Event log timestamps:</b> Windows Event Log 'TimeCreated' values in the "
        "source export are in .NET JSON date format (milliseconds since the Unix "
        "epoch, UTC) and were converted to human-readable UTC timestamps for this "
        "report.", body))
    story.append(Spacer(1, 0.08 * inch))
    story.append(Paragraph(
        "<b>Browser history keyword matching:</b> Section 2/7 keyword flags on URLs "
        "and page titles are a coarse triage heuristic. A match does not by itself "
        "establish intent - legitimate research, including forensic and security work, "
        "can also touch these terms - and absence of a match does not clear an entry.", body))
    story.append(Spacer(1, 0.08 * inch))
    story.append(Paragraph(
        "<b>Risk ratings:</b> Each row in Sections 3-7 carries a Risk label - the "
        "highest severity of any Section 2 finding tied to that row, or 'Clean' if "
        "no heuristic matched. Risk labels are triage aids, not a determination of "
        "maliciousness.", body))
    story.append(Spacer(1, 0.08 * inch))
    story.append(Paragraph(
        "<b>Limitations:</b> This tool does not perform memory carving, binary "
        "disassembly, digital-signature verification, or threat-intel lookups, and "
        "cannot recover login/USB/event-log/browser history that the source system "
        "failed to log or that fell outside the bounded per-source collection window "
        "(e.g. due to audit policy, permission gaps, or history retention limits at "
        "collection time).", body))

    def add_page_number(canvas_obj, doc_obj):
        canvas_obj.saveState()
        canvas_obj.setFont("Helvetica", 8)
        canvas_obj.setFillColor(colors.HexColor("#777777"))
        canvas_obj.drawRightString(
            letter[0] - 0.6 * inch, 0.4 * inch,
            f"Page {doc_obj.page} — {case_name}"
        )
        canvas_obj.restoreState()

    doc.build(story, onFirstPage=add_page_number, onLaterPages=add_page_number)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    evidence_dir = find_evidence_dir()
    print(f"Looking for evidence files in: {os.path.abspath(evidence_dir)}")

    proc_path = find_evidence_file(evidence_dir, ["process"])
    net_path = find_evidence_file(evidence_dir, ["network", "connection"])
    usb_path = find_evidence_file(evidence_dir, ["usb", "login"])
    eventlog_path = find_evidence_file(evidence_dir, ["eventlog", "winlog", "windowslog", "syslog", "event_log"])
    browser_path = find_evidence_file(evidence_dir, ["browser", "history"])

    if not proc_path or not net_path:
        print("ERROR: Could not find both a process export and a network export "
              f"in '{evidence_dir}'. Make sure your JSON files are in an 'Evidence' "
              "folder next to this script (or in the current directory) and that "
              "their filenames contain 'process' and 'network'/'connection'.",
              file=sys.stderr)
        sys.exit(1)

    print(f"  Process export : {proc_path}")
    print(f"  Network export : {net_path}")
    if usb_path:
        print(f"  USB/Login export: {usb_path}")
    else:
        print("  USB/Login export: not found (that section will be skipped)")
    if eventlog_path:
        print(f"  Event log export: {eventlog_path}")
    else:
        print("  Event log export: not found (that section will be skipped)")
    if browser_path:
        print(f"  Browser history export: {browser_path}")
    else:
        print("  Browser history export: not found (that section will be skipped)")

    case_name = input("Case Name: ").strip() or "UNSPECIFIED-CASE"
    examiner = input("Examiner name: ").strip() or "Unspecified Examiner"

    proc_meta, raw_processes = load_json_with_meta(proc_path)
    net_meta, raw_connections = load_json_with_meta(net_path)

    if usb_path:
        usb_meta, raw_usb_events, usb_note, raw_login_events, login_note = load_usb_login_json(usb_path)
    else:
        usb_meta, raw_usb_events, usb_note, raw_login_events, login_note = {}, [], "", [], ""

    if eventlog_path:
        eventlog_meta, raw_event_channels = load_eventlog_json(eventlog_path)
    else:
        eventlog_meta, raw_event_channels = {}, {}

    if browser_path:
        browser_meta, browsers = load_browser_json(browser_path)
    else:
        browser_meta, browsers = {}, {}

    hostname = (proc_meta.get("hostname") or net_meta.get("hostname") or usb_meta.get("hostname")
                or eventlog_meta.get("hostname") or browser_meta.get("hostname") or "Unknown host")
    evidence_source = f"Automated live triage export collected from '{hostname}'"

    processes = [normalize_process(r, i) for i, r in enumerate(raw_processes)]
    connections = [normalize_connection(r) for r in raw_connections]
    usb_events = [normalize_usb_event(r, i) for i, r in enumerate(raw_usb_events)]
    login_events = [normalize_login_event(r, i) for i, r in enumerate(raw_login_events)]

    event_logs = []
    for channel, entries in raw_event_channels.items():
        event_logs.extend(normalize_event_log(r, channel, i) for i, r in enumerate(entries))

    browser_entries = []
    for browser_name, info in browsers.items():
        browser_entries.extend(
            normalize_browser_entry(r, browser_name, i) for i, r in enumerate(info.get("history", []))
        )

    findings = analyze(processes, connections, usb_events, usb_note, login_events, login_note,
                        event_logs=event_logs, browser_entries=browser_entries)

    current_dir = os.getcwd()

    report_dir = os.path.join(current_dir, "Report")
    os.makedirs(report_dir, exist_ok=True)  

    output_path = os.path.join(report_dir, "Forensic_Report.pdf")

    generate_pdf(
        output_path=output_path,
        case_name=case_name,
        examiner=examiner,
        evidence_source=evidence_source,
        proc_path=proc_path,
        net_path=net_path,
        usb_path=usb_path,
        proc_meta=proc_meta,
        net_meta=net_meta,
        usb_meta=usb_meta,
        processes=processes,
        connections=connections,
        usb_events=usb_events,
        usb_note=usb_note,
        login_events=login_events,
        login_note=login_note,
        findings=findings,
        eventlog_path=eventlog_path,
        eventlog_meta=eventlog_meta,
        event_logs=event_logs,
        browser_path=browser_path,
        browser_meta=browser_meta,
        browsers=browsers,
        browser_entries=browser_entries,
    )

    print(f"\nReport written to: {output_path}")
    print(f"Processes parsed: {len(processes)}")
    print(f"Connections parsed: {len(connections)}")
    print(f"USB events parsed: {len(usb_events)}")
    print(f"Login events parsed: {len(login_events)}")
    print(f"Event log entries parsed: {len(event_logs)}")
    print(f"Browser history entries parsed: {len(browser_entries)}")
    print(f"Findings flagged: {len(findings)}")


if __name__ == "__main__":
    main()