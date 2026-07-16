import os
import json
import glob
import shutil
import sqlite3
import platform
import argparse
import tempfile
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


def ensure_evidence_dir():
    os.makedirs(EVIDENCE_DIR, exist_ok=True)


def get_chromium_paths(os_name):
    """Return dict of {browser_label: [profile_history_paths]}."""
    home = os.path.expanduser("~")
    candidates = {}

    if os_name == "Windows":
        base = os.path.join(home, "AppData", "Local")
        chromium_dirs = {
            "Chrome": os.path.join(base, "Google", "Chrome", "User Data"),
            "Edge": os.path.join(base, "Microsoft", "Edge", "User Data"),
            "Brave": os.path.join(base, "BraveSoftware", "Brave-Browser", "User Data"),
        }
    elif os_name == "Linux":
        chromium_dirs = {
            "Chrome": os.path.join(home, ".config", "google-chrome"),
            "Chromium": os.path.join(home, ".config", "chromium"),
            "Brave": os.path.join(home, ".config", "BraveSoftware", "Brave-Browser"),
        }
    elif os_name == "macOS":
        base = os.path.join(home, "Library", "Application Support")
        chromium_dirs = {
            "Chrome": os.path.join(base, "Google", "Chrome"),
            "Edge": os.path.join(base, "Microsoft Edge"),
            "Brave": os.path.join(base, "BraveSoftware", "Brave-Browser"),
        }
    else:
        chromium_dirs = {}

    for label, root in chromium_dirs.items():
        if not os.path.isdir(root):
            continue
        history_files = glob.glob(os.path.join(root, "*", "History"))
        history_files += glob.glob(os.path.join(root, "Default", "History"))
        history_files = sorted(set(history_files))
        if history_files:
            candidates[label] = history_files

    return candidates


def get_firefox_paths(os_name):
    home = os.path.expanduser("~")
    if os_name == "Windows":
        root = os.path.join(home, "AppData", "Roaming", "Mozilla", "Firefox", "Profiles")
    elif os_name == "Linux":
        root = os.path.join(home, ".mozilla", "firefox")
    elif os_name == "macOS":
        root = os.path.join(home, "Library", "Application Support", "Firefox", "Profiles")
    else:
        return []

    if not os.path.isdir(root):
        return []

    return sorted(glob.glob(os.path.join(root, "*", "places.sqlite")))


def read_sqlite_copy(db_path, query, columns):
    """Copy DB to a temp file (to dodge file locks) and run a query."""
    tmp_dir = tempfile.mkdtemp(prefix="browser_evidence_")
    tmp_path = os.path.join(tmp_dir, "copy.sqlite")
    rows_out = []
    error = None
    try:
        shutil.copy2(db_path, tmp_path)
        for ext in ("-wal", "-shm"):
            side_file = db_path + ext
            if os.path.exists(side_file):
                try:
                    shutil.copy2(side_file, tmp_path + ext)
                except Exception:
                    pass

        conn = sqlite3.connect(f"file:{tmp_path}?immutable=0", uri=True)
        cur = conn.cursor()
        cur.execute(query)
        for row in cur.fetchall():
            rows_out.append(dict(zip(columns, row)))
        conn.close()
    except Exception as e:
        error = str(e)
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    return rows_out, error


def chrome_time_to_iso(chrome_us):
    """Chromium timestamps are microseconds since 1601-01-01 UTC."""
    try:
        epoch_start = datetime(1601, 1, 1)
        return (epoch_start + timedelta(microseconds=chrome_us)).isoformat()
    except Exception:
        return None


def firefox_time_to_iso(ff_us):
    """Firefox timestamps are microseconds since 1970-01-01 UTC (unix epoch)."""
    try:
        return datetime.utcfromtimestamp(ff_us / 1_000_000).isoformat()
    except Exception:
        return None


def collect_chromium_history(path, limit):
    query = f"""
        SELECT url, title, visit_count, last_visit_time
        FROM urls
        ORDER BY last_visit_time DESC
        LIMIT {int(limit)}
    """
    rows, error = read_sqlite_copy(path, query, ["url", "title", "visit_count", "last_visit_time"])
    for r in rows:
        r["last_visit_time_iso"] = chrome_time_to_iso(r["last_visit_time"])
    return rows, error


def collect_chromium_search_terms(path, limit):
    """Chromium keeps a separate keyword_search_terms table for search-box queries."""
    query = f"""
        SELECT kst.term, u.url, u.last_visit_time
        FROM keyword_search_terms kst
        JOIN urls u ON kst.url_id = u.id
        ORDER BY u.last_visit_time DESC
        LIMIT {int(limit)}
    """
    rows, error = read_sqlite_copy(path, query, ["search_term", "url", "last_visit_time"])
    for r in rows:
        r["last_visit_time_iso"] = chrome_time_to_iso(r["last_visit_time"])
    return rows, error


def collect_firefox_history(path, limit):
    query = f"""
        SELECT url, title, visit_count, last_visit_date
        FROM moz_places
        WHERE last_visit_date IS NOT NULL
        ORDER BY last_visit_date DESC
        LIMIT {int(limit)}
    """
    rows, error = read_sqlite_copy(
        path, query, ["url", "title", "visit_count", "last_visit_date"]
    )
    for r in rows:
        r["last_visit_time_iso"] = firefox_time_to_iso(r["last_visit_date"])
    return rows, error

def save_evidence(payload, os_name):
    ensure_evidence_dir()
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = os.path.join(EVIDENCE_DIR, f"browser_artifacts.json")
    with open(fname, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False, default=str)
    return fname


def main():
    parser = argparse.ArgumentParser(description="Acquire local browser history/search artifacts.")
    parser.add_argument("--limit", type=int, default=1000,
                         help="Max rows to pull per browser profile (default: 1000)")
    args = parser.parse_args()

    os_name = detect_os()
    print(f"[*] Detected OS: {os_name}")
    print("[*] Locating browser profiles...")

    result = {
        "generated_at": datetime.now().isoformat(),
        "detected_os": os_name,
        "hostname": platform.node(),
        "browsers": {},
    }

    chromium_paths = get_chromium_paths(os_name)
    for label, history_files in chromium_paths.items():
        for hist_path in history_files:
            profile_name = os.path.basename(os.path.dirname(hist_path))
            key = f"{label} ({profile_name})"
            print(f"[*] Reading {key}...")

            history_rows, hist_err = collect_chromium_history(hist_path, args.limit)
            search_rows, search_err = collect_chromium_search_terms(hist_path, args.limit)

            result["browsers"][key] = {
                "source_path": hist_path,
                "history_count": len(history_rows),
                "history": history_rows,
                "history_error": hist_err,
                "search_terms_count": len(search_rows),
                "search_terms": search_rows,
                "search_terms_error": search_err,
            }

    ff_paths = get_firefox_paths(os_name)
    for places_path in ff_paths:
        profile_name = os.path.basename(os.path.dirname(places_path))
        key = f"Firefox ({profile_name})"
        print(f"[*] Reading {key}...")

        history_rows, hist_err = collect_firefox_history(places_path, args.limit)
        result["browsers"][key] = {
            "source_path": places_path,
            "history_count": len(history_rows),
            "history": history_rows,
            "history_error": hist_err,
        }

    if not result["browsers"]:
        result["note"] = "No known browser profiles found on this system for the current user."
        print("[i] No browser profiles found.")

    fname = save_evidence(result, os_name)
    total = sum(v.get("history_count", 0) for v in result["browsers"].values())
    print(f"[*] Total history entries collected: {total}")
    print(f"[+] Evidence saved to: {fname}")


if __name__ == "__main__":
    main()