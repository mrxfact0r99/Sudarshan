import os
import re
import json
import glob
import shutil
import sqlite3
import platform
import argparse
import tempfile
import sys
from datetime import datetime, timedelta
from ..common import EVIDENCE_DIR, detect_os, ensure_evidence_dir
sys.dont_write_bytecode = True


# --- Deleted-history recovery (string carving) --------------------------
#
# When a row is deleted from a SQLite table (e.g. Chrome/Firefox's
# history), SQLite does NOT zero out the bytes by default - the page is
# just returned to the file's freelist (or a "freeblock" gap inside a
# still-used page) and left as-is until something else happens to reuse
# that space. That means a deleted URL can often still be recovered by
# scanning the raw file bytes for URL-shaped text, even though a normal
# SQL query against the live tables can no longer see it.
#
# This is a lightweight, well-established technique (the same idea used
# by tools like bulk_extractor/strings-based carving) - NOT a full SQLite
# page/cell parser, so results are candidates for manual review rather
# than certainties. A match can be a duplicate of a live row, a stale
# but still-referenced value, or truncated at a page boundary.

URL_CARVE_RE = re.compile(
    rb"https?://[A-Za-z0-9\-\._~:/\?#\[\]@!\$&'\(\)\*\+,;=%]{8,600}"
)
MAX_CARVE_BYTES = 64 * 1024 * 1024  # cap raw scan at 64MB per DB file


def get_freelist_diagnostics(db_path):
    """Reports whether this SQLite file structurally *could* still hold
    carvable deleted bytes at collection time - independent of whether the
    regex actually found any. Answers the question 'why didn't a deletion
    I just made show up?' without guessing:

      - freelist_pages == 0 and auto_vacuum != 'none': the DB reclaims
        free space automatically on every commit, so deleted rows are
        wiped almost immediately - carving this file was never going to
        find anything, no matter how fast the collector ran.
      - freelist_pages == 0 and auto_vacuum == 'none': no free pages
        exist right now, meaning either nothing has been deleted since
        the last VACUUM, or every freed page has already been reused by
        a newer write (very possible if browsing continued after the
        deletion and before collection).
      - freelist_pages > 0: there IS unallocated space in the file that
        a plain SQL query can't see - a real chance for the regex scan to
        find something in it (though it can still miss non-URL-shaped or
        page-boundary-truncated remnants).

    Returns a dict; page_size/page_count/freelist_pages are None if the
    PRAGMA queries could not be run (e.g. file locked, not a SQLite file).
    """
    info = {"auto_vacuum": None, "page_size": None, "page_count": None, "freelist_pages": None, "error": None}
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro&immutable=1", uri=True)
        cur = conn.cursor()
        cur.execute("PRAGMA auto_vacuum")
        row = cur.fetchone()
        info["auto_vacuum"] = {0: "none", 1: "full", 2: "incremental"}.get(row[0] if row else None, row[0] if row else None)
        cur.execute("PRAGMA page_size")
        info["page_size"] = (cur.fetchone() or [None])[0]
        cur.execute("PRAGMA page_count")
        info["page_count"] = (cur.fetchone() or [None])[0]
        cur.execute("PRAGMA freelist_count")
        info["freelist_pages"] = (cur.fetchone() or [None])[0]
        conn.close()
    except Exception as e:
        info["error"] = str(e)
    return info


def carve_deleted_urls(db_path, known_urls, max_results=300):
    """Scan the raw SQLite file bytes for URL-shaped strings not present
    among the live rows already recovered by SQL, to surface likely
    deleted history entries. Returns (results, error)."""
    try:
        size = os.path.getsize(db_path)
        with open(db_path, "rb") as f:
            raw = f.read(MAX_CARVE_BYTES)
    except OSError as e:
        return [], str(e)

    truncated = size > MAX_CARVE_BYTES

    # SQLite's on-disk record format has no delimiter between adjacent
    # text columns (e.g. a row's url and title sit back-to-back, lengths
    # coming from a separate varint header) - so a URL regex match
    # frequently swallows a few bytes of the *next* column's text too
    # (e.g. "https://github.com/GitHub" for a row whose title is
    # "GitHub"). That means a still-LIVE row's URL can appear to be a
    # "new" string that isn't in known_urls verbatim, purely because of
    # the trailing garbage. To avoid reporting live rows as false
    # "recovered" deletions, a candidate is treated as already-known if
    # any known URL is a *prefix* of it, not just on an exact match.
    known_sorted = sorted((u for u in known_urls if u), key=len, reverse=True)

    results = []
    seen = set()
    for m in URL_CARVE_RE.finditer(raw):
        url = m.group(0).decode("utf-8", errors="replace").split("\x00")[0]
        if url in seen:
            continue
        if any(url.startswith(k) for k in known_sorted):
            continue
        seen.add(url)

        start = max(0, m.start() - 30)
        end = min(len(raw), m.end() + 30)
        context = (
            raw[start:end]
            .decode("utf-8", errors="replace")
            .replace("\n", " ")
            .replace("\r", " ")
        )
        results.append({
            "url": url,
            "byte_offset": m.start(),
            "context": context,
        })
        if len(results) >= max_results:
            break

    if truncated:
        note = ("File larger than the scan cap; only the first "
                 f"{MAX_CARVE_BYTES // (1024*1024)}MB was scanned.")
    else:
        note = None
    return results, note


def carve_deleted_urls_with_wal(db_path, known_urls, max_results=300):
    """SQLite's write-ahead-log file (<db>-wal) holds pages that have been
    written but not yet checkpointed back into the main DB file - a row
    deleted just before the WAL was captured can sit there even when the
    main file's copy of that page has already been reused. Carving the
    WAL alongside the main file catches that window without changing the
    main-file carve behaviour at all."""
    results, note = carve_deleted_urls(db_path, known_urls, max_results)
    for r in results:
        r["source"] = "main DB file"

    wal_path = db_path + "-wal"
    if os.path.isfile(wal_path):
        wal_results, wal_note = carve_deleted_urls(wal_path, known_urls, max_results)
        seen = {r["url"] for r in results}
        added = 0
        for r in wal_results:
            if r["url"] not in seen:
                r["source"] = "WAL file"
                results.append(r)
                seen.add(r["url"])
                added += 1
        if wal_note or added:
            wal_summary = (f"WAL file also scanned"
                            + (f" ({added} additional candidate(s) found)" if added else "")
                            + (f" - {wal_note}" if wal_note else "."))
            note = f"{note} {wal_summary}".strip() if note else wal_summary

    diag = get_freelist_diagnostics(db_path)
    if diag["error"]:
        diag_note = f"Freelist diagnostics unavailable: {diag['error']}."
    elif diag["freelist_pages"] is None:
        diag_note = "Freelist diagnostics unavailable."
    elif diag["freelist_pages"] == 0 and diag["auto_vacuum"] and diag["auto_vacuum"] != "none":
        diag_note = (
            f"This DB has auto_vacuum={diag['auto_vacuum']} and 0 free pages at "
            f"collection time - it reclaims deleted rows' space automatically on "
            f"every commit, so recently-deleted entries are not recoverable by "
            f"carving regardless of collection timing."
        )
    elif diag["freelist_pages"] == 0:
        diag_note = (
            "0 free pages in this DB at collection time - either nothing has "
            "been deleted since the last VACUUM, or every freed page has "
            "already been overwritten by a newer write (e.g. more browsing "
            "after the deletion and before this collection ran)."
        )
    else:
        diag_note = (
            f"{diag['freelist_pages']} free page(s) ({diag['page_size'] or '?'} bytes "
            f"each) exist in this DB at collection time - unallocated space a live "
            f"query can't see, and where the carve above looked for remnants."
        )
    note = f"{note} {diag_note}".strip() if note else diag_note

    return results, note


def get_chromium_paths(os_name):
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


def get_tor_paths(os_name):
    """Tor Browser is Firefox-based but ships as a self-contained,
    typically-portable bundle rather than installing into a fixed OS
    profile directory - so instead of one canonical path, this globs a
    short list of common extraction/launch locations (Desktop, Downloads,
    home directory, /opt on Linux, /Applications on macOS) for the
    'TorBrowser/Data/Browser/profile.default/places.sqlite' layout that
    the bundle always uses internally, regardless of where it was
    extracted to. This is a best-effort convenience on top of --extra-path,
    not a replacement for it - point --extra-path at the bundle directly
    if it lives somewhere unusual (e.g. a USB drive)."""
    home = os.path.expanduser("~")
    if os_name == "Windows":
        search_roots = [
            os.path.join(home, "Desktop"),
            os.path.join(home, "Downloads"),
            home,
        ]
    elif os_name == "macOS":
        search_roots = [
            "/Applications",
            os.path.join(home, "Applications"),
            os.path.join(home, "Desktop"),
            os.path.join(home, "Downloads"),
        ]
    elif os_name == "Linux":
        search_roots = [
            home,
            os.path.join(home, "Desktop"),
            os.path.join(home, "Downloads"),
            os.path.join(home, ".local", "share"),
            "/opt",
        ]
    else:
        search_roots = []

    found = []
    pattern = os.path.join("**", "TorBrowser", "Data", "Browser", "profile.default", "places.sqlite")
    for root in search_roots:
        if not os.path.isdir(root):
            continue
        try:
            found += glob.glob(os.path.join(root, pattern), recursive=True)
        except OSError:
            continue
    return sorted(set(found))


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
    try:
        epoch_start = datetime(1601, 1, 1)
        return (epoch_start + timedelta(microseconds=chrome_us)).isoformat()
    except Exception:
        return None


def firefox_time_to_iso(ff_us):
    """Firefox's moz_places.last_visit_date is microseconds since the Unix
    epoch (1970-01-01), unlike Chrome's WebKit epoch (1601-01-01)."""
    if ff_us is None:
        return None
    try:
        return datetime.fromtimestamp(ff_us / 1_000_000).isoformat()
    except (OverflowError, OSError, ValueError, TypeError):
        return None


def collect_chromium_all_urls(path):
    """Unlimited (no LIMIT/ORDER BY) fetch of every URL currently live in
    the urls table. Used only to build the known-URL filter for carving -
    collect_chromium_history() is capped by --limit for report readability,
    but the carve filter needs to see every live row or it will wrongly
    report live rows beyond that cap as 'deleted'."""
    rows, error = read_sqlite_copy(path, "SELECT url FROM urls", ["url"])
    return {r["url"] for r in rows if r.get("url")}, error


def collect_firefox_all_urls(path):
    rows, error = read_sqlite_copy(
        path, "SELECT url FROM moz_places WHERE url IS NOT NULL", ["url"]
    )
    return {r["url"] for r in rows if r.get("url")}, error


def collect_chromium_all_cookie_hosts(cookies_path):
    rows, error = read_sqlite_copy(cookies_path, "SELECT host_key AS host FROM cookies", ["host"])
    return {r["host"] for r in rows if r.get("host")}, error


def collect_firefox_all_cookie_hosts(cookies_path):
    rows, error = read_sqlite_copy(cookies_path, "SELECT host FROM moz_cookies", ["host"])
    return {r["host"] for r in rows if r.get("host")}, error


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


# --- Downloads, bookmarks, cookies ---------------------------------------
#
# These three artifact types are called out repeatedly in the browser
# forensics literature (search keywords, URLs, bookmarks, cookies, and
# downloads are the artifacts most consistently recoverable across normal,
# private, and portable browsing modes - see e.g. Chand, Sharma & Kabir,
# "Advancing Web Browser Forensics", SN Computer Science 6:355, 2025).
# Chromium's "History" SQLite file already holds a `downloads` table
# alongside `urls`, so it costs nothing extra to pull once the DB is
# copied. Bookmarks and cookies live in separate files per-browser.
#
# Cookie VALUES are encrypted at rest in every modern browser (tied to
# OS user-profile keys), so only cookie metadata (host, name, path,
# timestamps) is collected here - never the decrypted value.

def collect_chromium_downloads(path, limit):
    query = f"""
        SELECT target_path, tab_url, total_bytes, start_time, end_time, state
        FROM downloads
        ORDER BY start_time DESC
        LIMIT {int(limit)}
    """
    rows, error = read_sqlite_copy(
        path, query, ["target_path", "source_url", "total_bytes", "start_time", "end_time", "state"]
    )
    for r in rows:
        r["start_time_iso"] = chrome_time_to_iso(r["start_time"])
        r["end_time_iso"] = chrome_time_to_iso(r["end_time"])
    return rows, error


def collect_chromium_cookies_meta(root_dir):
    """Chromium keeps cookies in a sibling 'Cookies' (or 'Network/Cookies'
    on newer versions) file next to History, in the same profile folder."""
    profile_dir = os.path.dirname(root_dir)
    candidates = [
        os.path.join(profile_dir, "Cookies"),
        os.path.join(profile_dir, "Network", "Cookies"),
    ]
    cookies_path = next((c for c in candidates if os.path.isfile(c)), None)
    if not cookies_path:
        return [], None, "No Cookies file found alongside History."

    query = """
        SELECT host_key, name, path, creation_utc, last_access_utc,
               expires_utc, is_secure, is_httponly
        FROM cookies
        ORDER BY creation_utc DESC
        LIMIT 2000
    """
    rows, error = read_sqlite_copy(
        cookies_path, query,
        ["host", "name", "path", "creation_utc", "last_access_utc",
         "expires_utc", "is_secure", "is_httponly"]
    )
    for r in rows:
        r["creation_time_iso"] = chrome_time_to_iso(r["creation_utc"])
        r["last_access_time_iso"] = chrome_time_to_iso(r["last_access_utc"])
        r["expires_time_iso"] = chrome_time_to_iso(r["expires_utc"])
        r.pop("value", None)  # never collect decrypted cookie values
    return rows, cookies_path, error


def collect_chromium_bookmarks(root_dir):
    """Chromium bookmarks are a JSON tree in a 'Bookmarks' file that sits
    next to History in the same profile folder (not SQLite)."""
    profile_dir = os.path.dirname(root_dir)
    bookmarks_path = os.path.join(profile_dir, "Bookmarks")
    if not os.path.isfile(bookmarks_path):
        return [], bookmarks_path, "No Bookmarks file found alongside History."

    try:
        with open(bookmarks_path, "r", encoding="utf-8", errors="replace") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        return [], bookmarks_path, str(e)

    results = []

    def walk(node, folder_path):
        if not isinstance(node, dict):
            return
        node_type = node.get("type")
        if node_type == "url":
            results.append({
                "name": node.get("name", ""),
                "url": node.get("url", ""),
                "folder": folder_path,
                "date_added": node.get("date_added", ""),
            })
        elif node_type == "folder":
            here = f"{folder_path}/{node.get('name', '')}".strip("/")
            for child in node.get("children", []) or []:
                walk(child, here)

    for root_name, root_node in (data.get("roots") or {}).items():
        walk(root_node, root_name)

    return results, bookmarks_path, None


def collect_firefox_bookmarks(path, limit):
    query = f"""
        SELECT b.title, p.url, b.dateAdded
        FROM moz_bookmarks b
        JOIN moz_places p ON b.fk = p.id
        WHERE b.type = 1 AND p.url IS NOT NULL
        ORDER BY b.dateAdded DESC
        LIMIT {int(limit)}
    """
    rows, error = read_sqlite_copy(path, query, ["name", "url", "date_added"])
    for r in rows:
        r["date_added_iso"] = firefox_time_to_iso(r["date_added"])
    return rows, error


def collect_firefox_cookies_meta(profile_dir):
    cookies_path = os.path.join(profile_dir, "cookies.sqlite")
    if not os.path.isfile(cookies_path):
        return [], cookies_path, "No cookies.sqlite found in this profile."

    query = """
        SELECT host, name, path, creationTime, lastAccessed, expiry,
               isSecure, isHttpOnly
        FROM moz_cookies
        ORDER BY creationTime DESC
        LIMIT 2000
    """
    rows, error = read_sqlite_copy(
        cookies_path, query,
        ["host", "name", "path", "creation_utc", "last_access_utc",
         "expires_utc", "is_secure", "is_httponly"]
    )
    for r in rows:
        r["creation_time_iso"] = firefox_time_to_iso(r["creation_utc"])
        r["last_access_time_iso"] = firefox_time_to_iso(r["last_access_utc"])
        # expiry on moz_cookies is seconds (not microseconds) since epoch
        try:
            r["expires_time_iso"] = (
                datetime.fromtimestamp(r["expires_utc"]).isoformat()
                if r["expires_utc"] else None
            )
        except (OverflowError, OSError, ValueError, TypeError):
            r["expires_time_iso"] = None
    return rows, cookies_path, error


def collect_firefox_downloads(profile_dir, places_path, limit):
    """Modern Firefox has no separate downloads DB - completed/in-progress
    downloads are recorded as page annotations on moz_places. This schema
    has shifted across Firefox versions, so failures here are expected and
    reported rather than raised."""
    query = f"""
        SELECT p.url AS source_url, a.content AS destination, a.dateAdded
        FROM moz_annos a
        JOIN moz_places p ON a.place_id = p.id
        JOIN moz_anno_attributes attr ON a.anno_attribute_id = attr.id
        WHERE attr.name = 'downloads/destinationFileURI'
        ORDER BY a.dateAdded DESC
        LIMIT {int(limit)}
    """
    rows, error = read_sqlite_copy(
        places_path, query, ["source_url", "destination", "date_added"]
    )
    for r in rows:
        r["date_added_iso"] = firefox_time_to_iso(r["date_added"])
    return rows, error


def save_evidence(payload, os_name):
    ensure_evidence_dir()
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = os.path.join(EVIDENCE_DIR, f"browser_artifacts.json")
    with open(fname, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False, default=str)
    return fname


def find_extra_history_files(extra_paths):
    """Given user-supplied roots (e.g. a mounted portable-browser folder or
    a removable drive), glob for Chromium 'History' and Firefox
    'places.sqlite' files anywhere under them. This lets the tool reach
    portable installs, which live outside the standard per-OS profile
    paths that get_chromium_paths/get_firefox_paths look in."""
    chromium_found, firefox_found = [], []
    for root in extra_paths or []:
        if not os.path.isdir(root):
            print(f"[!] --extra-path not found or not a directory: {root}")
            continue
        chromium_found += glob.glob(os.path.join(root, "**", "History"), recursive=True)
        firefox_found += glob.glob(os.path.join(root, "**", "places.sqlite"), recursive=True)
    return sorted(set(chromium_found)), sorted(set(firefox_found))


def main():
    parser = argparse.ArgumentParser(description="Acquire local browser history/search artifacts.")
    parser.add_argument("--limit", type=int, default=1000,
                         help="Max rows to pull per browser profile (default: 1000)")
    parser.add_argument("--extra-path", action="append", default=[], dest="extra_paths",
                         help="Additional root folder to scan for browser profiles, e.g. a "
                              "portable browser install or a mounted removable drive. Can be "
                              "given multiple times.")
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

    extra_chromium, extra_firefox = find_extra_history_files(args.extra_paths)
    if args.extra_paths:
        print(f"[*] Scanned --extra-path root(s): {len(extra_chromium)} Chromium "
              f"History file(s), {len(extra_firefox)} Firefox places.sqlite file(s) found.")

    chromium_paths = get_chromium_paths(os_name)
    for extra_hist in extra_chromium:
        chromium_paths.setdefault("Chromium (extra-path)", []).append(extra_hist)

    for label, history_files in chromium_paths.items():
        for hist_path in history_files:
            profile_name = os.path.basename(os.path.dirname(hist_path))
            portable = label == "Chromium (extra-path)"
            key = f"{label} ({profile_name})"
            print(f"[*] Reading {key}{' [portable/extra-path]' if portable else ''}...")

            history_rows, hist_err = collect_chromium_history(hist_path, args.limit)
            search_rows, search_err = collect_chromium_search_terms(hist_path, args.limit)
            download_rows, download_err = collect_chromium_downloads(hist_path, args.limit)
            bookmark_rows, bookmarks_path, bookmarks_err = collect_chromium_bookmarks(hist_path)
            cookie_rows, cookies_path, cookies_err = collect_chromium_cookies_meta(hist_path)

            known_urls, known_urls_err = collect_chromium_all_urls(hist_path)
            if known_urls_err:
                # Fall back to the capped set rather than treating every
                # live row as "unknown"/deleted if the unlimited query fails.
                known_urls = {r["url"] for r in history_rows if r.get("url")}
            carved, carve_err = carve_deleted_urls_with_wal(hist_path, known_urls)

            # Cookie names/domains are recoverable from disk the same way
            # deleted history rows are (see carve_deleted_urls docstring) -
            # scan the raw Cookies file bytes too, treating any host that
            # doesn't already show up in the live cookie rows as "carved".
            cookie_carved, cookie_carve_err = [], None
            if cookies_path and os.path.isfile(cookies_path):
                known_hosts, known_hosts_err = collect_chromium_all_cookie_hosts(cookies_path)
                if known_hosts_err:
                    known_hosts = {r["host"] for r in cookie_rows if r.get("host")}
                cookie_carved, cookie_carve_err = carve_deleted_urls_with_wal(cookies_path, known_hosts)

            result["browsers"][key] = {
                "source_path": hist_path,
                "portable": portable,
                "history_count": len(history_rows),
                "history": history_rows,
                "history_error": hist_err,
                "search_terms_count": len(search_rows),
                "search_terms": search_rows,
                "search_terms_error": search_err,
                "downloads_count": len(download_rows),
                "downloads": download_rows,
                "downloads_error": download_err,
                "bookmarks_count": len(bookmark_rows),
                "bookmarks": bookmark_rows,
                "bookmarks_path": bookmarks_path,
                "bookmarks_error": bookmarks_err,
                "cookies_count": len(cookie_rows),
                "cookies": cookie_rows,
                "cookies_path": cookies_path,
                "cookies_error": cookies_err,
                "deleted_url_candidates_count": len(carved),
                "deleted_url_candidates": carved,
                "deleted_url_candidates_note": carve_err,
                "deleted_cookie_candidates_count": len(cookie_carved),
                "deleted_cookie_candidates": cookie_carved,
                "deleted_cookie_candidates_note": cookie_carve_err,
            }
            if carved:
                print(f"    [+] Recovered {len(carved)} possible deleted URL(s) via string carving.")
            if cookie_carved:
                print(f"    [+] Recovered {len(cookie_carved)} possible deleted cookie host(s) via string carving.")

    tor_paths = get_tor_paths(os_name)
    if tor_paths:
        print(f"[*] Found {len(tor_paths)} Tor Browser profile(s) via common-location search.")

    ff_paths = get_firefox_paths(os_name) + extra_firefox
    all_firefox_family = [(p, "firefox") for p in ff_paths] + [(p, "tor") for p in tor_paths]

    for places_path, family in all_firefox_family:
        profile_dir = os.path.dirname(places_path)
        profile_name = os.path.basename(profile_dir)
        is_tor = family == "tor"
        portable = is_tor or places_path in extra_firefox
        if is_tor:
            # profile.default is the same folder name for every Tor Browser
            # bundle, so it's useless for telling multiple bundles apart -
            # use the name of the folder the bundle was extracted into instead.
            bundle_marker = os.sep + "TorBrowser" + os.sep
            bundle_root = places_path.split(bundle_marker)[0] if bundle_marker in places_path else profile_dir
            key = f"Tor Browser ({os.path.basename(bundle_root)})"
        else:
            key = f"Firefox ({profile_name})"
        print(f"[*] Reading {key}{' [portable/extra-path]' if portable else ''}...")

        history_rows, hist_err = collect_firefox_history(places_path, args.limit)
        bookmark_rows, bookmarks_err = collect_firefox_bookmarks(places_path, args.limit)
        cookie_rows, cookies_path, cookies_err = collect_firefox_cookies_meta(profile_dir)
        download_rows, downloads_err = collect_firefox_downloads(profile_dir, places_path, args.limit)

        known_urls, known_urls_err = collect_firefox_all_urls(places_path)
        if known_urls_err:
            known_urls = {r["url"] for r in history_rows if r.get("url")}
        carved, carve_err = carve_deleted_urls_with_wal(places_path, known_urls)

        cookie_carved, cookie_carve_err = [], None
        if cookies_path and os.path.isfile(cookies_path):
            known_hosts, known_hosts_err = collect_firefox_all_cookie_hosts(cookies_path)
            if known_hosts_err:
                known_hosts = {r["host"] for r in cookie_rows if r.get("host")}
            cookie_carved, cookie_carve_err = carve_deleted_urls_with_wal(cookies_path, known_hosts)

        result["browsers"][key] = {
            "source_path": places_path,
            "portable": portable,
            "history_count": len(history_rows),
            "history": history_rows,
            "history_error": hist_err,
            "downloads_count": len(download_rows),
            "downloads": download_rows,
            "downloads_error": downloads_err,
            "bookmarks_count": len(bookmark_rows),
            "bookmarks": bookmark_rows,
            "bookmarks_error": bookmarks_err,
            "cookies_count": len(cookie_rows),
            "cookies": cookie_rows,
            "cookies_path": cookies_path,
            "cookies_error": cookies_err,
            "deleted_url_candidates_count": len(carved),
            "deleted_url_candidates": carved,
            "deleted_url_candidates_note": carve_err,
            "deleted_cookie_candidates_count": len(cookie_carved),
            "deleted_cookie_candidates": cookie_carved,
            "deleted_cookie_candidates_note": cookie_carve_err,
        }
        if carved:
            print(f"    [+] Recovered {len(carved)} possible deleted URL(s) via string carving.")
        if cookie_carved:
            print(f"    [+] Recovered {len(cookie_carved)} possible deleted cookie host(s) via string carving.")

    if not result["browsers"]:
        result["note"] = "No known browser profiles found on this system for the current user."
        print("[i] No browser profiles found.")

    fname = save_evidence(result, os_name)
    browsers_v = result["browsers"].values()
    total = sum(v.get("history_count", 0) for v in browsers_v)
    total_search = sum(v.get("search_terms_count", 0) for v in browsers_v)
    total_downloads = sum(v.get("downloads_count", 0) for v in browsers_v)
    total_bookmarks = sum(v.get("bookmarks_count", 0) for v in browsers_v)
    total_cookies = sum(v.get("cookies_count", 0) for v in browsers_v)
    total_carved = sum(v.get("deleted_url_candidates_count", 0) for v in browsers_v)
    total_cookie_carved = sum(v.get("deleted_cookie_candidates_count", 0) for v in browsers_v)
    print(f"[*] Total history entries collected: {total}")
    print(f"[*] Total search terms collected: {total_search}")
    print(f"[*] Total downloads collected: {total_downloads}")
    print(f"[*] Total bookmarks collected: {total_bookmarks}")
    print(f"[*] Total cookies (metadata only) collected: {total_cookies}")
    print(f"[*] Total possible deleted URLs recovered via carving: {total_carved}")
    print(f"[*] Total possible deleted cookie hosts recovered via carving: {total_cookie_carved}")
    print(f"[+] Evidence saved to: {fname}")


if __name__ == "__main__":
    main()