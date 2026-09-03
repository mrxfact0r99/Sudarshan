"""
Sudarshan EDR - central server.

Run with:
    export SUDARSHAN_ENROLL_TOKEN="pick-a-real-secret"
    python3 -m edr.server

Or use the easy startup script:
    python3 start_server.py
"""

import functools
import io
import json
import os
import queue as _queue
import secrets
import shutil
import socket
import sqlite3
import subprocess
import sys
import threading
import uuid
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from flask import (
    Flask, request, jsonify, render_template, abort, send_file, g,
    session, redirect, url_for
)

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from config import (  # noqa: E402
    ENROLL_TOKEN, DATA_DIR, DB_PATH, COLLECTOR_FILES,
    DASHBOARD_PASSWORD, SECRET_KEY,
)

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

app = Flask(__name__)
app.secret_key = SECRET_KEY or secrets.token_hex(32)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# --------------------------------------------------------------------------
# Timestamps are always STORED in UTC (see now_iso()) so the DB and any
# machine-to-machine comparisons never get confused about offsets. They are
# only converted to IST at DISPLAY time, in the dashboard templates, via the
# `to_ist` Jinja filter below. This is what drives the "agent connected at
# <time>" and "agent last seen at <time>" text on the dashboard.
# --------------------------------------------------------------------------
IST = ZoneInfo("Asia/Kolkata")


def to_ist(value, fmt="%d %b %Y, %I:%M:%S %p IST"):
    """Format a stored UTC ISO-8601 timestamp string as IST for display.
    Returns '-' for empty values and falls back to the raw string if it
    can't be parsed (so a bad value never crashes a template render)."""
    if not value:
        return "-"
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        return value
    if dt.tzinfo is None:
        # Older rows / any legacy naive timestamps are assumed UTC, since
        # that's what now_iso() has always produced.
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(IST).strftime(fmt)


app.jinja_env.filters["to_ist"] = to_ist

# --------------------------------------------------------------------------
# Thread-safe log queue — server_gui.py polls this to update its widget
# --------------------------------------------------------------------------
_log_queue = _queue.Queue()


def server_log(msg):
    """Print timestamped log to stdout AND put it in the queue for the GUI."""
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line, flush=True)
    try:
        _log_queue.put_nowait(line)
    except Exception:
        pass


# --------------------------------------------------------------------------
# Storage
#
# Every agent gets its own folder under DATA_DIR/agents/<agent_id>/.
# Each collection cycle (one full pass of all collectors, run by the agent
# on its interval) gets its OWN numbered sub-folder under that, so nothing
# from an earlier cycle is ever overwritten:
#
#   agents/<agent_id>/cycles/cycle_0001/Evidences/*.json
#   agents/<agent_id>/cycles/cycle_0001/Report/*.pdf
#   agents/<agent_id>/cycles/cycle_0002/Evidences/*.json
#   agents/<agent_id>/cycles/cycle_0002/Report/*.pdf
#   ...
#
# A report is generated automatically for a cycle as soon as that cycle
# finishes (the agent's checkin at the end of run_cycle() signals "done").
# The dashboard's "Generate Report" button just lets you re-run/regenerate
# the report for a given cycle on demand - it never deletes another cycle.
# --------------------------------------------------------------------------

def get_db():
    if "db" not in g:
        os.makedirs(DATA_DIR, exist_ok=True)
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    os.makedirs(DATA_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS agents (
            agent_id TEXT PRIMARY KEY,
            hostname TEXT,
            os_name  TEXT,
            label    TEXT,
            first_seen TEXT,
            last_seen  TEXT,
            desired_running INTEGER NOT NULL DEFAULT 1,
            interval_seconds INTEGER NOT NULL DEFAULT 900,
            command_version INTEGER NOT NULL DEFAULT 0,
            current_cycle INTEGER NOT NULL DEFAULT 1,
            terminate_requested INTEGER NOT NULL DEFAULT 0,
            terminated_at TEXT
        )
        """
    )
    # Lightweight schema migration for databases created by older versions.
    existing_cols = {row[1] for row in conn.execute("PRAGMA table_info(agents)").fetchall()}
    migrations = {
        "desired_running": "ALTER TABLE agents ADD COLUMN desired_running INTEGER NOT NULL DEFAULT 1",
        "interval_seconds": "ALTER TABLE agents ADD COLUMN interval_seconds INTEGER NOT NULL DEFAULT 900",
        "command_version": "ALTER TABLE agents ADD COLUMN command_version INTEGER NOT NULL DEFAULT 0",
        "current_cycle": "ALTER TABLE agents ADD COLUMN current_cycle INTEGER NOT NULL DEFAULT 1",
        "terminate_requested": "ALTER TABLE agents ADD COLUMN terminate_requested INTEGER NOT NULL DEFAULT 0",
        "terminated_at": "ALTER TABLE agents ADD COLUMN terminated_at TEXT",
    }
    for col, sql in migrations.items():
        if col not in existing_cols:
            conn.execute(sql)

    # NOTE: cycle is part of the primary key so every cycle's artifacts are
    # kept as their own row instead of overwriting the previous cycle's row.
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS artifacts (
            agent_id      TEXT,
            cycle         INTEGER NOT NULL DEFAULT 1,
            artifact_type TEXT,
            filename      TEXT,
            received_at   TEXT,
            PRIMARY KEY (agent_id, cycle, artifact_type)
        )
        """
    )
    existing_art_cols = {row[1] for row in conn.execute("PRAGMA table_info(artifacts)").fetchall()}
    if "cycle" not in existing_art_cols:
        conn.execute("ALTER TABLE artifacts ADD COLUMN cycle INTEGER NOT NULL DEFAULT 1")

    conn.commit()
    conn.close()


def agent_dir(agent_id):
    return os.path.join(DATA_DIR, "agents", agent_id)


def cycle_dir(agent_id, cycle):
    return os.path.join(agent_dir(agent_id), "cycles", f"cycle_{int(cycle):04d}")


def cycle_evidence_dir(agent_id, cycle):
    return os.path.join(cycle_dir(agent_id, cycle), "Evidences")


def cycle_report_dir(agent_id, cycle):
    return os.path.join(cycle_dir(agent_id, cycle), "Report")


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def known_cycles(db, agent_id):
    """All cycle numbers that have at least one uploaded artifact, newest first."""
    rows = db.execute(
        "SELECT DISTINCT cycle FROM artifacts WHERE agent_id=? ORDER BY cycle DESC", (agent_id,)
    ).fetchall()
    return [int(r["cycle"]) for r in rows]


# --------------------------------------------------------------------------
# Report generation (shared by the automatic trigger and the manual button)
# --------------------------------------------------------------------------

def generate_report_for_cycle(agent_id, cycle, hostname=""):
    """Runs Scripts.report.report against ONE cycle's Evidences folder and
    writes the PDFs into that SAME cycle's Report folder. Never touches any
    other cycle's data."""
    workspace = cycle_dir(agent_id, cycle)
    evid_dir = os.path.join(workspace, "Evidences")
    if not os.path.isdir(evid_dir) or not os.listdir(evid_dir):
        return False, "No evidence uploaded for this cycle yet.", []

    report_dir = os.path.join(workspace, "Report")
    # Safe to clear: this regenerates ONLY this cycle's own report, it does
    # not touch earlier or later cycles' folders.
    if os.path.isdir(report_dir):
        shutil.rmtree(report_dir, ignore_errors=True)

    env = dict(os.environ)
    env["PYTHONPATH"] = PROJECT_ROOT + os.pathsep + env.get("PYTHONPATH", "")

    server_log(f"[REPORT] Generating PDFs for {hostname!r} cycle {cycle} ({agent_id[:8]}...)")
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "Scripts.report.report"],
            cwd=workspace,
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except subprocess.TimeoutExpired:
        server_log(f"[REPORT] TIMED OUT for {hostname!r} cycle {cycle}")
        return False, "Report generation timed out.", []

    if proc.returncode != 0 or not os.path.isdir(report_dir):
        server_log(f"[REPORT] FAILED for {hostname!r} cycle {cycle}: {proc.stderr[-300:]}")
        return False, proc.stderr[-2000:] or "Report generation failed.", []

    pdfs = sorted(f for f in os.listdir(report_dir) if f.lower().endswith(".pdf"))
    if not pdfs:
        return False, "Report script ran but produced no PDF.", []

    server_log(f"[REPORT] Done — {len(pdfs)} PDF(s) for {hostname!r} cycle {cycle}")
    return True, "", pdfs


def _generate_report_background(agent_id, cycle, hostname):
    """Runs report generation on a background thread so the agent's checkin
    request (which signals a cycle just finished) doesn't have to wait on it."""
    try:
        generate_report_for_cycle(agent_id, cycle, hostname)
    except Exception as e:
        server_log(f"[REPORT] background generation error for {hostname!r} cycle {cycle}: {e}")


# --------------------------------------------------------------------------
# Auth helper
# --------------------------------------------------------------------------

def require_token():
    token = request.headers.get("X-Agent-Token", "")
    if token != ENROLL_TOKEN:
        abort(401, description="Invalid or missing X-Agent-Token header.")


def login_required(view):
    """Guards human-facing dashboard routes. Agent API routes are NOT
    wrapped with this - they authenticate separately via require_token()."""
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("logged_in"):
        return redirect(url_for("dashboard"))

    error = None
    if request.method == "POST":
        password = request.form.get("password", "")
        if secrets.compare_digest(password, DASHBOARD_PASSWORD):
            session.clear()
            session["logged_in"] = True
            session.permanent = True
            server_log(f"[LOGIN] dashboard login  ip={request.remote_addr}")
            nxt = request.args.get("next") or url_for("dashboard")
            return redirect(nxt)
        server_log(f"[LOGIN] FAILED dashboard login attempt  ip={request.remote_addr}")
        error = "Incorrect password."
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# --------------------------------------------------------------------------
# Agent-facing API
# --------------------------------------------------------------------------

@app.route("/api/enroll", methods=["POST"])
def enroll():
    require_token()
    body      = request.get_json(force=True, silent=True) or {}
    hostname  = body.get("hostname", "unknown-host")
    os_name   = body.get("os_name",  "unknown-os")
    client_ip = request.remote_addr
    agent_id  = body.get("agent_id") or str(uuid.uuid4())

    db  = get_db()
    row = db.execute("SELECT agent_id FROM agents WHERE agent_id=?", (agent_id,)).fetchone()
    ts  = now_iso()

    if row:
        # A fresh process start (even reusing the same persisted agent_id
        # from edr/.agent_id) is always a clean slate: clear any leftover
        # terminate_requested/terminated_at from a PREVIOUS dashboard
        # Terminate click, and restore desired_running=1. Without this,
        # terminate_requested is set once and NEVER cleared anywhere else,
        # so re-running the agent after a past Terminate would enroll fine,
        # run exactly one collection cycle, and then immediately see the
        # still-set terminate flag on its next heartbeat and shut itself
        # down again - looking like "runs once then goes offline" even
        # though nobody pressed Terminate this time.
        db.execute(
            "UPDATE agents SET hostname=?, os_name=?, last_seen=?, "
            "terminate_requested=0, terminated_at=NULL, desired_running=1 "
            "WHERE agent_id=?",
            (hostname, os_name, ts, agent_id),
        )
        server_log(f"[ENROLL] RE-ENROLLED  host={hostname!r}  os={os_name}  ip={client_ip}  id={agent_id[:8]}... (terminate/stop flags cleared)")
    else:
        db.execute(
            "INSERT INTO agents (agent_id, hostname, os_name, label, first_seen, last_seen, current_cycle) "
            "VALUES (?, ?, ?, ?, ?, ?, 1)",
            (agent_id, hostname, os_name, hostname, ts, ts),
        )
        server_log(f"[ENROLL] NEW AGENT    host={hostname!r}  os={os_name}  ip={client_ip}  id={agent_id[:8]}...")

    db.commit()
    os.makedirs(agent_dir(agent_id), exist_ok=True)
    return jsonify({"agent_id": agent_id, "status": "enrolled"})


@app.route("/api/checkin/<agent_id>", methods=["POST"])
def checkin(agent_id):
    """The agent calls this once at the END of a full collection cycle
    (after uploading every artifact type). That makes checkin the natural
    signal that a cycle is complete: we auto-generate that cycle's report
    in the background, then roll the agent over to a fresh cycle number so
    the NEXT cycle's uploads land in their own new sub-folder."""
    require_token()
    db  = get_db()
    row = db.execute("SELECT hostname, current_cycle FROM agents WHERE agent_id=?", (agent_id,)).fetchone()
    if not row:
        abort(404, description="Unknown agent_id - enroll first.")

    finished_cycle = int(row["current_cycle"])
    hostname = row["hostname"]

    db.execute(
        "UPDATE agents SET last_seen=?, current_cycle=current_cycle+1 WHERE agent_id=?",
        (now_iso(), agent_id),
    )
    db.commit()
    server_log(f"[CHECKIN] host={hostname!r}  ip={request.remote_addr}  "
               f"cycle {finished_cycle} complete  id={agent_id[:8]}...")

    # Auto-generate the report for the cycle that just finished, without
    # blocking the agent's HTTP request.
    evid_dir = cycle_evidence_dir(agent_id, finished_cycle)
    if os.path.isdir(evid_dir) and os.listdir(evid_dir):
        threading.Thread(
            target=_generate_report_background,
            args=(agent_id, finished_cycle, hostname),
            daemon=True,
        ).start()

    return jsonify({"status": "ok", "cycle_completed": finished_cycle})


@app.route("/api/heartbeat/<agent_id>", methods=["POST"])
def heartbeat(agent_id):
    """Heartbeat endpoint. Also returns dashboard-controlled agent settings."""
    require_token()
    db = get_db()
    row = db.execute(
        "SELECT desired_running, interval_seconds, command_version, terminate_requested "
        "FROM agents WHERE agent_id=?",
        (agent_id,),
    ).fetchone()
    if not row:
        abort(404, description="Unknown agent_id - enroll first.")

    ts = now_iso()
    terminate = bool(row["terminate_requested"])
    if terminate:
        # Record that the endpoint has been told to shut down. We don't
        # delete the agent row here - the agent still has to actually
        # exit and confirm; the dashboard shows "Terminating..." until
        # last_seen stops advancing (agent goes Offline for good).
        db.execute(
            "UPDATE agents SET last_seen=?, terminated_at=? WHERE agent_id=?",
            (ts, ts, agent_id),
        )
    else:
        db.execute("UPDATE agents SET last_seen=? WHERE agent_id=?", (ts, agent_id))
    db.commit()

    return jsonify({
        "status": "ok",
        "running": bool(row["desired_running"]),
        "interval_seconds": max(10, int(row["interval_seconds"])),
        "command_version": int(row["command_version"]),
        "terminate": terminate,
    })


@app.route("/api/control/<agent_id>", methods=["POST"])
@login_required
def control_agent(agent_id):
    """Dashboard control for telemetry collection. No arbitrary endpoint commands.
    Called from the browser (dashboard JS), so it's gated by the dashboard
    login session rather than the agent's X-Agent-Token."""
    db = get_db()
    row = db.execute("SELECT * FROM agents WHERE agent_id=?", (agent_id,)).fetchone()
    if not row:
        abort(404)

    body = request.get_json(force=True, silent=True) or {}
    action = body.get("action")
    interval = body.get("interval_seconds")

    if action not in (None, "start", "stop", "terminate"):
        return jsonify({"error": "action must be start, stop, terminate, or omitted"}), 400

    updates, values = [], []
    if action == "start":
        updates.append("desired_running=?")
        values.append(1)
    elif action == "stop":
        updates.append("desired_running=?")
        values.append(0)
    elif action == "terminate":
        # Fully shuts the endpoint agent process down (not just "stop
        # collecting"). Irreversible from this side - the agent has to be
        # started again by hand on the endpoint if you want it back.
        updates.append("terminate_requested=?")
        values.append(1)
        updates.append("desired_running=?")
        values.append(0)

    if interval is not None:
        try:
            interval = int(interval)
        except (TypeError, ValueError):
            return jsonify({"error": "interval_seconds must be an integer"}), 400
        if not 10 <= interval <= 86400:
            return jsonify({"error": "interval must be between 10 and 86400 seconds"}), 400
        updates.append("interval_seconds=?")
        values.append(interval)

    if not updates:
        return jsonify({"error": "No control change requested"}), 400

    updates.append("command_version=command_version+1")
    values.append(agent_id)
    db.execute(f"UPDATE agents SET {', '.join(updates)} WHERE agent_id=?", values)
    db.commit()

    updated = db.execute(
        "SELECT desired_running, interval_seconds, command_version, terminate_requested "
        "FROM agents WHERE agent_id=?",
        (agent_id,),
    ).fetchone()
    state = "started" if updated["desired_running"] else "stopped"
    if action == "terminate":
        server_log(
            f"[CONTROL] host={row['hostname']!r} TERMINATE requested "
            f"id={agent_id[:8]}... (agent will exit on its next heartbeat)"
        )
    else:
        server_log(
            f"[CONTROL] host={row['hostname']!r} collection={state} "
            f"interval={updated['interval_seconds']}s id={agent_id[:8]}..."
        )
    return jsonify({
        "status": "ok",
        "running": bool(updated["desired_running"]),
        "interval_seconds": int(updated["interval_seconds"]),
        "command_version": int(updated["command_version"]),
        "terminate_requested": bool(updated["terminate_requested"]),
    })


@app.route("/api/artifact/<agent_id>/<artifact_type>", methods=["POST"])
def upload_artifact(agent_id, artifact_type):
    require_token()
    if artifact_type not in COLLECTOR_FILES:
        abort(400, description=f"Unknown artifact_type '{artifact_type}'.")

    db  = get_db()
    row = db.execute("SELECT hostname, current_cycle FROM agents WHERE agent_id=?", (agent_id,)).fetchone()
    if not row:
        abort(404, description="Unknown agent_id - enroll first.")
    hostname  = row["hostname"]
    cycle     = int(row["current_cycle"])
    client_ip = request.remote_addr

    payload = request.get_json(force=True, silent=True)
    if payload is None:
        abort(400, description="Body must be valid JSON.")

    filename = COLLECTOR_FILES[artifact_type]
    dest_dir = cycle_evidence_dir(agent_id, cycle)
    os.makedirs(dest_dir, exist_ok=True)
    # Each cycle writes into its OWN Evidences folder, so this never
    # overwrites a previous cycle's file - only re-uploads within the SAME
    # still-in-progress cycle overwrite (e.g. a retried upload).
    with open(os.path.join(dest_dir, filename), "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False, default=str)

    # Count records for a meaningful log line
    if isinstance(payload, list):
        n_records = len(payload)
    elif isinstance(payload, dict):
        n_records = len(payload.get("data", payload))
    else:
        n_records = "?"

    label = artifact_type.rsplit(".", 1)[-1]
    ts    = now_iso()

    db.execute(
        "INSERT INTO artifacts (agent_id, cycle, artifact_type, filename, received_at) VALUES (?, ?, ?, ?, ?) "
        "ON CONFLICT(agent_id, cycle, artifact_type) DO UPDATE SET filename=excluded.filename, "
        "received_at=excluded.received_at",
        (agent_id, cycle, artifact_type, filename, ts),
    )
    db.execute("UPDATE agents SET last_seen=? WHERE agent_id=?", (ts, agent_id))
    db.commit()

    server_log(
        f"[ARTIFACT] host={hostname!r}  ip={client_ip}  "
        f"type={label}  records={n_records}  cycle={cycle}  id={agent_id[:8]}..."
    )
    return jsonify({"status": "stored", "artifact_type": artifact_type, "cycle": cycle})


# --------------------------------------------------------------------------
# Dashboard (human-facing)
# --------------------------------------------------------------------------

@app.route("/")
@login_required
def dashboard():
    db = get_db()
    agents          = db.execute("SELECT * FROM agents ORDER BY last_seen DESC").fetchall()
    total_artifacts = db.execute("SELECT COUNT(*) FROM artifacts").fetchone()[0]
    return render_template("dashboard.html", agents=agents, total_artifacts=total_artifacts)


@app.route("/agent/<agent_id>")
@login_required
def agent_detail(agent_id):
    db    = get_db()
    agent = db.execute("SELECT * FROM agents WHERE agent_id=?", (agent_id,)).fetchone()
    if not agent:
        abort(404)

    known_types = list(COLLECTOR_FILES.keys())
    cycles_data = []
    for cyc in known_cycles(db, agent_id):
        cyc_artifacts = db.execute(
            "SELECT * FROM artifacts WHERE agent_id=? AND cycle=? ORDER BY artifact_type",
            (agent_id, cyc),
        ).fetchall()
        have_types = {a["artifact_type"] for a in cyc_artifacts}
        report_dir = cycle_report_dir(agent_id, cyc)
        pdfs = []
        if os.path.isdir(report_dir):
            pdfs = sorted(f for f in os.listdir(report_dir) if f.lower().endswith(".pdf"))
        cycles_data.append({
            "cycle": cyc,
            "artifacts": cyc_artifacts,
            "missing_types": [t for t in known_types if t not in have_types],
            "pdfs": pdfs,
        })

    return render_template(
        "agent_detail.html",
        agent=agent,
        cycles=cycles_data,
        known_type_count=len(known_types),
    )


@app.route("/agent/<agent_id>/artifact/<int:cycle>/<artifact_type>")
@login_required
def view_artifact(agent_id, cycle, artifact_type):
    db  = get_db()
    row = db.execute(
        "SELECT * FROM artifacts WHERE agent_id=? AND cycle=? AND artifact_type=?",
        (agent_id, cycle, artifact_type),
    ).fetchone()
    if not row:
        abort(404)
    path = os.path.join(cycle_evidence_dir(agent_id, cycle), row["filename"])
    if not os.path.isfile(path):
        abort(404)
    with open(path, "r", encoding="utf-8") as f:
        data = f.read()
    return app.response_class(data, mimetype="application/json")


@app.route("/agent/<agent_id>/report", methods=["POST"])
@login_required
def generate_report(agent_id):
    """Manual (re)generation - defaults to the most recent cycle that has
    evidence, or a specific one via {"cycle": N} in the JSON body. This
    NEVER deletes any other cycle's data."""
    db    = get_db()
    agent = db.execute("SELECT * FROM agents WHERE agent_id=?", (agent_id,)).fetchone()
    if not agent:
        abort(404)

    body = request.get_json(force=True, silent=True) or {}
    requested_cycle = body.get("cycle")

    if requested_cycle is not None:
        try:
            cycle = int(requested_cycle)
        except (TypeError, ValueError):
            return jsonify({"error": "cycle must be an integer"}), 400
    else:
        cycles = known_cycles(db, agent_id)
        if not cycles:
            return jsonify({"error": "No evidence uploaded for this agent yet."}), 400
        cycle = cycles[0]  # most recent

    ok, err, pdfs = generate_report_for_cycle(agent_id, cycle, agent["hostname"])
    if not ok:
        return jsonify({"error": err}), 400 if "No evidence" in err else 500

    return jsonify({"status": "ok", "cycle": cycle, "files": pdfs})


@app.route("/agent/<agent_id>/report/<int:cycle>/<filename>")
@login_required
def download_report(agent_id, cycle, filename):
    """Serve PDF inline so it opens in the browser instead of downloading."""
    path = os.path.join(cycle_report_dir(agent_id, cycle), filename)
    if not os.path.isfile(path):
        abort(404)
    return send_file(path, mimetype="application/pdf", as_attachment=False)


# --------------------------------------------------------------------------
# Local IP helper
# --------------------------------------------------------------------------

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "127.0.0.1"


if __name__ == "__main__":
    init_db()
    port     = int(os.environ.get("SUDARSHAN_SERVER_PORT", "8443"))
    local_ip = get_local_ip()

    print("=" * 62)
    print("  Sudarshan EDR Server")
    print("=" * 62)
    print(f"  Dashboard  →  http://{local_ip}:{port}")
    print(f"  Password   →  {DASHBOARD_PASSWORD}   (change it in edr/config.py)")
    print(f"  LAN agents →  same URL, different machine")
    print(f"  Token env  →  SUDARSHAN_ENROLL_TOKEN")
    print(f"  Data dir   →  {DATA_DIR}")
    print("=" * 62)
    print("  Live agent logs will appear below:")
    print("=" * 62)
    app.run(host="0.0.0.0", port=port, debug=False)
