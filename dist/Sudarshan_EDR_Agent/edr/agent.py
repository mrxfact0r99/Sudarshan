"""
Sudarshan EDR - endpoint agent.

Run this ONLY on a machine you own or are explicitly authorized to monitor
(your own lab VM, your own spare laptop, etc). See edr/config.py for why.

    export SUDARSHAN_ENROLL_TOKEN="the-same-token-the-server-uses"
    python3 -m edr.agent --server http://192.168.1.50:8443 --once
    python3 -m edr.agent --server http://192.168.1.50:8443            # loop forever

The agent prints what it's doing to the console every cycle - it is not
hidden and does not try to disguise itself as another process. It reuses
the exact collector modules the local Sudarshan CLI already uses
(Scripts/collectors/*.py); this script just runs them on an interval and
ships the resulting JSON to the server instead of only building a local
PDF.
"""

import argparse
import json
import os
import runpy
import shutil
import sys
import tempfile
import time
import uuid
import socket
import threading

import requests

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from config import ENROLL_TOKEN, DEFAULT_SERVER_URL, DEFAULT_INTERVAL_SECONDS, COLLECTOR_FILES  # noqa: E402
import agent_status  # noqa: E402

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from Scripts.common import detect_os  # noqa: E402

sys.path.insert(0, os.path.join(PROJECT_ROOT, "deploy"))
try:
    from edr_self_protect_windows import protect_current_process  # noqa: E402
except ImportError:
    def protect_current_process():  # non-Windows release, or deploy/ missing
        return False

AGENT_ID_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".agent_id")

# Evidence is collection-only on the endpoint: each cycle's JSON files are
# written into a throwaway temp folder, uploaded to the server, and then
# deleted - nothing is kept in a persistent "Evidences" folder on the
# agent's own machine. The server is the only place evidence is retained
# (edr/server_data/agents/<agent_id>/cycles/...).


def load_or_create_agent_id():
    if os.path.isfile(AGENT_ID_FILE):
        with open(AGENT_ID_FILE, "r") as f:
            return f.read().strip()
    new_id = str(uuid.uuid4())
    with open(AGENT_ID_FILE, "w") as f:
        f.write(new_id)
    return new_id


def enroll(server_url, agent_id):
    resp = requests.post(
        f"{server_url}/api/enroll",
        headers={"X-Agent-Token": ENROLL_TOKEN},
        json={"agent_id": agent_id, "hostname": socket.gethostname(), "os_name": detect_os()},
        timeout=15,
    )
    resp.raise_for_status()
    data = resp.json()
    return data["agent_id"]


def run_collector(module_name):
    """Runs a collector the same way Scripts/cli.py does - writes into the
    local ./Evidences folder."""
    try:
        runpy.run_module(module_name, run_name="__main__")
        return True
    except SystemExit as e:
        return e.code is None or e.code == 0
    except Exception as e:
        print(f"  ! {module_name} failed: {e}")
        return False


def upload_artifact(server_url, agent_id, artifact_type, filename, evidence_dir):
    path = os.path.join(evidence_dir, filename)
    if not os.path.isfile(path):
        print(f"  ! expected evidence file missing: {path}")
        return False
    with open(path, "r", encoding="utf-8") as f:
        try:
            payload = json.load(f)
        except json.JSONDecodeError:
            print(f"  ! {filename} is not valid JSON, skipping upload")
            return False

    resp = requests.post(
        f"{server_url}/api/artifact/{agent_id}/{artifact_type}",
        headers={"X-Agent-Token": ENROLL_TOKEN},
        json=payload,
        timeout=30,
    )
    ok = resp.status_code == 200
    if not ok:
        print(f"  ! upload of {artifact_type} failed: {resp.status_code} {resp.text[:200]}")
    return ok


def run_cycle(server_url, agent_id):
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Starting collection cycle for agent {agent_id}")
    agent_status.write_status(agent_id=agent_id, server=server_url, state="collecting")

    # Each collector writes into a relative "Evidences" folder, so give it
    # a fresh throwaway directory to run in - this is deleted at the end of
    # the cycle regardless of success/failure, so no evidence JSON is left
    # sitting on the endpoint's disk after it's been uploaded to the server.
    cycle_workdir = tempfile.mkdtemp(prefix="sudarshan_edr_cycle_")
    evidence_dir = os.path.join(cycle_workdir, "Evidences")
    prev_cwd = os.getcwd()
    any_failed = False
    try:
        os.chdir(cycle_workdir)
        for module_name, filename in COLLECTOR_FILES.items():
            label = module_name.rsplit(".", 1)[-1]
            print(f"  - collecting {label} ...")
            success = run_collector(module_name)
            if success:
                uploaded = upload_artifact(server_url, agent_id, module_name, filename, evidence_dir)
                print(f"    uploaded" if uploaded else "    upload skipped/failed")
                any_failed = any_failed or not uploaded
            else:
                print(f"    collection failed, not uploading")
                any_failed = True
    finally:
        os.chdir(prev_cwd)
        shutil.rmtree(cycle_workdir, ignore_errors=True)

    try:
        requests.post(
            f"{server_url}/api/checkin/{agent_id}",
            headers={"X-Agent-Token": ENROLL_TOKEN},
            timeout=15,
        )
    except requests.RequestException as e:
        print(f"  ! checkin failed: {e}")
        any_failed = True
    print("Cycle complete.\n")
    agent_status.write_status(
        agent_id=agent_id, server=server_url, state="idle",
        last_cycle_at=time.time(), last_cycle_ok=not any_failed,
    )



class AgentController:
    """Keeps the endpoint connected and applies dashboard collection settings."""
    def __init__(self, server_url, agent_id):
        self.server_url = server_url.rstrip("/")
        self.agent_id = agent_id
        self.running = True
        self.interval = DEFAULT_INTERVAL_SECONDS
        self.command_version = 0
        self.terminate = False
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.ready = threading.Event()  # set once the FIRST real heartbeat reply is in
        self.thread = None

    def start(self):
        self.thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
        self.thread.start()

    def wait_until_ready(self, timeout=15):
        """Block until the first real heartbeat reply has come back (or
        timeout), so the main loop acts on the server's actual current
        running/terminate state instead of guessing from constructor
        defaults for the first few seconds after every restart."""
        return self.ready.wait(timeout)

    def _heartbeat_loop(self):
        while not self.stop_event.is_set():
            try:
                resp = requests.post(
                    f"{self.server_url}/api/heartbeat/{self.agent_id}",
                    headers={"X-Agent-Token": ENROLL_TOKEN},
                    timeout=10,
                )
                resp.raise_for_status()
                data = resp.json()
                with self.lock:
                    self.running = bool(data.get("running", True))
                    self.interval = max(10, int(data.get("interval_seconds", DEFAULT_INTERVAL_SECONDS)))
                    self.command_version = int(data.get("command_version", 0))
                    self.terminate = bool(data.get("terminate", False))
                agent_status.write_status(
                    agent_id=self.agent_id, server=self.server_url,
                    running=self.running, interval=self.interval,
                    terminate=self.terminate, last_heartbeat_at=time.time(),
                )
                self.ready.set()
            except requests.RequestException as e:
                print(f"  ! heartbeat failed: {e}")

            if self.terminate:
                # No point continuing to heartbeat once the dashboard has
                # told this endpoint to shut down - the server already
                # recorded the terminate confirmation on that last call.
                return

            # Short heartbeat period makes dashboard Online/Offline detection responsive.
            self.stop_event.wait(5)

    def snapshot(self):
        with self.lock:
            return self.running, self.interval, self.terminate

    def stop(self):
        self.stop_event.set()


def main():
    parser = argparse.ArgumentParser(description="Sudarshan EDR agent")
    parser.add_argument("--server", default=DEFAULT_SERVER_URL, help="EDR server base URL")
    parser.add_argument("--interval", type=int, default=DEFAULT_INTERVAL_SECONDS,
                         help="Initial interval; dashboard can change it after connection")
    parser.add_argument("--once", action="store_true", help="Run a single cycle and exit")
    args = parser.parse_args()

    agent_id = load_or_create_agent_id()
    print(f"Sudarshan EDR agent starting. Local agent id: {agent_id}")
    print(f"Reporting to server: {args.server}")
    print("This agent is running openly in this terminal/session - it is not hidden.\n")

    # Best-effort, no-admin-required tamper resistance: lock this
    # process's own DACL so a standard user's Task Manager "End Task" /
    # `taskkill` fails with Access is denied, while an actually elevated
    # admin session can still stop it. See deploy/edr_self_protect_windows.py
    # for exactly how and why this doesn't need admin rights to apply,
    # even though it results in admin-only termination. No-op on non-Windows
    # and on --once single-shot runs (nothing persistent to protect there).
    if not args.once:
        protect_current_process()

    try:
        agent_id = enroll(args.server, agent_id)
    except requests.RequestException as e:
        print(f"Could not reach server to enroll: {e}")
        sys.exit(1)

    agent_status.write_status(agent_id=agent_id, server=args.server, state="connected")

    if args.once:
        run_cycle(args.server, agent_id)
        return

    controller = AgentController(args.server, agent_id)
    controller.interval = max(10, args.interval)
    controller.start()

    # Wait for the FIRST real heartbeat reply before deciding whether to
    # collect, stay stopped, or terminate - avoids acting on the
    # constructor's guessed defaults for the first few seconds after
    # every restart (see AgentController.__init__ / wait_until_ready).
    if not controller.wait_until_ready(timeout=15):
        print("  ! no heartbeat reply yet - proceeding with defaults; will pick up the real state shortly.")

    print("Connected to dashboard. Collection is now controlled from the EDR dashboard.")
    print("Closing this agent will make the endpoint Offline after the heartbeat timeout.")
    print("A Terminate command from the dashboard will shut this agent down completely.\n")

    def _terminate_and_exit():
        print("\nDashboard command: TERMINATE received. Shutting this agent down completely.")
        controller.stop()
        sys.exit(0)

    try:
        while True:
            running, interval, terminate = controller.snapshot()
            if terminate:
                _terminate_and_exit()

            if not running:
                print("Dashboard command: collection STOPPED. Agent remains connected.")
                while True:
                    time.sleep(1)
                    running, interval, terminate = controller.snapshot()
                    if terminate:
                        _terminate_and_exit()
                    if running:
                        print("Dashboard command: collection STARTED.")
                        break
                continue

            run_cycle(args.server, agent_id)

            # Wait in short increments so Start/Stop/Terminate and interval changes take effect quickly.
            waited = 0
            while waited < interval:
                time.sleep(1)
                waited += 1
                running, new_interval, terminate = controller.snapshot()
                if terminate:
                    _terminate_and_exit()
                if not running:
                    break
                if new_interval != interval:
                    interval = new_interval
                    break
    except KeyboardInterrupt:
        print("\nAgent stopped by local user.")
    finally:
        controller.stop()


if __name__ == "__main__":
    main()
