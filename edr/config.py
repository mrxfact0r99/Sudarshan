"""
Shared configuration for the Sudarshan EDR server + agent.

IMPORTANT - AUTHORIZED USE ONLY
--------------------------------
This turns Sudarshan from a local triage tool into a client/server telemetry
tool: an "agent" runs on an endpoint, collects the same forensic artifacts
Sudarshan already collected locally, and ships them to a "server" you control
over your LAN.

Only deploy the agent on machines you own, or machines you have explicit
written/verbal authorization to monitor (e.g. your own lab VMs, a college
lab setup for a demo, a personal spare laptop/phone-hotspot rig). Installing
this on someone else's device without their knowledge is not "EDR", it's
unauthorized surveillance - don't do it. Real EDR products are installed
openly by the owner/administrator of a machine, and this should be no
different: run the agent yourself, on your own hardware, and say so in your
project writeup / demo.

Set these via environment variables so the shared secret isn't hardcoded
into code you might commit to a public repo.
"""

import os
import json

# Agents installed as a service (edr_service_windows.py / edr-agent.service)
# don't have the interactive shell's environment variables available to
# them, so deploy/install_agent.py writes the enroll token + server URL it
# was given into this file instead. Env vars still win if set, so manual
# `python -m edr.agent --server ...` runs are unaffected.
_INSTANCE_CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "instance_config.json")


def _load_instance_config():
    try:
        with open(_INSTANCE_CONFIG_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


_instance = _load_instance_config()

# Shared enrollment secret. The agent must present this to enroll with the
# server. Change it before you demo/deploy - do not use the default.
ENROLL_TOKEN = os.environ.get("SUDARSHAN_ENROLL_TOKEN", _instance.get("enroll_token", ""))

# Dashboard login (human access to the web UI in a browser, separate from
# the agent's X-Agent-Token above which agents use to talk to the API).
#
# TO CHANGE THE PASSWORD: just edit the string below, OR set the
# SUDARSHAN_DASHBOARD_PASSWORD environment variable (the env var wins if set).
DASHBOARD_PASSWORD = os.environ.get("SUDARSHAN_DASHBOARD_PASSWORD", "sudarshan123")

# Flask session signing key. If left unset, a random one is generated at
# server startup - that's fine for a demo, it just means everyone gets
# logged out if the server restarts. Set it yourself for a stable session
# across restarts.
SECRET_KEY = os.environ.get("SUDARSHAN_SECRET_KEY", "")

# Where the server stores per-agent data (SQLite DB + evidence JSON files).
DATA_DIR = os.environ.get(
    "SUDARSHAN_SERVER_DATA",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "server_data"),
)

DB_PATH = os.path.join(DATA_DIR, "sudarshan_edr.db")

# Default server URL the agent reports to. Override with --server / env var.
DEFAULT_SERVER_URL = os.environ.get(
    "SUDARSHAN_SERVER_URL", _instance.get("server_url", "http://ServerIP:8443")
)

# How often (seconds) the agent runs a full collection + upload cycle.
DEFAULT_INTERVAL_SECONDS = int(os.environ.get("SUDARSHAN_AGENT_INTERVAL", "900"))  # 15 min

# Maps collector module -> the evidence filename it writes (see Scripts/collectors/*.py)
COLLECTOR_FILES = {
    "Scripts.collectors.processes": "current_processes.json",
    "Scripts.collectors.networks": "network_connections.json",
    "Scripts.collectors.usb": "usb_login_events.json",
    "Scripts.collectors.history": "browser_artifacts.json",
    "Scripts.collectors.logs": "system_logs.json",
    "Scripts.collectors.recycle": "recycle_bin.json",
    "Scripts.collectors.clipboard": "clipboard_snapshot.json",
    "Scripts.collectors.commands": "command_history.json",
    "Scripts.collectors.execution": "executed_programs.json",
}
