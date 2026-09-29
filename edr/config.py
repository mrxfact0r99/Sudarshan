import os
import json


_INSTANCE_CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "instance_config.json")


def _load_instance_config():
    try:
        with open(_INSTANCE_CONFIG_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


_instance = _load_instance_config()


ENROLL_TOKEN = os.environ.get("SUDARSHAN_ENROLL_TOKEN", _instance.get("enroll_token", ""))


DASHBOARD_PASSWORD = os.environ.get("SUDARSHAN_DASHBOARD_PASSWORD", "sudarshan123")

SECRET_KEY = os.environ.get("SUDARSHAN_SECRET_KEY", "")

DATA_DIR = os.environ.get(
    "SUDARSHAN_SERVER_DATA",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "server_data"),
)

DB_PATH = os.path.join(DATA_DIR, "sudarshan_edr.db")

DEFAULT_SERVER_URL = os.environ.get(
    "SUDARSHAN_SERVER_URL", _instance.get("server_url", "http://ServerIP:8443")
)

DEFAULT_INTERVAL_SECONDS = int(os.environ.get("SUDARSHAN_AGENT_INTERVAL", "900"))  # 15 min

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
