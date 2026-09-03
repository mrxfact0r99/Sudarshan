#!/usr/bin/env python3
"""
Sudarshan EDR — Easy Server Startup
Run:  python3 start_server.py
"""

import os
import sys
import socket
import secrets
import subprocess

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return socket.gethostbyname(socket.gethostname())

def main():
    print("\n" + "═" * 62)
    print("  🛡  Sudarshan EDR — Server Setup")
    print("═" * 62)

    # ── 1. Enrollment token ───────────────────────────────────────
    token = os.environ.get("SUDARSHAN_ENROLL_TOKEN", "")
    if not token or token == "change-this-token":
        auto = secrets.token_hex(16)
        print(f"\n  No SUDARSHAN_ENROLL_TOKEN set.")
        ans = input(f"  Press Enter to use auto-generated token, or type your own: ").strip()
        token = ans if ans else auto

    os.environ["SUDARSHAN_ENROLL_TOKEN"] = token

    # ── 1b. Dashboard password ──────────────────────────────────
    dash_pass = os.environ.get("SUDARSHAN_DASHBOARD_PASSWORD", "")
    if not dash_pass:
        sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "edr"))
        import config as edr_config
        ans = input(f"\n  Dashboard password [Enter to keep '{edr_config.DASHBOARD_PASSWORD}']: ").strip()
        dash_pass = ans if ans else edr_config.DASHBOARD_PASSWORD
        os.environ["SUDARSHAN_DASHBOARD_PASSWORD"] = dash_pass

    # ── 2. Port ───────────────────────────────────────────────────
    port_str = os.environ.get("SUDARSHAN_SERVER_PORT", "")
    if not port_str:
        ans = input("  Server port [default 8443]: ").strip()
        port_str = ans if ans else "8443"

    try:
        port = int(port_str)
    except ValueError:
        print("  Invalid port, using 8443.")
        port = 8443

    os.environ["SUDARSHAN_SERVER_PORT"] = str(port)

    # ── 3. Show connection info ───────────────────────────────────
    local_ip = get_local_ip()
    print("\n" + "═" * 62)
    print("  Server will start with:")
    print(f"    Dashboard  →  http://{local_ip}:{port}")
    print(f"    Password   →  {dash_pass}")
    print(f"    Token      →  {token}")
    print("─" * 62)
    print("  To start an AGENT on another machine, run:")
    print(f"    export SUDARSHAN_ENROLL_TOKEN=\"{token}\"")
    print(f"    python3 -m edr.agent --server http://{local_ip}:{port}")
    print()
    print("  Or use the Agent GUI:")
    print(f"    python3 edr_agent_gui.py")
    print("    (Enter the token and URL shown above)")
    print("═" * 62 + "\n")

    input("  Press Enter to start server…")

    # ── 4. Launch server ──────────────────────────────────────────
    env = dict(os.environ)
    try:
        subprocess.run(
            [sys.executable, "-m", "edr.server"],
            cwd=os.path.dirname(os.path.abspath(__file__)),
            env=env,
        )
    except KeyboardInterrupt:
        print("\n\n  Server stopped.")

if __name__ == "__main__":
    main()
