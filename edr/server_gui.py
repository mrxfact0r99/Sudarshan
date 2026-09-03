"""
Sudarshan EDR - Server GUI.

Run with:
    python3 edr_server_gui.py
"""

import os
import sys
import socket
import threading
import webbrowser
import tkinter as tk
from tkinter import scrolledtext, messagebox

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from werkzeug.serving import make_server  # noqa: E402
import config as edr_config               # noqa: E402
import server as server_mod               # noqa: E402

# ── Colors ────────────────────────────────────────────────────────
BG     = "#0b0d12"
PANEL  = "#13161e"
PANEL2 = "#1a1e2a"
BORDER = "#252938"
FG     = "#dde1f0"
ACCENT = "#ffb703"
MUTED  = "#5c6380"
GREEN  = "#36d399"
RED    = "#f87171"
BLUE   = "#4895ef"


def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


# ── Flask server thread ───────────────────────────────────────────
class ServerThread(threading.Thread):
    def __init__(self, app, host, port):
        super().__init__(daemon=True)
        self.srv = make_server(host, port, app)
        self.ctx = app.app_context()
        self.ctx.push()

    def run(self):
        self.srv.serve_forever()

    def shutdown(self):
        self.srv.shutdown()


# ── Main GUI ──────────────────────────────────────────────────────
class ServerGUI:
    def __init__(self, root):
        self.root          = root
        self.server_thread = None
        self._poll_id      = None
        self.port          = None

        root.title("Sudarshan EDR — Server Console")
        root.geometry("760x560")
        root.configure(bg=BG)
        root.resizable(True, True)

        self._build_header()
        self._build_form()
        self._build_log()

    # ── Header ────────────────────────────────────────────────────
    def _build_header(self):
        hdr = tk.Frame(self.root, bg=PANEL, height=50)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)

        tk.Label(
            hdr, text="🛡  Sudarshan EDR", bg=PANEL, fg=ACCENT,
            font=("Segoe UI", 15, "bold")
        ).pack(side="left", padx=16)

        self.status_label = tk.Label(
            hdr, text="● Idle", bg=PANEL, fg=MUTED,
            font=("Segoe UI", 10)
        )
        self.status_label.pack(side="right", padx=16)

    # ── Config form ───────────────────────────────────────────────
    def _build_form(self):
        form = tk.Frame(self.root, bg=BG, padx=16, pady=12)
        form.pack(fill="x")

        # Row 1: note
        tk.Label(
            form,
            text="Only enroll endpoints you own or are explicitly authorized to monitor.",
            bg=BG, fg=MUTED, font=("Segoe UI", 9)
        ).grid(row=0, column=0, columnspan=5, sticky="w", pady=(0, 10))

        # Row 2: token + port
        tk.Label(form, text="Enroll token:", bg=BG, fg=FG,
                 font=("Segoe UI", 10)).grid(row=1, column=0, sticky="w")

        self.token_var = tk.StringVar(value=edr_config.ENROLL_TOKEN)
        self.token_entry = tk.Entry(
            form, textvariable=self.token_var, width=30,
            bg=PANEL2, fg=FG, insertbackground=FG,
            relief="flat", font=("Consolas", 10), show="*"
        )
        self.token_entry.grid(row=1, column=1, sticky="w", padx=(8, 4))

        self.token_visible = False
        self.toggle_token_btn = tk.Button(
            form, text="👁", command=self._toggle_token_visibility,
            bg=BG, fg=MUTED, relief="flat", font=("Segoe UI", 10),
            cursor="hand2", width=3
        )
        self.toggle_token_btn.grid(row=1, column=2, sticky="w", padx=(0, 16))

        tk.Label(form, text="Port:", bg=BG, fg=FG,
                 font=("Segoe UI", 10)).grid(row=1, column=3, sticky="w")

        self.port_var = tk.StringVar(value="8443")
        tk.Entry(
            form, textvariable=self.port_var, width=8,
            bg=PANEL2, fg=FG, insertbackground=FG,
            relief="flat", font=("Consolas", 10)
        ).grid(row=1, column=4, sticky="w", padx=8)

        # Row 2b: dashboard password
        tk.Label(form, text="Dashboard pass:", bg=BG, fg=FG,
                 font=("Segoe UI", 10)).grid(row=2, column=0, sticky="w", pady=(8, 0))

        self.dash_pass_var = tk.StringVar(value=edr_config.DASHBOARD_PASSWORD)
        self.dash_pass_entry = tk.Entry(
            form, textvariable=self.dash_pass_var, width=20,
            bg=PANEL2, fg=FG, insertbackground=FG,
            relief="flat", font=("Consolas", 10), show="*"
        )
        self.dash_pass_entry.grid(row=2, column=1, sticky="w", padx=(8, 16), pady=(8, 0))

        # Row 3: buttons
        btn_row = tk.Frame(form, bg=BG)
        btn_row.grid(row=3, column=0, columnspan=5, sticky="w", pady=(10, 0))

        self.start_btn = tk.Button(
            btn_row, text="▶  Start Server", command=self.start_server,
            bg=ACCENT, fg="#000", relief="flat",
            padx=14, pady=6, font=("Segoe UI", 10, "bold"), cursor="hand2"
        )
        self.start_btn.pack(side="left", padx=(0, 8))

        self.stop_btn = tk.Button(
            btn_row, text="■  Stop", command=self.stop_server,
            bg=PANEL2, fg=FG, relief="flat",
            padx=14, pady=6, font=("Segoe UI", 10), state="disabled", cursor="hand2"
        )
        self.stop_btn.pack(side="left", padx=(0, 8))

        self.dash_btn = tk.Button(
            btn_row, text="🌐  Open Dashboard", command=self.open_dashboard,
            bg=PANEL2, fg=FG, relief="flat",
            padx=14, pady=6, font=("Segoe UI", 10), state="disabled", cursor="hand2"
        )
        self.dash_btn.pack(side="left", padx=(0, 8))



    # ── Log panel ─────────────────────────────────────────────────
    def _build_log(self):
        # Label bar
        bar = tk.Frame(self.root, bg=PANEL2, height=28)
        bar.pack(fill="x")
        bar.pack_propagate(False)
        tk.Label(
            bar, text="  Server Log", bg=PANEL2, fg=MUTED,
            font=("Segoe UI", 9, "bold")
        ).pack(side="left", padx=4)

        clr_btn = tk.Button(
            bar, text="Clear", command=self._clear_log,
            bg=PANEL2, fg=MUTED, relief="flat",
            font=("Segoe UI", 8), cursor="hand2", pady=0
        )
        clr_btn.pack(side="right", padx=6)

        # Text widget — tag colours
        self.log_box = scrolledtext.ScrolledText(
            self.root,
            bg=BG, fg=FG, insertbackground=FG,
            relief="flat", font=("Consolas", 9),
            state="disabled", wrap="word"
        )
        self.log_box.pack(fill="both", expand=True, padx=0, pady=0)

        # Colour tags for log lines
        self.log_box.tag_config("enroll",   foreground=GREEN)
        self.log_box.tag_config("artifact", foreground=BLUE)
        self.log_box.tag_config("checkin",  foreground=MUTED)
        self.log_box.tag_config("report",   foreground=ACCENT)
        self.log_box.tag_config("error",    foreground=RED)
        self.log_box.tag_config("info",     foreground=FG)

        self._log("Ready. Set a token and port, then click Start Server.\n", "info")

    def _tag_for_line(self, line):
        low = line.lower()
        if "[enroll]"   in low: return "enroll"
        if "[artifact]" in low: return "artifact"
        if "[checkin]"  in low: return "checkin"
        if "[report]"   in low: return "report"
        if "error"      in low or "failed" in low: return "error"
        return "info"

    def _log(self, text, tag=None):
        """Append text to log box — MUST be called from the main thread."""
        self.log_box.configure(state="normal")
        self.log_box.insert("end", text + ("\n" if not text.endswith("\n") else ""),
                            tag or self._tag_for_line(text))
        self.log_box.see("end")
        self.log_box.configure(state="disabled")

    def _clear_log(self):
        self.log_box.configure(state="normal")
        self.log_box.delete("1.0", "end")
        self.log_box.configure(state="disabled")

    # ── Queue polling (thread-safe bridge) ───────────────────────
    def _poll_log_queue(self):
        """Drain the shared queue from server.py and display in GUI.
        Called every 250 ms via root.after — always runs on the main thread."""
        try:
            while True:
                line = server_mod._log_queue.get_nowait()
                self._log(line)
        except Exception:
            pass  # queue.Empty is normal
        # reschedule only while server is running
        if self.server_thread is not None:
            self._poll_id = self.root.after(250, self._poll_log_queue)

    # ── Server control ────────────────────────────────────────────
    def start_server(self):
        token = self.token_var.get().strip()
        if not token:
            messagebox.showerror("Missing token", "Please set an enroll token.")
            return
        try:
            port = int(self.port_var.get().strip())
        except ValueError:
            messagebox.showerror("Invalid port", "Port must be a number.")
            return

        dash_pass = self.dash_pass_var.get().strip() or edr_config.DASHBOARD_PASSWORD

        # Inject token + dashboard password into server module so
        # require_token()/login() see the values set in this form
        edr_config.ENROLL_TOKEN       = token
        server_mod.ENROLL_TOKEN       = token
        edr_config.DASHBOARD_PASSWORD = dash_pass
        server_mod.DASHBOARD_PASSWORD = dash_pass
        server_mod.init_db()

        try:
            self.server_thread = ServerThread(server_mod.app, "0.0.0.0", port)
            self.server_thread.start()
        except OSError as e:
            messagebox.showerror("Could not start server", str(e))
            return

        self.port = port
        local_ip  = get_local_ip()

        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.dash_btn.configure(state="normal")
        self.status_label.configure(
            text=f"● Running  http://{local_ip}:{port}", fg=GREEN
        )

        self._log(f"Server started on http://{local_ip}:{port}", "info")
        self._log(f"Dashboard password: {self._mask_token(dash_pass)}", "info")
        self._log(f"Token: {self._mask_token(token)}", "info")
        self._log(f"Agents command:", "info")
        self._log(f"  export SUDARSHAN_ENROLL_TOKEN=\"{self._mask_token(token)}\"  (use the real token you set above)", "info")
        self._log(f"  python3 -m edr.agent --server http://{local_ip}:{port}", "info")
        self._log("Waiting for agents...\n", "info")

        # Start polling the queue for live Flask logs
        self._poll_log_queue()

    def open_dashboard(self):
        if self.port:
            webbrowser.open(f"http://127.0.0.1:{self.port}")

    # ── Token visibility + safe copy ────────────────────────────────
    @staticmethod
    def _mask_token(token):
        """Never show the full token in the log — only first/last char."""
        if len(token) <= 2:
            return "*" * len(token)
        return token[0] + "*" * (len(token) - 2) + token[-1]

    def _toggle_token_visibility(self):
        self.token_visible = not self.token_visible
        self.token_entry.configure(show="" if self.token_visible else "*")
        self.toggle_token_btn.configure(text="🙈" if self.token_visible else "👁")


    def stop_server(self):
        # Cancel polling first
        if self._poll_id is not None:
            self.root.after_cancel(self._poll_id)
            self._poll_id = None

        if self.server_thread:
            self.server_thread.shutdown()
            self.server_thread = None

        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        self.dash_btn.configure(state="disabled")
        self.status_label.configure(text="● Idle", fg=MUTED)
        self._log("Server stopped.\n", "info")


def main():
    root = tk.Tk()
    ServerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
