import os
import sys
import time
import tkinter as tk

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

import agent_status  # noqa: E402

BG = "#0f1115"
PANEL = "#1a1d23"
FG = "#e6e6e6"
ACCENT = "#ffb703"
MUTED = "#9aa0a6"
GREEN = "#4caf50"
RED = "#e05252"

HEARTBEAT_STALE_AFTER = 30  


def _age(ts):
    return None if not ts else time.time() - ts


def _fmt_ago(seconds):
    if seconds is None:
        return "never"
    if seconds < 60:
        return f"{int(seconds)}s ago"
    if seconds < 3600:
        return f"{int(seconds // 60)}m ago"
    return f"{int(seconds // 3600)}h ago"


class AgentGUI:
    def __init__(self, root):
        self.root = root
        root.title("Sudarshan EDR - Agent")
        root.geometry("480x420")
        root.configure(bg=BG)
        root.resizable(False, False)


        tk.Label(root, text="Sudarshan EDR Agent", bg=BG, fg=ACCENT,
                 font=("Segoe UI", 15, "bold")).pack(anchor="w", padx=16, pady=(16, 0))
        tk.Label(
            root,
            text="Status only. Closing this window does NOT stop the agent - "
                 "reopen it any time to check again.",
            bg=BG, fg=MUTED, font=("Segoe UI", 9), wraplength=440, justify="left",
        ).pack(anchor="w", padx=16, pady=(2, 12))

        rows_frame = tk.Frame(root, bg=PANEL)
        rows_frame.pack(fill="both", expand=True, padx=16, pady=(0, 8))

        self.labels = {}
        for key, title in [
            ("agent_id", "Agent ID"),
            ("server", "Server"),
            ("connection", "Connection"),
            ("collection", "Collection"),
            ("last_cycle", "Last cycle"),
        ]:
            row = tk.Frame(rows_frame, bg=PANEL)
            row.pack(fill="x", padx=12, pady=8)
            tk.Label(row, text=title, bg=PANEL, fg=MUTED, font=("Segoe UI", 9)).pack(anchor="w")
            val = tk.Label(row, text="-", bg=PANEL, fg=FG, font=("Segoe UI", 11, "bold"),
                            wraplength=420, justify="left")
            val.pack(anchor="w")
            self.labels[key] = val

        tk.Label(
            root,
            text="To stop the agent: use the EDR dashboard's Stop/Terminate\n"
                 "controls, or an administrator/root session on this machine.",
            bg=BG, fg=MUTED, font=("Segoe UI", 9), justify="left",
        ).pack(anchor="w", padx=16, pady=(4, 16))

        self._refresh()

    def _refresh(self):
        status = agent_status.read_status()
        if not status:
            self.labels["agent_id"].configure(text="Waiting for the agent to report status...")
            self.labels["server"].configure(text="-")
            self.labels["connection"].configure(text="Unknown", fg=MUTED)
            self.labels["collection"].configure(text="-")
            self.labels["last_cycle"].configure(text="-")
        else:
            self.labels["agent_id"].configure(text=status.get("agent_id") or "-")
            self.labels["server"].configure(text=status.get("server") or "-")

            hb_age = _age(status.get("last_heartbeat_at"))
            if hb_age is not None and hb_age <= HEARTBEAT_STALE_AFTER:
                self.labels["connection"].configure(text=f"Connected ({_fmt_ago(hb_age)})", fg=GREEN)
            else:
                self.labels["connection"].configure(
                    text=f"Not responding (last seen {_fmt_ago(hb_age)})", fg=RED)

            if status.get("terminate"):
                self.labels["collection"].configure(
                    text="Shutting down (dashboard Terminate command)", fg=RED)
            elif status.get("running"):
                interval = status.get("interval")
                text = f"Running - every {interval}s" if interval else "Running"
                self.labels["collection"].configure(text=text, fg=GREEN)
            elif status.get("running") is False:
                self.labels["collection"].configure(text="Stopped (dashboard)", fg=MUTED)
            else:
                self.labels["collection"].configure(text=status.get("state", "-"), fg=MUTED)

            last_cycle_at = status.get("last_cycle_at")
            if last_cycle_at:
                ok = status.get("last_cycle_ok", True)
                self.labels["last_cycle"].configure(
                    text=f"{_fmt_ago(_age(last_cycle_at))} - {'OK' if ok else 'had errors'}",
                    fg=(FG if ok else RED),
                )
            else:
                self.labels["last_cycle"].configure(text="No cycle yet", fg=MUTED)

        self.root.after(2000, self._refresh)


def main():
    root = tk.Tk()
    AgentGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
