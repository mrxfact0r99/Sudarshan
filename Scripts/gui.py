import os
import sys
import time
import queue
import shutil
import runpy
import threading
import tkinter as tk
from io import StringIO
from tkinter import ttk, messagebox, filedialog

sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

COLLECTORS = [
    ("processes", "Scripts.collectors.processes", "Running Processes"),
    ("networks", "Scripts.collectors.networks", "Network Connections"),
    ("usb", "Scripts.collectors.usb", "USB & Login Events"),
    ("history", "Scripts.collectors.history", "Browser Artifacts"),
    ("logs", "Scripts.collectors.logs", "System Logs"),
    ("recycle", "Scripts.collectors.recycle", "Recycle Bin"),
    ("clipboard", "Scripts.collectors.clipboard", "Clipboard Contents"),
    ("commands", "Scripts.collectors.commands", "Command History"),
    ("execution", "Scripts.collectors.execution", "Executed Programs"),
]

REPORT_MODULE = "Scripts.report.report"


def clean_pycache(base="."):
    for root, dirs, _files in os.walk(base):
        if "__pycache__" in dirs:
            shutil.rmtree(os.path.join(root, "__pycache__"), ignore_errors=True)


def run_module_captured(module_name):
    start = time.time()
    captured = StringIO()
    old_stdout = sys.stdout
    try:
        sys.stdout = captured
        runpy.run_module(module_name, run_name="__main__")
        success, error_text = True, ""
    except SystemExit as e:
        success = (e.code is None or e.code == 0)
        error_text = "" if success else str(e.code)
    except Exception as e:  
        success = False
        error_text = str(e)
    finally:
        sys.stdout = old_stdout

    return {
        "module": module_name,
        "success": success,
        "elapsed": time.time() - start,
        "stdout": captured.getvalue(),
        "stderr": error_text,
    }


class CheckItem(tk.Frame):
    CHECKED = "\u2611"    
    UNCHECKED = "\u2610"  
    def __init__(self, parent, text, variable, bg, fg, accent, font=("TkDefaultFont", 10),
                 command=None, **kwargs):
        super().__init__(parent, bg=bg, **kwargs)
        self.var = variable
        self.accent = accent
        self.fg = fg
        self.command = command

        box_font = (font[0], 12) if isinstance(font, tuple) else font
        self.box_label = tk.Label(self, text=self._glyph(), bg=bg,
                                   fg=self._color(), font=box_font)
        self.box_label.pack(side="left", padx=(0, 6))

        self.text_label = tk.Label(self, text=text, bg=bg, fg=fg, font=font)
        self.text_label.pack(side="left")

        for widget in (self, self.box_label, self.text_label):
            widget.bind("<Button-1>", self._toggle)
            widget.configure(cursor="hand2")

    def _glyph(self):
        return self.CHECKED if self.var.get() else self.UNCHECKED

    def _color(self):
        return self.accent if self.var.get() else self.fg

    def _toggle(self, _event=None):
        self.var.set(not self.var.get())
        self.refresh()
        if self.command:
            self.command()

    def refresh(self):
        self.box_label.configure(text=self._glyph(), fg=self._color())


class SudarshanGUI(tk.Tk):
    BG = "#0f1117"
    PANEL = "#161923"
    ACCENT = "#e08a2c"
    ACCENT_DIM = "#8a5a1f"
    FG = "#e8e8ea"
    MUTED = "#8b8f9a"
    OK = "#3fbf6f"
    FAIL = "#e05252"

    CASE_NAME_PRESETS = ["Anonymous", "Custom..."]
    EXAMINER_PRESETS = ["Anonymous", "Custom..."]

    def __init__(self):
        super().__init__()
        self.title("Sudarshan - Rapid Digital Evidence Triage Toolkit")
        self.geometry("980x680")
        self._maximize()
        self.minsize(860, 600)
        self.configure(bg=self.BG)
        self.UI_FONT, self.MONO_FONT = self._pick_fonts()
        self.MONO = (self.MONO_FONT, 10)

        self.log_queue = queue.Queue()
        self.worker_running = False
        self.check_vars = {}

        self._build_style()
        self._build_layout()
        self.after(80, self._poll_queue)

    def _maximize(self):
        try:
            self.state("zoomed")
            return
        except tk.TclError:
            pass
        try:
            self.attributes("-zoomed", True)
            return
        except tk.TclError:
            pass
        try:
            self.geometry(f"{self.winfo_screenwidth()}x{self.winfo_screenheight()}+0+0")
        except tk.TclError:
            pass

    def _pick_fonts(self):
        import tkinter.font as tkfont
        available = set(tkfont.families())

        ui_candidates = ["Segoe UI", "Ubuntu", "Cantarell", "DejaVu Sans", "Helvetica", "Arial"]
        mono_candidates = ["Consolas", "Ubuntu Mono", "DejaVu Sans Mono", "Menlo", "Courier New"]

        ui_font = next((f for f in ui_candidates if f in available), "TkDefaultFont")
        mono_font = next((f for f in mono_candidates if f in available), "TkFixedFont")
        return ui_font, mono_font

    def _build_style(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        style.configure("TFrame", background=self.BG)
        style.configure("Panel.TFrame", background=self.PANEL)
        style.configure("TLabel", background=self.BG, foreground=self.FG,
                         font=(self.UI_FONT, 10))
        style.configure("Panel.TLabel", background=self.PANEL, foreground=self.FG,
                         font=(self.UI_FONT, 10))
        style.configure("Title.TLabel", background=self.BG, foreground=self.ACCENT,
                         font=(self.UI_FONT, 18, "bold"))
        style.configure("Subtitle.TLabel", background=self.BG, foreground=self.MUTED,
                         font=(self.UI_FONT, 10))
        style.configure("Section.TLabel", background=self.PANEL, foreground=self.ACCENT,
                         font=(self.UI_FONT, 11, "bold"))
        style.configure("TCheckbutton", background=self.PANEL, foreground=self.FG,
                         font=(self.UI_FONT, 10))
        style.map("TCheckbutton",
                  background=[("active", self.PANEL)],
                  foreground=[("disabled", self.MUTED)])
        style.configure("Accent.TButton", font=(self.UI_FONT, 10, "bold"),
                         padding=8)
        style.configure("TButton", font=(self.UI_FONT, 10), padding=6)
        style.configure("TProgressbar", troughcolor=self.PANEL,
                         background=self.ACCENT, thickness=10)

    def _build_layout(self):
        header = ttk.Frame(self, style="TFrame")
        header.pack(fill="x", padx=20, pady=(18, 10))
        ttk.Label(header, text="SUDARSHAN", style="Title.TLabel").pack(anchor="w")
        ttk.Label(header, text="Rapid Digital Evidence Triage Toolkit - GUI Mode",
                  style="Subtitle.TLabel").pack(anchor="w")

        body = ttk.Frame(self, style="TFrame")
        body.pack(fill="both", expand=True, padx=20, pady=(0, 10))
        body.columnconfigure(0, weight=0)
        body.columnconfigure(1, weight=1)
        body.rowconfigure(0, weight=1)

        left_container = ttk.Frame(body, style="Panel.TFrame")
        left_container.grid(row=0, column=0, sticky="nsw", padx=(0, 14))
        left_container.configure(width=300)
        left_container.grid_propagate(False)

        left_canvas = tk.Canvas(left_container, bg=self.PANEL, highlightthickness=0,
                                 width=300)
        left_scroll = ttk.Scrollbar(left_container, orient="vertical",
                                     command=left_canvas.yview)
        left_canvas.configure(yscrollcommand=left_scroll.set)
        left_canvas.pack(side="left", fill="both", expand=True)
        left_scroll.pack(side="right", fill="y")

        left = ttk.Frame(left_canvas, style="Panel.TFrame")
        left_window = left_canvas.create_window((0, 0), window=left, anchor="nw")

        def _on_left_configure(_event=None):
            left_canvas.configure(scrollregion=left_canvas.bbox("all"))
        left.bind("<Configure>", _on_left_configure)

        def _on_canvas_configure(event):
            left_canvas.itemconfig(left_window, width=event.width)
        left_canvas.bind("<Configure>", _on_canvas_configure)

        def _on_mousewheel(event):
            left_canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

        def _bind_wheel(_event=None):
            left_canvas.bind_all("<MouseWheel>", _on_mousewheel)
            left_canvas.bind_all("<Button-4>", lambda e: left_canvas.yview_scroll(-1, "units"))
            left_canvas.bind_all("<Button-5>", lambda e: left_canvas.yview_scroll(1, "units"))

        def _unbind_wheel(_event=None):
            left_canvas.unbind_all("<MouseWheel>")
            left_canvas.unbind_all("<Button-4>")
            left_canvas.unbind_all("<Button-5>")

        left_canvas.bind("<Enter>", _bind_wheel)
        left_canvas.bind("<Leave>", _unbind_wheel)

        pad = {"padx": 16, "pady": (14, 4)}

        ttk.Label(left, text="🗂  CASE DETAILS", style="Section.TLabel").pack(anchor="w", **pad)

        ttk.Label(left, text="Case No:", style="Panel.TLabel").pack(anchor="w", padx=16)
        self.case_name_choice = tk.StringVar(value=self.CASE_NAME_PRESETS[0])
        case_combo = ttk.Combobox(left, textvariable=self.case_name_choice,
                                   values=self.CASE_NAME_PRESETS, state="readonly")
        case_combo.pack(fill="x", padx=16, pady=(2, 4))
        self.case_name_entry_var = tk.StringVar(value="")
        self.case_name_entry = ttk.Entry(left, textvariable=self.case_name_entry_var,
                                          state="disabled")
        self.case_name_entry.pack(fill="x", padx=16, pady=(0, 1))
        ttk.Label(left, text="e.g. CR-2026-001", style="Panel.TLabel",
                  foreground=self.MUTED, font=(self.UI_FONT, 8)).pack(anchor="w", padx=17, pady=(0, 7))
        case_combo.bind("<<ComboboxSelected>>",
                         lambda e: self._toggle_custom_entry(self.case_name_choice,
                                                              self.case_name_entry))

        ttk.Label(left, text="Examiner Name:", style="Panel.TLabel").pack(anchor="w", padx=16)
        self.examiner_choice = tk.StringVar(value=self.EXAMINER_PRESETS[0])
        examiner_combo = ttk.Combobox(left, textvariable=self.examiner_choice,
                                       values=self.EXAMINER_PRESETS, state="readonly")
        examiner_combo.pack(fill="x", padx=16, pady=(2, 4))
        self.examiner_entry_var = tk.StringVar(value="")
        self.examiner_entry = ttk.Entry(left, textvariable=self.examiner_entry_var,
                                         state="disabled")
        self.examiner_entry.pack(fill="x", padx=16, pady=(0, 1))
        ttk.Label(left, text="e.g. Utsavpari Gosai", style="Panel.TLabel",
                  foreground=self.MUTED, font=(self.UI_FONT, 8)).pack(anchor="w", padx=17, pady=(0, 7))
        examiner_combo.bind("<<ComboboxSelected>>",
                             lambda e: self._toggle_custom_entry(self.examiner_choice,
                                                                  self.examiner_entry))

        ttk.Separator(left, orient="horizontal").pack(fill="x", padx=16, pady=(4, 10))

        ttk.Label(left, text="🧩  COLLECTION MODULES", style="Section.TLabel").pack(anchor="w", **pad)

        self.check_widgets = {}
        for key, module, label in COLLECTORS:
            var = tk.BooleanVar(value=False)
            self.check_vars[key] = var
            item = CheckItem(left, text=label, variable=var,
                              bg=self.PANEL, fg=self.FG, accent=self.ACCENT,
                              font=(self.UI_FONT, 10))
            item.pack(anchor="w", padx=16, pady=3, fill="x")
            self.check_widgets[key] = item

        sel_row = ttk.Frame(left, style="Panel.TFrame")
        sel_row.pack(anchor="w", padx=16, pady=(10, 4))
        ttk.Button(sel_row, text="Select All", command=self._select_all).pack(side="left", padx=(0, 6))
        ttk.Button(sel_row, text="Select None", command=self._select_none).pack(side="left")

        ttk.Separator(left, orient="horizontal").pack(fill="x", padx=16, pady=14)

        self.run_selected_btn = ttk.Button(
            left, text="▶  Run Selected Collectors",
            command=lambda: self._start_run(full=False))
        self.run_selected_btn.pack(fill="x", padx=16, pady=(4, 6))

        self.gen_report_btn = ttk.Button(
            left, text="📄  Generate Report", command=self._start_report_only)
        self.gen_report_btn.pack(fill="x", padx=16, pady=(0, 6))

        self.run_full_btn = ttk.Button(
            left, text="⚡ Run Full Triage + Report ⚡", style="Accent.TButton",
            command=lambda: self._start_run(full=True))
        self.run_full_btn.pack(fill="x", padx=16, pady=(0, 16))

        ttk.Separator(left, orient="horizontal").pack(fill="x", padx=16, pady=14)

        ttk.Label(left, text="📁  EVIDENCE FOLDER", style="Section.TLabel").pack(anchor="w", padx=16)
        self.evidence_dir_var = tk.StringVar(value=os.path.abspath("Evidences"))
        dir_row = ttk.Frame(left, style="Panel.TFrame")
        dir_row.pack(fill="x", padx=16, pady=(6, 4))
        ttk.Button(dir_row, text="Open Folder", command=self._open_evidence_folder).pack(side="left")
        ttk.Button(dir_row, text="Open Reports", command=self._open_report_folder).pack(side="left", padx=(6, 0))


        right = ttk.Frame(body, style="Panel.TFrame")
        right.grid(row=0, column=1, sticky="nsew")
        right.rowconfigure(2, weight=1)
        right.columnconfigure(0, weight=1)

        ttk.Label(right, text="ACTIVITY LOG", style="Section.TLabel").grid(
            row=0, column=0, sticky="w", padx=16, pady=(14, 4))

        self.status_var = tk.StringVar(value="Idle - select modules and run.")
        ttk.Label(right, textvariable=self.status_var, style="Panel.TLabel").grid(
            row=1, column=0, sticky="w", padx=16, pady=(0, 6))

        log_frame = tk.Frame(right, bg=self.PANEL)
        log_frame.grid(row=2, column=0, sticky="nsew", padx=16, pady=(0, 10))
        log_frame.rowconfigure(0, weight=1)
        log_frame.columnconfigure(0, weight=1)

        self.log_text = tk.Text(
            log_frame, bg="#0b0d13", fg=self.FG, insertbackground=self.FG,
            font=self.MONO, wrap="word", relief="flat", padx=10, pady=8)
        self.log_text.grid(row=0, column=0, sticky="nsew")
        scroll = ttk.Scrollbar(log_frame, command=self.log_text.yview)
        scroll.grid(row=0, column=1, sticky="ns")
        self.log_text.configure(yscrollcommand=scroll.set)

        self.log_text.tag_config("ok", foreground=self.OK)
        self.log_text.tag_config("fail", foreground=self.FAIL)
        self.log_text.tag_config("info", foreground=self.MUTED)
        self.log_text.tag_config("head", foreground=self.ACCENT, font=("Consolas", 10, "bold"))
        self.log_text.configure(state="disabled")

        progress_row = ttk.Frame(right, style="Panel.TFrame")
        progress_row.grid(row=3, column=0, sticky="ew", padx=16, pady=(0, 16))
        progress_row.columnconfigure(0, weight=1)

        self.progress = ttk.Progressbar(progress_row, mode="determinate", maximum=100)
        self.progress.grid(row=0, column=0, sticky="ew")

        self.progress_pct_var = tk.StringVar(value="0%")
        ttk.Label(progress_row, textvariable=self.progress_pct_var, style="Panel.TLabel",
                  width=5, anchor="e").grid(row=0, column=1, sticky="e", padx=(8, 0))

        footer = ttk.Frame(self, style="TFrame")
        footer.pack(fill="x", padx=20, pady=(0, 14))
        ttk.Label(footer, text="Cyber Crime Investigation Toolkit",
                  style="Subtitle.TLabel").pack(side="left")

    def _toggle_custom_entry(self, choice_var, entry_widget):
        if choice_var.get() == "Custom...":
            entry_widget.configure(state="normal")
            entry_widget.focus_set()
        else:
            entry_widget.configure(state="disabled")

    def _get_case_name(self):
        if self.case_name_choice.get() == "Custom...":
            return self.case_name_entry_var.get().strip() or "Anonymous"
        return self.case_name_choice.get()

    def _get_examiner(self):
        if self.examiner_choice.get() == "Custom...":
            return self.examiner_entry_var.get().strip() or "Anonymous"
        return self.examiner_choice.get()

    def _select_all(self):
        for key, v in self.check_vars.items():
            v.set(True)
            self.check_widgets[key].refresh()

    def _select_none(self):
        for key, v in self.check_vars.items():
            v.set(False)
            self.check_widgets[key].refresh()

    def _open_evidence_folder(self):
        self._open_path(os.path.abspath("Evidences"))

    def _open_report_folder(self):
        self._open_path(os.path.abspath("Report"))

    def _open_path(self, path):
        os.makedirs(path, exist_ok=True)
        try:
            if sys.platform.startswith("win"):
                os.startfile(path)  
            elif sys.platform == "darwin":
                os.system(f'open "{path}"')
            else:
                os.system(f'xdg-open "{path}" >/dev/null 2>&1 &')
        except Exception:
            messagebox.showinfo("Folder location", path)

    def _log(self, text, tag="info"):
        self.log_text.configure(state="normal")
        self.log_text.insert("end", text + "\n", tag)
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def _set_buttons_enabled(self, enabled):
        state = "normal" if enabled else "disabled"
        self.run_selected_btn.configure(state=state)
        self.run_full_btn.configure(state=state)
        self.gen_report_btn.configure(state=state)

    def _poll_queue(self):
        try:
            while True:
                kind, payload = self.log_queue.get_nowait()
                if kind == "log":
                    text, tag = payload
                    self._log(text, tag)
                elif kind == "status":
                    self.status_var.set(payload)
                elif kind == "progress":
                    self.progress["value"] = payload
                    self.progress_pct_var.set(f"{int(payload)}%")
                elif kind == "done":
                    self._set_buttons_enabled(True)
                    self.worker_running = False
        except queue.Empty:
            pass
        self.after(80, self._poll_queue)

    def _start_run(self, full: bool):
        if self.worker_running:
            return
        if full:
            selected = [m for _k, m, _l in COLLECTORS]
        else:
            selected = [m for k, m, _l in COLLECTORS if self.check_vars[k].get()]
        if not selected:
            messagebox.showwarning("Nothing selected", "Select at least one collector to run.")
            return

        self.worker_running = True
        self._set_buttons_enabled(False)
        self.progress["value"] = 0
        self.progress_pct_var.set("0%")
        thread = threading.Thread(
            target=self._worker_run, args=(selected, full), daemon=True)
        thread.start()

    def _start_report_only(self):
        if self.worker_running:
            return
        self.worker_running = True
        self._set_buttons_enabled(False)
        self.progress["value"] = 0
        self.progress_pct_var.set("0%")
        thread = threading.Thread(target=self._worker_report_only, daemon=True)
        thread.start()

    def _worker_run(self, modules, generate_report):
        os.environ["SUDARSHAN_CASE_NAME"] = self._get_case_name()
        os.environ["SUDARSHAN_EXAMINER"] = self._get_examiner()
        clean_pycache()
        total_steps = len(modules) + (1 if generate_report else 0)
        step = 0

        self.log_queue.put(("log", (f"\n{'='*54}", "head")))
        self.log_queue.put(("log", ("Starting collection...", "head")))
        self.log_queue.put(("log", (f"{'='*54}", "head")))

        failed = []
        for module in modules:
            label = next(l for _k, m, l in COLLECTORS if m == module)
            self.log_queue.put(("status", f"Running: {label}..."))
            self.log_queue.put(("log", (f"[*] {label} ...", "info")))

            res = run_module_captured(module)
            step += 1
            self.log_queue.put(("progress", int(step / total_steps * 100)))

            if res["success"]:
                self.log_queue.put(("log", (f"[✓] {label} done ({res['elapsed']:.1f}s)", "ok")))
                for line in res["stdout"].strip().splitlines():
                    self.log_queue.put(("log", (f"      {line}", "info")))
            else:
                failed.append(label)
                self.log_queue.put(("log", (f"[✗] {label} FAILED: {res['stderr']}", "fail")))

        if generate_report:
            self.log_queue.put(("status", "Generating report..."))
            self.log_queue.put(("log", ("[*] Generating consolidated PDF report ...", "info")))
            res = run_module_captured(REPORT_MODULE)
            step += 1
            self.log_queue.put(("progress", int(step / total_steps * 100)))
            if res["success"]:
                self.log_queue.put(("log", ("[✓] Report generated.", "ok")))
                for line in res["stdout"].strip().splitlines():
                    self.log_queue.put(("log", (f"      {line}", "info")))
                self.log_queue.put(("status", "Done — report ready in the Report folder."))
            else:
                self.log_queue.put(("log", (f"[✗] Report generation FAILED: {res['stderr']}", "fail")))
                self.log_queue.put(("status", "Finished with errors during report generation."))
        else:
            msg = "Collection complete." if not failed else f"Collection complete with {len(failed)} failure(s)."
            self.log_queue.put(("status", msg))

        self.log_queue.put(("progress", 100))
        clean_pycache()
        self.log_queue.put(("done", None))

    def _worker_report_only(self):
        os.environ["SUDARSHAN_CASE_NAME"] = self._get_case_name()
        os.environ["SUDARSHAN_EXAMINER"] = self._get_examiner()
        self.log_queue.put(("log", ("\n[*] Generating report from existing evidence ...", "info")))
        self.log_queue.put(("status", "Generating report..."))
        res = run_module_captured(REPORT_MODULE)
        self.log_queue.put(("progress", 100))
        if res["success"]:
            self.log_queue.put(("log", ("[✓] Report generated.", "ok")))
            for line in res["stdout"].strip().splitlines():
                self.log_queue.put(("log", (f"      {line}", "info")))
            self.log_queue.put(("status", "Done — report ready in the Report folder."))
        else:
            self.log_queue.put(("log", (f"[✗] Report generation FAILED: {res['stderr']}", "fail")))
            self.log_queue.put(("status", "Report generation failed."))
        self.log_queue.put(("done", None))


def main():
    app = SudarshanGUI()
    app.mainloop()


if __name__ == "__main__":
    main()