# Sudarshan - Rapid Digital Evidence Triage Toolkit
A lightweight, cross-platform (Windows / Linux, partial macOS) toolkit for
quickly collecting common live-triage digital forensics artifacts and
generating a single PDF investigation report from them.

## Running

**Command line (original menu-driven mode):**
```
python3 main.py
```

**Graphical interface:**
```
python3 main_gui.py
```
Requires Tkinter (bundled with most Python installs; on Debian/Ubuntu:
`sudo apt-get install python3-tk`).

The GUI lets you:
- Check/uncheck individual collectors (Processes, Network, USB & Login,
  Browser Artifacts, System Logs, Recycle Bin, Clipboard, Command History,
  Executed Programs)
- Run only the selected collectors, or run the full triage + report in one click
- Watch live progress and a scrolling activity log for each module
- Generate the PDF report on demand from previously collected evidence
- Jump straight to the `Evidences/` or `Report/` folders