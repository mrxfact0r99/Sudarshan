# Sudarshan - Rapid Digital Evidence Triage Toolkit
A lightweight, cross-platform (Windows / Linux) toolkit for
quickly collecting common live-triage digital forensics artifacts and
generating a PDF investigation report from them.

## Installation Process
```
git clone https://github.com/mrxfact0r99/Sudarshan.git
```
OR

Download the zip file https://github.com/mrxfact0r99/Sudarshan.git and extract and open in terminal 

``` 
cd Sudarshan
```

```
pip3 install -r requirements.txt
```

## Run

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

## Testing & Verification

The full pipeline (all 9 collectors → PDF report, via both `main.py`'s
"Run Full Triage" option and by running the collector/report modules
directly) was exercised end-to-end on Linux, including a real trash
deletion → recovery → report cycle. All 11 PDF report parts were
generated and verified to open and extract text correctly. Every
module degrades gracefully (prints a clear note instead of crashing)
when a data source isn't available on the host - e.g. no browser
profile, no journalctl, no admin/root privileges, no removable drive
plugged in.

Windows-specific code paths (registry reads, PowerShell/Get-WinEvent
calls, NTFS `$Recycle.Bin`/USN Journal parsing, `winreg`-based
artifacts) were reviewed for correctness but could not be executed in
this Linux-only environment - test them on a Windows machine before
relying on them for a real investigation, particularly the
Administrator-only USB read/write audit feature.

## Changelog

- **Added:** deleted browser history recovery. When a URL row is deleted
  from Chrome/Edge/Brave/Firefox's SQLite history database, SQLite does
  not zero out the bytes by default - the collector now scans each
  history file's raw bytes for URL-shaped text that isn't among the
  live rows, recovering likely-deleted entries. Verified against real
  SQLite databases (both a normal delete and one with `secure_delete`
  explicitly off, matching real Chrome/Firefox behavior) - correctly
  recovers the deleted URL while filtering out false positives caused
  by SQLite's lack of a delimiter between adjacent text columns. Shown
  in the PDF report under "7.4 Recovered Deleted URLs", with counts
  rolled into the Executive Summary.
- **Fixed:** the PDF report's Recycle Bin section only looked for the
  Windows JSON field name for a deleted item's original path, so on
  Linux/macOS every Trash item showed up as "(unknown)" and never
  matched the suspicious/sensitive file-extension risk checks, even
  though the collector had already captured the real path. It now
  reads both the Windows and Linux/macOS field names.
- **Added:** a new "Recovered File Copies" subsection in the Recycle
  Bin report page that lists every deleted item whose data was still
  on disk and was copied into `Evidences/recover/` at collection
  time, together with the SHA-256 hash of that recovered copy - so
  the chain of custody for recovered files is visible in the PDF
  itself, not just in the raw JSON.
- **Cleaned up:** the clipboard collector had its own private copy of
  the OS-detection function instead of using the shared one in
  `common.py` like every other collector; it now imports the shared
  version.