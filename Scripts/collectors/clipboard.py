import os
import re
import sys
import json
import platform
import subprocess
from pathlib import Path
from datetime import datetime

try:
    from ..common import detect_os
except ImportError:
    # Allows this file to still be run standalone (python clipboard.py)
    # instead of only as part of the Scripts.collectors package, matching
    # the fallback already used by commands.py and execution.py.
    sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
    from common import detect_os


def save_evidence(payload, os_name):
    project_root = Path(__file__).resolve().parent.parent.parent
    evidence_dir = project_root / "Evidences"
    evidence_dir.mkdir(exist_ok=True)

    file_path = evidence_dir / "clipboard_snapshot.json"

    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False, default=str)

    return str(file_path)


def read_via_pyperclip():
    try:
        import pyperclip
        return pyperclip.paste(), None
    except ImportError:
        return None, "pyperclip not installed"
    except Exception as e:
        return None, str(e)


def read_windows_clipboard_history():
    """
    Reads Windows' built-in Clipboard History (Win+V) via the
    Windows.ApplicationModel.DataTransfer.Clipboard WinRT API.

    This only returns items if the user has turned the feature on
    (Settings > System > Clipboard > Clipboard history) - it cannot
    recover items copied before that setting was enabled, and it
    cannot see items on other devices unless "Sync across devices"
    is also on. Requires the 'winsdk' package (pip install winsdk).

    Returns (items, source, error) where items is a list of dicts:
        {"index": int, "content": str, "content_length_chars": int}
    ordered most-recent-first, or (None, None, "<reason>") on failure.
    """
    try:
        import asyncio
        from winsdk.windows.applicationmodel.datatransfer import (
            Clipboard,
            ClipboardHistoryItemsResultStatus,
            StandardDataFormats,
        )
    except ImportError:
        return None, None, (
            "winsdk not installed - run 'pip install winsdk' to enable "
            "Clipboard History reads on Windows."
        )

    async def _fetch():
        result = await Clipboard.get_history_items_async()

        if result.status == ClipboardHistoryItemsResultStatus.ACCESS_DENIED:
            return None, "Access to Clipboard History was denied (policy or permission)."
        if result.status == ClipboardHistoryItemsResultStatus.CLIPBOARD_HISTORY_DISABLED:
            return None, "Clipboard History is turned off (Settings > System > Clipboard)."
        if result.status != ClipboardHistoryItemsResultStatus.SUCCESS:
            return None, f"Clipboard History returned status: {result.status!r}"

        items = []
        for i, hist_item in enumerate(result.items):
            content_view = hist_item.content
            try:
                if content_view.contains(StandardDataFormats.text):
                    text = await content_view.get_text_async()
                    text = str(text)
                    items.append({
                        "index": i,
                        "content": text,
                        "content_length_chars": len(text),
                    })
                else:
                    items.append({
                        "index": i,
                        "content": None,
                        "content_length_chars": 0,
                        "note": "Non-text clipboard history item (image/file/etc.), not captured.",
                    })
            except Exception as item_err:
                items.append({
                    "index": i,
                    "content": None,
                    "content_length_chars": 0,
                    "note": f"Could not read this history item: {item_err}",
                })
        return items, None

    try:
        items, err = asyncio.run(_fetch())
    except Exception as e:
        return None, None, str(e)

    if err:
        return None, None, err
    return items, "windows_clipboard_history_api", None


def read_linux_gpaste_history():
    """
    Reads clipboard history from GPaste (the GNOME clipboard manager),
    via its 'gpaste-client' CLI. Only returns items if GPaste is installed
    and its daemon has been tracking history on this system - it cannot
    recover items copied before the daemon started, and has no visibility
    into items on other machines.

    Returns (items, error) where items is a list of dicts:
        {"index": int, "content": str, "content_length_chars": int}
    ordered most-recent-first, or (None, "<reason>") on failure.
    """
    try:
        result = subprocess.run(
            ["gpaste-client", "history"],
            capture_output=True, text=True, timeout=10,
        )
    except FileNotFoundError:
        return None, "gpaste-client not installed (GPaste is not present on this system)."
    except Exception as e:
        return None, str(e)

    if result.returncode != 0:
        return None, (result.stderr.strip() or "gpaste-client history failed.")

    # Each history entry starts with a line like "0. some text" - any
    # following lines that don't match that pattern are continuation
    # lines of the same (multi-line) clipboard entry.
    entry_start = re.compile(r"^(\d+)\.\s?(.*)$")
    items = []
    current = None
    for line in result.stdout.splitlines():
        m = entry_start.match(line)
        if m:
            if current is not None:
                items.append(current)
            idx = int(m.group(1))
            current = {"index": idx, "content": m.group(2)}
        elif current is not None:
            current["content"] += "\n" + line
    if current is not None:
        items.append(current)

    if not items:
        return None, "GPaste history is empty."

    for item in items:
        item["content_length_chars"] = len(item["content"])

    return items, None


def read_linux_copyq_history(max_items=50):
    """
    Reads clipboard history from CopyQ, via its 'copyq' CLI. Only returns
    items if CopyQ is installed and running with its default tab populated -
    capped at max_items to avoid a very long history making the collector
    slow. Returns (items, error), same shape as read_linux_gpaste_history().
    """
    try:
        size_result = subprocess.run(
            ["copyq", "size"], capture_output=True, text=True, timeout=10,
        )
    except FileNotFoundError:
        return None, "copyq not installed (CopyQ is not present on this system)."
    except Exception as e:
        return None, str(e)

    if size_result.returncode != 0:
        return None, (size_result.stderr.strip() or "copyq size failed (is the CopyQ server running?).")

    try:
        count = int(size_result.stdout.strip())
    except ValueError:
        return None, "Could not parse item count from 'copyq size'."

    if count == 0:
        return None, "CopyQ history is empty."

    items = []
    for i in range(min(count, max_items)):
        try:
            r = subprocess.run(
                ["copyq", "read", str(i)], capture_output=True, text=True, timeout=10,
            )
        except Exception as e:
            items.append({"index": i, "content": None, "content_length_chars": 0,
                          "note": f"Could not read this history item: {e}"})
            continue
        if r.returncode == 0:
            items.append({"index": i, "content": r.stdout, "content_length_chars": len(r.stdout)})
        else:
            items.append({"index": i, "content": None, "content_length_chars": 0,
                          "note": "Non-text or unreadable history item."})

    if count > max_items:
        items.append({"index": max_items, "content": None, "content_length_chars": 0,
                      "note": f"{count - max_items} additional older item(s) not captured (capped at {max_items})."})

    return items, None


def read_linux_clipboard_history():
    """Tries GPaste first, then CopyQ. Returns (items, source, error)."""
    items, err = read_linux_gpaste_history()
    if items is not None:
        return items, "gpaste_history_cli", None

    items, err2 = read_linux_copyq_history()
    if items is not None:
        return items, "copyq_history_cli", None

    return None, None, (
        "No clipboard-history-capable tool found or populated. Tried GPaste "
        f"({err}) and CopyQ ({err2}). Only the current clipboard snapshot "
        "could be captured for this run."
    )


def read_macos_clipboard_history():
    """
    macOS has no built-in, always-on clipboard history equivalent to
    Windows' Clipboard History or Linux's GPaste/CopyQ daemons - the
    system pasteboard only ever holds the single most recent item.
    Recovering prior items requires a specific third-party clipboard
    manager (e.g. Maccy, Clipy, Pastebot) to already be installed and
    running, and each stores its history in its own private, undocumented
    format, so there is no single reliable way to read it here.

    Returns (None, None, "<reason>") - always, by design.
    """
    return None, None, (
        "macOS does not provide a built-in clipboard history API - only the "
        "current pasteboard item can be captured. Recovering prior items "
        "would require a specific third-party clipboard manager already "
        "installed on this machine."
    )


def read_windows_native():
    try:
        import ctypes
        from ctypes import wintypes

        CF_UNICODETEXT = 13

        user32 = ctypes.windll.user32
        kernel32 = ctypes.windll.kernel32

        user32.OpenClipboard.argtypes = [wintypes.HWND]
        user32.OpenClipboard.restype = wintypes.BOOL

        user32.GetClipboardData.argtypes = [wintypes.UINT]
        user32.GetClipboardData.restype = wintypes.HANDLE

        user32.CloseClipboard.argtypes = []
        user32.CloseClipboard.restype = wintypes.BOOL

        kernel32.GlobalLock.argtypes = [wintypes.HGLOBAL]
        kernel32.GlobalLock.restype = ctypes.c_void_p

        kernel32.GlobalUnlock.argtypes = [wintypes.HGLOBAL]
        kernel32.GlobalUnlock.restype = wintypes.BOOL

        if not user32.OpenClipboard(None):
            return None, "Could not open clipboard (may be in use by another app)."

        try:
            handle = user32.GetClipboardData(CF_UNICODETEXT)
            if not handle:
                return None, "Clipboard is empty or does not contain text."

            pointer = kernel32.GlobalLock(handle)
            if not pointer:
                return None, "Could not lock clipboard memory."

            try:
                data = ctypes.wstring_at(pointer)
                return data, None
            finally:
                kernel32.GlobalUnlock(handle)

        finally:
            user32.CloseClipboard()

    except Exception as e:
        return None, str(e)


def read_linux_native():
    """Try xclip, then xsel, then wl-paste (Wayland)."""
    for cmd in (
        ["xclip", "-selection", "clipboard", "-o"],
        ["xsel", "--clipboard", "--output"],
        ["wl-paste"],
    ):
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                return result.stdout, None
        except FileNotFoundError:
            continue
        except Exception as e:
            return None, str(e)

    return None, (
        "No clipboard tool found. Install one: "
        "'sudo apt install xclip' (X11) or "
        "'sudo apt install wl-clipboard' (Wayland)."
    )


def read_macos_native():
    try:
        result = subprocess.run(
            ["pbpaste"],
            capture_output=True,
            text=True,
            timeout=10,
        )

        if result.returncode == 0:
            return result.stdout, None

        return None, result.stderr.strip() or "pbpaste failed."

    except FileNotFoundError:
        return None, "pbpaste not found (unexpected on macOS)."
    except Exception as e:
        return None, str(e)


def get_clipboard_content(os_name):
    content, err = read_via_pyperclip()

    if content is not None:
        return content, "pyperclip", None

    if os_name == "Windows":
        content, native_err = read_windows_native()
        source = "windows_ctypes"
    elif os_name == "Linux":
        content, native_err = read_linux_native()
        source = "linux_native_tool"
    elif os_name == "macOS":
        content, native_err = read_macos_native()
        source = "pbpaste"
    else:
        content, native_err = None, f"Unsupported OS: {os_name}"
        source = None

    return content, source, (native_err or err)


def main():
    os_name = detect_os()

    print(f"[*] Detected OS: {os_name}")
    print("[*] Reading current clipboard content (one-time snapshot)...")

    content, source, error = get_clipboard_content(os_name)

    history_items, history_source, history_error = None, None, None
    if os_name == "Windows":
        print("[*] Checking Windows Clipboard History (Win+V) for prior items...")
        history_items, history_source, history_error = read_windows_clipboard_history()
    elif os_name == "Linux":
        print("[*] Checking GPaste/CopyQ for clipboard history...")
        history_items, history_source, history_error = read_linux_clipboard_history()
    elif os_name == "macOS":
        history_items, history_source, history_error = read_macos_clipboard_history()

    payload = {
        "generated_at": datetime.now().isoformat(),
        "detected_os": os_name,
        "hostname": platform.node(),
        "read_method": source,
        "clipboard_content": content,
        "content_length_chars": len(content) if content else 0,
        "error": error if content is None else None,
        "clipboard_history": history_items,
        "clipboard_history_source": history_source,
        "clipboard_history_error": history_error,
    }

    fname = save_evidence(payload, os_name)

    if content is not None:
        preview = content if len(content) <= 100 else content[:100] + "..."
        print(f"[*] Captured {len(content)} characters (current clipboard).")
        print(f"[*] Preview: {preview!r}")
    else:
        print(f"[i] Could not read current clipboard: {error}")

    if history_items is not None:
        text_items = [h for h in history_items if h.get("content")]
        print(f"[*] Clipboard History: {len(text_items)} text item(s) recovered "
              f"(of {len(history_items)} total entries).")
    elif history_error:
        print(f"[i] Clipboard History not captured: {history_error}")

    print(f"[+] Evidence saved to: {fname}")


if __name__ == "__main__":
    main()