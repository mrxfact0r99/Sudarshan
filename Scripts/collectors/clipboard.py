import os
import json
import platform
import subprocess
from pathlib import Path
from datetime import datetime


def detect_os():
    system = platform.system()
    if system == "Windows":
        return "Windows"
    elif system == "Linux":
        return "Linux"
    elif system == "Darwin":
        return "macOS"
    return f"Unknown ({system})"


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

    payload = {
        "generated_at": datetime.now().isoformat(),
        "detected_os": os_name,
        "hostname": platform.node(),
        "read_method": source,
        "clipboard_content": content,
        "content_length_chars": len(content) if content else 0,
        "error": error if content is None else None,
    }

    fname = save_evidence(payload, os_name)

    if content is not None:
        preview = content if len(content) <= 100 else content[:100] + "..."
        print(f"[*] Captured {len(content)} characters.")
        print(f"[*] Preview: {preview!r}")
    else:
        print(f"[i] Could not read clipboard: {error}")

    print(f"[+] Evidence saved to: {fname}")


if __name__ == "__main__":
    main()