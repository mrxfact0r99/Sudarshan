import os
import platform

EVIDENCE_DIR = "Evidences"


def detect_os():
    """Return a clean, human-readable OS name: Windows / Linux / macOS /
    Unknown (<raw platform.system() value>)."""
    system = platform.system()
    if system == "Windows":
        return "Windows"
    elif system == "Linux":
        return "Linux"
    elif system == "Darwin":
        return "macOS"
    return f"Unknown ({system})"


def ensure_evidence_dir(evidence_dir=EVIDENCE_DIR):
    """Create the evidence directory if it doesn't exist yet and return
    its path, so callers can do `path = ensure_evidence_dir()`."""
    os.makedirs(evidence_dir, exist_ok=True)
    return evidence_dir


def evidence_path(filename, evidence_dir=EVIDENCE_DIR):
    """Convenience: ensure the evidence dir exists and return the full
    path to `filename` inside it."""
    ensure_evidence_dir(evidence_dir)
    return os.path.join(evidence_dir, filename)
