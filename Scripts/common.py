import os
import platform

EVIDENCE_DIR = "Evidences"


def detect_os():
    system = platform.system()
    if system == "Windows":
        return "Windows"
    elif system == "Linux":
        return "Linux"
    elif system == "Darwin":
        return "macOS"
    return f"Unknown ({system})"


def ensure_evidence_dir(evidence_dir=EVIDENCE_DIR):
    os.makedirs(evidence_dir, exist_ok=True)
    return evidence_dir


def evidence_path(filename, evidence_dir=EVIDENCE_DIR):
    ensure_evidence_dir(evidence_dir)
    return os.path.join(evidence_dir, filename)
