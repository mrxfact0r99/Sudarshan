import time
import os
import shutil
import itertools
import threading
import runpy
from io import StringIO
import sys

# Stop Python from writing __pycache__ in the first place. This must happen
# before any of the collector modules get imported by runpy, so it's set
# right at the top before anything else runs.
sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"


def clean_pycache(base="."):
    """Actually remove any __pycache__ folders instead of just printing them."""
    for root, dirs, files in os.walk(base):
        if "__pycache__" in dirs:
            path = os.path.join(root, "__pycache__")
            shutil.rmtree(path, ignore_errors=True)
            print(f"Removed {path}")


clean_pycache()
sys.stdout.reconfigure(encoding="utf-8")

MENU = [
    "Collect Running Processes",
    "Capture Network Connections",
    "Gather USB & Login Events",
    "Acquire Browser Artifacts",
    "Collect System Logs",
    "Gather Recycle Bin",
    "Collect Clipboard Things",
    "Capture Command History",
    "Gather Executed Programs",
]

MODULES = {
    "1": "Scripts.collectors.processes",
    "2": "Scripts.collectors.networks",
    "3": "Scripts.collectors.usb",
    "4": "Scripts.collectors.history",
    "5": "Scripts.collectors.logs",
    "6": "Scripts.collectors.recycle",
    "7": "Scripts.collectors.clipboard",
    "8": "Scripts.collectors.commands",
    "9": "Scripts.collectors.execution"
    
}


COLLECTION_MODULES = [
    "Scripts.collectors.processes",
    "Scripts.collectors.networks",
    "Scripts.collectors.usb",
    "Scripts.collectors.history",
    "Scripts.collectors.logs",
    "Scripts.collectors.recycle",
    "Scripts.collectors.clipboard",
    "Scripts.collectors.commands",
    "Scripts.collectors.execution"

]

BANNER = r"""

                                 ✦ ✦ ✦ ☸ ✦ ✦ ✦


      ███████╗██╗   ██╗██████╗  █████╗ ██████╗ ███████╗██╗  ██╗ █████╗ ███╗   ██╗
      ██╔════╝██║   ██║██╔══██╗██╔══██╗██╔══██╗██╔════╝██║  ██║██╔══██╗████╗  ██║
      ███████╗██║   ██║██║  ██║███████║██████╔╝███████╗███████║███████║██╔██╗ ██║
      ╚════██║██║   ██║██║  ██║██╔══██║██╔══██╗╚════██║██╔══██║██╔══██║██║╚██╗██║
      ███████║╚██████╔╝██████╔╝██║  ██║██║  ██║███████║██║  ██║██║  ██║██║ ╚████║
      ╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝

                                 ✦ ✦ ✦ ☸ ✦ ✦ ✦


                         Rapid Digital Evidence Triage Toolkit
"""


def show_menu():
    print("\n" * 2)
    print(BANNER)
    print("=" * 60)
    for i, item in enumerate(MENU, start=1):
        print(f"[{i}] {item}")
    print("[99] Run Full Triage Collection")
    print("[0] Exit")
    print("=" * 60)

def run_module(module_name):
    start = time.time()
    captured = StringIO()
    old_stdout = sys.stdout
    try:
        sys.stdout = captured
        runpy.run_module(module_name, run_name="__main__")
        success = True
        error_text = ""
    except SystemExit as e:
        success = (e.code is None or e.code == 0)
        error_text = "" if success else str(e.code)
    except Exception as e:
        success = False
        error_text = str(e)
    finally:
        sys.stdout = old_stdout

    elapsed = time.time() - start
    return {
        "module": module_name,
        "success": success,
        "elapsed": elapsed,
        "stdout": captured.getvalue(),
        "stderr": error_text,
    }


SPINNER_FRAMES = ["[|]", "[/]", "[-]", "[\\]"]


def run_with_spinner(label, module_name):
    """Run a collector module in the background while animating a rotating
    spinner next to its label. The label only flips to a completed/failed
    state once the module has actually finished, never on a fixed delay."""
    box = {}

    def worker():
        box["result"] = run_module(module_name)

    t = threading.Thread(target=worker)
    t.start()

    spinner = itertools.cycle(SPINNER_FRAMES)
    while t.is_alive():
        frame = next(spinner)
        sys.__stdout__.write(f"\r{frame} {label}.....")
        sys.__stdout__.flush()
        time.sleep(0.12)
    t.join()

    res = box["result"]
    mark = "[✓]" if res["success"] else "[✗]"
    sys.__stdout__.write(f"\r{mark} {label}..... done ({res['elapsed']:.1f}s)\n")
    sys.__stdout__.flush()
    if not res["success"] and res["stderr"]:
        print(f"      error: {res['stderr'].strip()[:300]}")
    return res


MODULE_LABELS = {
    "Scripts.collectors.processes": "Collecting Processes",
    "Scripts.collectors.networks": "Collecting Network Information",
    "Scripts.collectors.usb": "Collecting USB Events",
    "Scripts.collectors.history": "Collecting Browser History",
    "Scripts.collectors.logs": "Collecting System Logs",
    "Scripts.collectors.recycle": "Collecting Recycle Bin",
    "Scripts.collectors.clipboard": "Collecting Clipboard History",
    "Scripts.collectors.commands": "Collecting Command History",
    "Scripts.collectors.execution": "Collecting Executed Programs",
}


def run_full_triage():
    run_start = time.time()
    print("\nRunning full triage collection.....\n")

    t0 = time.time()
    results = {}
    for module in COLLECTION_MODULES:
        label = MODULE_LABELS.get(module, module.rsplit(".", 1)[-1])
        results[module] = run_with_spinner(label, module)
    collection_time = time.time() - t0
    print(f"\nCollection phase complete in {collection_time:.1f}s\n")

    failed = [m for m, r in results.items() if not r["success"]]
    if failed:
        names = ", ".join(m.rsplit(".", 1)[-1] for m in failed)
        print(f"Warning: {len(failed)} step(s) failed: {names}")
        proceed = input("Continue to report generation anyway? (y/n): ").strip().lower()
        if proceed != "y":
            print("Aborting report generation.")
            total = time.time() - run_start
            print(f"\nTotal time: {total:.1f}s\n")
            return

    t1 = time.time()
    report_res = run_with_spinner("Generating Report", "Scripts.report.forensics")
    report_time = time.time() - t1

    total = time.time() - run_start
    print("=" * 60)
    print(f"Collection phase : {collection_time:.1f}s")
    print(f"Report phase     : {report_time:.1f}s")
    print(f"TOTAL TIME       : {total:.1f}s")
    print("=" * 60)

def run_single(choice):
    module_name = MODULES[choice]
    label = MENU[int(choice) - 1]
    print(f"\nGoing For {label}.....\n")
    runpy.run_module(module_name, run_name="__main__")
    print("\nDone\n")


def main():
    while True:
        show_menu()
        choice = input("Select an option: ").strip()

        if choice == "0":
            print("\nExiting Sudarshan.....\n")
            break
        elif choice in MODULES:
            try:
                run_single(choice)
            except SystemExit:
                pass
            input("Press Enter to return to the menu...")
        elif choice == "99":
            run_full_triage()
            input("Press Enter to return to the menu...")
        else:
            print("\nInvalid choice.\n")
            time.sleep(1)

clean_pycache()

if __name__ == "__main__":
    main()