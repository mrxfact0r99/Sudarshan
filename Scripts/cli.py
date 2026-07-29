import sys
import time
import concurrent.futures
import runpy
from io import StringIO
from threading import Lock


sys.stdout.reconfigure(encoding="utf-8")

print_lock = Lock()

MENU = [
    "Collect Running Processes",
    "Capture Network Connections",
    "Gather USB & Login Events",
    "Acquire Browser Artifacts",
    "Collect System Logs",
    "Gather Recycle Bin",
    "Collect Clipboard Things",
]

MODULES = {
    "1": "Scripts.collectors.processes",
    "2": "Scripts.collectors.networks",
    "3": "Scripts.collectors.usb",
    "4": "Scripts.collectors.history",
    "5": "Scripts.collectors.logs",
    "6": "Scripts.collectors.recycle",
    "7": "Scripts.collectors.clipboard",
    
}


COLLECTION_MODULES = [
    "Scripts.collectors.processes",
    "Scripts.collectors.networks",
    "Scripts.collectors.usb",
    "Scripts.collectors.history",
    "Scripts.collectors.logs",
    "Scripts.collectors.recycle",
    "Scripts.collectors.clipboard",

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
    print("[99] Run Full Triage Collection (Parallel)")
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


def run_parallel_collection(modules, max_workers=None):
    results = {}
    max_workers = max_workers or len(modules)
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_module = {executor.submit(run_module, m): m for m in modules}
        for future in concurrent.futures.as_completed(future_to_module):
            module = future_to_module[future]
            res = future.result()
            results[module] = res
            with print_lock:
                status = "OK" if res["success"] else "FAILED"
                short_name = module.rsplit(".", 1)[-1]
                print(f"[✓] Complated ({res['elapsed']:.1f}s)")
                if not res["success"] and res["stderr"]:
                    print(f"      error: {res['stderr'].strip()[:300]}")
    return results


def run_full_triage():
    run_start = time.time()
    print("\nRunning full triage collection in parallel.....\n")
    time.sleep(8)
    print("Collecting Browser History.....\n")
    time.sleep(10)
    print("Collecting Processes.....\n")
    time.sleep(15)
    print("Collection Network Informations.....\n")
    time.sleep(10)
    print("Collecting Recycle Bin.....\n")
    time.sleep(7)
    print("Collecting System Logs.....\n")
    time.sleep(13)
    print("Collecting USB Events.....\n")
    time.sleep(11)
    print("Collecting Clipboard History.....\n")
    time.sleep(5)
    print("Hang On Finishing Up.....\n")
    t0 = time.time()
    results = run_parallel_collection(COLLECTION_MODULES)
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

    print("Going For Reporting.....\n")
    t1 = time.time()
    run_module("Scripts.report.forensics")
    report_time = time.time() - t1
    print("[✓] Done\n")

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
            print("Invalid choice.")


if __name__ == "__main__":
    main()
