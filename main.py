import sys
import subprocess
from pathlib import Path
sys.stdout.reconfigure(encoding="utf-8")

MENU = [
    "Collect Running Processes",
    "Capture Network Connections",
    "Gather USB & Login Events",
    "Acquire Browser Artifacts",
    "Collect System Logs",
    "Generate PDF Investigation Report",
    
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

while True:
    show_menu()
    choice = input("Select an option: ").strip()

    if choice == "0":
        print("Exiting Sudarshan.")
        break
    elif choice == "1":
        print("Going For Processes.....")
        subprocess.run([sys.executable, str(Path(__file__).parent / "processes.py")])
        print("Done")
    elif choice == "2":
        print("Going For Networks.....")
        subprocess.run([sys.executable, str(Path(__file__).parent / "networks.py")])
        print("Done")        
    elif choice == "3":
        print("Going For USB Events.....")
        subprocess.run([sys.executable, str(Path(__file__).parent / "usb.py")])
        print("Done")
    elif choice == "4":
        print("Going For Browser Events.....")
        subprocess.run([sys.executable, str(Path(__file__).parent / "history.py")])
        print("Done") 
    elif choice == "5":
        print("Going For Logs Events.....")
        subprocess.run([sys.executable, str(Path(__file__).parent / "logs.py")])
        print("Done")      
    elif choice == "7":
        print("Going For Reporting.....")
        subprocess.run([sys.executable, str(Path(__file__).parent / "forensics.py")])
        print("Done")
    elif choice == "99":
        subprocess.run([sys.executable, str(Path(__file__).parent / "processes.py")])
        subprocess.run([sys.executable, str(Path(__file__).parent / "networks.py")])
        subprocess.run([sys.executable, str(Path(__file__).parent / "usb.py")])
        subprocess.run([sys.executable, str(Path(__file__).parent / "history.py")])
        subprocess.run([sys.executable, str(Path(__file__).parent / "logs.py")])        
        print("Going For Reporting.....")
        subprocess.run([sys.executable, str(Path(__file__).parent / "forensics.py")])
        print("Done")        

    if choice.isdigit() and 1 <= int(choice) <= len(MENU):
        input("Press Enter to return to the menu...")
    else:
        print("Invalid choice.")
