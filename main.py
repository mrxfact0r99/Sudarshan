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
    "Gather Recycle Bin",
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
        print("\nExiting Sudarshan.....\n")
        break
    elif choice == "1":
        print("\nGoing For Processes.....\n")
        subprocess.run([sys.executable, str(Path(__file__).parent / "processes.py")])
        print("\nDone\n")
    elif choice == "2":
        print("\nGoing For Networks.....\n")
        subprocess.run([sys.executable, str(Path(__file__).parent / "networks.py")])
        print("\nDone\n")        
    elif choice == "3":
        print("\nGoing For USB Events.....\n")
        subprocess.run([sys.executable, str(Path(__file__).parent / "usb.py")])
        print("\nDone\n")
    elif choice == "4":
        print("\nGoing For Browser Events.....\n")
        subprocess.run([sys.executable, str(Path(__file__).parent / "history.py")])
        print("\nDone\n") 
    elif choice == "5":
        print("\nGoing For Logs Events.....\n")
        subprocess.run([sys.executable, str(Path(__file__).parent / "logs.py")])
        print("\nDone\n")      
    elif choice == "6":
        print("\nGoing For Recycle Bin.....\n")
        subprocess.run([sys.executable, str(Path(__file__).parent / "recycle.py")])
        print("\nDone\n")
    elif choice == "7":
        print("\nGoing For Reporting.....\n")
        subprocess.run([sys.executable, str(Path(__file__).parent / "forensics.py")])
        print("\nDone\n")
    elif choice == "99":
        subprocess.run([sys.executable, str(Path(__file__).parent / "processes.py")])
        subprocess.run([sys.executable, str(Path(__file__).parent / "networks.py")])
        subprocess.run([sys.executable, str(Path(__file__).parent / "usb.py")])
        subprocess.run([sys.executable, str(Path(__file__).parent / "history.py")])
        subprocess.run([sys.executable, str(Path(__file__).parent / "logs.py")]) 
        subprocess.run([sys.executable, str(Path(__file__).parent / "recycle.py")])                       
        print("\nGoing For Reporting.....")
        subprocess.run([sys.executable, str(Path(__file__).parent / "forensics.py")])
        print("\nDone")        

    if choice.isdigit() and 1 <= int(choice) <= len(MENU):
        input("Press Enter to return to the menu...")
    elif choice == "99":
        pass
    else:
        print("Invalid choice.")
