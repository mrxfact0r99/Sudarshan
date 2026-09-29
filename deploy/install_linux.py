import argparse
import os
import platform
import sys

if platform.system() == "Windows":
    print("This installer is Linux-only. On Windows, use (elevated prompt):")
    print("  python deploy\\install_windows.py --server ... --token ...")
    sys.exit(1)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import install_agent as shared  


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--server", required=True, help="EDR server URL, e.g. http://192.168.1.50:8443")
    parser.add_argument("--token", required=True, help="Enrollment token given to you by the server owner")
    args = parser.parse_args()

    if not shared._is_root_linux():
        print("! Please re-run this with sudo:")
        print(f"    sudo python3 deploy/install_linux.py --server {args.server} --token {args.token}")
        sys.exit(1)

    shared.write_instance_config(args.server, args.token)
    shared.install_linux()


if __name__ == "__main__":
    main()
