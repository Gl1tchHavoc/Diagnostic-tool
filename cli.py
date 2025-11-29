import argparse
import sys
from utils.admin_check import require_admin
from core.orchestrator import run_full_scan

def main():
    # Sprawdź uprawnienia administratora (automatycznie próbuje uruchomić jako admin)
    if not require_admin(auto_restart=True):
        sys.exit(1)
    
    parser = argparse.ArgumentParser(description="Super Diagnostics Tool")
    parser.add_argument('--full', action='store_true', help='Run full scan')
    args = parser.parse_args()

    if args.full:
        run_full_scan()
    else:
        print("No option selected. Use --full to run full scan.")

if __name__ == "__main__":
    main()
