import argparse
from core.orchestrator import run_full_scan

def main():
    parser = argparse.ArgumentParser(description="Super Diagnostics Tool")
    parser.add_argument('--full', action='store_true', help='Run full scan')
    args = parser.parse_args()

    if args.full:
        run_full_scan()
    else:
        print("No option selected. Use --full to run full scan.")

if __name__ == "__main__":
    main()
