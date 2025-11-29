from modules import hardware, logs, drivers
from report.generator import generate_report
from learning.updater import update_cases

def run_full_scan():
    results = {}
    results['hardware'] = hardware.scan()
    results['logs'] = logs.scan()
    results['drivers'] = drivers.scan()

    generate_report(results)
    update_cases(results)

    print("Full scan completed. Report generated.")
