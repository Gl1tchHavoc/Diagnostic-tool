from modules import hardware, logs, drivers
from report.generator import generate_report
from learning.updater import update_cases

def run_full_scan():
    results = {}

    # 1. Hardware
    results['hardware'] = hardware.scan()

    # 2. Logs
    results['logs'] = logs.scan()

    # 3. Drivers
    results['drivers'] = drivers.scan()

    # 4. Generowanie raportu i zapis przypadków
    generate_report(results)
    update_cases(results)

    print("Full scan completed. Report generated.")
