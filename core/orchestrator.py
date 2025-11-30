from collectors.collector_master import collect_all
from learning.updater import update_cases
from processors.analyzer import analyze_all
from report.generator import generate_report


def run_full_scan():
    """
    Uruchamia pełne skanowanie systemu używając nowych collectorów.
    """
    # Zbierz wszystkie dane
    collected_data = collect_all(save_raw=True, output_dir="output/raw")

    # Przetwórz i przeanalizuj
    analysis_report = analyze_all(collected_data)

    # Generuj raport (używa starego formatu dla kompatybilności)
    # Konwertuj nowy format na stary dla report generatora
    results = {
        'hardware': collected_data.get('collectors', {}).get('hardware', {}),
        'logs': collected_data.get('collectors', {}).get('system_logs', {}),
        'drivers': collected_data.get('collectors', {}).get('drivers', [])
    }

    generate_report(results)
    update_cases(results)

    print("Full scan completed. Report generated.")
