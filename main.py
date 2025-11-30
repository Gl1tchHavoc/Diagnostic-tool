"""
Główny plik diagnostyczny - uruchamia pełne skanowanie systemu.
"""
import json
import logging
import sys
from datetime import datetime
from pathlib import Path

from collectors.collector_master import collect_all
# Processors moved to archive/ - not needed in MVP
# from processors.analyzer import analyze_all
from utils.admin_check import require_admin
from utils.logger import get_logger, setup_logger
from utils.requirements_check import (
    install_missing_packages,
    print_requirements_status,
)


def main():
    """Główna funkcja - wykonuje pełne skanowanie i analizę."""
    # Inicjalizuj logger z poziomem DEBUG dla testów
    logger = setup_logger(level=logging.DEBUG)
    logger.info("=" * 60)
    logger.info("Diagnostic Tool - Full System Scan")
    logger.info("=" * 60)
    logger.debug("Logger initialized with DEBUG level")

    # Sprawdź i automatycznie zainstaluj brakujące pakiety
    logger.info("Checking and installing requirements...")
    requirements_status = install_missing_packages(auto_install=True)
    if not requirements_status['all_installed']:
        logger.warning(
            "Some required packages are still missing after auto-installation")
        print_requirements_status(requirements_status)
        print("\n⚠️  Some required packages are still missing. The application may not work correctly.")
        print("Press Enter to continue anyway, or Ctrl+C to exit...")
        try:
            input()
        except KeyboardInterrupt:
            logger.info("User cancelled - exiting")
            sys.exit(1)
    else:
        logger.info("All requirements are satisfied")

    # Sprawdź uprawnienia administratora (automatycznie próbuje uruchomić jako
    # admin)
    if not require_admin(auto_restart=True):
        logger.error("Administrator privileges required")
        print("\nNaciśnij Enter aby zakończyć...")
        input()
        sys.exit(1)

    logger.info("Running with administrator privileges")

    print("=" * 60)
    print("Diagnostic Tool - Full System Scan")
    print("=" * 60)
    print()

    # Zbierz wszystkie dane
    logger.info("Step 1: Collecting system data...")
    logger.debug("Starting data collection with all collectors")
    print("Step 1: Collecting system data...")
    print("-" * 60)
    collected_data = collect_all(save_raw=True, output_dir="output/raw")
    logger.info(
        f"Data collection completed. Collected {len(collected_data.get('collectors', {}))} collector results")

    # Faza 1: Wyświetl statusy collectorów w konsoli
    print("\nCollectors Status:")
    print("-" * 60)
    collectors = collected_data.get("collectors", {})
    summary = collected_data.get("summary", {})

    # Tabela statusów
    print(f"{'Collector':<25} {'Status':<15} {'Time (ms)':<12} {'Error':<30}")
    print("-" * 60)

    for name, result in sorted(collectors.items()):
        if isinstance(result, dict):
            status = result.get("status", "Unknown")
            exec_time = result.get("execution_time_ms", 0)
            error = result.get("error", "")

            status_icon = "✅" if status == "Collected" else "❌"
            status_display = f"{status_icon} {status}"
            error_display = error[:28] + "..." if len(error) > 30 else error

            print(
                f"{name:<25} {status_display:<15} {exec_time:<12} {error_display:<30}")

    print("-" * 60)
    print(f"Total: {summary.get('total_collectors', 0)} | "
          f"Collected: {summary.get('collected', 0)} | "
          f"Errors: {summary.get('errors', 0)}")
    print()

    # Przetwórz i przeanalizuj
    # Processors moved to archive/ - not needed in MVP
    logger.info("Step 2: Processing and analyzing data... (disabled - processors in archive)")
    logger.debug("Data analysis disabled - processors moved to archive")
    print("Step 2: Processing and analyzing data... (disabled)")
    print("-" * 60)
    print("Processors moved to archive/ - analysis disabled in MVP")
    # analysis_report = analyze_all(collected_data)
    analysis_report = {}  # Placeholder - processors in archive
    logger.info("Data analysis skipped (processors in archive)")
    print()

    # Zapisz przetworzone dane używając wspólnego modułu eksportu
    json_file = None
    try:
        from utils.export_utils import export_html, export_json

        # Eksport JSON
        export_data = {
            "collected_data": collected_data,
            "processed_data": analysis_report
        }
        json_file = export_json(export_data, output_dir="output/processed")
        logger.info(f"Analysis report (JSON) saved to: {json_file}")
        print(f"Analysis report (JSON) saved to: {json_file}")

        # Eksport HTML (opcjonalnie)
        try:
            html_file = export_html(
                collected_data,
                analysis_report,
                output_dir="output/processed")
            logger.info(f"Analysis report (HTML) saved to: {html_file}")
            print(f"Analysis report (HTML) saved to: {html_file}")
        except Exception as e:
            logger.warning(f"Failed to export HTML report: {e}")
            print(f"Warning: HTML export failed: {e}")

    except Exception as e:
        logger.error(f"Failed to save report: {e}")
        print(f"Failed to save report: {e}")

    # Wyświetl podsumowanie
    print()
    print("=" * 60)
    print("ANALYSIS SUMMARY")
    print("=" * 60)

    diagnosis = analysis_report.get("diagnosis", {})
    scoring = analysis_report.get("scoring", {})

    print(f"System Status: {diagnosis.get('status', 'UNKNOWN')}")
    print(f"System Score: {scoring.get('system_score', 0)}/100")
    print()

    summary = scoring.get("summary", {})
    print(f"Total Issues: {summary.get('total_issues', 0)}")
    print(f"Total Warnings: {summary.get('total_warnings', 0)}")
    print(f"Total Critical: {summary.get('total_critical', 0)}")
    print()

    # Top przyczyny
    cause_analysis = scoring.get("cause_analysis", {})
    top_causes = cause_analysis.get("top_causes", [])
    if top_causes:
        print("Top Likely Causes:")
        for i, cause in enumerate(top_causes[:3], 1):
            print(
                f"  {i}. {cause.get('cause')} (confidence: {cause.get('confidence', 0):.2%})")
        print()

    # Rekomendacje
    recommendation = diagnosis.get("recommendation", "")
    if recommendation:
        print(f"Recommendation: {recommendation}")
        print()

    # Top akcje
    action_items = diagnosis.get("action_items", [])
    if action_items:
        print("Recommended Actions:")
        for i, action in enumerate(action_items[:5], 1):
            print(f"  {i}. [{action.get('priority')}] {action.get('action')}")
        print()

    print("=" * 60)
    print("Full report available in:", report_file)
    print("=" * 60)


if __name__ == "__main__":
    main()
