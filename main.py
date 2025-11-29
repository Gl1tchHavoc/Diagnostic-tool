"""
Główny plik diagnostyczny - uruchamia pełne skanowanie systemu.
"""
import json
import sys
import logging
from pathlib import Path
from datetime import datetime

from utils.admin_check import require_admin
from utils.logger import setup_logger, get_logger
from collectors.collector_master import collect_all
from processors.analyzer import analyze_all

def main():
    """Główna funkcja - wykonuje pełne skanowanie i analizę."""
    # Inicjalizuj logger z poziomem DEBUG dla testów
    logger = setup_logger(level=logging.DEBUG)
    logger.info("=" * 60)
    logger.info("Diagnostic Tool - Full System Scan")
    logger.info("=" * 60)
    logger.debug("Logger initialized with DEBUG level")
    
    # Sprawdź uprawnienia administratora (automatycznie próbuje uruchomić jako admin)
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
    logger.info(f"Data collection completed. Collected {len(collected_data.get('collectors', {}))} collector results")
    print()
    
    # Przetwórz i przeanalizuj
    logger.info("Step 2: Processing and analyzing data...")
    logger.debug("Starting data analysis and processing")
    print("Step 2: Processing and analyzing data...")
    print("-" * 60)
    analysis_report = analyze_all(collected_data)
    logger.info("Data analysis completed")
    print()
    
    # Zapisz przetworzone dane
    output_path = Path("output/processed")
    output_path.mkdir(parents=True, exist_ok=True)
    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = output_path / f"analysis_report_{timestamp_str}.json"
    
    try:
        with open(report_file, "w", encoding="utf-8") as f:
            json.dump(analysis_report, f, indent=2, ensure_ascii=False, default=str)
        logger.info(f"Analysis report saved to: {report_file}")
        print(f"Analysis report saved to: {report_file}")
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
            print(f"  {i}. {cause.get('cause')} (confidence: {cause.get('confidence', 0):.2%})")
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

