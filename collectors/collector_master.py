"""
Master collector - koordynuje zbieranie danych ze wszystkich collectors.
"""
import json
from datetime import datetime
from pathlib import Path

from . import (
    hardware, drivers, system_logs, registry_txr, storage_health, system_info,
    services, bsod_dumps, performance_counters, wer, processes
)

def collect_all(save_raw=True, output_dir="output/raw"):
    """
    Zbiera wszystkie dane diagnostyczne z wszystkich collectors.
    
    Args:
        save_raw (bool): Czy zapisać surowe dane do pliku JSON
        output_dir (str): Katalog do zapisu surowych danych
    
    Returns:
        dict: Słownik z wszystkimi zebranymi danymi
    """
    results = {
        "timestamp": datetime.now().isoformat(),
        "collectors": {}
    }
    
    print("Collecting hardware data...")
    try:
        results["collectors"]["hardware"] = hardware.collect()
    except Exception as e:
        results["collectors"]["hardware"] = {"error": f"Collection failed: {type(e).__name__}: {e}"}
    
    print("Collecting drivers data...")
    try:
        results["collectors"]["drivers"] = drivers.collect()
    except Exception as e:
        results["collectors"]["drivers"] = {"error": f"Collection failed: {type(e).__name__}: {e}"}
    
    print("Collecting system logs...")
    try:
        results["collectors"]["system_logs"] = system_logs.collect(max_events=200, filter_levels=['Error', 'Warning', 'Critical'])
    except Exception as e:
        results["collectors"]["system_logs"] = {"error": f"Collection failed: {type(e).__name__}: {e}"}
    
    print("Collecting Registry TxR errors...")
    try:
        results["collectors"]["registry_txr"] = registry_txr.collect(max_events=200)
    except Exception as e:
        results["collectors"]["registry_txr"] = {"error": f"Collection failed: {type(e).__name__}: {e}"}
    
    print("Collecting storage health data...")
    try:
        results["collectors"]["storage_health"] = storage_health.collect()
    except Exception as e:
        results["collectors"]["storage_health"] = {"error": f"Collection failed: {type(e).__name__}: {e}"}
    
    print("Collecting system info...")
    try:
        results["collectors"]["system_info"] = system_info.collect()
    except Exception as e:
        results["collectors"]["system_info"] = {"error": f"Collection failed: {type(e).__name__}: {e}"}
    
    print("Collecting services data...")
    try:
        results["collectors"]["services"] = services.collect()
    except Exception as e:
        results["collectors"]["services"] = {"error": f"Collection failed: {type(e).__name__}: {e}"}
    
    print("Collecting BSOD/dumps data...")
    try:
        results["collectors"]["bsod_dumps"] = bsod_dumps.collect()
    except Exception as e:
        results["collectors"]["bsod_dumps"] = {"error": f"Collection failed: {type(e).__name__}: {e}"}
    
    print("Collecting performance counters...")
    try:
        results["collectors"]["performance_counters"] = performance_counters.collect()
    except Exception as e:
        results["collectors"]["performance_counters"] = {"error": f"Collection failed: {type(e).__name__}: {e}"}
    
    print("Collecting Windows Error Reporting data...")
    try:
        results["collectors"]["wer"] = wer.collect()
    except Exception as e:
        results["collectors"]["wer"] = {"error": f"Collection failed: {type(e).__name__}: {e}"}
    
    print("Collecting processes data...")
    try:
        results["collectors"]["processes"] = processes.collect()
    except Exception as e:
        results["collectors"]["processes"] = {"error": f"Collection failed: {type(e).__name__}: {e}"}
    
    # Zapisz surowe dane jeśli wymagane
    if save_raw:
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = output_path / f"raw_data_{timestamp_str}.json"
        
        try:
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2, ensure_ascii=False, default=str)
            print(f"Raw data saved to: {filename}")
        except Exception as e:
            print(f"Failed to save raw data: {e}")
    
    return results

