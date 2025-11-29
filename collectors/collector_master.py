"""
Master collector - koordynuje zbieranie danych ze wszystkich collectors.
"""
import json
from datetime import datetime
from pathlib import Path
import time

from . import (
    hardware, drivers, system_logs, registry_txr, storage_health, system_info,
    services, bsod_dumps, performance_counters, wer, processes
)

from utils.logger import get_logger, log_collector_start, log_collector_end, log_performance

def collect_all(save_raw=True, output_dir="output/raw", progress_callback=None):
    """
    Zbiera wszystkie dane diagnostyczne z wszystkich collectors.
    
    Args:
        save_raw (bool): Czy zapisać surowe dane do pliku JSON
        output_dir (str): Katalog do zapisu surowych danych
        progress_callback (callable): Funkcja callback(step, total, message) do raportowania postępu
    
    Returns:
        dict: Słownik z wszystkimi zebranymi danymi
    """
    results = {
        "timestamp": datetime.now().isoformat(),
        "collectors": {}
    }
    
    # Lista wszystkich collectorów do wykonania
    collectors_list = [
        ("hardware", "Collecting hardware data...", lambda: hardware.collect()),
        ("drivers", "Collecting drivers data...", lambda: drivers.collect()),
        ("system_logs", "Collecting system logs...", lambda: system_logs.collect(max_events=200, filter_levels=None)),  # None = wszystkie poziomy
        ("registry_txr", "Collecting Registry TxR errors...", lambda: registry_txr.collect(max_events=200)),
        ("storage_health", "Collecting storage health data...", lambda: storage_health.collect()),
        ("system_info", "Collecting system info...", lambda: system_info.collect()),
        ("services", "Collecting services data...", lambda: services.collect()),
        ("bsod_dumps", "Collecting BSOD/dumps data...", lambda: bsod_dumps.collect()),
        ("performance_counters", "Collecting performance counters...", lambda: performance_counters.collect()),
        ("wer", "Collecting Windows Error Reporting data...", lambda: wer.collect()),
        ("processes", "Collecting processes data...", lambda: processes.collect()),
    ]
    
    total = len(collectors_list)
    
    logger = get_logger()
    logger.info(f"[COLLECTION] Starting collection of {total} collectors")
    
    for step, (collector_name, message, collector_func) in enumerate(collectors_list, 1):
        if progress_callback:
            progress_callback(step, total, message)
        else:
            print(message)
        
        log_collector_start(collector_name)
        start_time = time.time()
        
        try:
            collector_result = collector_func()
            duration = time.time() - start_time
            
            # Policz elementy w wynikach
            data_count = 0
            if isinstance(collector_result, dict):
                data_count = sum(len(v) if isinstance(v, (list, dict)) else 1 for v in collector_result.values())
            elif isinstance(collector_result, list):
                data_count = len(collector_result)
            
            results["collectors"][collector_name] = collector_result
            log_collector_end(collector_name, success=True, data_count=data_count)
            log_performance(f"Collector {collector_name}", duration, f"collected {data_count} items")
        except Exception as e:
            duration = time.time() - start_time
            error_msg = f"{type(e).__name__}: {e}"
            results["collectors"][collector_name] = {"error": f"Collection failed: {error_msg}"}
            log_collector_end(collector_name, success=False, error=error_msg)
            log_performance(f"Collector {collector_name}", duration, "FAILED")
            logger.exception(f"Collector {collector_name} raised exception")
    
    # Zapisz surowe dane jeśli wymagane
    if save_raw:
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = output_path / f"raw_data_{timestamp_str}.json"
        
        try:
            # Użyj safe_read_text dla spójności (chociaż to zapis, nie odczyt)
            # Ale dla zapisu używamy standardowego open z utf-8
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2, ensure_ascii=False, default=str)
            logger.info(f"[COLLECTOR_MASTER] Raw data saved to: {filename}")
        except Exception as e:
            logger.error(f"[COLLECTOR_MASTER] Failed to save raw data: {e}")
    
    return results

