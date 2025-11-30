"""
Master collector - koordynuje zbieranie danych ze wszystkich collectors.
MVP: Używa CollectorRegistry i obsługuje równoległe wykonanie.
"""
import json
import time
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

# Windows COM initialization for PowerShell/psutil
if sys.platform == "win32":
    try:
        import pythoncom

        def _init_thread_com():
            """Inicjalizuje COM w wątku - wymagane dla PowerShell i części psutil."""
            pythoncom.CoInitialize()
    except ImportError:
        # pythoncom nie dostępne (nie Windows lub brak pywin32)
        def _init_thread_com():
            """Pusta funkcja jeśli COM nie jest dostępne."""
            pass
else:
    def _init_thread_com():
        """Pusta funkcja dla systemów nie-Windows."""
        pass
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

from core.collector_registry import get_registry as get_collector_registry
from core.config_loader import get_config
from utils.logger import (
    get_logger,
    log_collector_end,
    log_collector_start,
    log_performance,
)


def cleanup_old_raw_files(output_dir="output/raw", keep_last=5):
    """
    Czyści stare pliki raw_data, zostawiając tylko ostatnie N plików.

    Args:
        output_dir (str): Katalog z plikami raw_data
        keep_last (int): Liczba ostatnich plików do zachowania (domyślnie 5)
    """
    logger = get_logger()
    output_path = Path(output_dir)

    if not output_path.exists():
        return

    try:
        # Znajdź wszystkie pliki raw_data_*.json
        raw_files = sorted(
            output_path.glob("raw_data_*.json"),
            key=lambda p: p.stat().st_mtime,
            reverse=True
        )

        if len(raw_files) <= keep_last:
            logger.debug(
                f"[COLLECTOR_MASTER] No cleanup needed: {len(raw_files)} files (limit: {keep_last})")
            return

        # Usuń stare pliki (zostaw tylko ostatnie N)
        files_to_delete = raw_files[keep_last:]
        deleted_count = 0
        freed_space = 0

        for file_path in files_to_delete:
            try:
                file_size = file_path.stat().st_size
                file_path.unlink()
                deleted_count += 1
                freed_space += file_size
                logger.debug(
                    f"[COLLECTOR_MASTER] Deleted old raw file: {file_path.name}")
            except Exception as e:
                logger.warning(
                    f"[COLLECTOR_MASTER] Failed to delete {file_path.name}: {e}")

        if deleted_count > 0:
            freed_mb = freed_space / (1024 * 1024)
            logger.info(
                f"[COLLECTOR_MASTER] Cleaned up {deleted_count} old raw files, freed {freed_mb:.2f} MB")
    except Exception as e:
        logger.warning(f"[COLLECTOR_MASTER] Error during cleanup: {e}")


def _run_collector(
        collector_name: str,
        collector_func: Callable,
        message: str,
        step: int,
        total: int,
        progress_callback: Optional[Callable]) -> tuple:
    """
    Uruchamia pojedynczy collector i zwraca zstandaryzowany wynik.

    Args:
        collector_name: Nazwa collectora
        collector_func: Funkcja collect() do wywołania
        message: Komunikat dla progress callback
        step: Numer kroku
        total: Całkowita liczba collectorów
        progress_callback: Funkcja callback do raportowania postępu

    Returns:
        tuple: (collector_name, standardized_result)
    """
    logger = get_logger()

    if progress_callback:
        progress_callback(step, total, message)

    log_collector_start(collector_name)
    start_time = time.time()
    collector_timestamp = datetime.now()

    try:
        collector_result = collector_func()
        duration_ms = int((time.time() - start_time) * 1000)

        # MVP: Standaryzuj format zwracany przez collector
        if isinstance(collector_result, dict) and "status" in collector_result:
            # Collector już zwraca standardowy format
            standardized_result = {
                "status": collector_result.get(
                    "status",
                    "Collected"),
                "data": collector_result.get(
                    "data",
                    collector_result),
                "error": collector_result.get("error"),
                "timestamp": collector_result.get(
                    "timestamp",
                    collector_timestamp.isoformat()),
                "collector_name": collector_result.get(
                    "collector_name",
                    collector_name),
                "execution_time_ms": collector_result.get(
                    "execution_time_ms",
                    duration_ms)}
        else:
            # Collector zwraca surowe dane - opakuj w standardowy format
            standardized_result = {
                "status": "Collected",
                "data": collector_result,
                "error": None,
                "timestamp": collector_timestamp.isoformat(),
                "collector_name": collector_name,
                "execution_time_ms": duration_ms
            }

        # Policz elementy w wynikach dla logowania
        data_count = 0
        data = standardized_result.get("data", {})
        if isinstance(data, dict):
            data_count = sum(
                len(v) if isinstance(
                    v, (list, dict)) else 1 for v in data.values())
        elif isinstance(data, list):
            data_count = len(data)

        log_collector_end(collector_name, success=True, data_count=data_count)
        log_performance(
            f"Collector {collector_name}",
            duration_ms / 1000,
            f"collected {data_count} items")

        # Faza 2: Rejestruj w monitorze wydajności
        try:
            from utils.performance_monitor import get_performance_monitor
            monitor = get_performance_monitor()
            monitor.record_collector(
                collector_name,
                duration_ms,
                "Collected",
                data_count)
        except Exception as e:
            logger.debug(
                f"[COLLECTOR_MASTER] Failed to record performance: {e}")

        return (collector_name, standardized_result)

    except Exception as e:
        duration_ms = int((time.time() - start_time) * 1000)
        error_msg = f"{type(e).__name__}: {e}"

        # MVP: Standaryzowany format błędu
        standardized_result = {
            "status": "Error",
            "data": None,
            "error": error_msg,
            "timestamp": collector_timestamp.isoformat(),
            "collector_name": collector_name,
            "execution_time_ms": duration_ms
        }

        log_collector_end(collector_name, success=False, error=error_msg)
        log_performance(
            f"Collector {collector_name}",
            duration_ms / 1000,
            "FAILED")
        logger.exception(f"Collector {collector_name} raised exception")

        # Faza 2: Rejestruj w monitorze wydajności
        try:
            from utils.performance_monitor import get_performance_monitor
            monitor = get_performance_monitor()
            monitor.record_collector(
                collector_name, duration_ms, "Error", 0, error_msg)
        except Exception as e:
            logger.debug(
                f"[COLLECTOR_MASTER] Failed to record performance: {e}")

        return (collector_name, standardized_result)


def collect_all(
        save_raw=True,
        output_dir="output/raw",
        progress_callback=None):
    """
    Zbiera wszystkie dane diagnostyczne z wszystkich collectors.

    MVP: Używa CollectorRegistry i obsługuje równoległe wykonanie.

    Args:
        save_raw (bool): Czy zapisać surowe dane do pliku JSON
        output_dir (str): Katalog do zapisu surowych danych
        progress_callback (callable): Funkcja callback(step, total, message) do raportowania postępu

    Returns:
        dict: Słownik z wszystkimi zebranymi danymi w formacie MVP
    """
    config = get_config()
    registry = get_collector_registry()
    collection_start_time = datetime.now()

    results = {
        "timestamp": collection_start_time.isoformat(),
        "collectors": {},
        "summary": {
            "total_collectors": 0,
            "collected": 0,
            "errors": 0
        }
    }

    # Pobierz listę collectorów z rejestru (tylko włączone)
    enabled_collectors = config.get("collectors.enabled", [])
    collectors_list = []

    for collector_name in enabled_collectors:
        collector_info = registry.get(collector_name)
        if collector_info and registry.is_enabled(collector_name):
            collectors_list.append(
                (collector_name,
                 f"Collecting {collector_info.get('description', collector_name)}...",
                 collector_info["collect_func"]))

    total = len(collectors_list)
    results["summary"]["total_collectors"] = total

    logger = get_logger()
    logger.info(f"[COLLECTION] Starting collection of {total} collectors")

    # MVP: Równoległe wykonanie jeśli włączone w config
    # Uwaga: Dla pełnej asynchroniczności użyj collect_all_async_wrapper z
    # collector_master_async
    parallel = config.get("collectors.parallel_execution", True)
    use_async = config.get("collectors.use_async", False)

    if use_async:
        # Użyj asynchronicznej wersji
        logger.info("[COLLECTION] Using async execution")
        from collectors.collector_master_async import collect_all_async_wrapper
        return collect_all_async_wrapper(
            save_raw, output_dir, progress_callback)

    if parallel and total > 1:
        # Równoległe wykonanie
        logger.info("[COLLECTION] Using parallel execution")
        with ThreadPoolExecutor(
            max_workers=min(total, 6),
            initializer=_init_thread_com
        ) as executor:
            # Uruchom wszystkie collectory
            future_to_collector = {
                executor.submit(_run_collector, name, func, msg, i + 1, total, progress_callback): name
                for i, (name, msg, func) in enumerate(collectors_list)
            }

            # Zbierz wyniki w miarę ich ukończenia
            completed = 0
            for future in as_completed(future_to_collector):
                completed += 1
                collector_name, standardized_result = future.result()
                results["collectors"][collector_name] = standardized_result

                if standardized_result["status"] == "Collected":
                    results["summary"]["collected"] += 1
                else:
                    results["summary"]["errors"] += 1

                if progress_callback:
                    progress_callback(
                        completed, total, f"Completed {collector_name}...")
    else:
        # Sekwencyjne wykonanie
        logger.info("[COLLECTION] Using sequential execution")
        for step, (collector_name, message, collector_func) in enumerate(
                collectors_list, 1):
            collector_name, standardized_result = _run_collector(
                collector_name, collector_func, message, step, total, progress_callback)
            results["collectors"][collector_name] = standardized_result

            if standardized_result["status"] == "Collected":
                results["summary"]["collected"] += 1
            else:
                results["summary"]["errors"] += 1

    # Zapisz surowe dane jeśli wymagane
    if save_raw:
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        # Wyczyść stare pliki przed zapisem nowego (zostaw tylko ostatnie 5)
        cleanup_old_raw_files(output_dir, keep_last=5)

        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = output_path / f"raw_data_{timestamp_str}.json"

        try:
            # Użyj safe_read_text dla spójności (chociaż to zapis, nie odczyt)
            # Ale dla zapisu używamy standardowego open z utf-8
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(
                    results,
                    f,
                    indent=2,
                    ensure_ascii=False,
                    default=str)

            file_size_mb = filename.stat().st_size / (1024 * 1024)
            logger.info(
                f"[COLLECTOR_MASTER] Raw data saved to: {filename} ({file_size_mb:.2f} MB)")
        except Exception as e:
            logger.error(f"[COLLECTOR_MASTER] Failed to save raw data: {e}")

    return results
