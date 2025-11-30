"""
Async Collector Master - pełna asynchroniczność używając asyncio.
Oferuje lepszą wydajność niż ThreadPoolExecutor dla I/O-bound operacji.
"""
import json
import asyncio
from datetime import datetime
from pathlib import Path
from typing import Optional, Callable, Dict, Any
import concurrent.futures

from utils.logger import get_logger, log_collector_start, log_collector_end, log_performance
from core.config_loader import get_config
from core.collector_registry import get_registry as get_collector_registry
from collectors.collector_master import cleanup_old_raw_files

logger = get_logger()


def run_sync_in_executor(func: Callable, *args, **kwargs):
    """
    Uruchamia synchroniczną funkcję w executorze (dla collectorów które nie są async).
    
    Args:
        func: Synchroniczna funkcja do uruchomienia
        *args, **kwargs: Argumenty dla funkcji
    
    Returns:
        Wynik funkcji
    """
    loop = asyncio.get_event_loop()
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    return loop.run_in_executor(executor, func, *args, **kwargs)


async def _run_collector_async(collector_name: str, collector_func: Callable, message: str,
                                step: int, total: int, progress_callback: Optional[Callable]) -> tuple:
    """
    Asynchronicznie uruchamia pojedynczy collector i zwraca zstandaryzowany wynik.
    
    Args:
        collector_name: Nazwa collectora
        collector_func: Funkcja collect() do wywołania (może być sync lub async)
        message: Komunikat dla progress callback
        step: Numer kroku
        total: Całkowita liczba collectorów
        progress_callback: Funkcja callback do raportowania postępu
    
    Returns:
        tuple: (collector_name, standardized_result)
    """
    if progress_callback:
        # Wywołaj callback w głównym wątku jeśli to GUI
        try:
            if asyncio.iscoroutinefunction(progress_callback):
                await progress_callback(step, total, message)
            else:
                # Sync callback - uruchom w executorze
                await run_sync_in_executor(progress_callback, step, total, message)
        except Exception as e:
            logger.debug(f"[COLLECTOR_MASTER_ASYNC] Progress callback error: {e}")
    
    log_collector_start(collector_name)
    start_time = datetime.now()
    collector_timestamp = datetime.now()
    
    try:
        # Sprawdź czy collector jest async
        if asyncio.iscoroutinefunction(collector_func):
            collector_result = await collector_func()
        else:
            # Synchroniczny collector - uruchom w executorze
            collector_result = await run_sync_in_executor(collector_func)
        
        end_time = datetime.now()
        duration_ms = int((end_time - start_time).total_seconds() * 1000)
        
        # MVP: Standaryzuj format zwracany przez collector
        if isinstance(collector_result, dict) and "status" in collector_result:
            # Collector już zwraca standardowy format
            standardized_result = {
                "status": collector_result.get("status", "Collected"),
                "data": collector_result.get("data", collector_result),
                "error": collector_result.get("error"),
                "timestamp": collector_result.get("timestamp", collector_timestamp.isoformat()),
                "collector_name": collector_result.get("collector_name", collector_name),
                "execution_time_ms": collector_result.get("execution_time_ms", duration_ms)
            }
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
            data_count = sum(len(v) if isinstance(v, (list, dict)) else 1 for v in data.values())
        elif isinstance(data, list):
            data_count = len(data)
        
        log_collector_end(collector_name, success=True, data_count=data_count)
        log_performance(f"Collector {collector_name}", duration_ms / 1000, f"collected {data_count} items")
        
        # Faza 2: Rejestruj w monitorze wydajności
        try:
            from utils.performance_monitor import get_performance_monitor
            monitor = get_performance_monitor()
            monitor.record_collector(collector_name, duration_ms, "Collected", data_count)
        except Exception as e:
            logger.debug(f"[COLLECTOR_ASYNC] Failed to record performance: {e}")
        
        return (collector_name, standardized_result)
        
    except Exception as e:
        end_time = datetime.now()
        duration_ms = int((end_time - start_time).total_seconds() * 1000)
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
        log_performance(f"Collector {collector_name}", duration_ms / 1000, "FAILED")
        logger.exception(f"Collector {collector_name} raised exception")
        
        # Faza 2: Rejestruj w monitorze wydajności
        try:
            from utils.performance_monitor import get_performance_monitor
            monitor = get_performance_monitor()
            monitor.record_collector(collector_name, duration_ms, "Error", 0, error_msg)
        except Exception as e:
            logger.debug(f"[COLLECTOR_ASYNC] Failed to record performance: {e}")
        
        return (collector_name, standardized_result)


async def collect_all_async(save_raw=True, output_dir="output/raw", progress_callback=None):
    """
    Asynchronicznie zbiera wszystkie dane diagnostyczne z wszystkich collectors.
    
    Używa pełnej asynchroniczności (asyncio) dla lepszej wydajności przy I/O-bound operacjach.
    
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
            collectors_list.append((
                collector_name,
                f"Collecting {collector_info.get('description', collector_name)}...",
                collector_info["collect_func"]
            ))
    
    total = len(collectors_list)
    results["summary"]["total_collectors"] = total
    
    logger.info(f"[COLLECTION_ASYNC] Starting async collection of {total} collectors")
    
    # Faza 4: Ograniczenie równoległości przy dużych skanach (asyncio.Semaphore)
    max_concurrent = config.get("collectors.max_concurrent", None)
    if max_concurrent and total > max_concurrent:
        logger.info(f"[COLLECTION_ASYNC] Limiting concurrency to {max_concurrent} collectors")
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def _run_with_semaphore(collector_name, collector_func, message, step, total, progress_callback):
            async with semaphore:
                return await _run_collector_async(
                    collector_name, collector_func, message, step, total, progress_callback
                )
        
        # Uruchom wszystkie collectory z semaforem
        tasks = []
        for step, (collector_name, message, collector_func) in enumerate(collectors_list, 1):
            task = _run_with_semaphore(
                collector_name, collector_func, message, step, total, progress_callback
            )
            tasks.append(task)
    else:
        # Pełna asynchroniczność - uruchom wszystkie collectory równocześnie
        tasks = []
        for step, (collector_name, message, collector_func) in enumerate(collectors_list, 1):
            task = _run_collector_async(
                collector_name, collector_func, message, step, total, progress_callback
            )
            tasks.append(task)
    
    # Uruchom wszystkie collectory równocześnie i zbierz wyniki
    completed = 0
    for coro in asyncio.as_completed(tasks):
        collector_name, standardized_result = await coro
        completed += 1
        results["collectors"][collector_name] = standardized_result
        
        if standardized_result["status"] == "Collected":
            results["summary"]["collected"] += 1
        else:
            results["summary"]["errors"] += 1
        
        if progress_callback:
            try:
                if asyncio.iscoroutinefunction(progress_callback):
                    await progress_callback(completed, total, f"Completed {collector_name}...")
                else:
                    await run_sync_in_executor(progress_callback, completed, total, f"Completed {collector_name}...")
            except Exception as e:
                logger.debug(f"[COLLECTOR_MASTER_ASYNC] Progress callback error: {e}")
    
    # Zapisz surowe dane jeśli wymagane (również asynchronicznie)
    if save_raw:
        await run_sync_in_executor(_save_raw_data, results, output_dir)
    
    return results


def _save_raw_data(results: Dict[str, Any], output_dir: str):
    """Zapisuje surowe dane do pliku (synchroniczna funkcja do uruchomienia w executorze)."""
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    # Wyczyść stare pliki przed zapisem nowego
    cleanup_old_raw_files(output_dir, keep_last=5)
    
    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = output_path / f"raw_data_{timestamp_str}.json"
    
    try:
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False, default=str)
        
        file_size_mb = filename.stat().st_size / (1024 * 1024)
        logger.info(f"[COLLECTOR_MASTER_ASYNC] Raw data saved to: {filename} ({file_size_mb:.2f} MB)")
    except Exception as e:
        logger.error(f"[COLLECTOR_MASTER_ASYNC] Failed to save raw data: {e}")


def collect_all_async_wrapper(save_raw=True, output_dir="output/raw", progress_callback=None):
    """
    Wrapper dla collect_all_async - uruchamia async funkcję w nowym event loop.
    Użyj tego jeśli wywołujesz z synchronicznego kodu (np. GUI).
    
    Args:
        save_raw (bool): Czy zapisać surowe dane do pliku JSON
        output_dir (str): Katalog do zapisu surowych danych
        progress_callback (callable): Funkcja callback(step, total, message) do raportowania postępu
    
    Returns:
        dict: Słownik z wszystkimi zebranymi danymi w formacie MVP
    """
    try:
        # Sprawdź czy już jest uruchomiony event loop
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # Event loop już działa - użyj run_until_complete w osobnym wątku
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as executor:
                future = executor.submit(asyncio.run, collect_all_async(save_raw, output_dir, progress_callback))
                return future.result()
        else:
            # Brak uruchomionego loop - użyj run
            return asyncio.run(collect_all_async(save_raw, output_dir, progress_callback))
    except RuntimeError:
        # Brak event loop - utwórz nowy
        return asyncio.run(collect_all_async(save_raw, output_dir, progress_callback))

