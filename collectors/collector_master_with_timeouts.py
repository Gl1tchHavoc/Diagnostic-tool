"""
Collector Master z timeoutami i fallback - Faza 2.
Dodaje timeouty dla collectorów i fallback mechanizmy.
"""
import asyncio
from datetime import datetime
from typing import Optional, Callable, Dict, Any
import concurrent.futures

from utils.logger import get_logger, log_collector_start, log_collector_end, log_performance
from core.config_loader import get_config
from core.collector_registry import get_registry as get_collector_registry
from collectors.collector_master_async import (
    run_sync_in_executor,
    _save_raw_data
)

logger = get_logger()


async def _run_collector_with_timeout(
    collector_name: str,
    collector_func: Callable,
    message: str,
    step: int,
    total: int,
    progress_callback: Optional[Callable],
    timeout_seconds: int = 300
) -> tuple:
    """
    Uruchamia collector z timeoutem i fallback.

    Args:
        collector_name: Nazwa collectora
        collector_func: Funkcja collect() do wywołania
        message: Komunikat dla progress callback
        step: Numer kroku
        total: Całkowita liczba collectorów
        progress_callback: Funkcja callback do raportowania postępu
        timeout_seconds: Timeout w sekundach (domyślnie 300)

    Returns:
        tuple: (collector_name, standardized_result)
    """
    if progress_callback:
        try:
            if asyncio.iscoroutinefunction(progress_callback):
                await progress_callback(step, total, message)
            else:
                await run_sync_in_executor(progress_callback, step, total, message)
        except Exception as e:
            logger.debug(f"[COLLECTOR_TIMEOUT] Progress callback error: {e}")

    log_collector_start(collector_name)
    start_time = datetime.now()
    collector_timestamp = datetime.now()

    try:
        # Uruchom collector z timeoutem
        if asyncio.iscoroutinefunction(collector_func):
            collector_result = await asyncio.wait_for(
                collector_func(),
                timeout=timeout_seconds
            )
        else:
            # Synchroniczny collector - uruchom w executorze z timeoutem
            loop = asyncio.get_event_loop()
            executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
            collector_result = await asyncio.wait_for(
                loop.run_in_executor(executor, collector_func),
                timeout=timeout_seconds
            )

        end_time = datetime.now()
        duration_ms = int((end_time - start_time).total_seconds() * 1000)

        # Standaryzuj format
        if isinstance(collector_result, dict) and "status" in collector_result:
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
            standardized_result = {
                "status": "Collected",
                "data": collector_result,
                "error": None,
                "timestamp": collector_timestamp.isoformat(),
                "collector_name": collector_name,
                "execution_time_ms": duration_ms
            }

        # Policz elementy
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

        return (collector_name, standardized_result)

    except asyncio.TimeoutError:
        end_time = datetime.now()
        duration_ms = int((end_time - start_time).total_seconds() * 1000)
        error_msg = f"Timeout after {timeout_seconds}s"

        standardized_result = {
            "status": "Error",
            "data": None,
            "error": error_msg,
            "timestamp": collector_timestamp.isoformat(),
            "collector_name": collector_name,
            "execution_time_ms": duration_ms,
            "timeout": True
        }

        log_collector_end(collector_name, success=False, error=error_msg)
        log_performance(
            f"Collector {collector_name}",
            duration_ms / 1000,
            "TIMEOUT")
        logger.warning(
            f"Collector {collector_name} timed out after {timeout_seconds}s")

        return (collector_name, standardized_result)

    except Exception as e:
        end_time = datetime.now()
        duration_ms = int((end_time - start_time).total_seconds() * 1000)
        error_msg = f"{type(e).__name__}: {e}"

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

        return (collector_name, standardized_result)


async def collect_all_with_timeouts(
    save_raw=True,
    output_dir="output/raw",
    progress_callback=None,
    timeout_seconds: Optional[int] = None
):
    """
    Zbiera wszystkie dane z timeoutami i fallback.

    Args:
        save_raw: Czy zapisać surowe dane
        output_dir: Katalog wyjściowy
        progress_callback: Callback dla postępu
        timeout_seconds: Timeout dla każdego collectora (None = z config)

    Returns:
        dict: Zebrane dane w formacie MVP
    """
    config = get_config()
    registry = get_collector_registry()
    collection_start_time = datetime.now()

    # Pobierz timeout z config jeśli nie podano
    if timeout_seconds is None:
        timeout_seconds = config.get("collectors.timeout_seconds", 300)

    results = {
        "timestamp": collection_start_time.isoformat(),
        "collectors": {},
        "summary": {
            "total_collectors": 0,
            "collected": 0,
            "errors": 0,
            "timeouts": 0
        }
    }

    # Pobierz listę collectorów
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

    logger.info(
        f"[COLLECTION_TIMEOUT] Starting collection of {total} collectors (timeout: {timeout_seconds}s)")

    # Uruchom wszystkie collectory z timeoutami
    tasks = []
    for step, (collector_name, message, collector_func) in enumerate(
            collectors_list, 1):
        task = _run_collector_with_timeout(
            collector_name, collector_func, message, step, total,
            progress_callback, timeout_seconds
        )
        tasks.append(task)

    # Zbierz wyniki
    completed = 0
    for coro in asyncio.as_completed(tasks):
        collector_name, standardized_result = await coro
        completed += 1
        results["collectors"][collector_name] = standardized_result

        if standardized_result["status"] == "Collected":
            results["summary"]["collected"] += 1
        else:
            results["summary"]["errors"] += 1
            if standardized_result.get("timeout"):
                results["summary"]["timeouts"] += 1

        if progress_callback:
            try:
                if asyncio.iscoroutinefunction(progress_callback):
                    await progress_callback(completed, total, f"Completed {collector_name}...")
                else:
                    await run_sync_in_executor(progress_callback, completed, total, f"Completed {collector_name}...")
            except Exception as e:
                logger.debug(
                    f"[COLLECTOR_TIMEOUT] Progress callback error: {e}")

    # Zapisz surowe dane
    if save_raw:
        await run_sync_in_executor(_save_raw_data, results, output_dir)

    return results


def collect_all_with_timeouts_wrapper(
    save_raw=True,
    output_dir="output/raw",
    progress_callback=None,
    timeout_seconds: Optional[int] = None
):
    """
    Wrapper dla collect_all_with_timeouts - uruchamia async funkcję w nowym event loop.
    """
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as executor:
                future = executor.submit(
                    asyncio.run,
                    collect_all_with_timeouts(
                        save_raw,
                        output_dir,
                        progress_callback,
                        timeout_seconds))
                return future.result()
        else:
            return asyncio.run(
                collect_all_with_timeouts(
                    save_raw,
                    output_dir,
                    progress_callback,
                    timeout_seconds))
    except RuntimeError:
        return asyncio.run(
            collect_all_with_timeouts(
                save_raw,
                output_dir,
                progress_callback,
                timeout_seconds))
