"""
Główny analyzer - łączy wszystkie procesory i nowy system scoringu w kompleksową analizę.
"""
import time
from . import (
    hardware_processor, driver_processor, system_logs_processor,
    registry_txr_processor, storage_health_processor, system_info_processor,
    whea_processor
)
from .report_builder import build_report
from .bsod_analyzer import analyze_bsod
from .cause_detector import detect_all_causes
from utils.logger import get_logger, log_processor_start, log_processor_end, log_performance, log_bsod_analysis


def analyze_all(collected_data, progress_callback=None):
    """
    Analizuje wszystkie zebrane dane i zwraca kompleksowy raport.

    Args:
        collected_data (dict): Dane z collectors.collector_master.collect_all()
        progress_callback (callable): Funkcja callback(step, total, message) do raportowania postępu

    Returns:
        dict: Kompleksowy raport analizy
    """
    logger = get_logger()
    logger.info("[ANALYSIS] Starting full system analysis")
    analysis_start_time = time.time()

    # Upewnij się, że collected_data jest słownikiem
    if not isinstance(collected_data, dict):
        logger.error(
            f"[ANALYSIS] collected_data is not a dict: {type(collected_data)}")
        return {"error": "Invalid collected_data format"}

    collectors_data = collected_data.get("collectors", {})

    # Upewnij się, że collectors_data jest słownikiem
    if not isinstance(collectors_data, dict):
        logger.error(
            f"[ANALYSIS] collectors_data is not a dict: {type(collectors_data)}")
        collectors_data = {}

    processed_data = {}

    # Lista procesorów do wykonania
    processors_list = [
        ("hardware", "Processing hardware data...",
         "hardware", hardware_processor.process),
        ("drivers", "Processing drivers data...",
         "drivers", driver_processor.process),
        ("system_logs", "Processing system logs...",
         "system_logs", system_logs_processor.process),
        ("registry_txr", "Processing Registry TxR errors...",
         "registry_txr", registry_txr_processor.process),
        ("storage_health", "Processing storage health...",
         "storage_health", storage_health_processor.process),
        ("system_info", "Processing system info...",
         "system_info", system_info_processor.process),
    ]

    total_processors = len(processors_list)

    # Przetwórz wszystkie dane
    for step, (name, message, key, processor_func) in enumerate(
            processors_list, 1):
        if progress_callback:
            progress_callback(step, total_processors, message)
        else:
            print(message)

        log_processor_start(name)
        processor_start_time = time.time()

        if key in collectors_data:
            try:
                # MVP: Obsługa nowego formatu z collector_master
                collector_result = collectors_data[key]

                # Sprawdź czy to nowy format MVP (z status, data, error)
                if isinstance(collector_result,
                              dict) and "status" in collector_result:
                    # Nowy format MVP - wyciągnij dane
                    collector_data = collector_result.get("data")
                    collector_status = collector_result.get("status")

                    # Jeśli collector zwrócił błąd, przekaż to do procesora
                    if collector_status == "Error":
                        processor_result = {
                            "status": "Error",
                            "data": None,
                            "errors": [
                                collector_result.get(
                                    "error",
                                    "Unknown error")],
                            "warnings": [],
                            "validation_passed": False,
                            "processor_name": name}
                    else:
                        # Przekaż dane do procesora (może być stary format lub nowy)
                        # Stare procesory oczekują surowych danych, więc
                        # przekazujemy collector_data
                        processor_result = processor_func(collector_data)
                else:
                    # Stary format - przekaż bezpośrednio (backward
                    # compatibility)
                    collector_data = collector_result
                    processor_result = processor_func(collector_data)

                duration = time.time() - processor_start_time

                # Policz znalezione problemy (dla starego formatu)
                issues_count = 0
                if isinstance(processor_result, dict):
                    # Nowy format MVP
                    if "status" in processor_result:
                        issues_count = (
                            len(processor_result.get("errors", []))
                            + len(processor_result.get("warnings", []))
                        )
                    else:
                        # Stary format
                        issues_count = (
                            len(processor_result.get("issues", []))
                            + len(processor_result.get("critical_issues", []))
                            + len(processor_result.get("critical_events", []))
                            + len(processor_result.get("warnings", []))
                        )

                processed_data[name] = processor_result
                log_processor_end(
                    name, success=True, issues_found=issues_count)
                log_performance(
                    f"Processor {name}",
                    duration,
                    f"found {issues_count} issues")

                # Faza 2: Rejestruj w monitorze wydajności
                try:
                    from utils.performance_monitor import get_performance_monitor
                    monitor = get_performance_monitor()
                    errors_count = len(
                        processor_result.get(
                            "errors",
                            [])) if isinstance(
                        processor_result,
                        dict) else 0
                    warnings_count = len(
                        processor_result.get(
                            "warnings",
                            [])) if isinstance(
                        processor_result,
                        dict) else 0
                    monitor.record_processor(
                        name, int(
                            duration * 1000), "Collected", errors_count, warnings_count)
                except Exception as e:
                    logger.debug(
                        f"[ANALYZER] Failed to record performance: {e}")
            except Exception as e:
                duration = time.time() - processor_start_time
                error_msg = f"{type(e).__name__}: {e}"
                log_processor_end(name, success=False, error=error_msg)
                log_performance(f"Processor {name}", duration, "FAILED")
                logger.exception(f"Processor {name} raised exception")
                # MVP: Zwróć błąd w standardowym formacie
                processed_data[name] = {
                    "status": "Error",
                    "data": None,
                    "errors": [error_msg],
                    "warnings": [],
                    "validation_passed": False,
                    "processor_name": name
                }

                # Faza 2: Rejestruj w monitorze wydajności
                try:
                    from utils.performance_monitor import get_performance_monitor
                    monitor = get_performance_monitor()
                    monitor.record_processor(
                        name, int(duration * 1000), "Error", 1, 0)
                except Exception as e:
                    logger.debug(
                        f"[ANALYZER] Failed to record performance: {e}")

    # Wykryj przyczyny problemów (przed budowaniem raportu)
    if progress_callback:
        progress_callback(
            total_processors + 1,
            total_processors + 4,
            "Detecting root causes...")
    else:
        print("Detecting root causes...")

    logger.info("[ANALYSIS] Detecting root causes")
    cause_detection_start = time.time()
    detected_causes = detect_all_causes(processed_data, collected_data)
    cause_detection_duration = time.time() - cause_detection_start
    logger.info(
        f"[ANALYSIS] Cause detection completed in {cause_detection_duration:.2f}s, found {detected_causes['total_causes']} causes")

    # Dodaj wykryte przyczyny do processed_data, żeby były dostępne w
    # report_builder
    processed_data['detected_causes'] = detected_causes

    # Buduj raport używając nowego systemu
    if progress_callback:
        progress_callback(
            total_processors + 2,
            total_processors + 4,
            "Building report...")
    else:
        print("Building report...")

    report = build_report(processed_data)

    if progress_callback:
        progress_callback(
            total_processors + 3,
            total_processors + 4,
            "Analysis completed")

    # 6. Analiza WHEA (przed BSOD, bo może być użyte w korelacji)
    logger.info("[ANALYSIS] Starting WHEA analysis")
    whea_analysis = None
    if "whea_analyzer" in collectors_data:
        try:
            whea_data = collectors_data.get("whea_analyzer", {})
            # Upewnij się, że whea_data jest słownikiem
            if not isinstance(whea_data, dict):
                logger.warning(
                    f"[ANALYSIS] whea_data is not a dict: {type(whea_data)}, using empty dict")
                whea_data = {}

            bsod_data = collectors_data.get("bsod_dumps", {})
            if not isinstance(bsod_data, dict):
                bsod_data = {}

            hardware_data = collectors_data.get("hardware", {})
            if not isinstance(hardware_data, dict):
                hardware_data = {}

            whea_analysis = whea_processor.process(
                whea_data, bsod_data, hardware_data)
            processed_data["whea"] = whea_analysis
        except Exception as e:
            logger.exception("WHEA analysis raised exception")
            whea_analysis = {"error": f"WHEA analysis failed: {e}"}

    # 7. Analiza BSOD (jeśli dostępne dane)
    bsod_analysis = None
    if "system_logs" in collectors_data and "hardware" in collectors_data and "drivers" in collectors_data:
        try:
            # Pobierz przetworzone logi systemowe
            system_logs_processed = processed_data.get("system_logs", {})
            system_logs_raw = system_logs_processed.get("data", {})

            # Pobierz dane hardware i drivers
            hardware_processed = processed_data.get("hardware", {})
            hardware_raw = hardware_processed.get("data", {})

            drivers_processed = processed_data.get("drivers", {})
            drivers_raw = drivers_processed.get("data", [])

            # Pobierz dane BSOD jeśli dostępne
            bsod_raw = collectors_data.get("bsod_dumps", {})

            # Uruchom analizę BSOD z timeline
            from .bsod_analyzer import analyze_bsod_with_timeline
            bsod_start_time = time.time()
            bsod_analysis = analyze_bsod_with_timeline(
                system_logs_raw,
                hardware_raw,
                drivers_raw,
                bsod_raw,
                time_window_minutes=15,
                max_timeline_events=30
            )
            bsod_duration = time.time() - bsod_start_time
            log_bsod_analysis(
                bsod_analysis.get("bsod_found", False),
                len(bsod_analysis.get("related_events", [])),
                len(bsod_analysis.get("top_causes", []))
            )
            log_performance("BSOD Analysis", bsod_duration)
        except Exception as e:
            # Nie przerywaj jeśli analiza BSOD się nie powiedzie
            error_msg = f"BSOD analysis failed: {type(e).__name__}: {e}"
            logger.exception("BSOD analysis raised exception")
            bsod_analysis = {
                "error": error_msg,
                "bsod_found": False
            }

    # Dodaj metadane
    analysis_duration = time.time() - analysis_start_time
    final_report = {
        "timestamp": collected_data.get("timestamp"),
        "processed_data": processed_data,
        "report": report,
        "whea_analysis": whea_analysis,
        "bsod_analysis": bsod_analysis,
        "detected_causes": detected_causes
    }

    logger.info(f"[ANALYSIS] Analysis completed in {analysis_duration:.2f}s")
    log_performance(
        "Full Analysis",
        analysis_duration,
        f"processed {len(processed_data)} processors, "
        f"found {report.get('summary', {}).get('total_issues', 0)} total issues")

    return final_report
