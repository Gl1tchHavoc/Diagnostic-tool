"""
Główny analyzer - łączy wszystkie procesory i nowy system scoringu w kompleksową analizę.
"""
import time
from . import (
    hardware_processor, driver_processor, system_logs_processor,
    registry_txr_processor, storage_health_processor, system_info_processor
)
from .report_builder import build_report
from .bsod_analyzer import analyze_bsod
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
    
    collectors_data = collected_data.get("collectors", {})
    processed_data = {}
    
    # Lista procesorów do wykonania
    processors_list = [
        ("hardware", "Processing hardware data...", "hardware", hardware_processor.process),
        ("drivers", "Processing drivers data...", "drivers", driver_processor.process),
        ("system_logs", "Processing system logs...", "system_logs", system_logs_processor.process),
        ("registry_txr", "Processing Registry TxR errors...", "registry_txr", registry_txr_processor.process),
        ("storage_health", "Processing storage health...", "storage_health", storage_health_processor.process),
        ("system_info", "Processing system info...", "system_info", system_info_processor.process),
    ]
    
    total_processors = len(processors_list)
    
    # Przetwórz wszystkie dane
    for step, (name, message, key, processor_func) in enumerate(processors_list, 1):
        if progress_callback:
            progress_callback(step, total_processors, message)
        else:
            print(message)
        
        log_processor_start(name)
        processor_start_time = time.time()
        
        if key in collectors_data:
            try:
                processor_result = processor_func(collectors_data[key])
                duration = time.time() - processor_start_time
                
                # Policz znalezione problemy
                issues_count = 0
                if isinstance(processor_result, dict):
                    issues_count = (
                        len(processor_result.get("issues", [])) +
                        len(processor_result.get("critical_issues", [])) +
                        len(processor_result.get("critical_events", [])) +
                        len(processor_result.get("warnings", []))
                    )
                
                processed_data[name] = processor_result
                log_processor_end(name, success=True, issues_found=issues_count)
                log_performance(f"Processor {name}", duration, f"found {issues_count} issues")
            except Exception as e:
                duration = time.time() - processor_start_time
                error_msg = f"{type(e).__name__}: {e}"
                log_processor_end(name, success=False, error=error_msg)
                log_performance(f"Processor {name}", duration, "FAILED")
                logger.exception(f"Processor {name} raised exception")
                processed_data[name] = {"error": error_msg}
    
    # Buduj raport używając nowego systemu
    if progress_callback:
        progress_callback(total_processors + 1, total_processors + 2, "Building report...")
    else:
        print("Building report...")
    
    report = build_report(processed_data)
    
    if progress_callback:
        progress_callback(total_processors + 2, total_processors + 2, "Analysis completed")
    
    # 6. Analiza BSOD (jeśli dostępne dane)
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
        "bsod_analysis": bsod_analysis
    }
    
    logger.info(f"[ANALYSIS] Analysis completed in {analysis_duration:.2f}s")
    log_performance("Full Analysis", analysis_duration, 
                   f"processed {len(processed_data)} processors, "
                   f"found {report.get('summary', {}).get('total_issues', 0)} total issues")
    
    return final_report
