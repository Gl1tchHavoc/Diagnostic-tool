"""
Główny analyzer - łączy wszystkie procesory i nowy system scoringu w kompleksową analizę.
"""
from . import (
    hardware_processor, driver_processor, system_logs_processor,
    registry_txr_processor, storage_health_processor, system_info_processor
)
from .report_builder import build_report
from .bsod_analyzer import analyze_bsod

def analyze_all(collected_data, progress_callback=None):
    """
    Analizuje wszystkie zebrane dane i zwraca kompleksowy raport.
    
    Args:
        collected_data (dict): Dane z collectors.collector_master.collect_all()
        progress_callback (callable): Funkcja callback(step, total, message) do raportowania postępu
    
    Returns:
        dict: Kompleksowy raport analizy
    """
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
        
        if key in collectors_data:
            processed_data[name] = processor_func(collectors_data[key])
    
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
            
            # Uruchom analizę BSOD
            bsod_analysis = analyze_bsod(
                system_logs_raw,
                hardware_raw,
                drivers_raw,
                bsod_raw
            )
        except Exception as e:
            # Nie przerywaj jeśli analiza BSOD się nie powiedzie
            bsod_analysis = {
                "error": f"BSOD analysis failed: {type(e).__name__}: {e}",
                "bsod_found": False
            }
    
    # Dodaj metadane
    final_report = {
        "timestamp": collected_data.get("timestamp"),
        "processed_data": processed_data,
        "report": report,
        "bsod_analysis": bsod_analysis
    }
    
    return final_report
