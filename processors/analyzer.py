"""
Główny analyzer - łączy wszystkie procesory i nowy system scoringu w kompleksową analizę.
"""
from . import (
    hardware_processor, driver_processor, system_logs_processor,
    registry_txr_processor, storage_health_processor, system_info_processor
)
from .report_builder import build_report

def analyze_all(collected_data):
    """
    Analizuje wszystkie zebrane dane i zwraca kompleksowy raport.
    
    Args:
        collected_data (dict): Dane z collectors.collector_master.collect_all()
    
    Returns:
        dict: Kompleksowy raport analizy
    """
    collectors_data = collected_data.get("collectors", {})
    processed_data = {}
    
    # Przetwórz wszystkie dane
    print("Processing hardware data...")
    if "hardware" in collectors_data:
        processed_data["hardware"] = hardware_processor.process(collectors_data["hardware"])
    
    print("Processing drivers data...")
    if "drivers" in collectors_data:
        processed_data["drivers"] = driver_processor.process(collectors_data["drivers"])
    
    print("Processing system logs...")
    if "system_logs" in collectors_data:
        processed_data["system_logs"] = system_logs_processor.process(collectors_data["system_logs"])
    
    print("Processing Registry TxR errors...")
    if "registry_txr" in collectors_data:
        processed_data["registry_txr"] = registry_txr_processor.process(collectors_data["registry_txr"])
    
    print("Processing storage health...")
    if "storage_health" in collectors_data:
        processed_data["storage_health"] = storage_health_processor.process(collectors_data["storage_health"])
    
    print("Processing system info...")
    if "system_info" in collectors_data:
        processed_data["system_info"] = system_info_processor.process(collectors_data["system_info"])
    
    # Przetwórz nowe collectory jeśli są dostępne (dodaj procesory gdy będą gotowe)
    # Na razie używamy surowych danych - procesory można dodać później
    
    # Buduj raport używając nowego systemu
    print("Building report...")
    report = build_report(processed_data)
    
    # Dodaj metadane
    final_report = {
        "timestamp": collected_data.get("timestamp"),
        "processed_data": processed_data,
        "report": report
    }
    
    return final_report
