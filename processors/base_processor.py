"""
Base Processor - klasa bazowa dla wszystkich procesorów MVP.
Każdy processor MVP powinien parsować i walidować dane z collectorów.
"""
from datetime import datetime
from typing import Dict, Any, List, Optional
from utils.logger import get_logger

logger = get_logger()


def process_collector_data(collector_result: Dict[str, Any], processor_name: str) -> Dict[str, Any]:
    """
    MVP: Minimalny processor - parsuje i waliduje dane z collectora.
    
    Args:
        collector_result (dict): Wynik z collectora w formacie MVP:
            {
                "status": "Collected" | "Error",
                "data": {...},
                "error": null | "error message",
                "timestamp": "ISO timestamp",
                "collector_name": "hardware",
                "execution_time_ms": 1234
            }
        processor_name (str): Nazwa procesora
    
    Returns:
        dict: Przetworzone dane w formacie MVP:
            {
                "status": "Collected" | "Error",
                "data": {...},  # przetworzone dane
                "errors": [],  # lista błędów walidacji
                "warnings": [],  # lista ostrzeżeń
                "validation_passed": true,
                "timestamp": "ISO timestamp",
                "processor_name": "hardware_processor"
            }
    """
    processor_start_time = datetime.now()
    
    # Jeśli collector zwrócił błąd, zwróć błąd w formacie procesora
    if collector_result.get("status") == "Error":
        return {
            "status": "Error",
            "data": None,
            "errors": [collector_result.get("error", "Unknown error")],
            "warnings": [],
            "validation_passed": False,
            "timestamp": processor_start_time.isoformat(),
            "processor_name": processor_name
        }
    
    # Pobierz dane z collectora
    collector_data = collector_result.get("data")
    
    # Walidacja podstawowa
    errors = []
    warnings = []
    validation_passed = True
    
    # Sprawdź czy dane są None
    if collector_data is None:
        errors.append("Collector data is None")
        validation_passed = False
    
    # Sprawdź typ danych
    elif not isinstance(collector_data, (dict, list)):
        errors.append(f"Invalid data type: {type(collector_data).__name__}, expected dict or list")
        validation_passed = False
    
    # Jeśli są błędy walidacji, zwróć błąd
    if not validation_passed:
        return {
            "status": "Error",
            "data": None,
            "errors": errors,
            "warnings": warnings,
            "validation_passed": False,
            "timestamp": processor_start_time.isoformat(),
            "processor_name": processor_name
        }
    
    # Domyślnie zwróć dane bez zmian (parser może być rozszerzony w konkretnych procesorach)
    return {
        "status": "Collected",
        "data": collector_data,
        "errors": errors,
        "warnings": warnings,
        "validation_passed": True,
        "timestamp": processor_start_time.isoformat(),
        "processor_name": processor_name
    }


def validate_data_structure(data: Any, required_fields: Optional[List[str]] = None) -> tuple[List[str], List[str]]:
    """
    Waliduje strukturę danych.
    
    Args:
        data: Dane do walidacji
        required_fields: Lista wymaganych pól (dla dict)
    
    Returns:
        tuple: (errors, warnings) - listy błędów i ostrzeżeń
    """
    errors = []
    warnings = []
    
    if required_fields and isinstance(data, dict):
        for field in required_fields:
            if field not in data:
                errors.append(f"Missing required field: {field}")
    
    return errors, warnings

