"""
Processor Registry - rejestr wszystkich dostępnych procesorów.
Umożliwia modularne dodawanie nowych procesorów bez zmian w głównym pipeline.
"""
from typing import Dict, Callable, Optional
from utils.logger import get_logger

logger = get_logger()


class ProcessorRegistry:
    """
    Rejestr procesorów - centralne miejsce rejestracji i zarządzania procesorami.
    """
    
    def __init__(self):
        """Inicjalizuje rejestr procesorów."""
        self._processors: Dict[str, Dict[str, any]] = {}
        logger.info("[PROCESSOR_REGISTRY] Initialized")
    
    def register(self, name: str, process_func: Callable, description: str = "",
                 collector_name: Optional[str] = None, enabled: bool = True):
        """
        Rejestruje nowy processor.
        
        Args:
            name: Nazwa procesora (np. "hardware_processor")
            process_func: Funkcja process() do wywołania
            description: Opis procesora
            collector_name: Nazwa powiązanego collectora (np. "hardware")
            enabled: Czy processor jest domyślnie włączony
        """
        self._processors[name] = {
            "name": name,
            "process_func": process_func,
            "description": description,
            "collector_name": collector_name,
            "enabled": enabled
        }
        logger.debug(f"[PROCESSOR_REGISTRY] Registered processor: {name}")
    
    def get(self, name: str) -> Optional[Dict]:
        """
        Pobiera informacje o processorze.
        
        Args:
            name: Nazwa procesora
        
        Returns:
            dict: Informacje o processorze lub None
        """
        return self._processors.get(name)
    
    def get_all(self, enabled_only: bool = False) -> Dict[str, Dict]:
        """
        Pobiera wszystkie procesory.
        
        Args:
            enabled_only: Czy zwrócić tylko włączone procesory
        
        Returns:
            dict: Wszystkie procesory
        """
        if enabled_only:
            return {name: info for name, info in self._processors.items() if info.get("enabled", True)}
        return self._processors.copy()
    
    def get_for_collector(self, collector_name: str) -> Optional[str]:
        """
        Pobiera nazwę procesora dla danego collectora.
        
        Args:
            collector_name: Nazwa collectora
        
        Returns:
            str: Nazwa procesora lub None
        """
        for name, info in self._processors.items():
            if info.get("collector_name") == collector_name:
                return name
        return None
    
    def is_enabled(self, name: str) -> bool:
        """
        Sprawdza czy processor jest włączony.
        
        Args:
            name: Nazwa procesora
        
        Returns:
            bool: True jeśli włączony
        """
        processor = self._processors.get(name)
        return processor is not None and processor.get("enabled", True)


# Globalna instancja rejestru
_registry_instance: Optional[ProcessorRegistry] = None

def get_registry() -> ProcessorRegistry:
    """Zwraca globalną instancję rejestru procesorów."""
    global _registry_instance
    if _registry_instance is None:
        _registry_instance = ProcessorRegistry()
    return _registry_instance

def register_all_processors():
    """
    Rejestruje wszystkie dostępne procesory.
    Wywoływane przy starcie aplikacji.
    """
    from processors import (
        hardware_processor, driver_processor, system_logs_processor,
        registry_txr_processor, storage_health_processor, system_info_processor
    )
    
    registry = get_registry()
    
    # Rejestracja wszystkich procesorów
    registry.register("hardware_processor", hardware_processor.process,
                     "Processes hardware data", "hardware")
    registry.register("driver_processor", driver_processor.process,
                     "Processes driver data", "drivers")
    registry.register("system_logs_processor", system_logs_processor.process,
                     "Processes system logs", "system_logs")
    registry.register("registry_txr_processor", registry_txr_processor.process,
                     "Processes Registry TxR errors", "registry_txr")
    registry.register("storage_health_processor", storage_health_processor.process,
                     "Processes storage health data", "storage_health")
    registry.register("system_info_processor", system_info_processor.process,
                     "Processes system info", "system_info")
    
    logger.info(f"[PROCESSOR_REGISTRY] Registered {len(registry.get_all())} processors")

