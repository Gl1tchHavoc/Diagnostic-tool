"""
Collector Registry - rejestr wszystkich dostępnych collectorów.
Umożliwia modularne dodawanie nowych collectorów bez zmian w głównym pipeline.
"""
from typing import Dict, Callable, Optional, List
from utils.logger import get_logger

logger = get_logger()


class CollectorRegistry:
    """
    Rejestr collectorów - centralne miejsce rejestracji i zarządzania collectorami.
    """
    
    def __init__(self):
        """Inicjalizuje rejestr collectorów."""
        self._collectors: Dict[str, Dict[str, any]] = {}
        logger.info("[COLLECTOR_REGISTRY] Initialized")
    
    def register(self, name: str, collect_func: Callable, description: str = "", 
                 category: str = "general", enabled: bool = True):
        """
        Rejestruje nowy collector.
        
        Args:
            name: Nazwa collectora (np. "hardware")
            collect_func: Funkcja collect() do wywołania
            description: Opis collectora
            category: Kategoria (hardware, system, logs, etc.)
            enabled: Czy collector jest domyślnie włączony
        """
        self._collectors[name] = {
            "name": name,
            "collect_func": collect_func,
            "description": description,
            "category": category,
            "enabled": enabled
        }
        logger.debug(f"[COLLECTOR_REGISTRY] Registered collector: {name} ({category})")
    
    def get(self, name: str) -> Optional[Dict]:
        """
        Pobiera informacje o collectorze.
        
        Args:
            name: Nazwa collectora
        
        Returns:
            dict: Informacje o collectorze lub None
        """
        return self._collectors.get(name)
    
    def get_all(self, enabled_only: bool = False) -> Dict[str, Dict]:
        """
        Pobiera wszystkie collectory.
        
        Args:
            enabled_only: Czy zwrócić tylko włączone collectory
        
        Returns:
            dict: Wszystkie collectory
        """
        if enabled_only:
            return {name: info for name, info in self._collectors.items() if info.get("enabled", True)}
        return self._collectors.copy()
    
    def get_by_category(self, category: str) -> List[str]:
        """
        Pobiera collectory z danej kategorii.
        
        Args:
            category: Kategoria
        
        Returns:
            list: Lista nazw collectorów
        """
        return [name for name, info in self._collectors.items() 
                if info.get("category") == category]
    
    def is_enabled(self, name: str) -> bool:
        """
        Sprawdza czy collector jest włączony.
        
        Args:
            name: Nazwa collectora
        
        Returns:
            bool: True jeśli włączony
        """
        collector = self._collectors.get(name)
        return collector is not None and collector.get("enabled", True)
    
    def set_enabled(self, name: str, enabled: bool) -> bool:
        """
        Włącza/wyłącza collector.
        
        Args:
            name: Nazwa collectora
            enabled: Czy włączyć
        
        Returns:
            bool: True jeśli collector istnieje
        """
        if name in self._collectors:
            self._collectors[name]["enabled"] = enabled
            logger.info(f"[COLLECTOR_REGISTRY] {'Enabled' if enabled else 'Disabled'} collector: {name}")
            return True
        return False


# Globalna instancja rejestru
_registry_instance: Optional[CollectorRegistry] = None

def get_registry() -> CollectorRegistry:
    """Zwraca globalną instancję rejestru collectorów."""
    global _registry_instance
    if _registry_instance is None:
        _registry_instance = CollectorRegistry()
    return _registry_instance

def register_all_collectors():
    """
    Rejestruje wszystkie dostępne collectory.
    Wywoływane przy starcie aplikacji.
    """
    from collectors import (
        hardware, drivers, system_logs, registry_txr, storage_health, system_info,
        services, bsod_dumps, performance_counters, wer, processes
    )
    import collectors.whea_analyzer as whea_analyzer
    
    registry = get_registry()
    
    # Rejestracja wszystkich collectorów
    registry.register("hardware", hardware.collect, 
                     "Hardware information (CPU, RAM, GPU, disks)", "hardware")
    registry.register("drivers", drivers.collect, 
                     "Driver information and status", "system")
    registry.register("system_logs", lambda: system_logs.collect(max_events=200, filter_levels=None),
                     "System event logs", "logs")
    registry.register("registry_txr", lambda: registry_txr.collect(max_events=200),
                     "Registry Transaction errors", "system")
    registry.register("storage_health", storage_health.collect,
                     "Storage health and SMART data", "storage")
    registry.register("system_info", system_info.collect,
                     "System information (OS, uptime, updates)", "system")
    registry.register("services", services.collect,
                     "Windows services status", "system")
    registry.register("bsod_dumps", bsod_dumps.collect,
                     "BSOD and memory dump analysis", "logs")
    registry.register("whea_analyzer", whea_analyzer.collect,
                     "WHEA hardware errors", "hardware")
    registry.register("performance_counters", performance_counters.collect,
                     "Performance counters", "system")
    registry.register("wer", wer.collect,
                     "Windows Error Reporting (application crashes)", "logs")
    registry.register("processes", processes.collect,
                     "Running processes information", "system")
    
    logger.info(f"[COLLECTOR_REGISTRY] Registered {len(registry.get_all())} collectors")

