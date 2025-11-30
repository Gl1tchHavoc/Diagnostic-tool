"""
Wrapper kolektory - opakowują istniejące funkcje collect() w BaseCollector.
"""
from collectors.base_collector import BaseCollector
from . import (
    hardware, drivers, system_logs, registry_txr, storage_health, system_info,
    services, bsod_dumps, performance_counters, wer, processes
)

class HardwareCollector(BaseCollector):
    """Kolektor danych sprzętowych."""
    
    def collect(self):
        self.set_progress(10.0, "Initializing")
        data = hardware.collect()
        self.set_progress(100.0, "Complete")
        return data

class DriversCollector(BaseCollector):
    """Kolektor danych o driverach."""
    
    def collect(self):
        self.set_progress(10.0, "Initializing")
        data = drivers.collect()
        self.set_progress(100.0, "Complete")
        return data

class SystemLogsCollector(BaseCollector):
    """Kolektor logów systemowych."""
    
    def collect(self):
        self.set_progress(10.0, "Collecting System logs")
        data = system_logs.collect(max_events=200, filter_levels=None)
        self.set_progress(50.0, "Collecting Application logs")
        # System logs już zbiera wszystkie kategorie, więc progress jest symulowany
        self.set_progress(100.0, "Complete")
        return data

class RegistryTxRCollector(BaseCollector):
    """Kolektor błędów Registry TxR."""
    
    def collect(self):
        self.set_progress(10.0, "Initializing")
        data = registry_txr.collect(max_events=200)
        self.set_progress(100.0, "Complete")
        return data

class StorageHealthCollector(BaseCollector):
    """Kolektor danych o zdrowiu dysków."""
    
    def collect(self):
        self.set_progress(10.0, "Initializing")
        data = storage_health.collect()
        self.set_progress(100.0, "Complete")
        return data

class SystemInfoCollector(BaseCollector):
    """Kolektor informacji o systemie."""
    
    def collect(self):
        self.set_progress(10.0, "Initializing")
        data = system_info.collect()
        self.set_progress(100.0, "Complete")
        return data

class ServicesCollector(BaseCollector):
    """Kolektor danych o usługach."""
    
    def collect(self):
        self.set_progress(10.0, "Initializing")
        data = services.collect()
        self.set_progress(100.0, "Complete")
        return data

class BSODDumpsCollector(BaseCollector):
    """Kolektor danych BSOD i memory dumps."""
    
    def collect(self):
        self.set_progress(10.0, "Collecting BSOD events")
        data = bsod_dumps.collect()
        self.set_progress(100.0, "Complete")
        return data

class PerformanceCountersCollector(BaseCollector):
    """Kolektor performance counters."""
    
    def collect(self):
        self.set_progress(10.0, "Initializing")
        data = performance_counters.collect()
        self.set_progress(100.0, "Complete")
        return data

class WHEAAnalyzerCollector(BaseCollector):
    """Kolektor WHEA (Windows Hardware Error Architecture)."""
    
    def collect(self):
        self.set_progress(10.0, "Initializing")
        import collectors.whea_analyzer as whea_analyzer
        data = whea_analyzer.collect()
        self.set_progress(100.0, "Complete")
        return data

class WERCollector(BaseCollector):
    """Kolektor Windows Error Reporting."""
    
    def collect(self):
        self.set_progress(10.0, "Initializing")
        data = wer.collect()
        self.set_progress(100.0, "Complete")
        return data

class ProcessesCollector(BaseCollector):
    """Kolektor danych o procesach."""
    
    def collect(self):
        self.set_progress(10.0, "Initializing")
        data = processes.collect()
        self.set_progress(100.0, "Complete")
        return data

