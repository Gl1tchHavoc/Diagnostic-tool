"""
Scan Manager / Orchestrator - zarządza Quick Scan i Full Scan.
"""
from datetime import datetime
from utils.logger import get_logger
from utils.progress import ProgressCalculator
from collectors.wrapper_collectors import (
    HardwareCollector, DriversCollector, SystemLogsCollector,
    RegistryTxRCollector, StorageHealthCollector, SystemInfoCollector,
    ServicesCollector, BSODDumpsCollector, PerformanceCountersCollector,
    WERCollector, ProcessesCollector
)

logger = get_logger()

class ScanManager:
    """
    Manager skanów - zarządza Quick Scan i Full Scan.
    """
    
    def __init__(self, scan_type="full", progress_callback=None):
        """
        Inicjalizuje manager skanów.
        
        Args:
            scan_type (str): Typ skanu ("quick" lub "full")
            progress_callback (callable): Funkcja callback(progress, message) do raportowania postępu
        """
        self.scan_type = scan_type.lower()
        self.progress_callback = progress_callback
        self.collectors = []
        self.weights = {}
        self._logger = get_logger()
        
        self._initialize_collectors()
    
    def _initialize_collectors(self):
        """Inicjalizuje kolektory w zależności od typu skanu."""
        if self.scan_type == "quick":
            # Quick Scan - tylko podstawowe kolektory
            self.collectors = [
                HardwareCollector("hardware"),
                DriversCollector("drivers")
            ]
            # Wagi dla Quick Scan: 50% Hardware, 50% Drivers
            self.weights = {
                "hardware": 50.0,
                "drivers": 50.0
            }
        else:
            # Full Scan - wszystkie kolektory
            self.collectors = [
                HardwareCollector("hardware"),
                DriversCollector("drivers"),
                SystemLogsCollector("system_logs"),
                RegistryTxRCollector("registry_txr"),
                StorageHealthCollector("storage_health"),
                SystemInfoCollector("system_info"),
                ServicesCollector("services"),
                BSODDumpsCollector("bsod_dumps"),
                PerformanceCountersCollector("performance_counters"),
                WERCollector("wer"),
                ProcessesCollector("processes")
            ]
            # Wagi dla Full Scan - proporcjonalnie do czasu/zasobów
            self.weights = {
                "hardware": 15.0,
                "drivers": 15.0,
                "system_logs": 20.0,  # Często najdłuższy
                "registry_txr": 5.0,
                "storage_health": 10.0,
                "system_info": 5.0,
                "services": 10.0,
                "bsod_dumps": 5.0,
                "performance_counters": 5.0,
                "wer": 5.0,
                "processes": 5.0
            }
    
    def run(self):
        """
        Uruchamia skan i zwraca wyniki.
        
        Returns:
            dict: {
                'scan_type': str,
                'timestamp': str,
                'results': dict,
                'progress_info': dict,
                'status_summary': dict
            }
        """
        self._logger.info(f"[SCAN_MANAGER] Starting {self.scan_type.upper()} scan with {len(self.collectors)} collectors")
        
        # Utwórz ProgressCalculator
        progress_calc = ProgressCalculator(self.collectors, self.weights)
        
        results = {
            "timestamp": datetime.now().isoformat(),
            "collectors": {}
        }
        
        # Uruchom wszystkie kolektory
        for collector in self.collectors:
            self._logger.info(f"[SCAN_MANAGER] Running collector: {collector.name}")
            
            # Raportuj postęp przed uruchomieniem
            if self.progress_callback:
                progress_info = progress_calc.get_progress()
                self.progress_callback(progress_info['global_progress'], f"Running {collector.name}...")
            
            # Uruchom kolektor
            collector_result = collector.run()
            
            # Zapisz wyniki
            results["collectors"][collector.name] = collector_result.get('data', {})
            
            # Raportuj postęp po zakończeniu
            if self.progress_callback:
                progress_info = progress_calc.get_progress()
                self.progress_callback(progress_info['global_progress'], f"Completed {collector.name}")
        
        # Pobierz finalne informacje o postępie
        progress_info = progress_calc.get_detailed_progress()
        status_summary = progress_calc.get_status_summary()
        
        self._logger.info(f"[SCAN_MANAGER] {self.scan_type.upper()} scan completed. Final progress: {progress_info['global_progress']}%")
        
        return {
            'scan_type': self.scan_type,
            'timestamp': results['timestamp'],
            'results': results,
            'progress_info': progress_info,
            'status_summary': status_summary
        }

class QuickScan(ScanManager):
    """Quick Scan - szybki skan podstawowych komponentów."""
    
    def __init__(self, progress_callback=None):
        super().__init__("quick", progress_callback)

class FullScan(ScanManager):
    """Full Scan - pełny skan wszystkich komponentów."""
    
    def __init__(self, progress_callback=None):
        super().__init__("full", progress_callback)

