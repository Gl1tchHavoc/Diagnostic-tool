"""
Scan Manager / Orchestrator - zarządza Quick Scan i Full Scan.
"""
from datetime import datetime
from utils.logger import get_logger
from utils.progress import ProgressCalculator
from collectors.wrapper_collectors import (
    HardwareCollector, DriversCollector, SystemLogsCollector,
    RegistryTxRCollector, StorageHealthCollector, SystemInfoCollector,
    ServicesCollector, BSODDumpsCollector, WHEAAnalyzerCollector,
    PerformanceCountersCollector, WERCollector, ProcessesCollector
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
                WHEAAnalyzerCollector("whea_analyzer"),
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
                "whea_analyzer": 8.0,
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
            try:
                self._logger.debug(f"[SCAN_MANAGER] DEBUG: About to run collector: {collector.name}")
                collector_result = collector.run()
                self._logger.debug(f"[SCAN_MANAGER] Collector {collector.name} returned: {type(collector_result)}")
                
                # DEBUG: Szczegółowe logowanie dla WER
                if collector.name == "wer":
                    self._logger.debug(f"[SCAN_MANAGER] DEBUG: WER collector_result type: {type(collector_result)}")
                    self._logger.debug(f"[SCAN_MANAGER] DEBUG: WER collector_result is dict: {isinstance(collector_result, dict)}")
                    if isinstance(collector_result, dict):
                        self._logger.debug(f"[SCAN_MANAGER] DEBUG: WER collector_result keys: {list(collector_result.keys())}")
                        if 'data' in collector_result:
                            self._logger.debug(f"[SCAN_MANAGER] DEBUG: WER collector_result['data'] type: {type(collector_result['data'])}")
                            if isinstance(collector_result['data'], dict) and 'grouped_crashes' in collector_result['data']:
                                self._logger.debug(f"[SCAN_MANAGER] DEBUG: WER grouped_crashes type: {type(collector_result['data']['grouped_crashes'])}")
                                self._logger.debug(f"[SCAN_MANAGER] DEBUG: WER grouped_crashes is list: {isinstance(collector_result['data']['grouped_crashes'], list)}")
            except Exception as e:
                self._logger.exception(f"[SCAN_MANAGER] Collector {collector.name} raised exception: {e}")
                collector_result = {
                    'name': collector.name,
                    'status': 'ERROR',
                    'progress': 0.0,
                    'data': {'error': str(e)},
                    'error': str(e)
                }
            
            # Zapisz wyniki - upewnij się, że collector_result jest słownikiem
            try:
                self._logger.debug(f"[SCAN_MANAGER] DEBUG: About to save results for {collector.name}")
                
                # KRYTYCZNE ZABEZPIECZENIE: collector_result może być listą zamiast dict!
                if isinstance(collector_result, list):
                    self._logger.error(f"[SCAN_MANAGER] CRITICAL: collector_result for {collector.name} is list (length: {len(collector_result)}) instead of dict!")
                    from utils.error_analyzer import log_error_with_analysis
                    log_error_with_analysis(
                        TypeError(f"collector_result is list instead of dict"),
                        collector_result,
                        {
                            'variable_name': 'collector_result',
                            'location': 'scan_manager.py:144',
                            'function': 'ScanManager.run'
                        },
                        continue_execution=True
                    )
                    collector_data = {'error': f'Collector result is list instead of dict (length: {len(collector_result)})'}
                elif isinstance(collector_result, dict):
                    collector_data = collector_result.get('data', {})
                    
                    # KRYTYCZNE ZABEZPIECZENIE: collector_data może być listą zamiast dict!
                    # Jeśli jest listą, to błąd - konwertuj na dict z błędem
                    if isinstance(collector_data, list):
                        self._logger.error(f"[SCAN_MANAGER] CRITICAL: collector_data for {collector.name} is list (length: {len(collector_data)}) instead of dict! Converting...")
                        # Użyj error_analyzer do kompleksowej analizy
                        from utils.error_analyzer import log_error_with_analysis
                        log_error_with_analysis(
                            TypeError(f"collector_data is list instead of dict"),
                            collector_data,
                            {
                                'variable_name': f'collector_result["data"]',
                                'location': 'scan_manager.py:145',
                                'function': 'ScanManager.run'
                            },
                            continue_execution=True
                        )
                        collector_data = {'error': f'Data is list instead of dict (length: {len(collector_data)})'}
                    elif not isinstance(collector_data, dict):
                        self._logger.warning(f"[SCAN_MANAGER] collector_data for {collector.name} is not a dict: {type(collector_data)}")
                        collector_data = {'error': f'Data is {type(collector_data).__name__} instead of dict'}
                    
                    # ZABEZPIECZENIE: Upewnij się, że collector_data jest bezpieczny do zapisania
                    if collector.name == "wer" and isinstance(collector_data, dict):
                        collector_data = self._sanitize_wer_data(collector_data)
                    
                    # DEBUG: Szczegółowe logowanie dla WER (tylko podstawowe info, nie pełne dane)
                    if collector.name == "wer":
                        self._logger.debug(f"[SCAN_MANAGER] DEBUG: WER collector_data type: {type(collector_data)}")
                        self._logger.debug(f"[SCAN_MANAGER] DEBUG: WER collector_data is dict: {isinstance(collector_data, dict)}")
                        if isinstance(collector_data, dict):
                            self._logger.debug(f"[SCAN_MANAGER] DEBUG: WER collector_data keys: {list(collector_data.keys())}")
                            if 'grouped_crashes' in collector_data:
                                gc = collector_data['grouped_crashes']
                                self._logger.debug(f"[SCAN_MANAGER] DEBUG: WER grouped_crashes type: {type(gc)}, is_list: {isinstance(gc, list)}")
                                if isinstance(gc, list):
                                    self._logger.debug(f"[SCAN_MANAGER] DEBUG: WER grouped_crashes length: {len(gc)}")
                    
                    results["collectors"][collector.name] = collector_data
                    self._logger.debug(f"[SCAN_MANAGER] Saved data for {collector.name}, type: {type(collector_data)}")
                    
                    # DEBUG: Sprawdź co zostało zapisane
                    if collector.name == "wer":
                        saved_data = results["collectors"].get(collector.name, {})
                        self._logger.debug(f"[SCAN_MANAGER] DEBUG: WER saved_data type: {type(saved_data)}")
                        if isinstance(saved_data, dict) and 'grouped_crashes' in saved_data:
                            self._logger.debug(f"[SCAN_MANAGER] DEBUG: WER saved_data['grouped_crashes'] type: {type(saved_data['grouped_crashes'])}")
                else:
                    # Jeśli kolektor zwrócił listę lub coś innego, zapisz jako data
                    self._logger.warning(f"[SCAN_MANAGER] Collector {collector.name} returned non-dict: {type(collector_result)}")
                    results["collectors"][collector.name] = collector_result if collector_result is not None else {}
            except Exception as e:
                self._logger.exception(f"[SCAN_MANAGER] Error saving results for {collector.name}: {e}")
                results["collectors"][collector.name] = {'error': f"Failed to save results: {e}"}
            
            # Raportuj postęp po zakończeniu
            if self.progress_callback:
                try:
                    self._logger.debug(f"[SCAN_MANAGER] DEBUG: About to get progress for {collector.name}")
                    progress_info = progress_calc.get_progress()
                    self._logger.debug(f"[SCAN_MANAGER] DEBUG: progress_info type: {type(progress_info)}")
                    self._logger.debug(f"[SCAN_MANAGER] DEBUG: progress_info is dict: {isinstance(progress_info, dict)}")
                    if isinstance(progress_info, dict):
                        self._logger.debug(f"[SCAN_MANAGER] DEBUG: progress_info keys: {list(progress_info.keys())}")
                        self._logger.debug(f"[SCAN_MANAGER] DEBUG: progress_info has 'global_progress': {'global_progress' in progress_info}")
                    
                    if isinstance(progress_info, dict) and 'global_progress' in progress_info:
                        self._logger.debug(f"[SCAN_MANAGER] DEBUG: Calling progress_callback with progress: {progress_info['global_progress']}")
                        self.progress_callback(progress_info['global_progress'], f"Completed {collector.name}")
                        self._logger.debug(f"[SCAN_MANAGER] DEBUG: progress_callback completed for {collector.name}")
                    else:
                        self._logger.warning(f"[SCAN_MANAGER] Invalid progress_info: {progress_info}")
                        self.progress_callback(100.0, f"Completed {collector.name}")
                except Exception as e:
                    self._logger.exception(f"[SCAN_MANAGER] Error in progress callback for {collector.name}: {e}")
                    self._logger.debug(f"[SCAN_MANAGER] DEBUG: Exception type: {type(e).__name__}, message: {str(e)}")
        
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
    
    def _sanitize_wer_data(self, wer_data):
        """
        Sanityzuje dane WER przed zapisaniem - usuwa potencjalnie problematyczne wartości.
        
        Args:
            wer_data: Dane WER do sanityzacji
            
        Returns:
            dict: Zsanityzowane dane WER
        """
        # KRYTYCZNE ZABEZPIECZENIE: wer_data może być listą zamiast dict!
        if isinstance(wer_data, list):
            self._logger.error(f"[SCAN_MANAGER] CRITICAL: WER data is list (length: {len(wer_data)}) instead of dict! Converting...")
            # Użyj error_analyzer do kompleksowej analizy
            from utils.error_analyzer import log_error_with_analysis
            log_error_with_analysis(
                TypeError(f"wer_data is list instead of dict"),
                wer_data,
                {
                    'variable_name': 'wer_data',
                    'location': 'scan_manager.py:226',
                    'function': '_sanitize_wer_data'
                },
                continue_execution=True
            )
            return {'error': f'WER data is list instead of dict (length: {len(wer_data)})'}
        elif not isinstance(wer_data, dict):
            self._logger.warning(f"[SCAN_MANAGER] WER data is not a dict: {type(wer_data)}")
            # Użyj error_analyzer do kompleksowej analizy
            from utils.error_analyzer import log_error_with_analysis
            log_error_with_analysis(
                TypeError(f"wer_data is {type(wer_data).__name__} instead of dict"),
                wer_data,
                {
                    'variable_name': 'wer_data',
                    'location': 'scan_manager.py:232',
                    'function': '_sanitize_wer_data'
                },
                continue_execution=True
            )
            return {'error': f'WER data is {type(wer_data).__name__} instead of dict'}
        
        try:
            sanitized = {}
            
            # recent_crashes - upewnij się, że to lista
            if 'recent_crashes' in wer_data:
                recent = wer_data['recent_crashes']
                if isinstance(recent, list):
                    sanitized['recent_crashes'] = recent
                else:
                    self._logger.warning(f"[SCAN_MANAGER] WER recent_crashes is not a list: {type(recent)}")
                    sanitized['recent_crashes'] = []
            else:
                sanitized['recent_crashes'] = []
            
            # reports - upewnij się, że to lista
            if 'reports' in wer_data:
                reports = wer_data['reports']
                if isinstance(reports, list):
                    sanitized['reports'] = reports
                else:
                    self._logger.warning(f"[SCAN_MANAGER] WER reports is not a list: {type(reports)}")
                    sanitized['reports'] = []
            else:
                sanitized['reports'] = []
            
            # grouped_crashes - KRYTYCZNE: musi być ZAWSZE listą (konsumenci iterują po niej)
            if 'grouped_crashes' in wer_data:
                grouped = wer_data['grouped_crashes']
                if isinstance(grouped, list):
                    # Dodatkowa walidacja: upewnij się, że wszystkie elementy są dict
                    validated_grouped = []
                    for i, item in enumerate(grouped):
                        if isinstance(item, dict):
                            validated_grouped.append(item)
                        else:
                            self._logger.warning(f"[SCAN_MANAGER] grouped_crashes[{i}] is not a dict: {type(item)}, skipping")
                    sanitized['grouped_crashes'] = validated_grouped
                elif isinstance(grouped, dict):
                    # BŁĄD: grouped_crashes jest dict zamiast listy - konwertuj
                    self._logger.error(f"[SCAN_MANAGER] CRITICAL: grouped_crashes is dict (keys: {list(grouped.keys())[:5]}) instead of list! Converting...")
                    sanitized['grouped_crashes'] = [grouped] if grouped else []
                else:
                    self._logger.warning(f"[SCAN_MANAGER] WER grouped_crashes is not a list: {type(grouped)}, converting to empty list")
                    sanitized['grouped_crashes'] = []
            else:
                sanitized['grouped_crashes'] = []
            
            # statistics - upewnij się, że to dict
            if 'statistics' in wer_data:
                stats = wer_data['statistics']
                if isinstance(stats, dict):
                    sanitized['statistics'] = stats
                else:
                    self._logger.warning(f"[SCAN_MANAGER] WER statistics is not a dict: {type(stats)}")
                    sanitized['statistics'] = {}
            else:
                sanitized['statistics'] = {}
            
            # Zachowaj inne pola jeśli istnieją
            for key, value in wer_data.items():
                if key not in ['recent_crashes', 'reports', 'grouped_crashes', 'statistics']:
                    sanitized[key] = value
            
            return sanitized
            
        except Exception as e:
            self._logger.exception(f"[SCAN_MANAGER] Error sanitizing WER data: {e}")
            # Zwróć bezpieczne puste dane zamiast crashować
            return {
                'recent_crashes': [],
                'reports': [],
                'grouped_crashes': [],
                'statistics': {},
                'error': f"Failed to sanitize WER data: {str(e)}"
            }

class QuickScan(ScanManager):
    """Quick Scan - szybki skan podstawowych komponentów."""
    
    def __init__(self, progress_callback=None):
        super().__init__("quick", progress_callback)

class FullScan(ScanManager):
    """Full Scan - pełny skan wszystkich komponentów."""
    
    def __init__(self, progress_callback=None):
        super().__init__("full", progress_callback)

