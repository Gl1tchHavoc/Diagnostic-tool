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
        import sys  # Import na początku funkcji, przed użyciem
        try:
            self._logger.info("[wer] DEBUG: WERCollector.collect() CALLED - START")
            sys.stdout.flush()
            
            self._logger.debug("[wer] DEBUG: About to call set_progress(10.0)")
            sys.stdout.flush()
            self.set_progress(10.0, "Initializing")
            self._logger.debug("[wer] DEBUG: set_progress(10.0) completed")
            sys.stdout.flush()
            
            self._logger.debug("[wer] DEBUG: About to call wer.collect()")
            sys.stdout.flush()
            
            try:
                self._logger.info("[wer] DEBUG: About to call wer.collect() - BEFORE CALL")
                sys.stdout.flush()
                data = wer.collect()
                self._logger.info(f"[wer] DEBUG: wer.collect() RETURNED, type: {type(data)}")
                sys.stdout.flush()
                
                # Sprawdź czy data nie jest None
                if data is None:
                    self._logger.error("[wer] DEBUG: wer.collect() returned None!")
                    sys.stdout.flush()
                    data = {}
                
                self._logger.debug(f"[wer] DEBUG: data is dict: {isinstance(data, dict)}")
                if isinstance(data, dict):
                    self._logger.debug(f"[wer] DEBUG: data has {len(data)} keys")
                    # Nie loguj wszystkich kluczy - może być za dużo
                    if 'grouped_crashes' in data:
                        try:
                            gc_type = type(data['grouped_crashes'])
                            gc_is_list = isinstance(data['grouped_crashes'], list)
                            gc_len = len(data['grouped_crashes']) if gc_is_list else 'N/A'
                            self._logger.debug(f"[wer] DEBUG: grouped_crashes type: {gc_type}, is_list: {gc_is_list}, len: {gc_len}")
                        except Exception as e:
                            self._logger.warning(f"[wer] DEBUG: Error checking grouped_crashes: {e}")
                            sys.stdout.flush()
                
                self._logger.info("[wer] DEBUG: About to return data from WERCollector.collect()")
                sys.stdout.flush()
            except Exception as e:
                self._logger.exception(f"[wer] DEBUG: Exception in wer.collect(): {e}")
                sys.stdout.flush()
                raise
            
            # ZABEZPIECZENIE: Utwórz kopię danych zamiast referencji, aby uniknąć problemów z pamięcią
            try:
                import copy
                self._logger.debug("[wer] DEBUG: Creating deep copy of data")
                sys.stdout.flush()
                data_copy = copy.deepcopy(data)
                self._logger.debug("[wer] DEBUG: Deep copy completed")
                sys.stdout.flush()
                data = data_copy
            except Exception as e:
                self._logger.warning(f"[wer] DEBUG: Failed to create deep copy: {e}, using original data")
                sys.stdout.flush()
                # Jeśli deepcopy nie działa, spróbuj shallow copy
                try:
                    import copy
                    data = copy.copy(data)
                except Exception:
                    pass  # Użyj oryginalnych danych
            
            self._logger.debug("[wer] DEBUG: About to set progress to 100.0")
            sys.stdout.flush()
            self.set_progress(100.0, "Complete")
            self._logger.debug("[wer] DEBUG: set_progress(100.0) completed")
            sys.stdout.flush()
            
            self._logger.info("[wer] DEBUG: About to return data - END")
            sys.stdout.flush()
            return data
        except Exception as e:
            self._logger.exception(f"[wer] DEBUG: FATAL EXCEPTION in WERCollector.collect(): {e}")
            sys.stdout.flush()
            raise

class ProcessesCollector(BaseCollector):
    """Kolektor danych o procesach."""
    
    def collect(self):
        self.set_progress(10.0, "Initializing")
        data = processes.collect()
        self.set_progress(100.0, "Complete")
        return data

