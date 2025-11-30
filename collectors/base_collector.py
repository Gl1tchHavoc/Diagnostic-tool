"""
Base Collector - klasa bazowa dla wszystkich kolektorów.
Każdy kolektor dziedziczy po tej klasie i implementuje metodę collect().
"""
from abc import ABC, abstractmethod
from utils.logger import get_logger

logger = get_logger()

class BaseCollector(ABC):
    """
    Klasa bazowa dla wszystkich kolektorów.
    
    Atrybuty:
        name (str): Nazwa kolektora
        data (dict): Miejsce na wyniki kolektora
        status (str): Status kolektora ("PENDING" | "RUNNING" | "DONE" | "ERROR")
        progress (float): Postęp kolektora 0-100%
        error (str): Komunikat błędu jeśli status = "ERROR"
        subtasks (list): Lista subtasków z ich postępem
    """
    
    def __init__(self, name: str):
        """
        Inicjalizuje kolektor.
        
        Args:
            name (str): Nazwa kolektora
        """
        self.name = name
        self.data = {}
        self.status = "PENDING"
        self.progress = 0.0
        self.error = None
        self.subtasks = []
        self._logger = get_logger()
    
    @abstractmethod
    def collect(self):
        """
        Abstrakcyjna metoda do zbierania danych.
        Musi być zaimplementowana w klasach dziedziczących.
        
        Returns:
            dict: Zebrane dane
        """
        pass
    
    def set_status(self, status: str):
        """
        Ustawia status kolektora.
        
        Args:
            status (str): Status ("PENDING" | "RUNNING" | "DONE" | "ERROR")
        """
        self.status = status
        self._logger.debug(f"[{self.name}] Status changed to: {status}")
    
    def set_progress(self, progress: float, subtask_name: str = None):
        """
        Ustawia postęp kolektora.
        
        Args:
            progress (float): Postęp 0-100%
            subtask_name (str, optional): Nazwa subtaska
        """
        self.progress = max(0.0, min(100.0, progress))
        
        if subtask_name:
            # Aktualizuj lub dodaj subtask
            subtask = next((s for s in self.subtasks if s['name'] == subtask_name), None)
            if subtask:
                subtask['progress'] = self.progress
            else:
                self.subtasks.append({
                    'name': subtask_name,
                    'progress': self.progress,
                    'status': 'RUNNING' if self.progress < 100 else 'DONE'
                })
        
        self._logger.debug(f"[{self.name}] Progress: {self.progress:.1f}%")
    
    def set_error(self, error: str):
        """
        Ustawia błąd kolektora.
        
        Args:
            error (str): Komunikat błędu
        """
        self.error = error
        self.status = "ERROR"
        self._logger.error(f"[{self.name}] Error: {error}")
    
    def run(self):
        """
        Uruchamia kolektor i zwraca wyniki.
        
        Returns:
            dict: Wyniki kolektora
        """
        try:
            self._logger.debug(f"[{self.name}] DEBUG: Entering run() method")
            self.set_status("RUNNING")
            self._logger.debug(f"[{self.name}] DEBUG: Status set to RUNNING")
            self.set_progress(0.0)
            self._logger.debug(f"[{self.name}] DEBUG: Progress set to 0.0")
            
            self._logger.info(f"[{self.name}] Starting collection")
            self._logger.debug(f"[{self.name}] DEBUG: About to call self.collect()")
            
            try:
                self._logger.debug(f"[{self.name}] DEBUG: Calling self.collect() NOW")
                if self.name == "wer":
                    self._logger.info(f"[{self.name}] DEBUG: WER - About to call collect()")
                collected_data = self.collect()
                self._logger.debug(f"[{self.name}] DEBUG: self.collect() returned, type: {type(collected_data)}")
                if self.name == "wer":
                    self._logger.info(f"[{self.name}] DEBUG: WER - collect() returned successfully")
                    self._logger.debug(f"[{self.name}] DEBUG: WER - About to assign data to self.data")
                
                # ZABEZPIECZENIE: Dla WER, upewnij się, że dane są bezpieczne przed przypisaniem
                if self.name == "wer" and isinstance(collected_data, dict):
                    # Sprawdź czy dane nie są zbyt duże lub problematyczne
                    try:
                        # Próba serializacji do JSON jako test
                        import json
                        json.dumps(collected_data, default=str)
                        self._logger.debug(f"[{self.name}] DEBUG: WER data is JSON-serializable")
                    except Exception as e:
                        self._logger.warning(f"[{self.name}] DEBUG: WER data may not be JSON-serializable: {e}")
                
                self.data = collected_data
                self._logger.debug(f"[{self.name}] DEBUG: self.data assigned successfully")
                if self.name == "wer":
                    self._logger.info(f"[{self.name}] DEBUG: WER - self.data assigned successfully")
            except Exception as collect_error:
                self._logger.exception(f"[{self.name}] DEBUG: Exception in self.collect(): {collect_error}")
                raise
            
            # DEBUG: Sprawdź dane przed zapisaniem
            self._logger.debug(f"[{self.name}] DEBUG: self.data assigned, type: {type(self.data)}")
            if self.name == "wer":
                self._logger.debug(f"[{self.name}] DEBUG: self.data type: {type(self.data)}")
                self._logger.debug(f"[{self.name}] DEBUG: self.data is dict: {isinstance(self.data, dict)}")
                if isinstance(self.data, dict):
                    self._logger.debug(f"[{self.name}] DEBUG: self.data keys: {list(self.data.keys())}")
                    if 'grouped_crashes' in self.data:
                        self._logger.debug(f"[{self.name}] DEBUG: grouped_crashes type: {type(self.data['grouped_crashes'])}")
                        self._logger.debug(f"[{self.name}] DEBUG: grouped_crashes is list: {isinstance(self.data.get('grouped_crashes'), list)}")
            
            self._logger.debug(f"[{self.name}] DEBUG: About to set progress to 100.0")
            self.set_progress(100.0)
            self._logger.debug(f"[{self.name}] DEBUG: Progress set to 100.0")
            
            self._logger.debug(f"[{self.name}] DEBUG: About to set status to DONE")
            self.set_status("DONE")
            self._logger.debug(f"[{self.name}] DEBUG: Status set to DONE")
            
            self._logger.info(f"[{self.name}] Collection completed")
            
            self._logger.debug(f"[{self.name}] DEBUG: About to create result dict")
            result = {
                'name': self.name,
                'status': self.status,
                'progress': self.progress,
                'data': self.data,
                'subtasks': self.subtasks
            }
            self._logger.debug(f"[{self.name}] DEBUG: Result dict created")
            
            # DEBUG: Sprawdź wynik przed zwróceniem
            if self.name == "wer":
                self._logger.debug(f"[{self.name}] DEBUG: Returning result, type: {type(result)}")
                self._logger.debug(f"[{self.name}] DEBUG: result['data'] type: {type(result.get('data'))}")
                if isinstance(result.get('data'), dict) and 'grouped_crashes' in result.get('data', {}):
                    self._logger.debug(f"[{self.name}] DEBUG: result['data']['grouped_crashes'] type: {type(result['data']['grouped_crashes'])}")
            
            self._logger.debug(f"[{self.name}] DEBUG: About to return result")
            return result
        except Exception as e:
            self._logger.debug(f"[{self.name}] DEBUG: Exception caught in run(): {type(e).__name__}: {str(e)}")
            error_msg = f"{type(e).__name__}: {str(e)}"
            self._logger.debug(f"[{self.name}] DEBUG: About to set_error")
            self.set_error(error_msg)
            self._logger.debug(f"[{self.name}] DEBUG: Error set, about to log exception")
            self._logger.exception(f"[{self.name}] Collection failed")
            
            self._logger.debug(f"[{self.name}] DEBUG: About to create error result dict")
            error_result = {
                'name': self.name,
                'status': self.status,
                'progress': self.progress,
                'data': {'error': error_msg},
                'error': error_msg,
                'subtasks': self.subtasks
            }
            self._logger.debug(f"[{self.name}] DEBUG: About to return error result")
            return error_result
    
    def get_info(self):
        """
        Zwraca informacje o kolektorze.
        
        Returns:
            dict: Informacje o kolektorze
        """
        return {
            'name': self.name,
            'status': self.status,
            'progress': self.progress,
            'error': self.error,
            'subtasks': self.subtasks
        }

