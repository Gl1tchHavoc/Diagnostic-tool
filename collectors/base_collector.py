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
            self.set_status("RUNNING")
            self.set_progress(0.0)
            
            self._logger.info(f"[{self.name}] Starting collection")
            self.data = self.collect()
            
            self.set_progress(100.0)
            self.set_status("DONE")
            
            self._logger.info(f"[{self.name}] Collection completed")
            
            return {
                'name': self.name,
                'status': self.status,
                'progress': self.progress,
                'data': self.data,
                'subtasks': self.subtasks
            }
        except Exception as e:
            error_msg = f"{type(e).__name__}: {str(e)}"
            self.set_error(error_msg)
            self._logger.exception(f"[{self.name}] Collection failed")
            
            return {
                'name': self.name,
                'status': self.status,
                'progress': self.progress,
                'data': {'error': error_msg},
                'error': error_msg,
                'subtasks': self.subtasks
            }
    
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

