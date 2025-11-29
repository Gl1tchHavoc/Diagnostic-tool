"""
Base parser class for all log parsers.
"""
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import List, Dict, Optional, Tuple
from utils.safe_read import safe_read
from utils.logger import get_logger

logger = get_logger()

class BaseLogParser(ABC):
    """
    Bazowa klasa dla wszystkich parserów logów.
    Wszystkie parsery muszą implementować metody: load(), parse(), get_events_between()
    """
    
    def __init__(self, log_source):
        """
        Args:
            log_source: Źródło logów (ścieżka do pliku, nazwa logu Windows, itp.)
        """
        self.log_source = log_source
        self.raw_data = None
        self.parsed_events = []
        self.loaded = False
        self.parsed = False
    
    @abstractmethod
    def load(self) -> Tuple[bool, Optional[str]]:
        """
        Bezpieczne wczytywanie pliku/logu.
        
        Returns:
            tuple: (success: bool, error: str or None)
        """
        pass
    
    @abstractmethod
    def parse(self) -> Tuple[bool, Optional[str]]:
        """
        Parsuje surowe dane i zwraca ujednolicony format.
        
        Returns:
            tuple: (success: bool, error: str or None)
        """
        pass
    
    def get_events_between(self, start: datetime, end: datetime) -> List[Dict]:
        """
        Filtruje zdarzenia w określonym przedziale czasowym.
        
        Args:
            start (datetime): Początek przedziału (UTC)
            end (datetime): Koniec przedziału (UTC)
        
        Returns:
            list: Lista zdarzeń w formacie ujednoliconym
        """
        if not self.parsed:
            logger.warning(f"[{self.__class__.__name__}] Cannot filter events: data not parsed yet")
            return []
        
        # Upewnij się, że daty są w UTC
        if start.tzinfo is None:
            start = start.replace(tzinfo=timezone.utc)
        if end.tzinfo is None:
            end = end.replace(tzinfo=timezone.utc)
        
        filtered = []
        for event in self.parsed_events:
            event_time = event.get('timestamp')
            if event_time is None:
                continue
            
            # Upewnij się, że event_time jest w UTC
            if isinstance(event_time, datetime):
                if event_time.tzinfo is None:
                    event_time = event_time.replace(tzinfo=timezone.utc)
                elif event_time.tzinfo != timezone.utc:
                    event_time = event_time.astimezone(timezone.utc)
                
                if start <= event_time <= end:
                    filtered.append(event)
        
        logger.debug(f"[{self.__class__.__name__}] Filtered {len(filtered)} events between {start} and {end}")
        return filtered
    
    def normalize_timestamp(self, timestamp_str: str, default_tz=timezone.utc) -> Optional[datetime]:
        """
        Normalizuje timestamp do datetime w UTC.
        
        Args:
            timestamp_str (str): String z timestampem
            default_tz: Domyślna strefa czasowa jeśli nie można określić
        
        Returns:
            datetime or None: Znormalizowany timestamp w UTC lub None jeśli nie można sparsować
        """
        if not timestamp_str:
            return None
        
        # Różne formaty timestampów
        formats = [
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y/%m/%d %H:%M:%S",
            "%m/%d/%Y %I:%M:%S %p",  # 11/29/2025 10:04:12 AM
            "%m/%d/%Y %H:%M:%S",
            "%d/%m/%Y %H:%M:%S",
            "%d.%m.%Y %H:%M:%S",
        ]
        
        timestamp_clean = timestamp_str.strip()
        
        # Próbuj różne formaty
        for fmt in formats:
            try:
                dt = datetime.strptime(timestamp_clean, fmt)
                # Jeśli nie ma timezone, dodaj domyślną
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=default_tz)
                # Konwertuj do UTC
                if dt.tzinfo != timezone.utc:
                    dt = dt.astimezone(timezone.utc)
                return dt
            except (ValueError, TypeError):
                continue
        
        # Próbuj parsować z AM/PM
        try:
            if " AM" in timestamp_str or " PM" in timestamp_str:
                dt = datetime.strptime(timestamp_str.strip(), "%m/%d/%Y %I:%M:%S %p")
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=default_tz)
                if dt.tzinfo != timezone.utc:
                    dt = dt.astimezone(timezone.utc)
                return dt
        except (ValueError, TypeError):
            pass
        
        logger.debug(f"[{self.__class__.__name__}] Failed to parse timestamp: {timestamp_str}")
        return None
    
    def get_all_events(self) -> List[Dict]:
        """
        Zwraca wszystkie sparsowane zdarzenia.
        
        Returns:
            list: Lista wszystkich zdarzeń
        """
        return self.parsed_events if self.parsed else []


