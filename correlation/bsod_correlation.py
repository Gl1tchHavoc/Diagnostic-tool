"""
BSOD Correlation Engine - correlates events across multiple logs to identify BSOD causes.
"""
import re
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Optional, Tuple
from collections import defaultdict
from utils.logger import get_logger
from log_parsers.minidump_parser import MinidumpParser
from log_parsers.system_log_parser import SystemLogParser
from log_parsers.application_log_parser import ApplicationLogParser
from log_parsers.kernel_log_parser import KernelLogParser

logger = get_logger()

# Regex patterns dla noise (false positives)
NOISE_PATTERNS = [
    re.compile(r"The description for Event ID .* cannot be found", re.IGNORECASE),
    re.compile(r"Audit Success", re.IGNORECASE),
    re.compile(r"Service .* running", re.IGNORECASE),
    re.compile(r"Service .* started successfully", re.IGNORECASE),
    re.compile(r"DNS request", re.IGNORECASE),
    re.compile(r"Connection established", re.IGNORECASE),
    re.compile(r"User logged on", re.IGNORECASE),
    re.compile(r"User logged off", re.IGNORECASE),
    re.compile(r"Windows Update", re.IGNORECASE),
    re.compile(r"Defender", re.IGNORECASE),
    re.compile(r"Antivirus scan", re.IGNORECASE),
    re.compile(r"Backup", re.IGNORECASE),
    re.compile(r"Maintenance", re.IGNORECASE),
    re.compile(r"Idle", re.IGNORECASE),
    re.compile(r"Timeout", re.IGNORECASE),
    re.compile(r"Heartbeat", re.IGNORECASE),
    re.compile(r"Scheduled task", re.IGNORECASE),
    re.compile(r"Task completed", re.IGNORECASE),
    re.compile(r"Time synchronization", re.IGNORECASE),
    re.compile(r"System time", re.IGNORECASE),
]

# Słowa kluczowe dla częstych, nieszkodliwych eventów
COMMON_NOISE_KEYWORDS = [
    "heartbeat", "health check", "status check",
    "logon", "logoff", "login", "logout",
    "update installed", "update downloaded",
    "backup completed", "backup started",
    "task scheduler", "scheduled task",
    "service started", "service stopped",
    "dhcp", "dns query", "network adapter",
    "time synchronization", "ntp",
    "disk cleanup", "defrag", "chkdsk completed",
]

class BSODCorrelator:
    """
    Klasa do korelacji zdarzeń z BSOD.
    """
    
    def __init__(self, time_window_minutes=5):
        """
        Args:
            time_window_minutes (int): Okno czasowe przed BSOD do analizy (domyślnie 5 minut)
        """
        self.time_window_minutes = time_window_minutes
        self.parsers = {}
        self.bsod_timestamp = None
        self.correlated_events = []
    
    def find_latest_bsod(self) -> Optional[Dict]:
        """
        Znajduje ostatni BSOD z minidump files.
        
        Returns:
            dict or None: Informacje o ostatnim BSOD lub None
        """
        try:
            logger.info("[BSOD_CORRELATOR] Finding latest BSOD")
            
            minidump_parser = MinidumpParser()
            success, error = minidump_parser.load()
            if not success:
                logger.warning(f"[BSOD_CORRELATOR] Failed to load minidumps: {error}")
                return None
            
            success, error = minidump_parser.parse()
            if not success:
                logger.warning(f"[BSOD_CORRELATOR] Failed to parse minidumps: {error}")
                return None
            
            latest_bsod = minidump_parser.get_latest_bsod()
            if latest_bsod:
                self.bsod_timestamp = latest_bsod['timestamp']
                logger.info(f"[BSOD_CORRELATOR] Found latest BSOD at {self.bsod_timestamp}")
                return latest_bsod
            else:
                logger.info("[BSOD_CORRELATOR] No BSOD found in minidumps")
                return None
                
        except Exception as e:
            logger.exception(f"[BSOD_CORRELATOR] Error finding latest BSOD: {e}")
            return None
    
    def collect_all_logs(self) -> Dict[str, List[Dict]]:
        """
        Zbiera wszystkie logi (System, Application, Security, Kernel).
        
        Returns:
            dict: Słownik z logami {log_name: [events]}
        """
        all_logs = {}
        
        # System log
        try:
            logger.info("[BSOD_CORRELATOR] Collecting System log")
            system_parser = SystemLogParser("System", max_events=2000)
            if system_parser.load()[0] and system_parser.parse()[0]:
                all_logs['System'] = system_parser.get_all_events()
                logger.info(f"[BSOD_CORRELATOR] Collected {len(all_logs['System'])} System events")
        except Exception as e:
            logger.error(f"[BSOD_CORRELATOR] Error collecting System log: {e}")
            all_logs['System'] = []
        
        # Application log
        try:
            logger.info("[BSOD_CORRELATOR] Collecting Application log")
            app_parser = ApplicationLogParser("Application", max_events=2000)
            if app_parser.load()[0] and app_parser.parse()[0]:
                all_logs['Application'] = app_parser.get_all_events()
                logger.info(f"[BSOD_CORRELATOR] Collected {len(all_logs['Application'])} Application events")
        except Exception as e:
            logger.error(f"[BSOD_CORRELATOR] Error collecting Application log: {e}")
            all_logs['Application'] = []
        
        # Kernel events
        try:
            logger.info("[BSOD_CORRELATOR] Collecting Kernel events")
            kernel_parser = KernelLogParser("Kernel")
            if kernel_parser.load()[0] and kernel_parser.parse()[0]:
                all_logs['Kernel'] = kernel_parser.get_all_events()
                logger.info(f"[BSOD_CORRELATOR] Collected {len(all_logs['Kernel'])} Kernel events")
        except Exception as e:
            logger.error(f"[BSOD_CORRELATOR] Error collecting Kernel events: {e}")
            all_logs['Kernel'] = []
        
        return all_logs
    
    def filter_events_by_time(self, events: List[Dict], bsod_time: datetime) -> List[Dict]:
        """
        Filtruje zdarzenia w oknie czasowym (-time_window_minutes do +1 minuta od BSOD).
        
        Args:
            events (list): Lista zdarzeń
            bsod_time (datetime): Czas BSOD
        
        Returns:
            list: Przefiltrowane zdarzenia
        """
        if bsod_time is None:
            return []
        
        # Upewnij się, że bsod_time jest w UTC
        if bsod_time.tzinfo is None:
            bsod_time = bsod_time.replace(tzinfo=timezone.utc)
        elif bsod_time.tzinfo != timezone.utc:
            bsod_time = bsod_time.astimezone(timezone.utc)
        
        window_start = bsod_time - timedelta(minutes=self.time_window_minutes)
        window_end = bsod_time + timedelta(minutes=1)
        
        filtered = []
        for event in events:
            event_time = event.get('timestamp')
            if event_time is None:
                continue
            
            # Upewnij się, że event_time jest w UTC
            if isinstance(event_time, datetime):
                if event_time.tzinfo is None:
                    event_time = event_time.replace(tzinfo=timezone.utc)
                elif event_time.tzinfo != timezone.utc:
                    event_time = event_time.astimezone(timezone.utc)
                
                if window_start <= event_time <= window_end:
                    filtered.append(event)
        
        logger.info(f"[BSOD_CORRELATOR] Filtered {len(filtered)} events in time window ({window_start} to {window_end})")
        return filtered
    
    def is_noise(self, event: Dict) -> bool:
        """
        Sprawdza czy event jest noise (false positive).
        
        Args:
            event (dict): Event do sprawdzenia
        
        Returns:
            bool: True jeśli event jest noise
        """
        message = event.get('message', '').lower()
        level = event.get('level', '').lower()
        event_id = str(event.get('event_id', '')).lower()
        
        # Odrzuć Information level
        if level == 'information':
            return True
        
        # Sprawdź regex patterns
        for pattern in NOISE_PATTERNS:
            if pattern.search(message):
                return True
        
        # Sprawdź common noise keywords
        for keyword in COMMON_NOISE_KEYWORDS:
            if keyword in message:
                return True
        
        return False
    
    def calculate_event_score(self, event: Dict, bsod_time: datetime) -> float:
        """
        Oblicza score dla eventu na podstawie różnych czynników.
        
        Args:
            event (dict): Event do oceny
            bsod_time (datetime): Czas BSOD
        
        Returns:
            float: Score eventu
        """
        score = 0.0
        
        event_time = event.get('timestamp')
        if event_time is None:
            return -5.0  # Brak timestamp = bardzo niski score
        
        # Upewnij się, że czasy są w UTC
        if event_time.tzinfo is None:
            event_time = event_time.replace(tzinfo=timezone.utc)
        elif event_time.tzinfo != timezone.utc:
            event_time = event_time.astimezone(timezone.utc)
        
        if bsod_time.tzinfo is None:
            bsod_time = bsod_time.replace(tzinfo=timezone.utc)
        elif bsod_time.tzinfo != timezone.utc:
            bsod_time = bsod_time.astimezone(timezone.utc)
        
        # Czas w zakresie 0-30 sek. od BSOD: +3
        time_diff = abs((bsod_time - event_time).total_seconds())
        if time_diff <= 30:
            score += 3.0
        # Czas w zakresie 31-120 sek.: +2
        elif time_diff <= 120:
            score += 2.0
        
        # Error / Critical: +3
        level = event.get('level', '').lower()
        if level in ['error', 'critical']:
            score += 3.0
        # Warning: +1
        elif level == 'warning':
            score += 1.0
        
        # Kernel / Hardware event: +5
        category = event.get('category', '').upper()
        if category in ['KERNEL_CRASH', 'GPU_DRIVER', 'DISK_ERROR', 'MEMORY_ERROR', 'DRIVER_ERROR', 'TXR_FAILURE']:
            score += 5.0
        
        # Common noise: -5
        if self.is_noise(event):
            score -= 5.0
        
        # Powtarzalne codzienne eventy: -2 (heurystyka - jeśli event ma bardzo niski score, może być codzienny)
        # TODO: Implementacja wykrywania wzorców czasowych
        
        return score
    
    def correlate_events(self, bsod_timestamp: datetime) -> List[Dict]:
        """
        Koreluje zdarzenia z BSOD.
        
        Args:
            bsod_timestamp (datetime): Timestamp BSOD
        
        Returns:
            list: Lista skorelowanych zdarzeń z scores
        """
        logger.info(f"[BSOD_CORRELATOR] Correlating events with BSOD at {bsod_timestamp}")
        
        # Zbierz wszystkie logi
        all_logs = self.collect_all_logs()
        
        # Połącz wszystkie eventy
        all_events = []
        for log_name, events in all_logs.items():
            for event in events:
                event['log_source'] = log_name
                all_events.append(event)
        
        logger.info(f"[BSOD_CORRELATOR] Collected {len(all_events)} total events from all logs")
        
        # Filtruj po czasie
        time_filtered = self.filter_events_by_time(all_events, bsod_timestamp)
        logger.info(f"[BSOD_CORRELATOR] {len(time_filtered)} events in time window")
        
        # Filtruj noise
        filtered_events = []
        for event in time_filtered:
            if not self.is_noise(event):
                filtered_events.append(event)
        
        logger.info(f"[BSOD_CORRELATOR] {len(filtered_events)} events after noise filtering")
        
        # Oblicz scores
        scored_events = []
        for event in filtered_events:
            score = self.calculate_event_score(event, bsod_timestamp)
            event['correlation_score'] = score
            event['time_from_bsod_seconds'] = abs((bsod_timestamp - event.get('timestamp', bsod_timestamp)).total_seconds())
            
            # Ignoruj eventy z score < 0
            if score >= 0:
                scored_events.append(event)
        
        # Sortuj po score (malejąco)
        scored_events.sort(key=lambda x: x.get('correlation_score', 0), reverse=True)
        
        logger.info(f"[BSOD_CORRELATOR] {len(scored_events)} events with positive scores")
        self.correlated_events = scored_events
        
        return scored_events
    
    def analyze_bsod(self) -> Dict:
        """
        Główna metoda analizy BSOD - znajduje BSOD i koreluje zdarzenia.
        
        Returns:
            dict: Wynik analizy z listą skorelowanych zdarzeń
        """
        logger.info("[BSOD_CORRELATOR] Starting BSOD analysis")
        
        # Znajdź ostatni BSOD
        latest_bsod = self.find_latest_bsod()
        if not latest_bsod:
            return {
                'bsod_found': False,
                'message': 'No BSOD found in minidump files',
                'correlated_events': []
            }
        
        bsod_timestamp = latest_bsod['timestamp']
        
        # Koreluj zdarzenia
        correlated_events = self.correlate_events(bsod_timestamp)
        
        # Grupuj po poziomie
        events_by_level = defaultdict(list)
        for event in correlated_events:
            level = event.get('level', 'Unknown')
            events_by_level[level].append(event)
        
        return {
            'bsod_found': True,
            'bsod_timestamp': bsod_timestamp.isoformat(),
            'bsod_details': latest_bsod,
            'correlated_events': correlated_events,
            'events_by_level': {
                level: len(events) for level, events in events_by_level.items()
            },
            'total_correlated': len(correlated_events),
            'time_window_minutes': self.time_window_minutes
        }


