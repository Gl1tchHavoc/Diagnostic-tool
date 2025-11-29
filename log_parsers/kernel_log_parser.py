"""
Parser for Kernel events and bugchecks.
"""
from datetime import datetime, timezone
from typing import List, Dict, Optional, Tuple
from log_parsers.base_parser import BaseLogParser
from utils.logger import get_logger

logger = get_logger()

class KernelLogParser(BaseLogParser):
    """
    Parser dla zdarzeń kernel i bugchecks.
    """
    
    def load(self) -> Tuple[bool, Optional[str]]:
        """
        Wczytuje zdarzenia kernel z System log (bugchecks, stop errors).
        
        Returns:
            tuple: (success: bool, error: str or None)
        """
        try:
            logger.info("[KERNEL_LOG_PARSER] Loading kernel events from System log")
            
            # Użyj SystemLogParser do wczytania logów
            from log_parsers.system_log_parser import SystemLogParser
            system_parser = SystemLogParser("System", max_events=2000)
            success, error = system_parser.load()
            
            if not success:
                return False, error
            
            # Filtruj tylko kernel events
            self.raw_data = system_parser.raw_data
            self.loaded = True
            logger.info("[KERNEL_LOG_PARSER] Successfully loaded kernel events")
            return True, None
            
        except Exception as e:
            error_msg = f"Failed to load kernel events: {type(e).__name__}: {e}"
            logger.exception(f"[KERNEL_LOG_PARSER] {error_msg}")
            return False, error_msg
    
    def parse(self) -> Tuple[bool, Optional[str]]:
        """
        Parsuje zdarzenia kernel (bugchecks, stop errors).
        
        Returns:
            tuple: (success: bool, error: str or None)
        """
        if not self.loaded:
            return False, "Data not loaded. Call load() first."
        
        try:
            logger.info("[KERNEL_LOG_PARSER] Parsing kernel events")
            
            # Użyj SystemLogParser do parsowania
            from log_parsers.system_log_parser import SystemLogParser
            system_parser = SystemLogParser("System")
            system_parser.raw_data = self.raw_data
            system_parser.loaded = True
            
            success, error = system_parser.parse()
            if not success:
                return False, error
            
            # Filtruj tylko kernel-related events
            kernel_keywords = ["bugcheck", "stop error", "bsod", "blue screen", 
                              "system crash", "unexpected shutdown", "kernel", 
                              "event id 41", "event id 1001", "event id 6008"]
            
            events = []
            for event in system_parser.parsed_events:
                message = event.get("message", "").lower()
                event_id = str(event.get("event_id", "")).lower()
                level = event.get("level", "").lower()
                
                # Sprawdź czy to kernel event
                is_kernel = (
                    any(keyword in message for keyword in kernel_keywords) or
                    (level in ["critical", "error"] and event_id in ["41", "1001", "6008"])
                )
                
                if is_kernel:
                    event['category'] = 'KERNEL_CRASH'
                    events.append(event)
            
            self.parsed_events = events
            self.parsed = True
            logger.info(f"[KERNEL_LOG_PARSER] Parsed {len(events)} kernel events")
            return True, None
            
        except Exception as e:
            error_msg = f"Parse error: {type(e).__name__}: {e}"
            logger.exception(f"[KERNEL_LOG_PARSER] {error_msg}")
            return False, error_msg


