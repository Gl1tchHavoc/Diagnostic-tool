"""
Parser for Windows System Event Log.
"""
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import List, Dict, Optional, Tuple
from log_parsers.base_parser import BaseLogParser
from utils.subprocess_helper import run_powershell_hidden
from utils.logger import get_logger
from utils.shadowcopy_helper import is_shadowcopy_path

logger = get_logger()

class SystemLogParser(BaseLogParser):
    """
    Parser dla Windows System Event Log.
    """
    
    def __init__(self, log_source="System", max_events=1000):
        """
        Args:
            log_source (str): Nazwa logu Windows (domyślnie "System")
            max_events (int): Maksymalna liczba zdarzeń do pobrania
        """
        super().__init__(log_source)
        self.max_events = max_events
    
    def load(self) -> Tuple[bool, Optional[str]]:
        """
        Wczytuje logi systemowe z Windows Event Log.
        
        Returns:
            tuple: (success: bool, error: str or None)
        """
        try:
            logger.info(f"[SYSTEM_LOG_PARSER] Loading {self.log_source} log (max_events={self.max_events})")
            
            # Pobierz logi przez PowerShell
            cmd = f"Get-WinEvent -LogName {self.log_source} -MaxEvents {self.max_events} -ErrorAction SilentlyContinue | ConvertTo-Xml -As String -Depth 3"
            output = run_powershell_hidden(cmd)
            
            if not output or len(output.strip()) < 50:
                error_msg = f"Empty or invalid output from {self.log_source} log"
                logger.warning(f"[SYSTEM_LOG_PARSER] {error_msg}")
                return False, error_msg
            
            self.raw_data = output
            self.loaded = True
            logger.info(f"[SYSTEM_LOG_PARSER] Successfully loaded {self.log_source} log ({len(output)} chars)")
            return True, None
            
        except Exception as e:
            error_msg = f"Failed to load {self.log_source} log: {type(e).__name__}: {e}"
            logger.exception(f"[SYSTEM_LOG_PARSER] {error_msg}")
            return False, error_msg
    
    def parse(self) -> Tuple[bool, Optional[str]]:
        """
        Parsuje XML z logów systemowych.
        
        Returns:
            tuple: (success: bool, error: str or None)
        """
        if not self.loaded:
            return False, "Data not loaded. Call load() first."
        
        try:
            logger.info(f"[SYSTEM_LOG_PARSER] Parsing {self.log_source} log")
            
            root = ET.fromstring(self.raw_data)
            objects = root.findall(".//Object")
            logger.debug(f"[SYSTEM_LOG_PARSER] Found {len(objects)} Object elements")
            
            events = []
            for obj in objects:
                record = {}
                for prop in obj.findall("Property"):
                    name = prop.attrib.get("Name")
                    if name:
                        text_content = prop.text if prop.text else ""
                        nested_props = prop.findall("Property")
                        if nested_props:
                            for nested in nested_props:
                                nested_name = nested.attrib.get("Name")
                                if nested_name and nested.text:
                                    record[f"{name}.{nested_name}"] = nested.text
                        else:
                            record[name] = text_content
                
                # Pobierz dane eventu
                timestamp_str = record.get("TimeCreated") or record.get("Time") or record.get("TimeCreated.SystemTime") or ""
                message = record.get("Message") or record.get("Message.Message") or ""
                
                # Normalizuj level
                level = self._normalize_level(
                    record.get("LevelDisplayName") or 
                    record.get("Level") or 
                    record.get("LevelName") or 
                    "Information"
                )
                
                event_id = record.get("Id") or record.get("EventID") or record.get("EventId") or "N/A"
                
                # Parsuj timestamp
                timestamp = self.normalize_timestamp(timestamp_str)
                if timestamp is None:
                    logger.debug(f"[SYSTEM_LOG_PARSER] Skipping event with invalid timestamp: {timestamp_str}")
                    continue
                
                # Sprawdź czy to ShadowCopy event
                is_shadowcopy = self._is_shadowcopy_event(message, event_id)
                
                # Utwórz ujednolicony format eventu
                event = {
                    'timestamp': timestamp,
                    'level': level,
                    'event_id': str(event_id),
                    'message': message,
                    'source': self.log_source,
                    'category': self._categorize_event(message, event_id, level),
                    'is_shadowcopy': is_shadowcopy,
                    'raw': f"[{timestamp}] [{level}] [ID:{event_id}] {message}"
                }
                
                # Jeśli to ShadowCopy event, zmień kategorię
                if is_shadowcopy:
                    event['category'] = 'SHADOWCOPY_ERROR'
                    logger.debug(f"[SYSTEM_LOG_PARSER] Detected ShadowCopy event: {event_id} - {message[:100]}")
                
                events.append(event)
            
            # De-duplikuj eventy
            from utils.event_deduplicator import deduplicate_events
            events = deduplicate_events(events)
            logger.debug(f"[SYSTEM_LOG_PARSER] After deduplication: {len(events)} unique events")
            
            self.parsed_events = events
            self.parsed = True
            logger.info(f"[SYSTEM_LOG_PARSER] Parsed {len(events)} events from {self.log_source} log")
            return True, None
            
        except ET.ParseError as e:
            error_msg = f"XML parse error: {str(e)}"
            logger.exception(f"[SYSTEM_LOG_PARSER] {error_msg}")
            return False, error_msg
        except Exception as e:
            error_msg = f"Parse error: {type(e).__name__}: {e}"
            logger.exception(f"[SYSTEM_LOG_PARSER] {error_msg}")
            return False, error_msg
    
    def _normalize_level(self, level: str) -> str:
        """Normalizuje poziom logu."""
        if not level:
            return "Information"
        
        level_lower = level.lower()
        if level_lower in ["error", "err", "2", "błąd", "błęd"]:
            return "Error"
        elif level_lower in ["warning", "warn", "3", "ostrzeżenie", "ostrzeg"]:
            return "Warning"
        elif level_lower in ["critical", "crit", "1", "krytyczny", "krytyczn"]:
            return "Critical"
        elif level_lower in ["information", "info", "informational", "4", "0", "informacje", "informacj"]:
            return "Information"
        else:
            return level.capitalize()
    
    def _is_shadowcopy_event(self, message: str, event_id: str) -> bool:
        """
        Sprawdza czy event dotyczy ShadowCopy.
        
        Args:
            message (str): Wiadomość eventu
            event_id (str): ID eventu
        
        Returns:
            bool: True jeśli event dotyczy ShadowCopy
        """
        return is_shadowcopy_path(message)
    
    def _categorize_event(self, message: str, event_id: str, level: str) -> str:
        """Kategoryzuje event na podstawie wiadomości i ID."""
        message_lower = message.lower()
        event_id_lower = str(event_id).lower()
        
        # Sprawdź czy to ShadowCopy (przed innymi kategoriami)
        if self._is_shadowcopy_event(message, event_id):
            return "SHADOWCOPY_ERROR"
        
        # Sprawdź różne kategorie
        if any(kw in message_lower for kw in ["gpu", "graphics", "display", "dxgkrnl", "nvlddmkm", "atikmpag"]):
            return "GPU_DRIVER"
        elif any(kw in message_lower for kw in ["disk", "volume", "ntfs", "volsnap", "i/o error"]):
            return "DISK_ERROR"
        elif any(kw in message_lower for kw in ["memory", "page fault", "ram"]):
            return "MEMORY_ERROR"
        elif any(kw in message_lower for kw in ["driver", "failed to load"]):
            return "DRIVER_ERROR"
        elif any(kw in message_lower for kw in ["txr", "transaction", "registry", "0xc00000a2"]):
            return "TXR_FAILURE"
        elif any(kw in message_lower for kw in ["service", "failed to start"]):
            return "SERVICE_FAILURE"
        elif level in ["Critical", "Error"]:
            return "SYSTEM_CRITICAL"
        else:
            return "OTHER"


