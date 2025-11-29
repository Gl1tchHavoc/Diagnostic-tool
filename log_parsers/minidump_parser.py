"""
Parser for Windows Minidump files.
"""
import os
from datetime import datetime, timezone
from typing import List, Dict, Optional, Tuple
from log_parsers.base_parser import BaseLogParser
from utils.logger import get_logger

logger = get_logger()

class MinidumpParser(BaseLogParser):
    """
    Parser dla plików minidump (BSOD dumps).
    """
    
    def __init__(self, minidump_dir="C:\\Windows\\Minidump"):
        """
        Args:
            minidump_dir (str): Katalog z plikami minidump
        """
        super().__init__(minidump_dir)
        self.minidump_dir = minidump_dir
    
    def load(self) -> Tuple[bool, Optional[str]]:
        """
        Wczytuje informacje o plikach minidump.
        
        Returns:
            tuple: (success: bool, error: str or None)
        """
        try:
            logger.info(f"[MINIDUMP_PARSER] Loading minidump files from {self.minidump_dir}")
            
            if not os.path.exists(self.minidump_dir):
                error_msg = f"Minidump directory does not exist: {self.minidump_dir}"
                logger.warning(f"[MINIDUMP_PARSER] {error_msg}")
                return False, error_msg
            
            # Pobierz listę plików minidump
            minidump_files = []
            for filename in os.listdir(self.minidump_dir):
                if filename.endswith('.dmp'):
                    filepath = os.path.join(self.minidump_dir, filename)
                    file_stat = os.stat(filepath)
                    minidump_files.append({
                        'filename': filename,
                        'filepath': filepath,
                        'size': file_stat.st_size,
                        'modified_time': datetime.fromtimestamp(file_stat.st_mtime, tz=timezone.utc),
                        'created_time': datetime.fromtimestamp(file_stat.st_ctime, tz=timezone.utc)
                    })
            
            # Sortuj po czasie modyfikacji (najnowsze pierwsze)
            minidump_files.sort(key=lambda x: x['modified_time'], reverse=True)
            
            self.raw_data = minidump_files
            self.loaded = True
            logger.info(f"[MINIDUMP_PARSER] Found {len(minidump_files)} minidump files")
            return True, None
            
        except Exception as e:
            error_msg = f"Failed to load minidump files: {type(e).__name__}: {e}"
            logger.exception(f"[MINIDUMP_PARSER] {error_msg}")
            return False, error_msg
    
    def parse(self) -> Tuple[bool, Optional[str]]:
        """
        Parsuje informacje o minidump files.
        
        Returns:
            tuple: (success: bool, error: str or None)
        """
        if not self.loaded:
            return False, "Data not loaded. Call load() first."
        
        try:
            logger.info("[MINIDUMP_PARSER] Parsing minidump files")
            
            events = []
            for dump_file in self.raw_data:
                # Utwórz event dla każdego minidump
                event = {
                    'timestamp': dump_file['modified_time'],
                    'level': 'Critical',
                    'event_id': 'MINIDUMP',
                    'message': f"BSOD minidump: {dump_file['filename']}",
                    'source': 'Minidump',
                    'category': 'KERNEL_CRASH',
                    'filename': dump_file['filename'],
                    'filepath': dump_file['filepath'],
                    'size': dump_file['size'],
                    'raw': f"[{dump_file['modified_time']}] [Critical] [MINIDUMP] {dump_file['filename']}"
                }
                events.append(event)
            
            self.parsed_events = events
            self.parsed = True
            logger.info(f"[MINIDUMP_PARSER] Parsed {len(events)} minidump events")
            return True, None
            
        except Exception as e:
            error_msg = f"Parse error: {type(e).__name__}: {e}"
            logger.exception(f"[MINIDUMP_PARSER] {error_msg}")
            return False, error_msg
    
    def get_latest_bsod(self) -> Optional[Dict]:
        """
        Zwraca informacje o najnowszym BSOD (minidump).
        
        Returns:
            dict or None: Informacje o najnowszym BSOD lub None
        """
        if not self.parsed:
            return None
        
        if not self.parsed_events:
            return None
        
        # Najnowszy event (pierwszy w liście, bo są posortowane)
        return self.parsed_events[0]


