"""
Parser for Windows Application Event Log.
"""
from log_parsers.system_log_parser import SystemLogParser
from utils.logger import get_logger

logger = get_logger()

class ApplicationLogParser(SystemLogParser):
    """
    Parser dla Windows Application Event Log.
    Dziedziczy z SystemLogParser, ponieważ struktura jest taka sama.
    """
    
    def __init__(self, log_source="Application", max_events=1000):
        super().__init__(log_source, max_events)


