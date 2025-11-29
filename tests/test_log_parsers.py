"""
Tests for log parsers.
"""
import pytest
from datetime import datetime, timezone
from log_parsers.system_log_parser import SystemLogParser
from log_parsers.minidump_parser import MinidumpParser

class TestSystemLogParser:
    """Testy dla SystemLogParser."""
    
    def test_parser_initialization(self):
        """Test inicjalizacji parsera."""
        parser = SystemLogParser("System", max_events=100)
        assert parser.log_source == "System"
        assert parser.max_events == 100
        assert not parser.loaded
        assert not parser.parsed
    
    def test_normalize_timestamp(self):
        """Test normalizacji timestampów."""
        parser = SystemLogParser("System")
        
        # Test różnych formatów
        test_cases = [
            ("2025-11-29 10:04:12", datetime(2025, 11, 29, 10, 4, 12, tzinfo=timezone.utc)),
            ("2025-11-29T10:04:12Z", datetime(2025, 11, 29, 10, 4, 12, tzinfo=timezone.utc)),
            ("11/29/2025 10:04:12 AM", datetime(2025, 11, 29, 10, 4, 12, tzinfo=timezone.utc)),
        ]
        
        for timestamp_str, expected in test_cases:
            result = parser.normalize_timestamp(timestamp_str)
            assert result is not None
            assert result.year == expected.year
            assert result.month == expected.month
            assert result.day == expected.day

class TestMinidumpParser:
    """Testy dla MinidumpParser."""
    
    def test_parser_initialization(self):
        """Test inicjalizacji parsera."""
        parser = MinidumpParser()
        assert parser.minidump_dir == "C:\\Windows\\Minidump"
        assert not parser.loaded
        assert not parser.parsed


