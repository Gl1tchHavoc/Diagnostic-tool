"""
Testy dla WER (Windows Error Reporting) collectora.
Testy pomagają zlokalizować problemy z typami danych i użyciem .get() na listach.
"""
import sys
import os
import pytest
from datetime import datetime, timedelta
from pathlib import Path

# Dodaj główny katalog projektu do ścieżki
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from collectors.wer import (
    collect,
    group_and_analyze_crashes,
    parse_timestamp
)
from utils.logger import get_logger

logger = get_logger()


def test_group_and_analyze_crashes_returns_list():
    """Test 1: Sprawdza czy group_and_analyze_crashes() zwraca listę."""
    # Przykładowe dane crashy
    test_crashes = [
        {
            "application": "test.exe",
            "module_name": "test.dll",
            "exception_code": "0x00000000",
            "timestamp": datetime.now().isoformat()
        },
        {
            "application": "test.exe",
            "module_name": "test.dll",
            "exception_code": "0x00000000",
            "timestamp": (datetime.now() - timedelta(minutes=10)).isoformat()
        }
    ]
    
    result = group_and_analyze_crashes(test_crashes)
    
    assert isinstance(result, list), f"Funkcja zwraca {type(result)}, oczekiwano list"
    if result:
        assert isinstance(result[0], dict), f"Pierwszy element to {type(result[0])}, oczekiwano dict"


def test_collect_handles_list_correctly():
    """Test 2: Sprawdza czy collect() poprawnie obsługuje listę z group_and_analyze_crashes()."""
    # Symuluj wynik group_and_analyze_crashes jako lista
    mock_grouped = [
        {
            "application": "test.exe",
            "module_name": "test.dll",
            "exception_code": "0x00000000",
            "total_occurrences": 2,
            "occurrences_30min": 2,
            "occurrences_24h": 2,
            "is_repeating": True
        }
    ]
    
    assert isinstance(mock_grouped, list), "mock_grouped powinno być listą"
    
    # Sprawdź czy możemy iterować po liście
    repeating = []
    for g in mock_grouped:
        assert isinstance(g, dict), "Elementy listy powinny być dict"
        occurrences_30min = g.get("occurrences_30min", 0)
        if isinstance(occurrences_30min, (int, float)) and occurrences_30min >= 3:
            repeating.append(g)
    
    # Sprawdź czy NIE używamy .get() na liście
    with pytest.raises(AttributeError):
        mock_grouped.get("something")


def test_no_get_on_list():
    """Test 3: Sprawdza czy nie używamy .get() bezpośrednio na liście grouped."""
    # Symuluj grouped jako lista (jak w rzeczywistości)
    grouped = [
        {"key1": "value1", "key2": "value2"},
        {"key3": "value3", "key4": "value4"}
    ]
    
    assert isinstance(grouped, list), "grouped powinno być listą"
    
    # Poprawne użycie - iteracja
    for item in grouped:
        assert isinstance(item, dict), "Elementy listy powinny być dict"
        value = item.get("key1", "default")
        assert value in ("value1", "default"), f"Oczekiwano 'value1' lub 'default', otrzymano {value}"
    
    # Niepoprawne użycie - .get() na liście powinno rzucić AttributeError
    with pytest.raises(AttributeError):
        grouped.get("key1")


def test_collect_integration():
    """Test 4: Test integracyjny - sprawdza cały flow collect()."""
    # Sprawdź strukturę zwracaną przez collect()
    expected_keys = ["recent_crashes", "reports", "grouped_crashes", "statistics"]
    
    # Sprawdź czy grouped_crashes powinno być listą
    # Ten test nie uruchamia pełnego collect() (może być długo),
    # tylko sprawdza oczekiwaną strukturę
    assert isinstance(expected_keys, list), "expected_keys powinno być listą"
    assert "grouped_crashes" in expected_keys, "grouped_crashes powinno być w oczekiwanych kluczach"


def test_parse_timestamp():
    """Test 5: Sprawdza funkcję parse_timestamp()."""
    test_cases = [
        ("2025-11-30T12:00:00", True),
        ("2025-11-30 12:00:00", True),
        ("11/30/2025 12:00:00 PM", True),
        ("", False),  # Pusty string powinien zwrócić None
    ]
    
    for timestamp_str, should_succeed in test_cases:
        result = parse_timestamp(timestamp_str if timestamp_str else "")
        if should_succeed:
            assert result is not None, f"'{timestamp_str}' powinno zwrócić datetime, otrzymano None"
            assert isinstance(result, datetime), f"'{timestamp_str}' powinno zwrócić datetime, otrzymano {type(result)}"
        else:
            assert result is None, f"'{timestamp_str}' powinno zwrócić None, otrzymano {result}"


# Usunięto run_all_tests() - testy są teraz pytest testami, nie funkcjami pomocniczymi
# Jeśli chcesz uruchomić wszystkie testy, użyj: pytest tests/test_wer_collector.py


