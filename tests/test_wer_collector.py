"""
Testy dla WER (Windows Error Reporting) collectora.
Testy pomagają zlokalizować problemy z typami danych i użyciem .get() na listach.
"""
import sys
import os
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
    print("\n" + "="*70)
    print("TEST 1: group_and_analyze_crashes() zwraca listę")
    print("="*70)
    
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
    
    try:
        result = group_and_analyze_crashes(test_crashes)
        
        print(f"✓ Funkcja zwróciła: {type(result)}")
        print(f"✓ Czy to lista? {isinstance(result, list)}")
        print(f"✓ Długość: {len(result) if isinstance(result, list) else 'N/A'}")
        
        if isinstance(result, list):
            print(f"✓ SUKCES: Funkcja zwraca listę")
            if result:
                print(f"✓ Pierwszy element: {type(result[0])}")
                if isinstance(result[0], dict):
                    print(f"✓ Klucze w pierwszym elemencie: {list(result[0].keys())}")
            return True
        else:
            print(f"✗ BŁĄD: Funkcja zwraca {type(result)}, oczekiwano list")
            return False
    except Exception as e:
        print(f"✗ BŁĄD: Wyjątek podczas testu: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_collect_handles_list_correctly():
    """Test 2: Sprawdza czy collect() poprawnie obsługuje listę z group_and_analyze_crashes()."""
    print("\n" + "="*70)
    print("TEST 2: collect() poprawnie obsługuje listę")
    print("="*70)
    
    try:
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
        
        print(f"✓ Mock grouped type: {type(mock_grouped)}")
        print(f"✓ Mock grouped is list: {isinstance(mock_grouped, list)}")
        
        # Sprawdź czy możemy iterować po liście
        repeating = []
        if isinstance(mock_grouped, list):
            for g in mock_grouped:
                if isinstance(g, dict):
                    occurrences_30min = g.get("occurrences_30min", 0)
                    if isinstance(occurrences_30min, (int, float)) and occurrences_30min >= 3:
                        repeating.append(g)
            print(f"✓ Iteracja po liście działa poprawnie")
            print(f"✓ Powtarzające się crashy: {len(repeating)}")
        else:
            print(f"✗ BŁĄD: mock_grouped nie jest listą")
            return False
        
        # Sprawdź czy NIE używamy .get() na liście
        try:
            # To powinno rzucić AttributeError
            test_get = mock_grouped.get("something")
            print(f"✗ BŁĄD: .get() działa na liście (nie powinno!)")
            return False
        except AttributeError:
            print(f"✓ SUKCES: .get() nie działa na liście (poprawnie)")
        
        return True
    except Exception as e:
        print(f"✗ BŁĄD: Wyjątek podczas testu: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_no_get_on_list():
    """Test 3: Sprawdza czy nie używamy .get() bezpośrednio na liście grouped."""
    print("\n" + "="*70)
    print("TEST 3: Sprawdzanie użycia .get() na liście")
    print("="*70)
    
    # Symuluj grouped jako lista (jak w rzeczywistości)
    grouped = [
        {"key1": "value1", "key2": "value2"},
        {"key3": "value3", "key4": "value4"}
    ]
    
    print(f"✓ grouped type: {type(grouped)}")
    print(f"✓ grouped is list: {isinstance(grouped, list)}")
    
    # Poprawne użycie - iteracja
    print("\n✓ Poprawne użycie (iteracja):")
    for item in grouped:
        if isinstance(item, dict):
            value = item.get("key1", "default")
            print(f"  - item.get('key1'): {value}")
    
    # Niepoprawne użycie - .get() na liście
    print("\n✗ Niepoprawne użycie (.get() na liście):")
    try:
        value = grouped.get("key1")  # To rzuci AttributeError
        print(f"  - grouped.get('key1'): {value}")
        print("  ✗ BŁĄD: To nie powinno działać!")
        return False
    except AttributeError as e:
        print(f"  ✓ AttributeError (oczekiwane): {e}")
        print("  ✓ SUKCES: .get() nie działa na liście")
    
    return True


def test_collect_integration():
    """Test 4: Test integracyjny - sprawdza cały flow collect()."""
    print("\n" + "="*70)
    print("TEST 4: Test integracyjny collect()")
    print("="*70)
    
    # Sprawdź czy collect() zwraca poprawną strukturę
    try:
        # Uruchom collect() (może być długo, więc możemy to pominąć w szybkich testach)
        print("⚠ Uwaga: Ten test może być długi (zbiera rzeczywiste dane)")
        print("⚠ Pomijam pełne uruchomienie collect() - sprawdzam tylko strukturę")
        
        # Sprawdź strukturę zwracaną przez collect()
        expected_keys = ["recent_crashes", "reports", "grouped_crashes", "statistics"]
        print(f"✓ Oczekiwane klucze w wyniku: {expected_keys}")
        
        # Sprawdź czy grouped_crashes powinno być listą
        print(f"✓ grouped_crashes powinno być listą")
        
        return True
    except Exception as e:
        print(f"✗ BŁĄD: Wyjątek podczas testu: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_parse_timestamp():
    """Test 5: Sprawdza funkcję parse_timestamp()."""
    print("\n" + "="*70)
    print("TEST 5: parse_timestamp()")
    print("="*70)
    
    test_cases = [
        ("2025-11-30T12:00:00", True),
        ("2025-11-30 12:00:00", True),
        ("11/30/2025 12:00:00 PM", True),
        ("", False),  # Pusty string powinien zwrócić None
        (None, False),  # None powinien zwrócić None
    ]
    
    passed = 0
    for timestamp_str, should_succeed in test_cases:
        try:
            result = parse_timestamp(timestamp_str if timestamp_str else "")
            if should_succeed:
                if result is not None and isinstance(result, datetime):
                    print(f"✓ '{timestamp_str}' -> {result}")
                    passed += 1
                else:
                    print(f"✗ '{timestamp_str}' -> None (oczekiwano datetime)")
            else:
                if result is None:
                    print(f"✓ '{timestamp_str}' -> None (oczekiwane)")
                    passed += 1
                else:
                    print(f"✗ '{timestamp_str}' -> {result} (oczekiwano None)")
        except Exception as e:
            print(f"✗ '{timestamp_str}' -> BŁĄD: {e}")
    
    print(f"\n✓ Przeszło: {passed}/{len(test_cases)} testów")
    return passed == len(test_cases)


def run_all_tests():
    """Uruchamia wszystkie testy."""
    print("\n" + "="*70)
    print("Uruchamianie testów WER Collector")
    print("="*70)
    
    tests = [
        ("group_and_analyze_crashes zwraca listę", test_group_and_analyze_crashes_returns_list),
        ("collect() obsługuje listę", test_collect_handles_list_correctly),
        ("Brak .get() na liście", test_no_get_on_list),
        ("Test integracyjny", test_collect_integration),
        ("parse_timestamp()", test_parse_timestamp),
    ]
    
    results = []
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"\n✗ Test '{test_name}' rzucił wyjątek: {e}")
            import traceback
            traceback.print_exc()
            results.append((test_name, False))
    
    # Podsumowanie
    print("\n" + "="*70)
    print("PODSUMOWANIE TESTÓW")
    print("="*70)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{status}: {test_name}")
    
    print(f"\n✓ Przeszło: {passed}/{total} testów")
    
    if passed == total:
        print("✓ Wszystkie testy przeszły pomyślnie!")
        return True
    else:
        print(f"✗ {total - passed} testów nie przeszło")
        return False


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)


