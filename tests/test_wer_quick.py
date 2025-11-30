"""
Szybki test diagnostyczny dla WER - pomaga zlokalizować problem z .get() na liście.
"""
import sys
from pathlib import Path

# Dodaj główny katalog projektu do ścieżki
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from collectors.wer import group_and_analyze_crashes
from datetime import datetime, timedelta


def quick_test():
    """Szybki test - sprawdza typ zwracany przez group_and_analyze_crashes()."""
    print("="*70)
    print("SZYBKI TEST DIAGNOSTYCZNY - WER Collector")
    print("="*70)
    
    # Testowe dane
    test_crashes = [
        {
            "application": "test.exe",
            "module_name": "test.dll",
            "exception_code": "0x00000000",
            "timestamp": datetime.now().isoformat()
        }
    ]
    
    print(f"\n1. Wywołuję group_and_analyze_crashes()...")
    try:
        result = group_and_analyze_crashes(test_crashes)
        
        print(f"\n2. Wynik:")
        print(f"   - Typ: {type(result)}")
        print(f"   - Czy to lista? {isinstance(result, list)}")
        print(f"   - Czy to dict? {isinstance(result, dict)}")
        
        if isinstance(result, list):
            print(f"   - Długość: {len(result)}")
            if result:
                print(f"   - Typ pierwszego elementu: {type(result[0])}")
                if isinstance(result[0], dict):
                    print(f"   - Klucze: {list(result[0].keys())}")
        elif isinstance(result, dict):
            print(f"   - Klucze: {list(result.keys())}")
            print(f"   ⚠ UWAGA: Funkcja zwraca dict, a powinna zwracać listę!")
        
        print(f"\n3. Test użycia .get() na wyniku:")
        try:
            test_get = result.get("something")
            print(f"   ✗ BŁĄD: .get() działa na {type(result)} - to może być problem!")
            print(f"   ⚠ Jeśli result to lista, .get() nie powinno działać")
        except AttributeError:
            print(f"   ✓ OK: .get() nie działa (oczekiwane dla listy)")
        
        print(f"\n4. Test iteracji:")
        if isinstance(result, list):
            print(f"   ✓ Można iterować: for item in result:")
            for i, item in enumerate(result[:3]):  # Tylko pierwsze 3
                print(f"      [{i}] {type(item)}")
        else:
            print(f"   ⚠ Nie można iterować bezpośrednio (to dict)")
        
        print(f"\n{'='*70}")
        print("PODSUMOWANIE:")
        print(f"{'='*70}")
        if isinstance(result, list):
            print("✓ group_and_analyze_crashes() zwraca listę - POPRAWNIE")
            print("✓ W collect() należy używać: for g in grouped:")
            print("✗ NIE używaj: grouped.get(...)")
        else:
            print("✗ group_and_analyze_crashes() zwraca coś innego niż lista")
            print("  To może być źródłem problemu!")
        
        return isinstance(result, list)
        
    except Exception as e:
        print(f"\n✗ BŁĄD: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = quick_test()
    print(f"\n{'='*70}")
    if success:
        print("✓ Test zakończony pomyślnie")
    else:
        print("✗ Test wykrył problemy")
    print(f"{'='*70}\n")
    sys.exit(0 if success else 1)


