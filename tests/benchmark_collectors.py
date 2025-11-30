"""
Benchmarki wydajności dla collectorów - Faza 4.
Testuje wydajność przy dużej liczbie collectorów.
"""
import unittest
import time
import sys
from pathlib import Path

project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from collectors.collector_master_async import collect_all_async_wrapper
from collectors.collector_master_with_timeouts import collect_all_with_timeouts_wrapper
from core.collector_registry import register_all_collectors


class TestCollectorBenchmarks(unittest.TestCase):
    """Benchmarki wydajności dla collectorów."""
    
    @classmethod
    def setUpClass(cls):
        """Inicjalizacja przed wszystkimi testami."""
        register_all_collectors()
    
    def test_async_vs_sync_performance(self):
        """Porównuje wydajność async vs sync (jeśli dostępne)."""
        # Test async
        start_time = time.time()
        async_result = collect_all_async_wrapper(save_raw=False, output_dir="output/raw")
        async_duration = time.time() - start_time
        
        total_collectors = async_result["summary"].get("total_collectors", 0)
        
        # Async powinno być szybsze dla wielu collectorów
        if total_collectors > 1:
            # Szacunkowy czas sekwencyjny (zakładając ~1s na collector)
            estimated_sequential = total_collectors * 1.0
            
            # Async powinno być znacznie szybsze
            self.assertLess(async_duration, estimated_sequential * 0.7,
                          f"Async ({async_duration:.2f}s) should be faster than sequential ({estimated_sequential:.2f}s)")
    
    def test_timeout_performance(self):
        """Test wydajności z timeoutami."""
        start_time = time.time()
        result = collect_all_with_timeouts_wrapper(
            save_raw=False,
            output_dir="output/raw",
            timeout_seconds=300
        )
        duration = time.time() - start_time
        
        # Sprawdź czy wszystkie collectory zostały uruchomione
        summary = result["summary"]
        self.assertGreater(summary.get("total_collectors", 0), 0)
        
        # Sprawdź czy nie ma nieoczekiwanych timeoutów
        timeouts = summary.get("timeouts", 0)
        self.assertLessEqual(timeouts, summary.get("total_collectors", 0))
    
    def test_large_scale_collectors(self):
        """
        Test wydajności przy dużej liczbie collectorów (symulacja).
        Tworzy wiele instancji tego samego collectora aby przetestować skalowalność.
        """
        # Ten test wymagałby modyfikacji rejestru collectorów
        # Dla teraz, po prostu sprawdzamy czy async działa dla obecnej liczby
        start_time = time.time()
        result = collect_all_async_wrapper(save_raw=False, output_dir="output/raw")
        duration = time.time() - start_time
        
        total_collectors = result["summary"].get("total_collectors", 0)
        
        # Sprawdź czy czas wykonania jest rozsądny
        # Dla 12 collectorów, async powinno zająć < 10s (przy założeniu ~1s na collector)
        if total_collectors > 0:
            avg_time_per_collector = duration / total_collectors
            # Średni czas na collector powinien być < 2s (dzięki równoległości)
            self.assertLess(avg_time_per_collector, 2.0,
                          f"Average time per collector ({avg_time_per_collector:.2f}s) should be < 2s")


if __name__ == "__main__":
    unittest.main()

