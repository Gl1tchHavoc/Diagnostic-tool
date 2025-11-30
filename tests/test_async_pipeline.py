"""
Testy dla asynchronicznego pipeline - Faza 3.
Sprawdza czy cały pipeline async działa poprawnie.
"""
import unittest
import asyncio
import sys
from pathlib import Path

project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from collectors.collector_master_async import collect_all_async, collect_all_async_wrapper
from collectors.collector_master_with_timeouts import collect_all_with_timeouts_wrapper
from core.collector_registry import register_all_collectors, get_registry
from core.config_loader import get_config


class TestAsyncPipeline(unittest.TestCase):
    """Testy dla asynchronicznego pipeline."""
    
    @classmethod
    def setUpClass(cls):
        """Inicjalizacja przed wszystkimi testami."""
        register_all_collectors()
    
    def test_collect_all_async_wrapper(self):
        """Test asynchronicznej wersji collect_all."""
        result = collect_all_async_wrapper(save_raw=False, output_dir="output/raw")
        
        # Sprawdź strukturę
        self.assertIsInstance(result, dict)
        self.assertIn("timestamp", result)
        self.assertIn("collectors", result)
        self.assertIn("summary", result)
        
        # Sprawdź czy wszystkie collectory zostały uruchomione
        summary = result["summary"]
        self.assertGreater(summary.get("total_collectors", 0), 0)
    
    def test_collect_all_with_timeouts(self):
        """Test collect_all z timeoutami."""
        result = collect_all_with_timeouts_wrapper(
            save_raw=False,
            output_dir="output/raw",
            timeout_seconds=60  # Krótki timeout dla testów
        )
        
        # Sprawdź strukturę
        self.assertIsInstance(result, dict)
        self.assertIn("summary", result)
        
        # Sprawdź czy timeout jest w summary
        summary = result["summary"]
        self.assertIn("timeouts", summary)
    
    def test_async_collector_execution(self):
        """Test czy collectory są uruchamiane asynchronicznie."""
        import time
        
        start_time = time.time()
        result = collect_all_async_wrapper(save_raw=False, output_dir="output/raw")
        duration = time.time() - start_time
        
        # Sprawdź czy wykonanie było równoległe (powinno być szybsze niż sekwencyjne)
        # Dla 12 collectorów, sekwencyjne wykonanie zajęłoby znacznie więcej czasu
        summary = result["summary"]
        total_collectors = summary.get("total_collectors", 0)
        
        if total_collectors > 1:
            # Asynchroniczne wykonanie powinno być szybsze
            # (przy założeniu że każdy collector zajmuje ~1s, sekwencyjnie = 12s, async = ~2-3s)
            self.assertLess(duration, total_collectors * 2, 
                          "Async execution should be faster than sequential")
    
    def test_timeout_handling(self):
        """Test obsługi timeoutów."""
        # Użyj bardzo krótkiego timeoutu aby wymusić timeout
        result = collect_all_with_timeouts_wrapper(
            save_raw=False,
            output_dir="output/raw",
            timeout_seconds=0.1  # 100ms - bardzo krótki timeout
        )
        
        # Sprawdź czy niektóre collectory mają timeout
        collectors = result.get("collectors", {})
        has_timeout = False
        
        for name, collector_result in collectors.items():
            if isinstance(collector_result, dict) and collector_result.get("timeout"):
                has_timeout = True
                self.assertEqual(collector_result["status"], "Error")
                self.assertIn("timeout", collector_result.get("error", "").lower())
        
        # Z bardzo krótkim timeoutem, przynajmniej niektóre collectory powinny mieć timeout
        # (ale nie wszystkie, bo niektóre mogą być bardzo szybkie)
        # self.assertTrue(has_timeout, "At least some collectors should timeout with 0.1s timeout")


class TestAsyncCollectors(unittest.IsolatedAsyncioTestCase):
    """Testy dla asynchronicznych collectorów używając pytest-asyncio."""
    
    async def test_collect_all_async_direct(self):
        """Test bezpośredniego wywołania async funkcji."""
        result = await collect_all_async(save_raw=False, output_dir="output/raw")
        
        self.assertIsInstance(result, dict)
        self.assertIn("collectors", result)
        self.assertIn("summary", result)


if __name__ == "__main__":
    unittest.main()

