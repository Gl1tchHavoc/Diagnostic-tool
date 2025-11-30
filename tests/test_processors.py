"""
Testy dla wszystkich procesorów - rozszerzone coverage.
"""
import unittest
import sys
from pathlib import Path

# Dodaj główny katalog projektu do ścieżki
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from processors import (
    hardware_processor, driver_processor, system_logs_processor,
    registry_txr_processor, storage_health_processor, system_info_processor
)
from processors.base_processor import process_collector_data
from core.processor_registry import get_registry, register_all_processors


class TestProcessors(unittest.TestCase):
    """Testy podstawowe dla wszystkich procesorów."""
    
    @classmethod
    def setUpClass(cls):
        """Inicjalizacja przed wszystkimi testami."""
        register_all_processors()
    
    def test_hardware_processor(self):
        """Test procesora hardware."""
        # Mock data
        mock_data = {
            "cpu": {"usage_percent": 50},
            "ram": {"percent": 60}
        }
        result = hardware_processor.process(mock_data)
        self.assertIsNotNone(result)
        self.assertIsInstance(result, dict)
    
    def test_driver_processor(self):
        """Test procesora driver."""
        # Mock data
        mock_data = []
        result = driver_processor.process(mock_data)
        self.assertIsNotNone(result)
        self.assertIsInstance(result, dict)
    
    def test_system_logs_processor(self):
        """Test procesora system_logs."""
        # Mock data
        mock_data = {
            "error": [],
            "warning": []
        }
        result = system_logs_processor.process(mock_data)
        self.assertIsNotNone(result)
        self.assertIsInstance(result, dict)
    
    def test_registry_txr_processor(self):
        """Test procesora registry_txr."""
        # Mock data
        mock_data = {
            "txr_errors": []
        }
        result = registry_txr_processor.process(mock_data)
        self.assertIsNotNone(result)
        self.assertIsInstance(result, dict)
    
    def test_storage_health_processor(self):
        """Test procesora storage_health."""
        # Mock data
        mock_data = {
            "disks": []
        }
        result = storage_health_processor.process(mock_data)
        self.assertIsNotNone(result)
        self.assertIsInstance(result, dict)
    
    def test_system_info_processor(self):
        """Test procesora system_info."""
        # Mock data
        mock_data = {
            "os_version": "Windows 10"
        }
        result = system_info_processor.process(mock_data)
        self.assertIsNotNone(result)
        self.assertIsInstance(result, dict)


class TestBaseProcessor(unittest.TestCase):
    """Testy dla bazowego procesora MVP."""
    
    def test_process_collector_data_success(self):
        """Test przetwarzania danych collectora - sukces."""
        collector_result = {
            "status": "Collected",
            "data": {"test": "data"},
            "error": None,
            "timestamp": "2025-11-30T12:00:00",
            "collector_name": "test",
            "execution_time_ms": 100
        }
        
        result = process_collector_data(collector_result, "test_processor")
        
        self.assertIsNotNone(result)
        self.assertEqual(result["status"], "Collected")
        self.assertEqual(result["processor_name"], "test_processor")
        self.assertTrue(result["validation_passed"])
        self.assertEqual(result["data"], {"test": "data"})
    
    def test_process_collector_data_error(self):
        """Test przetwarzania danych collectora - błąd."""
        collector_result = {
            "status": "Error",
            "data": None,
            "error": "Test error",
            "timestamp": "2025-11-30T12:00:00",
            "collector_name": "test",
            "execution_time_ms": 100
        }
        
        result = process_collector_data(collector_result, "test_processor")
        
        self.assertIsNotNone(result)
        self.assertEqual(result["status"], "Error")
        self.assertFalse(result["validation_passed"])
        self.assertIn("Test error", result["errors"])
    
    def test_process_collector_data_invalid(self):
        """Test przetwarzania danych collectora - nieprawidłowe dane."""
        collector_result = {
            "status": "Collected",
            "data": None,  # None data
            "error": None,
            "timestamp": "2025-11-30T12:00:00",
            "collector_name": "test",
            "execution_time_ms": 100
        }
        
        result = process_collector_data(collector_result, "test_processor")
        
        self.assertIsNotNone(result)
        self.assertEqual(result["status"], "Error")
        self.assertFalse(result["validation_passed"])
        self.assertGreater(len(result["errors"]), 0)


class TestProcessorRegistry(unittest.TestCase):
    """Testy dla Processor Registry."""
    
    @classmethod
    def setUpClass(cls):
        """Inicjalizacja przed wszystkimi testami."""
        register_all_processors()
    
    def test_registry_get_all(self):
        """Test pobierania wszystkich procesorów z rejestru."""
        registry = get_registry()
        processors = registry.get_all()
        
        self.assertIsInstance(processors, dict)
        self.assertGreater(len(processors), 0)
        
        # Sprawdź czy wszystkie mają wymagane pola
        for name, info in processors.items():
            self.assertIn("name", info)
            self.assertIn("process_func", info)
    
    def test_registry_get_for_collector(self):
        """Test pobierania procesora dla collectora."""
        registry = get_registry()
        processor_name = registry.get_for_collector("hardware")
        
        self.assertIsNotNone(processor_name)
        self.assertEqual(processor_name, "hardware_processor")


if __name__ == "__main__":
    unittest.main()

