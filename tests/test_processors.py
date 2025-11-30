"""
Testy dla wszystkich procesorów - rozszerzone coverage.

NOTE: Processors moved to archive/ - not needed in MVP.
All tests in this file are disabled until processors are restored.
"""
import unittest
import sys
from pathlib import Path

# Dodaj główny katalog projektu do ścieżki
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# Processors moved to archive/ - not needed in MVP
# from processors import (
#     hardware_processor, driver_processor, system_logs_processor,
#     registry_txr_processor, storage_health_processor, system_info_processor
# )
# from processors.base_processor import process_collector_data
from core.processor_registry import get_registry, register_all_processors


class TestProcessors(unittest.TestCase):
    """Testy podstawowe dla wszystkich procesorów."""
    
    @classmethod
    def setUpClass(cls):
        """Inicjalizacja przed wszystkimi testami."""
        # register_all_processors()  # Disabled - processors in archive
        pass
    
    def test_hardware_processor(self):
        """Test procesora hardware."""
        # Processors moved to archive/ - test disabled
        self.skipTest("Processors moved to archive/ - not needed in MVP")
    
    def test_driver_processor(self):
        """Test procesora driver."""
        self.skipTest("Processors moved to archive/ - not needed in MVP")
    
    def test_system_logs_processor(self):
        """Test procesora system_logs."""
        self.skipTest("Processors moved to archive/ - not needed in MVP")
    
    def test_registry_txr_processor(self):
        """Test procesora registry_txr."""
        self.skipTest("Processors moved to archive/ - not needed in MVP")
    
    def test_storage_health_processor(self):
        """Test procesora storage_health."""
        self.skipTest("Processors moved to archive/ - not needed in MVP")
    
    def test_system_info_processor(self):
        """Test procesora system_info."""
        self.skipTest("Processors moved to archive/ - not needed in MVP")


class TestBaseProcessor(unittest.TestCase):
    """Testy dla bazowego procesora MVP."""
    
    def test_process_collector_data_success(self):
        """Test przetwarzania danych collectora - sukces."""
        self.skipTest("Processors moved to archive/ - not needed in MVP")
    
    def test_process_collector_data_error(self):
        """Test przetwarzania danych collectora - błąd."""
        self.skipTest("Processors moved to archive/ - not needed in MVP")
    
    def test_process_collector_data_invalid(self):
        """Test przetwarzania danych collectora - nieprawidłowe dane."""
        self.skipTest("Processors moved to archive/ - not needed in MVP")


class TestProcessorRegistry(unittest.TestCase):
    """Testy dla Processor Registry."""
    
    @classmethod
    def setUpClass(cls):
        """Inicjalizacja przed wszystkimi testami."""
        # register_all_processors()  # Disabled - processors in archive
        pass
    
    def test_registry_get_all(self):
        """Test pobierania wszystkich procesorów z rejestru."""
        self.skipTest("Processors moved to archive/ - not needed in MVP")
    
    def test_registry_get_for_collector(self):
        """Test pobierania procesora dla collectora."""
        self.skipTest("Processors moved to archive/ - not needed in MVP")


if __name__ == "__main__":
    unittest.main()
