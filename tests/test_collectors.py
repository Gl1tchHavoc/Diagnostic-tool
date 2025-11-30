"""
Testy dla wszystkich collectorów - rozszerzone coverage.
"""
import os
import unittest
import sys
from pathlib import Path
from unittest.mock import patch

# Dodaj główny katalog projektu do ścieżki
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from collectors import (
    hardware, drivers, system_logs, registry_txr, storage_health, system_info,
    services, bsod_dumps, performance_counters, wer, processes
)
import collectors.whea_analyzer as whea_analyzer
from collectors.collector_master import collect_all
from collectors.collector_master_async import collect_all_async_wrapper
from core.collector_registry import get_registry, register_all_collectors

# Wykryj środowisko CI
# Rozwiązuje problemy z WMI/SPD w CI (GitHub Actions, Azure DevOps)
# gdzie niektóre funkcje hardware wymagają prawdziwego sprzętu
IS_CI = (
    os.environ.get("CI") in ("true", "1", "True") or
    os.environ.get("GITHUB_ACTIONS") == "true" or
    os.environ.get("TF_BUILD") == "True"  # Azure DevOps
)


class TestCollectors(unittest.TestCase):
    """Testy podstawowe dla wszystkich collectorów."""
    
    @classmethod
    def setUpClass(cls):
        """Inicjalizacja przed wszystkimi testami."""
        register_all_collectors()
    
    def test_hardware_collector(self):
        """Test collectora hardware."""
        # W CI mockuj wszystkie funkcje używające WMI - mogą powodować access violation
        if IS_CI:
            with patch('collectors.hardware._collect_memory_spd') as mock_spd, \
                 patch('collectors.hardware._collect_pci') as mock_pci, \
                 patch('collectors.hardware._collect_ram_slots') as mock_ram_slots, \
                 patch('collectors.hardware._collect_motherboard') as mock_mb, \
                 patch('collectors.hardware._collect_chassis') as mock_chassis, \
                 patch('collectors.hardware._collect_usb') as mock_usb, \
                 patch('collectors.hardware._collect_gpu') as mock_gpu:
                
                mock_spd.return_value = [
                    {
                        'manufacturer': 'Test Manufacturer',
                        'part_number': 'TEST-1234',
                        'capacity': 8589934592,
                        'speed': 3200
                    }
                ]
                mock_pci.return_value = [
                    {
                        'name': 'Test PCI Device',
                        'device_id': 'PCI\\VEN_TEST&DEV_1234',
                        'manufacturer': 'Test Manufacturer',
                        'pnp_class': 'PCI'
                    }
                ]
                mock_ram_slots.return_value = []
                mock_mb.return_value = {
                    'boards': [],
                    'bios': [],
                    'chipset': []
                }
                mock_chassis.return_value = []
                mock_usb.return_value = []
                mock_gpu.return_value = []
                
                result = hardware.collect()
        else:
            # Lokalnie - użyj prawdziwej funkcji
            result = hardware.collect()
        
        self.assertIsNotNone(result)
        self.assertIsInstance(result, dict)
        # Sprawdź podstawowe pola
        if "cpu" in result:
            self.assertIsInstance(result["cpu"], dict)
        if "ram" in result:
            self.assertIsInstance(result["ram"], dict)
        # Sprawdź czy memory_spd jest w wynikach
        if "memory_spd" in result:
            self.assertIsInstance(result["memory_spd"], list)
        # Sprawdź czy pci_devices jest w wynikach
        if "pci_devices" in result:
            self.assertIsInstance(result["pci_devices"], list)
    
    def test_drivers_collector(self):
        """Test collectora drivers."""
        result = drivers.collect()
        self.assertIsNotNone(result)
        self.assertIsInstance(result, (dict, list))
    
    def test_system_info_collector(self):
        """Test collectora system_info."""
        result = system_info.collect()
        self.assertIsNotNone(result)
        self.assertIsInstance(result, dict)
        # Sprawdź podstawowe pola
        if "os_version" in result:
            self.assertIsInstance(result["os_version"], str)
    
    def test_storage_health_collector(self):
        """Test collectora storage_health."""
        result = storage_health.collect()
        self.assertIsNotNone(result)
        self.assertIsInstance(result, dict)
    
    def test_services_collector(self):
        """Test collectora services."""
        result = services.collect()
        self.assertIsNotNone(result)
        self.assertIsInstance(result, (dict, list))
    
    def test_processes_collector(self):
        """Test collectora processes."""
        result = processes.collect()
        self.assertIsNotNone(result)
        self.assertIsInstance(result, (dict, list))
    
    def test_system_logs_collector(self):
        """Test collectora system_logs."""
        result = system_logs.collect(max_events=10, filter_levels=['Error'])
        self.assertIsNotNone(result)
        self.assertIsInstance(result, dict)
    
    def test_registry_txr_collector(self):
        """Test collectora registry_txr."""
        result = registry_txr.collect(max_events=10)
        self.assertIsNotNone(result)
        # registry_txr.collect() zwraca listę, nie dict
        self.assertIsInstance(result, (list, dict))
        # Jeśli to lista, sprawdź czy nie jest pusta lub czy elementy są dict
        if isinstance(result, list):
            if result:
                self.assertIsInstance(result[0], dict)
    
    def test_bsod_dumps_collector(self):
        """Test collectora bsod_dumps."""
        result = bsod_dumps.collect()
        self.assertIsNotNone(result)
        self.assertIsInstance(result, dict)
    
    def test_whea_analyzer_collector(self):
        """Test collectora whea_analyzer."""
        result = whea_analyzer.collect()
        self.assertIsNotNone(result)
        self.assertIsInstance(result, dict)
    
    def test_performance_counters_collector(self):
        """Test collectora performance_counters."""
        result = performance_counters.collect()
        self.assertIsNotNone(result)
        self.assertIsInstance(result, dict)
    
    def test_wer_collector(self):
        """Test collectora wer."""
        result = wer.collect()
        self.assertIsNotNone(result)
        self.assertIsInstance(result, dict)


class TestCollectorMaster(unittest.TestCase):
    """Testy dla Collector Master."""
    
    @classmethod
    def setUpClass(cls):
        """Inicjalizacja przed wszystkimi testami."""
        register_all_collectors()
    
    def test_collect_all_format(self):
        """Test czy collect_all zwraca poprawny format MVP."""
        # W CI mockuj wszystkie funkcje hardware używające WMI
        if IS_CI:
            with patch('collectors.hardware._collect_memory_spd') as mock_spd, \
                 patch('collectors.hardware._collect_pci') as mock_pci, \
                 patch('collectors.hardware._collect_ram_slots') as mock_ram_slots, \
                 patch('collectors.hardware._collect_motherboard') as mock_mb, \
                 patch('collectors.hardware._collect_chassis') as mock_chassis, \
                 patch('collectors.hardware._collect_usb') as mock_usb, \
                 patch('collectors.hardware._collect_gpu') as mock_gpu:
                
                mock_spd.return_value = []
                mock_pci.return_value = []
                mock_ram_slots.return_value = []
                mock_mb.return_value = {'boards': [], 'bios': [], 'chipset': []}
                mock_chassis.return_value = []
                mock_usb.return_value = []
                mock_gpu.return_value = []
                
                result = collect_all(save_raw=False, output_dir="output/raw")
        else:
            # Lokalnie - użyj prawdziwej funkcji
            result = collect_all(save_raw=False, output_dir="output/raw")
        
        # Sprawdź strukturę
        self.assertIsInstance(result, dict)
        self.assertIn("timestamp", result)
        self.assertIn("collectors", result)
        self.assertIn("summary", result)
        
        # Sprawdź summary
        summary = result["summary"]
        self.assertIn("total_collectors", summary)
        self.assertIn("collected", summary)
        self.assertIn("errors", summary)
        
        # Sprawdź format każdego collectora
        collectors = result["collectors"]
        for name, collector_result in collectors.items():
            self.assertIsInstance(collector_result, dict)
            if "status" in collector_result:
                self.assertIn(collector_result["status"], ["Collected", "Error"])
                if collector_result["status"] == "Collected":
                    self.assertIn("data", collector_result)
                if collector_result["status"] == "Error":
                    self.assertIn("error", collector_result)
    
    def test_collect_all_async_wrapper(self):
        """Test asynchronicznej wersji collect_all."""
        # W CI mockuj wszystkie funkcje hardware używające WMI
        if IS_CI:
            with patch('collectors.hardware._collect_memory_spd') as mock_spd, \
                 patch('collectors.hardware._collect_pci') as mock_pci, \
                 patch('collectors.hardware._collect_ram_slots') as mock_ram_slots, \
                 patch('collectors.hardware._collect_motherboard') as mock_mb, \
                 patch('collectors.hardware._collect_chassis') as mock_chassis, \
                 patch('collectors.hardware._collect_usb') as mock_usb, \
                 patch('collectors.hardware._collect_gpu') as mock_gpu:
                
                mock_spd.return_value = []
                mock_pci.return_value = []
                mock_ram_slots.return_value = []
                mock_mb.return_value = {'boards': [], 'bios': [], 'chipset': []}
                mock_chassis.return_value = []
                mock_usb.return_value = []
                mock_gpu.return_value = []
                
                result = collect_all_async_wrapper(
                    save_raw=False, output_dir="output/raw"
                )
        else:
            # Lokalnie - użyj prawdziwej funkcji
            result = collect_all_async_wrapper(
                save_raw=False, output_dir="output/raw"
            )
        
        # Sprawdź strukturę (taka sama jak synchroniczna)
        self.assertIsInstance(result, dict)
        self.assertIn("timestamp", result)
        self.assertIn("collectors", result)
        self.assertIn("summary", result)


class TestCollectorRegistry(unittest.TestCase):
    """Testy dla Collector Registry."""
    
    @classmethod
    def setUpClass(cls):
        """Inicjalizacja przed wszystkimi testami."""
        register_all_collectors()
    
    def test_registry_get_all(self):
        """Test pobierania wszystkich collectorów z rejestru."""
        registry = get_registry()
        collectors = registry.get_all()
        
        self.assertIsInstance(collectors, dict)
        self.assertGreater(len(collectors), 0)
        
        # Sprawdź czy wszystkie mają wymagane pola
        for name, info in collectors.items():
            self.assertIn("name", info)
            self.assertIn("collect_func", info)
            self.assertIn("enabled", info)
    
    def test_registry_get_enabled(self):
        """Test pobierania tylko włączonych collectorów."""
        registry = get_registry()
        enabled = registry.get_all(enabled_only=True)
        
        self.assertIsInstance(enabled, dict)
        for name, info in enabled.items():
            self.assertTrue(info.get("enabled", False))


if __name__ == "__main__":
    unittest.main()

