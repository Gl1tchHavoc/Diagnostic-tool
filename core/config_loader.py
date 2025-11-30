"""
Config Loader - wczytuje i zarządza konfiguracją aplikacji.
"""
import json
from pathlib import Path
from typing import Any, Dict, Optional

from utils.logger import get_logger

logger = get_logger()

# Domyślna konfiguracja
DEFAULT_CONFIG = {
    "app": {
        "name": "Diagnostic Tool MVP",
        "version": "1.0.0",
        "mode": "GUI",
        "log_level": "INFO"
    },
    "collectors": {
        "enabled": [
            "hardware",
            "drivers",
            "system_logs",
            "registry_txr",
            "storage_health",
            "system_info",
            "services",
            "bsod_dumps",
            "whea_analyzer",
            "performance_counters",
            "wer",
            "processes"
        ],
        "timeout_seconds": 300,
        "parallel_execution": True,
        "max_events": {
            "system_logs": 200,
            "registry_txr": 200
        }
    },
    "processors": {
        "enabled": [
            "hardware_processor",
            "driver_processor",
            "system_logs_processor",
            "registry_txr_processor",
            "storage_health_processor",
            "system_info_processor"
        ],
        "validation_strict": False
    },
    "output": {
        "save_raw": True,
        "raw_output_dir": "output/raw",
        "processed_output_dir": "output/processed",
        "keep_last_raw_files": 5,
        "export_formats": ["json", "html"]
    },
    "gui": {
        "show_raw_data": True,
        "auto_refresh_interval_seconds": 0,
        "theme": "dark"
    },
    "logging": {
        "file_logging": True,
        "console_logging": False,
        "log_dir": "logs",
        "log_file_prefix": "diagnostic_tool",
        "log_rotation": True,
        "max_log_files": 10
    }
}


class ConfigLoader:
    """Klasa do wczytywania i zarządzania konfiguracją."""

    def __init__(self, config_path: Optional[str] = None):
        """
        Inicjalizuje ConfigLoader.

        Args:
            config_path: Ścieżka do pliku konfiguracyjnego (domyślnie config.json)
        """
        self.config_path = Path(
            config_path) if config_path else Path("config.json")
        self.config = DEFAULT_CONFIG.copy()
        self.load_config()

    def load_config(self) -> Dict[str, Any]:
        """
        Wczytuje konfigurację z pliku lub używa domyślnej.

        Returns:
            dict: Wczytana konfiguracja
        """
        if self.config_path.exists():
            try:
                with open(self.config_path, "r", encoding="utf-8") as f:
                    file_config = json.load(f)
                    # Merge z domyślną konfiguracją
                    self.config = self._merge_config(
                        DEFAULT_CONFIG, file_config)
                    logger.info(
                        f"[CONFIG] Loaded configuration from {self.config_path}")
            except Exception as e:
                logger.warning(
                    f"[CONFIG] Failed to load config file: {e}, using defaults")
        else:
            logger.info(f"[CONFIG] Config file not found, using defaults")
            # Utwórz domyślny plik konfiguracyjny
            self.save_config()

        return self.config

    def _merge_config(self, default: Dict, override: Dict) -> Dict:
        """Rekurencyjnie łączy konfiguracje."""
        result = default.copy()
        for key, value in override.items():
            if key in result and isinstance(
                    result[key], dict) and isinstance(value, dict):
                result[key] = self._merge_config(result[key], value)
            else:
                result[key] = value
        return result

    def save_config(self) -> bool:
        """
        Zapisuje aktualną konfigurację do pliku.

        Returns:
            bool: True jeśli zapis się powiódł
        """
        try:
            with open(self.config_path, "w", encoding="utf-8") as f:
                json.dump(self.config, f, indent=2, ensure_ascii=False)
            logger.info(f"[CONFIG] Saved configuration to {self.config_path}")
            return True
        except Exception as e:
            logger.error(f"[CONFIG] Failed to save config: {e}")
            return False

    def get(self, key_path: str, default: Any = None) -> Any:
        """
        Pobiera wartość z konfiguracji używając ścieżki kluczy (np. "collectors.timeout_seconds").

        Args:
            key_path: Ścieżka do wartości (np. "collectors.timeout_seconds")
            default: Wartość domyślna jeśli klucz nie istnieje

        Returns:
            Wartość z konfiguracji lub default
        """
        keys = key_path.split(".")
        value = self.config
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default
        return value

    def set(self, key_path: str, value: Any) -> bool:
        """
        Ustawia wartość w konfiguracji używając ścieżki kluczy.

        Args:
            key_path: Ścieżka do wartości
            value: Nowa wartość

        Returns:
            bool: True jeśli ustawienie się powiodło
        """
        keys = key_path.split(".")
        config = self.config
        for key in keys[:-1]:
            if key not in config:
                config[key] = {}
            config = config[key]
        config[keys[-1]] = value
        return True


# Globalna instancja konfiguracji
_config_instance: Optional[ConfigLoader] = None


def get_config() -> ConfigLoader:
    """Zwraca globalną instancję konfiguracji."""
    global _config_instance
    if _config_instance is None:
        _config_instance = ConfigLoader()
    return _config_instance
