# BSOD Collector - Ulepszenia i Funkcjonalności

## Przegląd

Collector BSOD (`collectors/bsod_dumps.py`) został znacząco ulepszony, aby zapewnić kompleksową analizę crashy systemu Windows z pełnym kontekstem sprzętowym i systemowym.

## Główne Funkcjonalności

### 1. Automatyczne Wykrywanie Ścieżek Dumpów

**Problem:** Minidumps mogą być przechowywane w niestandardowych lokalizacjach, które nie są sprawdzane przez standardowe ścieżki.

**Rozwiązanie:**
- Odczyt ścieżek z rejestru Windows:
  - `HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl` → `DumpFile` (pełny dump)
  - `HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl` → `MinidumpDir` (minidumps)
- Fallback paths:
  - `C:\Windows\Minidump`
  - `C:\Windows\MEMORY.DMP`
  - `%LOCALAPPDATA%\CrashDumps`

**Funkcje:**
- `_get_dump_paths_from_registry()` - Odczytuje ścieżki z rejestru
- `_get_fallback_dump_paths()` - Zwraca standardowe ścieżki fallback
- Graceful handling błędów rejestru (nie przerywa procesu)

### 2. Ulepszone Parsowanie Minidumpów

**Problem:** Podstawowe parsowanie binarnych danych często nie znajduje drivera odpowiedzialnego za crash.

**Rozwiązanie:**
- Fallback do WinDbg dla lepszego wykrywania driverów
- Zwiększone timeouty dla dużych dumpów (60s dla >100MB, 30s dla mniejszych)
- Lepsze logowanie znalezionych driverów

**Funkcje:**
- `_parse_bugcheck_with_windbg()` - Parsowanie z WinDbg
- `_create_enhanced_dump_info()` - Tworzy rozszerzone informacje o dumpie
- Automatyczne użycie WinDbg jeśli `parse_minidump` nie znalazło drivera

**Przykład:**
```python
# Jeśli parse_minidump zwróci "Unknown" lub None
if not faulting_driver or faulting_driver == "Unknown":
    windbg_info = _parse_bugcheck_with_windbg(str(dump_path))
    if windbg_info and windbg_info.get('faulting_driver'):
        faulting_driver = windbg_info.get('faulting_driver')
```

### 3. Rozszerzona Korelacja WHEA z Crashami

**Problem:** WHEA errors mogą być powiązane z crashami, ale korelacja czasowa była zbyt wąska.

**Rozwiązanie:**
- Rozszerzone okno korelacji do ±10 minut
- Kierunek korelacji (WHEA→BSOD, BSOD→WHEA, WHEA→MINIDUMP, MINIDUMP→WHEA)
- Dokładna różnica czasowa w sekundach

**Funkcje:**
- `_correlate_whea_with_crashes()` - Koreluje WHEA events z bugchecks/minidumps
- `_determine_whea_hardware_component()` - Określa komponent sprzętowy z rozszerzonymi keywords

**Przykład outputu:**
```json
{
  "related_bugcheck": {
    "bugcheck_code": "0x0000000A",
    "timestamp": "2025-12-01T17:21:14",
    "correlation_direction": "WHEA→BSOD",
    "time_difference_seconds": 45
  }
}
```

### 4. Kontekst Sprzętowy w Czasie Crashu

**Problem:** Brak informacji o stanie sprzętu w momencie crashu utrudnia diagnozę.

**Rozwiązanie:**
- Zbieranie temperatury CPU/GPU
- Zbieranie użycia RAM (total, used, available, percent, swap)
- Zbieranie danych SMART dysków
- Synchronizacja z timestampami crashy

**Funkcje:**
- `_get_hardware_temperature_and_parameters()` - Temperatura i parametry sprzętu
- `_get_enhanced_smart_disk_health()` - Rozszerzone dane SMART
- `_get_hardware_context_optional()` - Agregacja wszystkich danych

**Zbierane dane:**
- CPU temperature (WMI)
- GPU temperature (GPUtil/WMI)
- RAM usage (psutil): total, used, available, percent, swap info
- SMART status: ReallocatedSectors, PendingSectors, Temperature, PowerOnHours
- Normalizacja dysków (device_id + serial jako klucz)

### 5. Rozszerzone Eventy Systemowe i Driver Logs

**Problem:** Zbieranie wszystkich eventów systemowych jest zbyt wolne i generuje zbyt dużo danych.

**Rozwiązanie:**
- Filtrowanie czasowe (±10 minut od crashu)
- Specyficzne Event IDs dla crashy: 41, 6008, 10016, 1001, 1074, 1076, 20001-20003, 219, 1000
- Pełne wiadomości eventów (bez limitów)
- Zwiększone timeouty (60s) dla długotrwałych operacji

**Funkcje:**
- `_collect_system_events_and_driver_logs()` - Zbiera eventy z filtrowaniem
- Filtrowanie po czasie crashu (jeśli dostępne)
- Zbieranie wszystkich eventów (bez limitu) jeśli brak crashu

**Event IDs:**
- `41` - Unexpected shutdown
- `6008` - Unexpected shutdown detected
- `1001` - Bugcheck
- `1000` - Application crash
- `1074`, `1076` - Shutdown events
- `20001-20003` - Driver events
- `219` - Kernel events
- `10016` - COM events

### 6. Lepsze Logowanie Błędów

**Problem:** Błędy PowerShell nie wskazywały, która komenda się nie powiodła.

**Rozwiązanie:**
- Logowanie komendy która się nie powiodła (pierwsze 200 znaków)
- Szczegółowe logowanie błędów z kodem powrotu
- Graceful handling błędów (nie przerywa innych collectorów)

**Funkcje:**
- `run_powershell_safe()` - Loguje komendę przy błędzie
- `run_powershell_hidden()` - Wrapper z obsługą błędów

**Przykład logu:**
```
[SUBPROCESS] PowerShell command failed with code 1: Get-WinEvent -LogName System | Select-Object Id, LevelDisplayName, Message, TimeCreated, ProviderName | ConvertTo-Json -Depth 3
```

## Struktura Danych Wyjściowych

### Format BSOD Data

```json
{
  "source": "bsod_collector",
  "timestamp": "2025-12-01 17:21:14",
  "bugchecks": [
    {
      "timestamp": "2025-12-01T17:21:14",
      "bugcheck_code": "0x0000000A",
      "bugcheck_code_name": "IRQL_NOT_LESS_OR_EQUAL",
      "faulting_driver": "nvlddmkm.sys",
      "parameters": ["0x...", "0x...", "0x...", "0x..."],
      "filename": "stremio.exe.13328.dmp"
    }
  ],
  "minidumps": [
    {
      "filename": "stremio.exe.13328.dmp",
      "filepath": "C:\\Users\\...\\CrashDumps\\stremio.exe.13328.dmp",
      "size_bytes": 1234567,
      "timestamp": "2025-12-01T17:21:14",
      "type": "MINIDUMP",
      "bugcheck_code": "0x0000000A",
      "faulting_driver": "nvlddmkm.sys",
      "severity": "Medium"
    }
  ],
  "whea_errors": [
    {
      "timestamp": "2025-12-01T17:21:14",
      "event_id": 18,
      "component": "CPU",
      "error_source": "Processor",
      "description": "A corrected hardware error has occurred.",
      "related_bugcheck": {
        "bugcheck_code": "0x0000000A",
        "correlation_direction": "WHEA→BSOD",
        "time_difference_seconds": 45
      }
    }
  ],
  "hardware": {
    "cpu_temp_celsius": 65.5,
    "gpu_temp_celsius": 72.0,
    "cpu_load_percent": 45.2,
    "ram_total_gb": 16.0,
    "ram_used_gb": 8.5,
    "ram_usage_percent": 53.1,
    "ram": {
      "total_gb": 16.0,
      "used_gb": 8.5,
      "available_gb": 7.5,
      "usage_percent": 53.1,
      "swap_total_gb": 4.0,
      "swap_used_gb": 0.5,
      "swap_usage_percent": 12.5
    }
  },
  "smart_disks": [
    {
      "model": "Samsung SSD 980",
      "serial": "S5JZNG0N123456",
      "status": "OK",
      "reallocated_sectors": 0,
      "pending_sectors": 0,
      "temperature_celsius": 45,
      "power_on_hours": 1234
    }
  ],
  "system_events": {
    "system_events": [...],
    "driver_events": [...],
    "application_events": [...]
  }
}
```

## Konfiguracja

### Timeouty

- **WinDbg parsing:** 60s dla dumpów >100MB, 30s dla mniejszych
- **System events collection:** 60s
- **Driver events collection:** 60s
- **Application events collection:** 60s

### Ścieżki Dumpów

Automatycznie wykrywane z rejestru, z fallback do standardowych ścieżek:
- `C:\Windows\Minidump`
- `C:\Windows\MEMORY.DMP`
- `%LOCALAPPDATA%\CrashDumps`

## Użycie

### Podstawowe użycie

```python
from collectors.bsod_dumps import collect

bsod_data = collect()
print(f"Found {len(bsod_data['bugchecks'])} bugchecks")
print(f"Found {len(bsod_data['minidumps'])} minidumps")
print(f"Found {len(bsod_data['whea_errors'])} WHEA errors")
```

### Integracja z Collector Master

```python
from collectors.collector_master import collect_all

result = collect_all()
bsod_data = result.get('collectors', {}).get('bsod_dumps', {})
```

## Testy

Testy jednostkowe znajdują się w:
- `tests/test_collectors.py` - Testy podstawowe
- `tests/test_wer.py` - Testy WER (powiązane)

## Przyszłe Ulepszenia

- [ ] Wizualizacja korelacji WHEA-BSOD w GUI
- [ ] Eksport minidumpów do zewnętrznych narzędzi analitycznych
- [ ] Automatyczna analiza z użyciem WinDbg dla wszystkich dumpów
- [ ] Integracja z zewnętrznymi bazami danych driverów
- [ ] Machine learning dla przewidywania crashy na podstawie kontekstu sprzętowego

