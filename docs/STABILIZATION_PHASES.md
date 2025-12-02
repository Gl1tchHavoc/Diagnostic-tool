# Fazy Stabilizacji MVP - Dokumentacja

## Faza 1: Stabilizacja MVP ✅

### Ujednolicenie eksportu JSON/HTML

**Utworzone:**
- `utils/export_utils.py` - Wspólny moduł eksportu dla GUI i CLI
  - `export_json()` - Ujednolicony eksport JSON
  - `export_html()` - Ujednolicony eksport HTML z ładnym stylingiem
  - `generate_html_report()` - Generowanie raportu HTML

**Zaktualizowane:**
- `gui_mvp.py` - Używa wspólnego modułu eksportu
- `main.py` - Używa wspólnego modułu eksportu (JSON + HTML)

**Rezultat:**
- ✅ GUI i CLI używają tego samego formatu eksportu
- ✅ Spójny format JSON/HTML w całej aplikacji
- ✅ Ładny styling HTML z responsywnym designem

### Sprawdzenie GUI MVP

**Status:**
- ✅ GUI MVP wyświetla pełne dane z wszystkich collectorów
- ✅ Lista collectorów z statusami działa poprawnie
- ✅ Podgląd surowych danych działa
- ✅ Eksport JSON/HTML działa

## Faza 2: Pipeline i asynchroniczność ✅

### Timeouty i fallback dla collectorów

**Utworzone:**
- `collectors/collector_master_with_timeouts.py` - Wersja z timeoutami
  - `collect_all_with_timeouts()` - Async z timeoutami
  - `_run_collector_with_timeout()` - Uruchamianie z timeoutem
  - Obsługa `asyncio.TimeoutError`

**Funkcjonalności:**
- ✅ Timeouty konfigurowalne przez `config.json` → `collectors.timeout_seconds`
- ✅ Fallback - błędy/timeouty nie przerywają innych collectorów
- ✅ Licznik timeoutów w summary

### Centralny Logger

**Status:**
- ✅ Logger rejestruje statusy wszystkich collectorów (`log_collector_start/end`)
- ✅ Logger rejestruje statusy wszystkich procesorów (`log_processor_start/end`)
- ✅ Logger rejestruje metryki wydajności (`log_performance`)

**Zaktualizowane:**
- `collectors/collector_master.py` - Rejestruje w monitorze wydajności
- `collectors/collector_master_async.py` - Rejestruje w monitorze wydajności
- `processors/analyzer.py` - Rejestruje w monitorze wydajności

### Monitorowanie wydajności

**Utworzone:**
- `utils/performance_monitor.py` - Monitor wydajności
  - `PerformanceMonitor` - Klasa monitorująca metryki
  - `record_collector()` - Rejestruje metryki collectora
  - `record_processor()` - Rejestruje metryki procesora
  - `get_all_stats()` - Zwraca wszystkie statystyki
  - `log_summary()` - Loguje podsumowanie wydajności

**Funkcjonalności:**
- ✅ Zbieranie metryk dla każdego collectora (czas wykonania, status, liczba danych)
- ✅ Zbieranie metryk dla każdego procesora (czas wykonania, błędy, ostrzeżenia)
- ✅ Statystyki (średni czas, min, max, success rate)
- ✅ Top 5 najwolniejszych collectorów
- ✅ Podsumowanie wydajności w CLI

## Faza 3: Testy i CI/CD ✅

### Coverage testów dla async pipeline

**Utworzone:**
- `tests/test_async_pipeline.py` - Testy asynchronicznego pipeline
  - `TestAsyncPipeline` - Testy podstawowe async
  - `TestAsyncCollectors` - Testy z pytest-asyncio
  - Testy timeoutów
  - Testy wydajności async vs sync

**Status:**
- ✅ Testy pokrywają async pipeline
- ✅ Testy timeoutów
- ✅ Testy wydajności

### CI/CD (GitHub Actions)

**Utworzone:**
- `.github/workflows/ci.yml` - GitHub Actions workflow
  - Uruchamianie testów na Windows
  - Generowanie raportu coverage
  - Upload coverage do Codecov
  - Walidacja diagramów PlantUML
  - Sprawdzanie jakości kodu (flake8)

**Funkcjonalności:**
- ✅ Automatyczne uruchamianie testów przy push/PR
- ✅ Generowanie raportu coverage (HTML + XML)
- ✅ Walidacja diagramów PlantUML
- ✅ Sprawdzanie jakości kodu

## Faza 4: Przygotowanie na skalowalność ✅

### Benchmarki wydajności

**Utworzone:**
- `tests/benchmark_collectors.py` - Benchmarki wydajności
  - `test_async_vs_sync_performance()` - Porównanie async vs sync
  - `test_timeout_performance()` - Test wydajności z timeoutami
  - `test_large_scale_collectors()` - Test skalowalności

**Funkcjonalności:**
- ✅ Benchmarki porównujące async vs sync
- ✅ Testy wydajności przy dużej liczbie collectorów
- ✅ Metryki czasu wykonania

### Ograniczenie równoległości (asyncio.Semaphore)

**Zaimplementowane:**
- `collectors/collector_master_async.py` - Dodano semafor
  - `max_concurrent` w config.json
  - `asyncio.Semaphore` dla ograniczenia równoległości
  - Automatyczne użycie przy dużych skanach

**Konfiguracja:**
```json
{
  "collectors": {
    "max_concurrent": null  // null = bez limitu, liczba = limit równoległości
  }
}
```

### Rozszerzony dashboard (przygotowanie)

**Status:**
- ⏳ Przygotowanie - wymaga dodatkowych modułów
- ✅ Monitor wydajności gotowy do użycia w dashboardzie
- ✅ Statystyki historyczne można agregować z logów

## Użycie

### Eksport raportów (Faza 1)

**GUI:**
- Kliknij "💾 Export JSON" lub "📄 Export HTML"
- Wybierz lokalizację pliku

**CLI:**
- Automatyczny eksport JSON i HTML po skanie
- Pliki w `output/processed/`

### Timeouty (Faza 2)

**Konfiguracja:**
```json
{
  "collectors": {
    "timeout_seconds": 300  // 5 minut
  }
}
```

**Użycie:**
```python
from collectors.collector_master_with_timeouts import collect_all_with_timeouts_wrapper
result = collect_all_with_timeouts_wrapper(timeout_seconds=60)
```

### Monitorowanie wydajności (Faza 2)

```python
from utils.performance_monitor import get_performance_monitor

monitor = get_performance_monitor()
stats = monitor.get_all_stats()
monitor.log_summary()
```

### Ograniczenie równoległości (Faza 4)

**Konfiguracja:**
```json
{
  "collectors": {
    "max_concurrent": 6  // Maksymalnie 6 collectorów równocześnie
  }
}
```

## Faza 5: Ulepszenia BSOD Collector ✅

### Automatyczne wykrywanie ścieżek dumpów

**Zaimplementowane:**
- `_get_dump_paths_from_registry()` - Odczytuje ścieżki dumpów z rejestru Windows
  - `HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl` → `DumpFile`
  - `HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl` → `MinidumpDir`
- `_get_fallback_dump_paths()` - Fallback paths jeśli rejestr nie działa
  - `C:\Windows\Minidump`
  - `C:\Windows\MEMORY.DMP`
  - `%LOCALAPPDATA%\CrashDumps`

**Funkcjonalności:**
- ✅ Automatyczne wykrywanie niestandardowych ścieżek dumpów
- ✅ Graceful handling błędów rejestru
- ✅ Informacyjne logowanie wszystkich sprawdzonych ścieżek

### Ulepszone parsowanie minidumpów

**Zaimplementowane:**
- `_parse_bugcheck_with_windbg()` - Parsowanie z WinDbg dla lepszego wykrywania driverów
- Fallback do WinDbg jeśli `parse_minidump` nie znalazło drivera
- Zwiększone timeouty dla dużych dumpów (60s dla >100MB, 30s dla mniejszych)

**Funkcjonalności:**
- ✅ Lepsze wykrywanie driverów przez WinDbg
- ✅ Obsługa dużych pełnych dumpów
- ✅ Logowanie znalezionych driverów

### Rozszerzona korelacja WHEA

**Zaimplementowane:**
- `_correlate_whea_with_crashes()` - Korelacja z oknem ±10 minut
- Kierunek korelacji (WHEA→BSOD, BSOD→WHEA, WHEA→MINIDUMP, MINIDUMP→WHEA)
- Różnica czasowa w sekundach

**Funkcjonalności:**
- ✅ Rozszerzone okno korelacji (±10 minut)
- ✅ Informacje o kierunku korelacji
- ✅ Dokładna różnica czasowa

### Kontekst sprzętowy w czasie crashu

**Zaimplementowane:**
- `_get_hardware_temperature_and_parameters()` - Temperatura CPU/GPU, RAM usage
- `_get_enhanced_smart_disk_health()` - Rozszerzone dane SMART (ReallocatedSectors, PendingSectors, Temperature, PowerOnHours)
- `_get_hardware_context_optional()` - Agregacja wszystkich danych sprzętowych

**Funkcjonalności:**
- ✅ Temperatura CPU (WMI)
- ✅ Temperatura GPU (GPUtil/WMI)
- ✅ RAM usage (total, used, available, percent, swap info)
- ✅ SMART status dysków z normalizacją (device_id + serial)
- ✅ Obsługa NVMe i SATA

### Rozszerzone eventy systemowe

**Zaimplementowane:**
- `_collect_system_events_and_driver_logs()` - Zbieranie eventów z filtrowaniem czasowym
- Specyficzne Event IDs: 41, 6008, 10016, 1001, 1074, 1076, 20001-20003, 219, 1000
- Filtrowanie ±10 minut od crashu
- Pełne wiadomości eventów (bez limitów)

**Funkcjonalności:**
- ✅ Filtrowanie czasowe eventów (±10 minut)
- ✅ Specyficzne Event IDs dla crashy
- ✅ Pełne wiadomości eventów
- ✅ Zwiększone timeouty (60s) dla długotrwałych operacji

### Lepsze logowanie błędów

**Zaimplementowane:**
- `run_powershell_safe()` - Logowanie komendy która się nie powiodła
- Logowanie pierwszych 200 znaków komendy dla łatwej identyfikacji

**Funkcjonalności:**
- ✅ Identyfikacja problematycznych komend PowerShell
- ✅ Szczegółowe logowanie błędów z kodem powrotu
- ✅ Graceful handling błędów (nie przerywa innych collectorów)

## Przyszłe ulepszenia

- [ ] Dashboard webowy z metrykami historycznymi
- [ ] Agregacja danych z wielu skanów
- [ ] Wykresy wydajności w czasie
- [ ] Alerty przy spadku wydajności
- [ ] Eksport metryk do Prometheus/Grafana
- [ ] Wizualizacja korelacji WHEA-BSOD w GUI
- [ ] Eksport minidumpów do zewnętrznych narzędzi analitycznych

