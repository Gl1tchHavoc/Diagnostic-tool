# Changelog - Safe Read, ShadowCopy Events, Disk Detection, Deduplication, Confidence Normalization

## Wprowadzone zmiany

### 1. ✅ safe_read_text() - zastąpienie bezpośrednich open()
- **Plik**: `utils/safe_read.py`
- **Nowa funkcja**: `safe_read_text()` - prosta funkcja zwracająca tylko zawartość pliku
- **Status**: Funkcja dodana, gotowa do użycia
- **Uwaga**: W `collector_master.py` zapis używa standardowego `open()` (to jest zapis, nie odczyt)

### 2. ✅ is_shadowcopy_event() i filtr w parserze eventów
- **Pliki**:
  - `log_parsers/system_log_parser.py` - dodano `_is_shadowcopy_event()` i filtrowanie
  - `collectors/system_logs.py` - dodano wykrywanie ShadowCopy w parse_xml_logs()
- **Funkcje**:
  - `_is_shadowcopy_event()` w SystemLogParser
  - Automatyczne kategoryzowanie jako `SHADOWCOPY_ERROR`
  - Flaga `is_shadowcopy` w każdym evencie
- **Efekt**: Eventy ShadowCopy są automatycznie wykrywane i kategoryzowane

### 3. ✅ get_logical_volumes() - zastąpienie wykrywania dysków
- **Plik**: `utils/disk_helper.py`
- **Nowa funkcja**: `get_logical_volumes()` - pobiera szczegółowe informacje o wszystkich wolumenach
- **Zmiany w**: `collectors/hardware.py`
  - Zastąpiono `psutil.disk_partitions()` przez `get_logical_volumes()`
  - Używa WMI do pobrania pełnych informacji
  - Automatycznie filtruje shadowcopy i virtual disks
  - Fallback do psutil jeśli WMI nie działa
- **Efekt**: Bardziej precyzyjne wykrywanie dysków z pełnymi informacjami

### 4. ✅ Deduplikacja eventów (dedupe_events)
- **Plik**: `utils/event_deduplicator.py` (już istnieje)
- **Zastosowanie**:
  - `log_parsers/system_log_parser.py` - deduplikacja po parsowaniu
  - `collectors/system_logs.py` - deduplikacja w parse_xml_logs()
  - `processors/bsod_analyzer.py` - deduplikacja przed analizą
  - `processors/registry_txr_processor.py` - deduplikacja błędów TxR
  - `processors/storage_health_processor.py` - deduplikacja błędów SMART, I/O, disk
- **Efekt**: Identyczne eventy w tej samej sekundzie są liczone jako 1 z atrybutem `occurrences`

### 5. ✅ normalize_confidence() - normalizacja confidence scores
- **Plik**: `utils/confidence_normalizer.py` (nowy)
- **Funkcje**:
  - `normalize_confidence()` - normalizuje score do zakresu 0-100
  - `calculate_weighted_confidence()` - oblicza ważoną średnią
  - `apply_confidence_decay()` - stosuje decay na podstawie wieku zdarzenia
- **Zastosowanie**: `processors/bsod_analyzer.py`
  - Normalizuje confidence scores w scored_events
  - Normalizuje confidence w top_causes
- **Efekt**: Wszystkie confidence scores są w zakresie 0-100

### 6. ✅ Rozszerzone logowanie (logger)
- **Zmiany**:
  - `main.py` - inicjalizacja loggera z poziomem DEBUG
  - Wszystkie moduły używają loggera z odpowiednimi poziomami
  - Dodano debug logging w kluczowych miejscach:
    - `collectors/hardware.py` - logowanie każdej sekcji zbierania danych
    - `processors/bsod_analyzer.py` - logowanie każdego etapu analizy
    - `utils/disk_helper.py` - logowanie wykrywania dysków
    - `log_parsers/system_log_parser.py` - logowanie parsowania
    - `collectors/system_logs.py` - logowanie zbierania logów
- **Efekt**: Pełne logowanie wszystkich operacji na poziomie DEBUG

## Pliki zmodyfikowane

1. `utils/safe_read.py` - dodano `safe_read_text()`
2. `utils/disk_helper.py` - dodano `get_logical_volumes()`
3. `utils/confidence_normalizer.py` - nowy plik
4. `collectors/hardware.py` - zastąpiono wykrywanie dysków przez `get_logical_volumes()`
5. `collectors/system_logs.py` - dodano ShadowCopy detection i deduplikację
6. `collectors/collector_master.py` - dodano logowanie
7. `log_parsers/system_log_parser.py` - dodano `_is_shadowcopy_event()` i deduplikację
8. `processors/bsod_analyzer.py` - dodano deduplikację i normalize_confidence
9. `main.py` - inicjalizacja loggera z DEBUG level

## Nowe funkcjonalności

### ShadowCopy Event Detection
- Automatyczne wykrywanie eventów ShadowCopy w parserach
- Kategoryzacja jako `SHADOWCOPY_ERROR`
- Flaga `is_shadowcopy` w każdym evencie

### Enhanced Disk Detection
- `get_logical_volumes()` zwraca pełne informacje o wolumenach
- Automatyczne filtrowanie shadowcopy/virtual disks
- Pełne informacje z WMI (physical disk, partitions, etc.)

### Event Deduplication
- Grupowanie identycznych eventów w tym samym oknie czasowym
- Atrybut `occurrences` dla duplikatów
- Zastosowane we wszystkich parserach i procesorach

### Confidence Normalization
- Wszystkie confidence scores normalizowane do 0-100
- Ważona średnia dla wielu score'ów
- Decay na podstawie wieku zdarzenia

### Enhanced Logging
- DEBUG level włączony w main.py
- Szczegółowe logowanie wszystkich operacji
- Logi zapisywane do `logs/diagnostic_tool_YYYYMMDD.log`

## Gotowe do testowania

Wszystkie zmiany są zaimplementowane i gotowe do testowania lokalnie. Logger jest skonfigurowany na poziomie DEBUG, więc wszystkie operacje będą logowane.

