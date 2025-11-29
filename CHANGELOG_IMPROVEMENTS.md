# Changelog - Major Improvements

## Implementowane funkcje

### A. ShadowCopy – eliminacja false positives ✅
- **Moduł**: `utils/shadowcopy_helper.py`
- **Funkcje**:
  - `is_shadowcopy_path()` - wykrywa ścieżki ShadowCopy
  - `filter_shadowcopy_errors()` - filtruje błędy ShadowCopy
  - `categorize_txr_errors()` - kategoryzuje błędy TxR na rzeczywiste i ShadowCopy
  - `get_shadowcopy_info()` - pobiera informacje o VSS i snapshotach
- **Zmiany w procesorach**:
  - `processors/registry_txr_processor.py` - filtruje ShadowCopy errors
  - `processors/storage_health_processor.py` - oddziela błędy ShadowCopy od rzeczywistych błędów dysku
- **Efekt**: ShadowCopy errors nie wpływają na scoring i są kategoryzowane osobno

### B. Obsługa kodowania logów – poprawne czytanie polskich znaków ✅
- **Plik**: `utils/safe_read.py`
- **Zmiany**: Sekwencja fallback UTF-8 → UTF-16 LE → CP1250 → inne
- **Efekt**: Poprawne dekodowanie polskich znaków w logach

### C. BSOD Analysis 2.0 – zaawansowana analiza błędów ✅
- **Plik**: `processors/bsod_analyzer.py`
- **Nowe funkcje**:
  - `extract_bugcheck_from_event()` - wyciąga bugcheck code z Event 1001/41
  - `extract_bugcheck_parameters()` - wyciąga parametry bugcheck
  - `extract_dump_file()` - wyciąga ścieżkę do pliku dump
  - `analyze_minidumps()` - analizuje minidump files
- **Zmiany**:
  - Primary window: 3 minuty przed crash
  - Extended window: 15 minut przed crash
  - Korelacja zdarzeń według komponentów
- **Efekt**: Bardziej precyzyjna analiza BSOD z lepszą korelacją zdarzeń

### D. Poprawne wykrywanie dysków – usunięcie błędu "dysk E" ✅
- **Plik**: `utils/disk_helper.py`
- **Zmiany**:
  - Używa WMI (`Win32_DiskDrive`, `Win32_LogicalDisk`, `Win32_Volume`)
  - Filtruje shadowcopy disks
  - Filtruje virtual disks
  - Sprawdza czy dysk jest online
  - Sprawdza czy dysk jest dostępny
- **Efekt**: Nie generuje błędów dla dysków offline, shadowcopy, nieistniejących

### E. Event De-duplication ✅
- **Moduł**: `utils/event_deduplicator.py`
- **Funkcje**:
  - `deduplicate_events()` - de-duplikuje zdarzenia
  - `group_by_time_window()` - grupuje zdarzenia według okna czasowego
- **Zastosowanie**:
  - `processors/registry_txr_processor.py`
  - `processors/storage_health_processor.py`
- **Efekt**: Identyczne zdarzenia w tej samej sekundzie są liczone jako 1 z atrybutem `occurrences`

### F. Zmiana scoringu ✅
- **Plik**: `processors/scorer.py`
- **Zmiany**:
  - ShadowCopyErrors → 0 punktów
  - Błędy z nieistniejących wolumenów → 0 punktów
  - Registry TxR errors → pełne punkty TYLKO jeśli nie dotyczą ShadowCopy
  - BSOD z Kernel-Power 41 → nie daje maksymalnych punktów bez dowodów
- **Efekt**: Bardziej precyzyjny scoring, który nie karze za ShadowCopy errors

### G. Sekcja ShadowCopy w raporcie ✅
- **Plik**: `processors/report_builder.py`
- **Nowa sekcja**: `shadowcopy_diagnostic`
- **Zawiera**:
  - Informacje o VSS service
  - Lista snapshotów
  - Błędy ShadowCopy
  - Rekomendacje (usuń stare shadowcopies, zweryfikuj VSS, zresetuj repozytorium)
- **Efekt**: Osobna sekcja w raporcie dla ShadowCopy issues

### H. Raport końcowy – kategoryzacja błędów ✅
- **Plik**: `processors/report_builder.py`
- **Nowe kategorie**:
  - `real_disk_errors` - rzeczywiste błędy dysku
  - `shadowcopy_errors` - błędy ShadowCopy (nie wpływają na zdrowie dysku)
  - `registry_txr_real` - prawdziwa korupcja systemu
  - `registry_txr_shadowcopy` - błędy TxR dotyczące ShadowCopy
- **Efekt**: Raport rozróżnia różne typy błędów i ich wpływ na system

### I. Globalny logger ✅
- **Plik**: `utils/logger.py`
- **Status**: Logger już działa globalnie przez cały runtime
- **Funkcje**:
  - `get_logger()` - zwraca globalny logger
  - `setup_logger()` - konfiguruje logger
  - Logi zapisywane do `logs/diagnostic_tool_YYYYMMDD.log`
- **Efekt**: Wszystkie moduły używają tego samego loggera

## Dobre praktyki zastosowane

1. **Modularność**: Każda funkcjonalność w osobnym module
2. **Czytelność**: Jasne nazwy funkcji i zmiennych
3. **Dokumentacja**: Docstringi dla wszystkich funkcji
4. **Error handling**: Try-except bloki z logowaniem
5. **Logging**: Wszystkie operacje logowane
6. **Type hints**: Gdzie możliwe (w nowych funkcjach)
7. **Separation of concerns**: Logika biznesowa oddzielona od I/O

## Pliki zmodyfikowane

- `utils/shadowcopy_helper.py` (nowy)
- `utils/event_deduplicator.py` (nowy)
- `utils/safe_read.py` (zmodyfikowany)
- `utils/disk_helper.py` (zmodyfikowany)
- `processors/registry_txr_processor.py` (zmodyfikowany)
- `processors/storage_health_processor.py` (zmodyfikowany)
- `processors/bsod_analyzer.py` (zmodyfikowany)
- `processors/scorer.py` (zmodyfikowany)
- `processors/report_builder.py` (zmodyfikowany)

## Pliki nowe

- `utils/shadowcopy_helper.py`
- `utils/event_deduplicator.py`
- `CHANGELOG_IMPROVEMENTS.md` (ten plik)

