# Diagnostic Tool MVP - Architecture Documentation

## Overview

Diagnostic Tool MVP to modularne narzędzie do zbierania i prezentacji danych diagnostycznych systemu Windows. Aplikacja została zaprojektowana zgodnie z zasadami modularności, skalowalności i łatwego rozszerzania.

## Architecture Flow

```
User → GUI MVP → Collector Master → Collectors (parallel) → Collector Master → GUI MVP
                                                              ↓
                                                         Processors MVP → GUI MVP
```

### 1. GUI MVP Layer

**Odpowiedzialność:**
- Wyświetlanie statusu collectorów
- Podgląd surowych danych
- Eksport raportów (JSON/HTML)
- Interakcja z użytkownikiem

**Komponenty:**
- `gui_mvp.py` - Główny interfejs graficzny
- Lista collectorów z statusami (TreeView)
- Panel podglądu danych (ScrolledText)
- Przyciski akcji (Full Scan, Run Selected, View Data, Export)

**Funkcjonalności:**
- ✅ Wyświetlanie listy collectorów + status (Collected/Error)
- ✅ Uruchamianie pełnego skanu
- ✅ Uruchamianie pojedynczych collectorów
- ✅ Wyświetlanie danych pojedynczych collectorów
- ✅ Eksport JSON/HTML
- ✅ Cache danych collectorów

### 2. Collector Master (Orchestrator)

**Odpowiedzialność:**
- Koordynacja zbierania danych ze wszystkich collectorów
- Standaryzacja formatu zwracanego
- Obsługa błędów (błędy nie przerywają innych collectorów)
- Równoległe wykonanie (ThreadPoolExecutor)

**Komponenty:**
- `collectors/collector_master.py` - Główny orchestrator
- `core/collector_registry.py` - Rejestr collectorów

**Format zwracany:**
```json
{
    "status": "Collected" | "Error",
    "data": {...},
    "error": null | "error message",
    "timestamp": "ISO timestamp",
    "collector_name": "hardware",
    "execution_time_ms": 1234
}
```

**Funkcjonalności:**
- ✅ Równoległe wykonanie collectorów (konfigurowalne)
- ✅ Standaryzacja formatu zwracanego
- ✅ Obsługa błędów bez przerywania innych collectorów
- ✅ Użycie CollectorRegistry dla modularności
- ✅ Zapisywanie surowych danych do pliku

### 3. Collectors Layer

**Odpowiedzialność:**
- Zbieranie danych z różnych źródeł systemowych
- Zwracanie danych w standardowym formacie

**Dostępne collectory:**
- `hardware` - CPU, RAM, GPU, temperatura, wykorzystanie zasobów
- `system_info` - Wersja Windows, uptime, aktualizacje, patch level
- `processes` - Uruchomione procesy
- `services` - Status usług systemowych
- `system_logs` - Event Logi (System, Application)
- `storage_health` - Dyski, partycje, wolne miejsce, SMART
- `drivers` - Informacje o sterownikach
- `registry_txr` - Błędy transakcji rejestru
- `bsod_dumps` - Analiza zrzutów pamięci z rozszerzonymi funkcjami:
  - Automatyczne wykrywanie ścieżek dumpów z rejestru Windows (`DumpFile`, `MinidumpDir`)
  - Obsługa pełnych dumpów (MEMORY.DMP) i minidumpów
  - Parsowanie z WinDbg dla lepszego wykrywania driverów (fallback)
  - Korelacja WHEA errors z crashami (±10 minut, z kierunkiem korelacji)
  - Zbieranie kontekstu sprzętowego (temperatura CPU/GPU, SMART, RAM usage) w czasie crashu
  - Rozszerzone eventy systemowe i driver logs z filtrowaniem czasowym (±10 minut)
  - Lepsze logowanie błędów PowerShell z identyfikacją komend
  - Zwiększone timeouty dla długotrwałych operacji (60s dla eventów systemowych)
- `whea_analyzer` - Błędy sprzętowe WHEA
- `performance_counters` - Liczniki wydajności
- `wer` - Windows Error Reporting

**Modularność:**
- Każdy collector jest niezależnym modułem
- Rejestracja w `CollectorRegistry`
- Łatwe dodawanie nowych collectorów bez zmian w pipeline

### 4. Processors Layer (MVP - Minimalna wersja)

**Odpowiedzialność:**
- Walidacja danych z collectorów
- Parsowanie i transformacja do wewnętrznego formatu
- Status "Collected" / "Error" dla każdego collectora

**Komponenty:**
- `processors/analyzer.py` - Główny analyzer
- `processors/base_processor.py` - Bazowy processor
- `core/processor_registry.py` - Rejestr procesorów

**Format zwracany:**
```json
{
    "status": "Collected" | "Error",
    "data": {...},
    "errors": [],
    "warnings": [],
    "validation_passed": true,
    "timestamp": "ISO timestamp",
    "processor_name": "hardware_processor"
}
```

**Funkcjonalności:**
- ✅ Minimalna walidacja danych
- ✅ Sprawdzanie poprawności typów
- ✅ Wykrywanie błędów w strukturze danych
- ✅ Obsługa nowego formatu MVP (backward compatible)

## Data Flow

### Full Scan Flow

1. **User initiates scan** → GUI MVP
2. **GUI MVP** → Collector Master (collect_all)
3. **Collector Master** → Collectors (parallel execution)
4. **Collectors** → Collector Master (standardized format)
5. **Collector Master** → GUI MVP (aggregated data + summary)
6. **GUI MVP** → Processors MVP (optional - analyze_all)
7. **Processors MVP** → GUI MVP (processed data)
8. **GUI MVP** → Display results + cache data

### Single Collector Flow

1. **User selects collector** → GUI MVP
2. **User clicks "Run Selected"** → GUI MVP
3. **GUI MVP** → Collector Registry (get collector function)
4. **GUI MVP** → Collector (direct call in thread)
5. **Collector** → GUI MVP (standardized format)
6. **GUI MVP** → Display data + update status

## Configuration

**Plik:** `config.json`

**Kluczowe ustawienia:**
- `collectors.enabled` - Lista włączonych collectorów
- `collectors.parallel_execution` - Równoległe wykonanie (true/false)
- `collectors.timeout_seconds` - Timeout dla collectorów
- `output.save_raw` - Zapisywanie surowych danych
- `output.raw_output_dir` - Katalog dla surowych danych
- `gui.show_raw_data` - Wyświetlanie surowych danych

## Error Handling

**Zasady:**
- Błędy w jednym collectorze nie przerywają innych
- Każdy collector zwraca status "Error" z komunikatem błędu
- GUI wyświetla status "❌ Error" dla nieudanych collectorów
- Logi zawierają szczegółowe informacje o błędach

## Extensibility

### Dodawanie nowego collectora

1. Utwórz plik `collectors/new_collector.py`
2. Zaimplementuj funkcję `collect()` zwracającą dane
3. Zarejestruj w `core/collector_registry.py` → `register_all_collectors()`
4. Dodaj do `config.json` → `collectors.enabled`

### Dodawanie nowego procesora

1. Utwórz plik `processors/new_processor.py`
2. Zaimplementuj funkcję `process(collector_data)`
3. Zarejestruj w `core/processor_registry.py` → `register_all_processors()`
4. Dodaj do `processors/analyzer.py` → `processors_list`

## Performance

**Optymalizacje:**
- Równoległe wykonanie collectorów (ThreadPoolExecutor, max 6 workers)
- Cache danych collectorów w GUI
- Zapisywanie surowych danych tylko jeśli włączone
- Automatyczne czyszczenie starych plików raw_data

## Logging

**Poziomy logowania:**
- INFO - Główne operacje (start/stop collectorów, skany)
- DEBUG - Szczegółowe informacje (postęp, dane)
- WARNING - Ostrzeżenia (brakujące dane, timeouty)
- ERROR - Błędy (wyjątki, nieudane collectory)

**Lokalizacja logów:**
- `logs/diagnostic_tool_YYYYMMDD.log`

## Testing

**Uruchomienie GUI MVP:**
```bash
python gui_mvp.py
```

**Uruchomienie CLI:**
```bash
python main.py
```

## Future Enhancements

- [ ] Async/await zamiast threading dla lepszej wydajności
- [ ] Real-time updates w GUI podczas zbierania danych
- [ ] Filtrowanie i sortowanie danych w GUI
- [ ] Więcej formatów eksportu (CSV, XML)
- [ ] Agregacja i scoring (opcjonalnie dla MVP)
- [ ] CLI z tabelą statusów collectorów

