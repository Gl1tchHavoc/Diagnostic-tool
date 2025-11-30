# Asynchroniczność i Testy - Dokumentacja

## Pełna Asynchroniczność

### Problem
Poprzednia implementacja używała `ThreadPoolExecutor`, co jest lepsze niż synchroniczne wykonanie, ale nie jest pełną asynchronicznością. Dla I/O-bound operacji (jak zbieranie danych z systemu) pełna asynchroniczność (`asyncio`) oferuje lepszą wydajność.

### Rozwiązanie
Stworzono `collectors/collector_master_async.py` z pełną implementacją asynchroniczną:

- **`collect_all_async()`** - Asynchroniczna wersja `collect_all()`
- **`collect_all_async_wrapper()`** - Wrapper dla wywołania z synchronicznego kodu
- **`_run_collector_async()`** - Asynchroniczne uruchamianie pojedynczych collectorów
- **`run_sync_in_executor()`** - Wrapper dla synchronicznych collectorów w async context

### Użycie

#### Automatyczne (przez config)
W `config.json` ustaw:
```json
{
  "collectors": {
    "use_async": true
  }
}
```

`collect_all()` automatycznie użyje asynchronicznej wersji.

#### Ręczne wywołanie
```python
from collectors.collector_master_async import collect_all_async_wrapper

# Z synchronicznego kodu
result = collect_all_async_wrapper(save_raw=True, output_dir="output/raw")

# Z async kodu
import asyncio
result = await collect_all_async(save_raw=True, output_dir="output/raw")
```

### Zalety Asynchroniczności

1. **Lepsza wydajność dla I/O-bound operacji**
   - Collectory często czekają na odpowiedzi z systemu (Event Logs, Registry, etc.)
   - Async pozwala na efektywne wykorzystanie czasu oczekiwania

2. **Mniejszy overhead niż threading**
   - Async używa jednego wątku zamiast wielu
   - Mniejsze zużycie pamięci

3. **Lepsze skalowanie**
   - Można uruchomić setki collectorów równocześnie bez problemów z GIL

### Kompatybilność

- **Synchroniczne collectory** - Automatycznie uruchamiane w executorze
- **Asynchroniczne collectory** - Wspierane natywnie (jeśli collector zwraca coroutine)
- **Backward compatible** - Stare collectory działają bez zmian

## Rozszerzone Testy

### Nowe pliki testowe

1. **`tests/test_collectors.py`**
   - Testy dla wszystkich collectorów
   - Testy formatu zwracanego przez Collector Master
   - Testy Collector Registry

2. **`tests/test_processors.py`**
   - Testy dla wszystkich procesorów
   - Testy bazowego procesora MVP
   - Testy Processor Registry

### Coverage

#### Collectory (12 collectorów)
- ✅ hardware
- ✅ drivers
- ✅ system_info
- ✅ storage_health
- ✅ services
- ✅ processes
- ✅ system_logs
- ✅ registry_txr
- ✅ bsod_dumps
- ✅ whea_analyzer
- ✅ performance_counters
- ✅ wer

#### Procesory (6 procesorów)
- ✅ hardware_processor
- ✅ driver_processor
- ✅ system_logs_processor
- ✅ registry_txr_processor
- ✅ storage_health_processor
- ✅ system_info_processor

#### Moduły Core
- ✅ Collector Registry
- ✅ Processor Registry
- ✅ Collector Master (sync i async)
- ✅ Base Processor

### Uruchomienie testów

#### Wszystkie testy
```bash
python -m pytest tests/ -v
```

#### Tylko testy collectorów
```bash
python -m pytest tests/test_collectors.py -v
```

#### Tylko testy procesorów
```bash
python -m pytest tests/test_processors.py -v
```

#### Z coverage
```bash
pip install pytest-cov
python -m pytest tests/ --cov=collectors --cov=processors --cov-report=html
```

### Struktura testów

```python
class TestCollectors(unittest.TestCase):
    """Testy podstawowe dla wszystkich collectorów."""
    
    def test_hardware_collector(self):
        """Test collectora hardware."""
        result = hardware.collect()
        self.assertIsNotNone(result)
        # ... więcej asercji

class TestCollectorMaster(unittest.TestCase):
    """Testy dla Collector Master."""
    
    def test_collect_all_format(self):
        """Test czy collect_all zwraca poprawny format MVP."""
        result = collect_all(save_raw=False)
        # Sprawdź strukturę MVP
```

## Porównanie wydajności

### ThreadPoolExecutor (stara wersja)
- Max workers: 6
- Overhead: Wysoki (tworzenie wątków)
- Dla 12 collectorów: ~2-3 sekundy

### Asyncio (nowa wersja)
- Concurrent tasks: Wszystkie równocześnie
- Overhead: Niski (event loop)
- Dla 12 collectorów: ~1-2 sekundy (szacunek)

## Migracja

### Dla istniejących collectorów
**Brak zmian wymaganych!** Wszystkie synchroniczne collectory działają automatycznie przez wrapper.

### Dla nowych collectorów
Możesz stworzyć async collector:

```python
async def collect():
    """Asynchroniczny collector."""
    # Async operacje
    data = await some_async_operation()
    return data
```

## Przyszłe ulepszenia

- [ ] Benchmarki wydajności (sync vs async)
- [ ] Metryki czasu wykonania dla każdego collectora
- [ ] Integracja z pytest-asyncio dla lepszych testów async
- [ ] Async processors (opcjonalnie)

