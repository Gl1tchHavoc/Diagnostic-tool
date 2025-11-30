# WER Collector - Dokładny Flow Wykonania

## Kolejność wykonania po zakończeniu WER Collection

### 1. WER Collector kończy pracę (`collectors/wer.py`)

**Linia 103:** `logger.info("[WER] Collected X crashes...")`

**Co się dzieje:**
- Funkcja `collect()` zwraca `wer_data` (dict)
- Struktura zwracana:
  ```python
  {
      "recent_crashes": [...],      # lista dict
      "reports": [...],              # lista dict
      "grouped_crashes": [...],      # lista dict (WAŻNE: to jest LISTA!)
      "statistics": {...}            # dict
  }
  ```

---

### 2. WERCollector.run() (`collectors/base_collector.py`)

**Linia 106:** `self.data = self.collect()`

**Co się dzieje:**
- `WERCollector.collect()` wywołuje `wer.collect()`
- Wynik zapisywany w `self.data`
- Zwraca:
  ```python
  {
      'name': 'wer',
      'status': 'DONE',
      'progress': 100.0,
      'data': wer_data,  # <-- tutaj jest wer_data z collect()
      'subtasks': []
  }
  ```

---

### 3. ScanManager zapisuje wyniki (`scans/scan_manager.py`)

**Linia 115-140:** Po `collector.run()`

**Kolejność:**
1. **Linia 116:** `collector_result = collector.run()`
   - Zwraca dict z kluczem `'data'`

2. **Linia 130-132:** Sprawdzenie typu i zapisanie
   ```python
   if isinstance(collector_result, dict):
       collector_data = collector_result.get('data', {})
       results["collectors"][collector.name] = collector_data
   ```
   - `collector_data` = `wer_data` (dict z `recent_crashes`, `grouped_crashes`, etc.)
   - Zapisane do: `results["collectors"]["wer"] = wer_data`

3. **Linia 142-152:** Progress callback
   ```python
   progress_info = progress_calc.get_progress()
   self.progress_callback(progress_info['global_progress'], f"Completed {collector.name}")
   ```
   - **TUTAJ MOŻE BYĆ PROBLEM** - jeśli `progress_calc.get_progress()` zwraca coś nieoczekiwanego

4. **Linia 154-156:** Finalne informacje
   ```python
   progress_info = progress_calc.get_detailed_progress()
   status_summary = progress_calc.get_status_summary()
   ```

5. **Linia 160-165:** Zwraca wyniki
   ```python
   return {
       'scan_type': 'full',
       'timestamp': '...',
       'results': {
           'collectors': {
               'wer': wer_data,  # <-- tutaj jest wer_data
               ...
           }
       },
       'progress_info': {...},
       'status_summary': {...}
   }
   ```

---

### 4. GUI otrzymuje wyniki (`gui.py`)

**Linia 313:** `scan_results = full_scan.run()`

**Kolejność:**
1. **Linia 313:** Otrzymuje `scan_results` (dict)

2. **Linia 320-330:** Konwersja do formatu analyzer
   ```python
   results = scan_results.get('results', {})
   collectors = results.get('collectors', {})
   collected_data = {
       "timestamp": scan_results.get('timestamp', ''),
       "collectors": collectors  # <-- tutaj jest {'wer': wer_data, ...}
   }
   ```

3. **Linia 333-338:** Progress info
   ```python
   progress_info = scan_results.get('progress_info', {})
   global_progress = progress_info.get('global_progress', 100.0)
   ```

4. **Linia 358:** Wywołanie analyzer
   ```python
   analysis_report = analyze_all(collected_data, progress_callback=analysis_callback)
   ```

---

### 5. Analyzer przetwarza dane (`processors/analyzer.py`)

**Linia 35-40:** Pobranie danych
```python
collectors_data = collected_data.get("collectors", {})
# collectors_data = {'wer': wer_data, 'hardware': {...}, ...}
```

**Linia 57-84:** Przetwarzanie przez procesory
- NIE MA procesora dla WER w `processors_list`!
- WER nie jest przetwarzany przez standardowe procesory

**Linia 110-120:** Analiza WHEA (jeśli dostępne)
- Nie dotyczy WER

**Linia 122-165:** Analiza BSOD
- Nie dotyczy WER bezpośrednio

**Linia 81-87:** Wykrywanie przyczyn (`detect_all_causes`)
```python
detected_causes = detect_all_causes(processed_data, collected_data)
```
- **TUTAJ** jest używane `collected_data.get('collectors', {}).get('wer', {})`
- Wywołuje `detect_wer_causes()` w `processors/cause_detector.py`

---

### 6. Cause Detector - WER Causes (`processors/cause_detector.py`)

**Linia 769-775:** Pobranie danych WER
```python
wer_data = collected_data.get('collectors', {}).get('wer', {})
recent_crashes = wer_data.get('recent_crashes', [])
grouped_crashes = wer_data.get('grouped_crashes', [])  # <-- LISTA!
```

**Linia 773-780:** Sprawdzenie typu (DODANE ZABEZPIECZENIE)
```python
if not isinstance(grouped_crashes, list):
    logger.warning(...)
    grouped_crashes = [grouped_crashes] if grouped_crashes is not None else []
```

**Linia 801-810:** Iteracja po grouped_crashes
```python
for group in grouped_crashes:  # <-- POPRAWNIE: iteracja po liście
    if group.get('is_repeating', False):  # <-- POPRAWNIE: .get() na elemencie (dict)
        ...
```

---

## Potencjalne miejsca błędów

### ❌ MIEJSCE 1: `scan_manager.py` linia 131
```python
collector_data = collector_result.get('data', {})
```
- Jeśli `collector_result` nie jest dict → błąd
- **ZABEZPIECZONE:** Linia 130 sprawdza `isinstance(collector_result, dict)`

### ❌ MIEJSCE 2: `scan_manager.py` linia 145
```python
progress_info = progress_calc.get_progress()
self.progress_callback(progress_info['global_progress'], ...)
```
- Jeśli `progress_info` nie ma klucza `'global_progress'` → KeyError
- **ZABEZPIECZONE:** Linia 146 sprawdza `'global_progress' in progress_info`

### ❌ MIEJSCE 3: `gui.py` linia 324
```python
collectors = results.get('collectors', {})
```
- Jeśli `results` nie jest dict → błąd
- **ZABEZPIECZONE:** Linia 321 sprawdza `isinstance(results, dict)`

### ❌ MIEJSCE 4: `processors/cause_detector.py` linia 774
```python
grouped_crashes = wer_data.get('grouped_crashes', [])
```
- Jeśli `grouped_crashes` nie jest listą i użyjemy `.get()` na nim → AttributeError
- **ZABEZPIECZONE:** Linia 777-780 sprawdza typ i konwertuje

### ❌ MIEJSCE 5: `processors/cause_detector.py` linia 801
```python
for group in grouped_crashes:
    if group.get('is_repeating', False):
```
- Jeśli `grouped_crashes` jest dict zamiast listy → błąd w iteracji
- **ZABEZPIECZONE:** Linia 777-780 konwertuje do listy

---

## Flow diagram

```
WER.collect() 
    ↓
zwraca wer_data (dict)
    ↓
WERCollector.run()
    ↓
zwraca {'data': wer_data, ...}
    ↓
ScanManager.run() - linia 131
    ↓
zapisuje: results["collectors"]["wer"] = wer_data
    ↓
zwraca scan_results
    ↓
GUI.run_full_scan() - linia 313
    ↓
konwertuje: collected_data = {"collectors": {"wer": wer_data, ...}}
    ↓
analyze_all(collected_data) - linia 358
    ↓
detect_all_causes() - linia 81
    ↓
detect_wer_causes() - linia 758
    ↓
wer_data.get('grouped_crashes', []) - linia 774
    ↓
for group in grouped_crashes: - linia 801
    ↓
group.get('is_repeating', False) - linia 802
```

---

## Jak debugować

1. **Sprawdź logi** po linii: `[WER] Collected X crashes...`
2. **Szukaj błędów** w:
   - `[SCAN_MANAGER]` - zapisywanie wyników
   - `[GUI]` - konwersja danych
   - `[ANALYSIS]` - przetwarzanie
   - `[CAUSE_DETECTOR]` - wykrywanie przyczyn

3. **Sprawdź typy** w logach:
   - `[SCAN_MANAGER] Collector wer returned: <type>`
   - `[SCAN_MANAGER] Saved data for wer, type: <type>`
   - `[CAUSE_DETECTOR] grouped_crashes is not a list: <type>`

4. **Dodaj więcej logowania** jeśli potrzeba:
   ```python
   logger.debug(f"[DEBUG] grouped_crashes type: {type(grouped_crashes)}")
   logger.debug(f"[DEBUG] grouped_crashes value: {grouped_crashes}")
   ```

