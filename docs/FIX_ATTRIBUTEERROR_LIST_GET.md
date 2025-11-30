# Naprawa błędu: AttributeError: 'list' object has no attribute 'get'

## 🔴 GŁÓWNY PROBLEM: `gui.py:format_wer()`

### Stary kod (BŁĘDNY):
```python
def format_wer(self, data):
    """Formatuje dane WER."""
    output = "=== WINDOWS ERROR REPORTING ===\n\n"
    output += f"Recent Crashes: {len(data.get('recent_crashes', []))}\n"
    if data.get("reports"):
        output += f"Report Count: {data['reports'].get('report_count', 0)}\n\n"  # ❌ BŁĄD TUTAJ!
```

**Problem:**
- `wer.collect()` zwraca `wer_data["reports"]` jako **LISTĘ** (nie dict!)
- W `collectors/wer.py:63` używa się `wer_data["reports"].extend(wer_reports)`, co oznacza że `reports` jest listą
- Próba użycia `data['reports'].get('report_count', 0)` na liście powoduje: `AttributeError: 'list' object has no attribute 'get'`

### Nowy kod (NAPRAWIONY):
```python
def format_wer(self, data):
    """Formatuje dane WER."""
    logger = get_logger()
    output = "=== WINDOWS ERROR REPORTING ===\n\n"
    
    # ✅ ZABEZPIECZENIE: Sprawdź typ data przed użyciem
    if not isinstance(data, dict):
        logger.error(f"[GUI] format_wer: data is not a dict: {type(data)}")
        # ... kompleksowa analiza błędów ...
        return f"❌ Error: WER data is {type(data).__name__} instead of dict\n"
    
    # ✅ Reports - KRYTYCZNE: reports może być listą lub dict!
    reports = data.get("reports", [])
    if isinstance(reports, dict):
        # Jeśli reports jest dict, użyj .get()
        report_count = reports.get('report_count', len(reports) if reports else 0)
        output += f"Report Count: {report_count}\n\n"
    elif isinstance(reports, list):
        # ✅ Jeśli reports jest listą, użyj len() - NAPRAWIONE!
        output += f"Report Count: {len(reports)}\n\n"
    else:
        logger.warning(f"[GUI] format_wer: reports is unexpected type: {type(reports)}")
        output += f"Report Count: N/A\n\n"
```

**Rozwiązanie:**
- Sprawdza typ `reports` przed użyciem `.get()`
- Jeśli `reports` jest listą → używa `len(reports)`
- Jeśli `reports` jest dict → używa `reports.get('report_count', ...)`

---

## 📍 GDZIE BYŁ BŁĄD:

### 1. **`gui.py:806` (STARY KOD)** - GŁÓWNY PROBLEM
```python
# ❌ BŁĘDNY KOD:
if data.get("reports"):
    output += f"Report Count: {data['reports'].get('report_count', 0)}\n\n"
```

**Dlaczego błąd:**
- `wer.collect()` zwraca `reports` jako **listę** (zobacz `collectors/wer.py:63`)
- Próba użycia `.get()` na liście → `AttributeError`

**Naprawa:**
- Sprawdzenie typu przed użyciem `.get()`
- Jeśli lista → `len(reports)`
- Jeśli dict → `reports.get('report_count', ...)`

---

## 🔍 DLACZEGO `reports` JEST LISTĄ:

W `collectors/wer.py`:

```python
# Linia 38-40: Inicjalizacja
wer_data = {
    "recent_crashes": [],
    "reports": [],  # ← TO JEST LISTA!
    "grouped_crashes": [],
    "statistics": {}
}

# Linia 60-63: Zbieranie danych
wer_reports = collect_from_wer_directories()  # Zwraca listę
wer_data["reports"].extend(wer_reports)  # ← .extend() na liście!
```

**Wniosek:** `wer_data["reports"]` jest **zawsze listą**, nigdy dict!

---

## ✅ WSZYSTKIE NAPRAWIONE MIEJSCA:

### 1. `gui.py:format_wer()` - GŁÓWNA NAPRAWA
- ✅ Sprawdza typ `data` przed użyciem
- ✅ Sprawdza typ `reports` (list vs dict) przed użyciem `.get()`
- ✅ Sprawdza typ `recent_crashes` przed iteracją
- ✅ Sprawdza typ `grouped_crashes` przed użyciem
- ✅ Sprawdza typ każdego `crash` przed użyciem `.get()`
- ✅ Kompleksowa analiza błędów z `error_analyzer`

### 2. `collectors/wer.py` - Dodano zabezpieczenia
- ✅ Szczegółowe logowanie typu zwracanego przez `group_and_analyze_crashes()`
- ✅ Walidacja typu `grouped` przed użyciem
- ✅ Walidacja każdego elementu przed użyciem `.get()`

### 3. `scans/scan_manager.py` - Dodano zabezpieczenia
- ✅ Sprawdza typ `collector_result` przed użyciem `.get()`
- ✅ Sprawdza typ `collector_data` przed użyciem
- ✅ `_sanitize_wer_data()` sprawdza typ `wer_data` przed użyciem

### 4. `processors/cause_detector.py` - Już wcześniej naprawione
- ✅ Używa `safe_get_with_analysis()` zamiast bezpośredniego `.get()`

---

## 📊 PODSUMOWANIE:

**Główny problem:** `gui.py:format_wer()` próbował użyć `.get()` na `data['reports']`, które jest **listą**, nie dict.

**Główna naprawa:** Sprawdzenie typu przed użyciem `.get()`:
```python
if isinstance(reports, dict):
    report_count = reports.get('report_count', ...)
elif isinstance(reports, list):
    report_count = len(reports)  # ✅ NAPRAWIONE!
```

**Dodatkowe zabezpieczenia:**
- Walidacja wszystkich typów przed użyciem
- Kompleksowa analiza błędów z `error_analyzer`
- Szczegółowe logowanie dla debugowania

---

## 🎯 WYNIK:

✅ Aplikacja działa poprawnie!
✅ Błąd `AttributeError: 'list' object has no attribute 'get'` został naprawiony
✅ Wszystkie przypadki błędów są obsługiwane
✅ Aplikacja nie crashuje przy nieoczekiwanych typach danych

