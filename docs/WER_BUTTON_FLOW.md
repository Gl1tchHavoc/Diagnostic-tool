# Flow wykonania po kliknięciu przycisku WER w GUI

## Przegląd
Po kliknięciu przycisku WER w GUI następuje następująca sekwencja:

1. **GUI** → `start_collector_scan(wer.collect, "WER")`
2. **GUI** → `run_collector_scan()` w osobnym wątku
3. **GUI** → `wer.collect()` - zbieranie danych
4. **GUI** → `format_collector_result("WER", result)`
5. **GUI** → `format_wer(result)` - formatowanie do wyświetlenia

---

## Krok 1: Kliknięcie przycisku WER
**Lokalizacja:** `gui.py:123`
```python
("WER", wer.collect, col2),
```

**Lokalizacja:** `gui.py:130-131`
```python
btn = tk.Button(
    parent, text=name, command=lambda c=collector_func, n=name: self.start_collector_scan(c, n),
    ...
)
```

**Wywołanie:** `self.start_collector_scan(wer.collect, "WER")`

---

## Krok 2: start_collector_scan()
**Lokalizacja:** `gui.py:458-460`
```python
def start_collector_scan(self, collector_func, collector_name):
    thread = Thread(target=self.run_collector_scan, args=(collector_func, collector_name), daemon=True)
    thread.start()
```

**Co się dzieje:**
- Tworzy nowy wątek (daemon=True)
- Uruchamia `run_collector_scan(wer.collect, "WER")` w osobnym wątku

---

## Krok 3: run_collector_scan()
**Lokalizacja:** `gui.py:462-490`
```python
def run_collector_scan(self, collector_func, collector_name):
    # 1. Wyłącz przycisk
    btn = self.collector_buttons.get(collector_name)
    if btn:
        btn.config(state=tk.DISABLED)
    
    # 2. Aktualizuj UI
    self.status.config(text=f"Collecting {collector_name}...")
    self.output_text.delete("1.0", tk.END)
    self.output_text.insert(tk.END, "=" * 70 + "\n")
    self.output_text.insert(tk.END, f"COLLECTING: {collector_name.upper()}\n")
    self.output_text.insert(tk.END, "=" * 70 + "\n\n")
    self.root.update()
    
    # 3. WYWOŁANIE WER.COLLECT() - TUTAJ MOŻE BYĆ BŁĄD!
    try:
        result = collector_func()  # <-- wer.collect()
        
        # 4. Formatuj wynik
        formatted = self.format_collector_result(collector_name, result)
        self.output_text.insert(tk.END, formatted)
        self.output_text.see(tk.END)
        
        self.status.config(text=f"{collector_name} Collection Completed")
    except Exception as e:
        error_msg = f"Collection failed: {type(e).__name__}: {str(e)}"
        messagebox.showerror("Error", error_msg)
        self.output_text.insert(tk.END, f"\n❌ ERROR: {error_msg}\n")
        self.status.config(text="Collection Failed")
    finally:
        if btn:
            btn.config(state=tk.NORMAL)
```

**KRYTYCZNE MIEJSCE:** Linia 475 - `result = collector_func()` wywołuje `wer.collect()`

---

## Krok 4: wer.collect()
**Lokalizacja:** `collectors/wer.py:21-384`

**Flow:**
1. **Inicjalizacja** (linia 38-52)
   - Sprawdza czy Windows
   - Tworzy pustą strukturę `wer_data`

2. **Zbieranie z Event Log** (linia 55-58)
   - `event_crashes = collect_from_event_log()`
   - `wer_data["recent_crashes"].extend(event_crashes)`

3. **Zbieranie z katalogów WER** (linia 60-63)
   - `wer_reports = collect_from_wer_directories()`
   - `wer_data["reports"].extend(wer_reports)`

4. **Grupowanie crashy** (linia 65-91) ⚠️ **KRYTYCZNE MIEJSCE**
   - `grouped = group_and_analyze_crashes(wer_data["recent_crashes"])`
   - Walidacja typu - upewnia się, że `grouped` jest listą
   - Walidacja elementów - upewnia się, że wszystkie elementy są dict
   - `wer_data["grouped_crashes"] = grouped`

5. **Obliczanie statystyk** (linia 112-147)
   - Filtrowanie crashy z timestampami
   - Filtrowanie powtarzających się crashy (linia 130-140)
     - **TUTAJ:** Iteracja po `grouped` (która jest listą)
     - Użycie `.get()` na elementach (które są dict) - OK

6. **Optymalizacja danych** (linia 149-211)
   - Ograniczenie `recent_crashes` do 50
   - Uproszczenie `grouped_crashes` (linia 177-209) ⚠️ **KRYTYCZNE MIEJSCE**
     - Iteracja: `for group in wer_data["grouped_crashes"][:MAX_GROUPED_CRASHES_DETAIL]:`
     - Sprawdzenie: `if isinstance(group, dict):`
     - Użycie: `group.get("application", "")` - OK, bo `group` jest dict

7. **Konwersja datetime** (linia 294-305)
   - Konwersja datetime → string dla serializacji

8. **Zwrócenie wyniku** (linia 370-384)
   - `return result` (gdzie `result = wer_data`)

**Zwracany typ:** `dict` z kluczami:
- `recent_crashes`: `list[dict]`
- `reports`: `list[dict]`
- `grouped_crashes`: `list[dict]` ⚠️ **LISTA, NIE DICT!**
- `statistics`: `dict`

---

## Krok 5: format_collector_result()
**Lokalizacja:** `gui.py:492-525`
```python
def format_collector_result(self, collector_name, result):
    if isinstance(result, dict):
        if collector_name == "WER":
            output += self.format_wer(result)  # <-- TUTAJ
```

---

## Krok 6: format_wer()
**Lokalizacja:** `gui.py:801-840` (NAPRAWIONY)

**NOWY KOD (Z ZABEZPIECZENIAMI):**
```python
def format_wer(self, data):
    """Formatuje dane WER."""
    logger = get_logger()
    output = "=== WINDOWS ERROR REPORTING ===\n\n"
    
    # ✅ ZABEZPIECZENIE: Sprawdź typ data przed użyciem
    if not isinstance(data, dict):
        logger.error(f"[GUI] format_wer: data is not a dict: {type(data)}")
        from utils.error_analyzer import log_error_with_analysis
        log_error_with_analysis(...)
        return f"❌ Error: WER data is {type(data).__name__} instead of dict\n"
    
    # ✅ Recent Crashes - bezpieczne pobranie
    recent_crashes = data.get('recent_crashes', [])
    if not isinstance(recent_crashes, list):
        recent_crashes = []
    output += f"Recent Crashes: {len(recent_crashes)}\n"
    
    # ✅ Reports - KRYTYCZNE: reports może być listą lub dict!
    reports = data.get("reports", [])
    if isinstance(reports, dict):
        report_count = reports.get('report_count', len(reports) if reports else 0)
        output += f"Report Count: {report_count}\n\n"
    elif isinstance(reports, list):
        output += f"Report Count: {len(reports)}\n\n"
    else:
        output += f"Report Count: N/A\n\n"
    
    # ✅ Grouped Crashes - bezpieczne pobranie
    grouped_crashes = data.get('grouped_crashes', [])
    if isinstance(grouped_crashes, list):
        output += f"Grouped Crashes: {len(grouped_crashes)} groups\n\n"
    else:
        output += f"Grouped Crashes: N/A\n\n"
    
    # ✅ Statistics - bezpieczne pobranie
    statistics = data.get('statistics', {})
    if isinstance(statistics, dict):
        output += "STATISTICS:\n"
        output += f"  Total Crashes: {statistics.get('total_crashes', 0)}\n"
        # ...
    
    # ✅ Recent Crashes - szczegóły z walidacją
    if recent_crashes:
        output += "RECENT CRASHES (first 10):\n"
        for idx, crash in enumerate(recent_crashes[:10]):
            try:
                if isinstance(crash, dict):
                    app = crash.get('application', 'N/A')
                    timestamp = crash.get('timestamp', 'N/A')
                    output += f"  {app}: {timestamp}\n"
                else:
                    logger.warning(f"[GUI] format_wer: crash[{idx}] is not a dict: {type(crash)}")
                    output += f"  [Invalid crash data: {type(crash).__name__}]\n"
            except Exception as e:
                logger.warning(f"[GUI] format_wer: Error formatting crash[{idx}]: {e}")
                output += f"  [Error formatting crash]\n"
    
    return output
```

**ANALIZA:**
- ✅ Sprawdza typ `data` przed użyciem
- ✅ Sprawdza typ `reports` (list vs dict) przed użyciem `.get()`
- ✅ Sprawdza typ `recent_crashes` przed iteracją
- ✅ Sprawdza typ `grouped_crashes` przed użyciem
- ✅ Sprawdza typ każdego `crash` przed użyciem `.get()`
- ✅ Kompleksowa analiza błędów z `error_analyzer`

---

## Potencjalne problemy:

### Problem 1: `data['reports']` może być listą
**Lokalizacja:** `gui.py:806`
```python
output += f"Report Count: {data['reports'].get('report_count', 0)}\n\n"
```

**Rozwiązanie:** Sprawdź typ przed użyciem `.get()`
```python
if isinstance(data.get("reports"), dict):
    output += f"Report Count: {data['reports'].get('report_count', 0)}\n\n"
elif isinstance(data.get("reports"), list):
    output += f"Report Count: {len(data['reports'])}\n\n"
```

### Problem 2: Brak walidacji w `format_wer()`
- Nie sprawdza, czy `data` jest dict
- Nie sprawdza typów przed użyciem `.get()`
- Nie obsługuje przypadków, gdy dane są w nieoczekiwanym formacie

---

## Miejsca, gdzie może wystąpić błąd:

1. **`gui.py:475`** - `result = collector_func()` - jeśli `wer.collect()` rzuci wyjątek
2. **`gui.py:806`** - `data['reports'].get('report_count', 0)` - jeśli `reports` jest listą
3. **`gui.py:808-811`** - Iteracja po `recent_crashes` - jeśli elementy nie są dict

---

## Rekomendacje:

1. **Dodać walidację w `format_wer()`:**
   - Sprawdzić, czy `data` jest dict
   - Sprawdzić typy przed użyciem `.get()`
   - Obsłużyć przypadki, gdy dane są w nieoczekiwanym formacie

2. **Dodać try-except w `run_collector_scan()`:**
   - Już jest (linia 483-487), ale można dodać bardziej szczegółowe logowanie

3. **Dodać walidację w `format_collector_result()`:**
   - Sprawdzić typ `result` przed formatowaniem
   - Obsłużyć przypadki, gdy `result` nie jest dict

