# Diagnostic Tool

Zaawansowane narzędzie diagnostyczne systemu Windows do identyfikacji problemów z ~99% skutecznością.

## Funkcje

- **Kompleksowe zbieranie danych**: Hardware, drivers, logi systemowe, Registry TxR, storage health, services, BSOD/dumps, performance counters, WER, processes
- **Inteligentna analiza**: System scoring, confidence engine, status classification
- **Automatyczne rekomendacje**: Dopasowane zalecenia naprawcze na podstawie wykrytych problemów
- **GUI i CLI**: Interfejs graficzny oraz wiersz poleceń

## Instalacja

```bash
pip install -r requirements.txt
```

## ⚠️ Wymagane uprawnienia

**Program wymaga uprawnień administratora** do:
- Czytania logów systemowych Windows
- Dostępu do Registry TxR errors
- Sprawdzania statusu usług systemowych
- Analizy BSOD i memory dumps

### Jak uruchomić jako administrator:

**Windows:**
1. Kliknij prawym przyciskiem na plik `.py` lub skrót
2. Wybierz **"Uruchom jako administrator"**

**Lub przez PowerShell (jako administrator):**
```powershell
python gui.py
python main.py
```

## Użycie

### GUI (Interfejs graficzny)
```bash
python gui.py
```

### CLI (Wiersz poleceń)
```bash
# Pełne skanowanie
python main.py

# Lub przez orchestrator
python cli.py --full
```

## Struktura projektu

```
/diagnostic_tool/
├── collectors/          # Moduły zbierające dane
│   ├── hardware.py
│   ├── drivers.py
│   ├── system_logs.py
│   ├── registry_txr.py
│   ├── storage_health.py
│   ├── services.py
│   ├── bsod_dumps.py
│   ├── performance_counters.py
│   ├── wer.py
│   └── processes.py
├── processors/         # Moduły przetwarzające dane
│   ├── status_calculator.py
│   ├── score_calculator.py
│   ├── confidence_engine.py
│   ├── recommendation_engine.py
│   └── report_builder.py
├── output/             # Wygenerowane raporty
│   ├── raw/           # Surowe dane
│   └── processed/     # Przetworzone raporty
└── gui.py             # Interfejs graficzny
```

## System Scoring

- **Critical**: 40 pkt
- **Error**: 20 pkt
- **Warning**: 10 pkt
- **Info**: 0 pkt

**Status:**
- 🟢 HEALTHY (0 Critical)
- 🟠 DEGRADED (1 Critical)
- 🔴 UNHEALTHY (2+ Critical lub dysk/rejestr/kernel)

## Wymagania

- Windows 10/11
- Python 3.7+
- Wymagane biblioteki w `requirements.txt`

## Licencja

Zobacz plik LICENSE.
