# Plan Refaktoryzacji do MVP

## Cel MVP
Zebrać i zaprezentować dane diagnostyczne Windows w sposób spójny, czytelny i łatwy do przetworzenia przez dalsze moduły analityczne.

## Zakres funkcjonalny MVP

### 1. Collectory (dane źródłowe)
**Status:** ✅ Już zaimplementowane, wymaga standaryzacji formatu zwracanego

**Wymagane collectory:**
- ✅ Hardware: CPU, RAM, dyski, GPU, temperatura, wykorzystanie zasobów
- ✅ System: wersja Windows, uptime, aktualizacje, patch level
- ✅ Procesy i usługi: uruchomione procesy, autostart, status usług
- ✅ Logi systemowe: wybrane Event Logi (System, Application)
- ✅ Storage: dostępne dyski, partycje, wolne miejsce, SMART dysków
- ✅ Sieć: konfiguracja adapterów, IP, status połączeń

**Zmiany wymagane:**
- Standaryzacja formatu zwracanego przez każdy collector:
  ```python
  {
      "status": "Collected" | "Error",
      "data": {...},  # lub None jeśli Error
      "error": "error message" | None,
      "timestamp": "ISO timestamp",
      "collector_name": "hardware"
  }
  ```

### 2. Procesory (MVP w wersji minimalnej)
**Status:** ⚠️ Wymaga uproszczenia - obecnie zbyt złożone

**Wymagane funkcjonalności:**
- ✅ Parser danych na wewnętrzny format JSON
- ✅ Minimalna walidacja danych: brak błędów, poprawny typ wartości
- ✅ Status "Collected" / "Error" dla każdego collectora

**Zmiany wymagane:**
- Uprościć procesory do minimalnej wersji:
  ```python
  def process(collector_data):
      """
      Minimalny processor - parsuje i waliduje dane.
      
      Returns:
          {
              "status": "Collected" | "Error",
              "data": {...},  # przetworzone dane
              "errors": [],  # lista błędów walidacji
              "warnings": []  # lista ostrzeżeń
          }
      """
  ```

### 3. GUI MVP
**Status:** ⚠️ Wymaga refaktoryzacji

**Wymagane funkcjonalności:**
- ✅ Wyświetlanie listy collectorów + statusu (Collected / Error)
- ✅ Możliwość podglądu surowych danych w formie czytelnej tabeli lub drzewa
- ✅ Eksport raportu (JSON/HTML) w łatwej do przetworzenia formie

**Zmiany wymagane:**
- Dodać panel z listą collectorów i ich statusami
- Dodać widok surowych danych (TreeView lub tabela)
- Dodać przycisk eksportu raportu (JSON/HTML)

### 4. CLI MVP (opcjonalnie)
**Status:** ⚠️ Wymaga uproszczenia

**Wymagane funkcjonalności:**
- ✅ Możliwość uruchomienia pełnego skanu
- ✅ Możliwość wyświetlenia statusu każdego collectora w konsoli

**Zmiany wymagane:**
- Uprościć output CLI do czytelnego formatu tabeli
- Dodać wyświetlanie statusu każdego collectora

## Plan implementacji

### ✅ Faza 1: Standaryzacja Collectorów (ZAKOŃCZONA)
1. ✅ Zaktualizować `collector_master.py` aby zwracał spójny format
2. ✅ Zaktualizować każdy collector aby zwracał standardowy format z statusem
3. ✅ Dodać walidację formatu zwracanego
4. ✅ Dodać CollectorRegistry dla modularności
5. ✅ Dodać równoległe wykonanie collectorów

### ✅ Faza 2: Uproszczenie Procesorów (ZAKOŃCZONA)
1. ✅ Stworzyć bazowy processor z minimalną funkcjonalnością
2. ✅ Zrefaktoryzować `analyzer.py` do obsługi nowego formatu
3. ✅ Dodać ProcessorRegistry dla modularności

### ✅ Faza 3: Refaktoryzacja GUI (ZAKOŃCZONA)
1. ✅ Dodać panel z listą collectorów i statusami (TreeView)
2. ✅ Dodać widok surowych danych (ScrolledText)
3. ✅ Dodać eksport raportu (JSON/HTML)
4. ✅ Dodać możliwość uruchamiania pojedynczych collectorów
5. ✅ Dodać wyświetlanie danych pojedynczych collectorów
6. ✅ Dodać cache danych collectorów

### ✅ Faza 4: Uproszczenie CLI (ZAKOŃCZONA)
1. ✅ Zrefaktoryzować `main.py` aby wyświetlał status collectorów
2. ✅ Dodać czytelny format tabeli dla outputu

### ✅ Faza 6: Ulepszenia BSOD Collector (ZAKOŃCZONA)
1. ✅ Automatyczne wykrywanie ścieżek dumpów z rejestru Windows
2. ✅ Obsługa pełnych dumpów (MEMORY.DMP) i minidumpów
3. ✅ Parsowanie z WinDbg dla lepszego wykrywania driverów (fallback)
4. ✅ Rozszerzona korelacja WHEA errors z crashami (±10 minut)
5. ✅ Zbieranie kontekstu sprzętowego (temperatura, SMART, RAM) w czasie crashu
6. ✅ Rozszerzone eventy systemowe i driver logs z filtrowaniem czasowym
7. ✅ Lepsze logowanie błędów PowerShell z identyfikacją komend
8. ✅ Zwiększone timeouty dla długotrwałych operacji (60s dla eventów)

### ✅ Faza 5: Dokumentacja (ZAKOŃCZONA)
1. ✅ Zaktualizować README.md
2. ✅ Dodać plan refaktoryzacji (MVP_REFACTORING_PLAN.md)
3. ✅ Dodać dokumentację architektury (docs/MVP_ARCHITECTURE.md)
4. ✅ Dodać diagram flow (docs/MVP_PIPELINE_FLOW.puml)

## Struktura danych MVP

### Format zwracany przez Collector
```json
{
    "status": "Collected",
    "data": {
        // Dane specyficzne dla collectora
    },
    "error": null,
    "timestamp": "2025-11-30T12:00:00",
    "collector_name": "hardware",
    "execution_time_ms": 1234
}
```

### Format zwracany przez Processor
```json
{
    "status": "Collected",
    "data": {
        // Przetworzone dane
    },
    "errors": [],
    "warnings": [],
    "validation_passed": true,
    "timestamp": "2025-11-30T12:00:00",
    "processor_name": "hardware_processor"
}
```

### Format raportu końcowego
```json
{
    "timestamp": "2025-11-30T12:00:00",
    "collectors": {
        "hardware": {
            "status": "Collected",
            "data": {...},
            "error": null
        },
        // ... inne collectory
    },
    "processors": {
        "hardware_processor": {
            "status": "Collected",
            "data": {...},
            "errors": [],
            "warnings": []
        },
        // ... inne procesory
    },
    "summary": {
        "total_collectors": 11,
        "collected": 10,
        "errors": 1,
        "total_processors": 6,
        "processed": 5,
        "processor_errors": 1
    }
}
```

