# BSOD Analysis - Dokumentacja

## Opis algorytmu korelacji

System analizy BSOD wykorzystuje wieloetapowy proces korelacji zdarzeń z różnych źródeł logów, aby zidentyfikować najbardziej prawdopodobne przyczyny Blue Screen of Death.

### Etapy analizy:

1. **Wykrywanie BSOD**
   - Skanowanie folderu `C:\Windows\Minidump` w poszukiwaniu plików `.dmp`
   - Identyfikacja najnowszego minidump (najnowszy timestamp)
   - Ekstrakcja timestamp BSOD

2. **Zbieranie logów**
   - **System Event Log**: Zdarzenia systemowe (błędy, ostrzeżenia, krytyczne)
   - **Application Event Log**: Zdarzenia aplikacji
   - **Kernel Events**: Bugchecks, stop errors, kernel crashes
   - **Security Event Log**: (opcjonalnie) Zdarzenia bezpieczeństwa

3. **Filtrowanie czasowe**
   - Okno czasowe: **-5 minut do +1 minuta** względem timestamp BSOD
   - Tylko zdarzenia w tym oknie są analizowane

4. **Eliminacja false positives**
   - Odrzucanie poziomu **Information** (nie są przydatne diagnostycznie)
   - Filtrowanie przez regex patterns (np. "The description for Event ID .* cannot be found")
   - Odrzucanie częstych, nieszkodliwych eventów (DNS requests, service started, itp.)

5. **System scoringu**
   - Każde zdarzenie otrzymuje score na podstawie:
     - **Czas od BSOD**: 0-30 sek = +3, 31-120 sek = +2
     - **Poziom**: Error/Critical = +3, Warning = +1
     - **Kategoria**: Kernel/Hardware = +5
     - **Noise**: -5
   - Zdarzenia z score < 0 są ignorowane

6. **Ranking i prezentacja**
   - Sortowanie zdarzeń po score (malejąco)
   - Grupowanie po poziomie (Error, Warning, Critical)
   - Prezentacja top zdarzeń z najwyższymi scores

## Przykłady logów wejściowych

### System Event Log (XML format):
```xml
<Object>
  <Property Name="TimeCreated">2025-11-29T10:04:12.000Z</Property>
  <Property Name="Id">41</Property>
  <Property Name="LevelDisplayName">Critical</Property>
  <Property Name="Message">System został uruchomiony ponownie bez uprzedniego czystego zamknięcia.</Property>
</Object>
```

### Minidump file:
```
C:\Windows\Minidump\112925-12345-01.dmp
Modified: 2025-11-29 10:04:12
Size: 256 KB
```

## Proces eliminacji false positives

### Regex patterns ignorowane:
- `"The description for Event ID .* cannot be found"`
- `"Audit Success"`
- `"Service .* running"`
- `"Service .* started successfully"`
- `"DNS request"`
- `"Connection established"`
- `"User logged on/off"`
- `"Windows Update"`
- `"Defender"`
- `"Antivirus scan"`
- `"Backup"`
- `"Maintenance"`
- `"Heartbeat"`
- `"Scheduled task"`
- `"Time synchronization"`

### Słowa kluczowe ignorowane:
- heartbeat, health check, status check
- logon, logoff, login, logout
- update installed, update downloaded
- backup completed, backup started
- task scheduler, scheduled task
- service started, service stopped
- dhcp, dns query, network adapter
- time synchronization, ntp
- disk cleanup, defrag, chkdsk completed

### Heurystyki:
- Jeśli event ma poziom **Information** → odrzuć
- Jeśli event nie ma timestamp → odrzuć
- Jeśli event ma score < 0 → odrzuć

## Przykłady outputu

### Przykład 1: BSOD z powodu błędu dysku

```json
{
  "bsod_found": true,
  "bsod_timestamp": "2025-11-29T10:04:12Z",
  "correlated_events": [
    {
      "timestamp": "2025-11-29T10:03:45Z",
      "level": "Error",
      "event_id": "51",
      "message": "An error was detected on device \\Device\\Harddisk0\\DR0 during a paging operation.",
      "category": "DISK_ERROR",
      "correlation_score": 11.0,
      "time_from_bsod_seconds": 27.0
    },
    {
      "timestamp": "2025-11-29T10:03:50Z",
      "level": "Warning",
      "event_id": "129",
      "message": "Reset to device, \\Device\\RaidPort0, was issued.",
      "category": "DISK_ERROR",
      "correlation_score": 6.0,
      "time_from_bsod_seconds": 22.0
    }
  ],
  "events_by_level": {
    "Error": 1,
    "Warning": 1
  },
  "total_correlated": 2
}
```

### Przykład 2: BSOD z powodu sterownika GPU

```json
{
  "bsod_found": true,
  "bsod_timestamp": "2025-11-29T10:04:12Z",
  "correlated_events": [
    {
      "timestamp": "2025-11-29T10:04:00Z",
      "level": "Critical",
      "event_id": "1001",
      "message": "The computer has rebooted from a bugcheck. The bugcheck was: 0x00000116 (0xfffffa8001234567, 0xfffff88001234567, 0x0000000000000000, 0x0000000000000002).",
      "category": "GPU_DRIVER",
      "correlation_score": 11.0,
      "time_from_bsod_seconds": 12.0
    },
    {
      "timestamp": "2025-11-29T10:03:55Z",
      "level": "Error",
      "event_id": "14",
      "message": "The description for Event ID 14 from source nvlddmkm cannot be found.",
      "category": "GPU_DRIVER",
      "correlation_score": 8.0,
      "time_from_bsod_seconds": 17.0
    }
  ],
  "events_by_level": {
    "Critical": 1,
    "Error": 1
  },
  "total_correlated": 2
}
```

## System scoringu - szczegóły

### Tabela scoringu:

| Cecha | Punkty |
|------|--------|
| Czas w zakresie 0–30 sek. od BSOD | +3 |
| Czas w zakresie 31–120 sek. | +2 |
| Error / Critical level | +3 |
| Warning level | +1 |
| Ten sam proces/sterownik co BSOD dump | +5 |
| Kernel / Hardware event | +5 |
| Common noise | -5 |
| Powtarzalne codzienne eventy | -2 |

### Przykład obliczania score:

Event: Disk error, 25 sekund przed BSOD, poziom Error, kategoria DISK_ERROR
- Czas 0-30 sek: +3
- Error level: +3
- Hardware event: +5
- **Total score: 11.0**

## Użycie

```python
from correlation.bsod_correlation import BSODCorrelator

# Utwórz korelator z oknem czasowym 5 minut
correlator = BSODCorrelator(time_window_minutes=5)

# Wykonaj analizę
result = correlator.analyze_bsod()

if result['bsod_found']:
    print(f"BSOD found at: {result['bsod_timestamp']}")
    print(f"Correlated events: {result['total_correlated']}")
    
    for event in result['correlated_events'][:10]:  # Top 10
        print(f"  [{event['correlation_score']:.1f}] {event['timestamp']} - {event['message'][:100]}")
else:
    print("No BSOD found")
```

## Integracja z głównym programem

Moduł jest zintegrowany z głównym programem diagnostycznym przez:
- `processors/bsod_analyzer.py` - używa korelatora do analizy
- `gui.py` - opcja "Analyze last BSOD" w menu
- Automatyczne wywołanie podczas pełnego skanowania systemu

## Testy

Testy jednostkowe znajdują się w folderze `tests/`:
- `test_log_parsers.py` - testy parserów
- `test_correlation.py` - testy korelacji
- `test_scoring.py` - testy scoringu
- `test_noise_filtering.py` - testy filtracji noise


