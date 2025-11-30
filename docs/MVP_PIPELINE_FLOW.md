# Diagnostic Tool MVP - Pipeline Flow

## Diagram Flow

### PlantUML Version

Diagram w formacie PlantUML można wyświetlić na kilka sposobów:

1. **Online Viewer (PlantUML):**
   - Skopiuj zawartość pliku `MVP_PIPELINE_FLOW.puml`
   - Wklej na: http://www.plantuml.com/plantuml/uml/
   - Lub użyj: https://www.planttext.com/

2. **VS Code:**
   - Zainstaluj rozszerzenie "PlantUML" (jebbs.plantuml)
   - Otwórz plik `.puml` i naciśnij `Alt+D` aby wyświetlić podgląd

3. **IntelliJ/PyCharm:**
   - Zainstaluj wtyczkę "PlantUML integration"
   - Otwórz plik `.puml` i użyj podglądu

### Mermaid Version (Renderowany w GitHub)

Poniższy diagram jest renderowany automatycznie w GitHub:

```mermaid
graph TB
    User[👤 User]
    GUIMVP[GUI MVP<br/>- Display collector status<br/>- View detailed data<br/>- Export JSON/HTML]
    CLIMVP[CLI MVP<br/>- Trigger full scan<br/>- Show collector statuses<br/>- Export JSON]
    CollectorMaster[Collector Master Async<br/>- Parallel async execution<br/>- Standardize format<br/>- Error handling]
    ProcessorsMVP[Processors MVP<br/>- Validate data<br/>- Parse JSON<br/>- Prepare for reporting<br/>- Optional scoring]
    Logger[Logger / Audit<br/>- Collector statuses<br/>- Errors<br/>- Timestamps<br/>- Performance metrics]
    
    Hardware[Collector: Hardware<br/>CPU, RAM, GPU, Temp]
    System[Collector: System<br/>Windows version, uptime, patches]
    Storage[Collector: Storage<br/>Disks, partitions, SMART]
    Network[Collector: Network<br/>Adapters, IP, connections]
    Processes[Collector: Processes & Services<br/>Running processes, autostart, services]
    EventLogs[Collector: Event Logs<br/>System & Application]
    Drivers[Collector: Drivers & Registry TxR]
    
    User -->|Initiates scan / views results| GUIMVP
    User -->|Initiates scan / views results| CLIMVP
    GUIMVP -->|Request full scan / single collector| CollectorMaster
    CLIMVP -->|Request full scan| CollectorMaster
    
    CollectorMaster -->|Async request parallel| Hardware
    CollectorMaster -->|Async request parallel| System
    CollectorMaster -->|Async request parallel| Storage
    CollectorMaster -->|Async request parallel| Network
    CollectorMaster -->|Async request parallel| Processes
    CollectorMaster -->|Async request parallel| EventLogs
    CollectorMaster -->|Async request parallel| Drivers
    
    Hardware -->|JSON + status| CollectorMaster
    System -->|JSON + status| CollectorMaster
    Storage -->|JSON + status| CollectorMaster
    Network -->|JSON + status| CollectorMaster
    Processes -->|JSON + status| CollectorMaster
    EventLogs -->|JSON + status| CollectorMaster
    Drivers -->|JSON + status| CollectorMaster
    
    CollectorMaster -->|Aggregated data + summary| GUIMVP
    CollectorMaster -->|Aggregated data + summary| CLIMVP
    
    GUIMVP -->|Request processing optional| ProcessorsMVP
    CLIMVP -->|Request processing optional| ProcessorsMVP
    ProcessorsMVP -->|Processed data + validation| GUIMVP
    ProcessorsMVP -->|Processed data + validation| CLIMVP
    
    Hardware --> Logger
    System --> Logger
    Storage --> Logger
    Network --> Logger
    Processes --> Logger
    EventLogs --> Logger
    Drivers --> Logger
    CollectorMaster --> Logger
    ProcessorsMVP --> Logger
    
    classDef gui fill:#fff4a3,stroke:#333,stroke-width:2px
    classDef orchestrator fill:#ffcccc,stroke:#333,stroke-width:2px
    classDef processor fill:#ccffcc,stroke:#333,stroke-width:2px
    classDef collector fill:#cce5ff,stroke:#333,stroke-width:2px
    classDef logger fill:#f0f0f0,stroke:#333,stroke-width:1px,stroke-dasharray: 5 5
    
    class GUIMVP,CLIMVP gui
    class CollectorMaster orchestrator
    class ProcessorsMVP processor
    class Hardware,System,Storage,Network,Processes,EventLogs,Drivers collector
    class Logger logger
```

## Opis Flow

### 1. Full Scan Flow

1. **User** inicjuje skan przez GUI MVP
2. **GUI MVP** wysyła żądanie do Collector Master
3. **Collector Master** uruchamia wszystkie collectory równolegle
4. **Collectors** zbierają dane i zwracają w standardowym formacie
5. **Collector Master** agreguje dane i zwraca do GUI MVP
6. **GUI MVP** opcjonalnie wysyła dane do Processors MVP
7. **Processors MVP** waliduje i przetwarza dane
8. **GUI MVP** wyświetla wyniki użytkownikowi

### 2. Single Collector Flow

1. **User** wybiera pojedynczy collector w GUI MVP
2. **GUI MVP** bezpośrednio wywołuje collector (lub przez Collector Master)
3. **Collector** zwraca dane w standardowym formacie
4. **GUI MVP** wyświetla dane użytkownikowi

## Format Danych

### Collector Output Format

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

### Processor Output Format

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

## Zobacz też

- [MVP Architecture Documentation](MVP_ARCHITECTURE.md)
- [MVP Refactoring Plan](../MVP_REFACTORING_PLAN.md)

