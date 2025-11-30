"""
BSOD Analyzer - analizuje ostatni BSOD i identyfikuje najbardziej prawdopodobne przyczyny.
Używa nowego modułu correlation/bsod_correlation.py dla ulepszonej korelacji.
"""
import re
from collections import defaultdict
from datetime import datetime, timedelta

from utils.confidence_normalizer import (
    calculate_weighted_confidence,
    normalize_confidence,
)
from utils.event_deduplicator import deduplicate_events
from utils.logger import get_logger

# Inicjalizacja loggera
logger = get_logger()

# Import nowego modułu korelacji
try:
    from correlation.bsod_correlation import BSODCorrelator
    NEW_CORRELATION_AVAILABLE = True
except ImportError:
    NEW_CORRELATION_AVAILABLE = False
    logger.warning(
        "[BSOD_ANALYZER] New correlation module not available, using legacy method")

# Konfiguracja - BSOD Analysis 2.0
DEFAULT_TIME_WINDOW_MINUTES = 10  # Zmienione z 15 na 10 minut
PRIMARY_TIME_WINDOW_MINUTES = 3  # Primary window dla krytycznych zdarzeń
EXTENDED_TIME_WINDOW_MINUTES = 10  # Extended window (zmienione z 15 na 10)
MAX_TIME_WINDOW_MINUTES = 60

# Wagi kategorii eventów
CATEGORY_WEIGHTS = {
    "GPU_DRIVER": 50,
    "DISK_ERROR": 50,
    "MEMORY_ERROR": 40,
    "DRIVER_ERROR": 40,
    "SYSTEM_CRITICAL": 30,
    "TXR_FAILURE": 50,
    "SERVICE_FAILURE": 25,
    "OTHER": 10
}

# Słowa kluczowe dla różnych kategorii
KEYWORDS = {
    "GPU_DRIVER": [
        "dxgkrnl", "nvlddmkm", "atikmpag", "igdkmd64", "amdkmdap",
        "gpu", "graphics", "display", "video", "directx"
    ],
    "DISK_ERROR": [
        "disk", "volume", "volsnap", "ntfs", "file system",
        "i/o error", "read error", "write error", "bad block",
        "event id 51", "event id 55", "event id 57", "event id 7"
    ],
    "MEMORY_ERROR": [
        "memory management", "page fault", "memory", "ram",
        "event id 1001", "bugcheck", "stop error"
    ],
    "DRIVER_ERROR": [
        "driver", "failed to load", "driver error", "driver crash"
    ],
    "TXR_FAILURE": [
        "txr", "transaction", "registry", "0xc00000a2", "event id 8193"
    ],
    "SERVICE_FAILURE": [
        "service", "failed to start", "service error", "event id 7000",
        "event id 7001", "event id 7023", "event id 7024"
    ],
    "SYSTEM_CRITICAL": [
        "critical", "stop error", "system crash", "fatal error"
    ]
}

# Eventy do wykluczenia (informacyjne, rutynowe)
EXCLUDE_KEYWORDS = [
    "heartbeat", "scheduled task", "login", "logoff", "user logged",
    "windows update", "defender", "antivirus scan", "backup",
    "maintenance", "idle", "timeout", "connection established"
]


def extract_bugcheck_from_event(event):
    """Wyciąga bugcheck code z eventu (Event ID 1001 lub 41)."""
    message = event.get("message", "")
    event_id = str(event.get("event_id", ""))

    # Event ID 1001 zawiera bugcheck code
    if event_id == "1001" or "bugcheck" in message.lower():
        import re
        patterns = [
            r'BugCheck\s+([0-9A-Fa-f]+)',
            r'0x([0-9A-Fa-f]{8})',
            r'stop\s+code\s+([0-9A-Fa-f]+)',
            r'BugCheckCode:\s*([0-9A-Fa-f]+)'
        ]
        for pattern in patterns:
            match = re.search(pattern, message, re.IGNORECASE)
            if match:
                code = match.group(1)
                return f"0x{code.upper().zfill(8)}"

    # Event ID 41 może zawierać bugcheck code
    if event_id == "41":
        import re
        patterns = [
            r'BugCheckCode:\s*([0-9A-Fa-f]+)',
            r'0x([0-9A-Fa-f]{8})'
        ]
        for pattern in patterns:
            match = re.search(pattern, message, re.IGNORECASE)
            if match:
                code = match.group(1)
                return f"0x{code.upper().zfill(8)}"

    return None


def extract_bugcheck_parameters(event):
    """Wyciąga parametry bugcheck (Parameter1-4) z eventu."""
    message = event.get("message", "")
    params = {}

    import re
    for i in range(1, 5):
        pattern = rf'Parameter{i}:\s*([0-9A-Fa-f]+)'
        match = re.search(pattern, message, re.IGNORECASE)
        if match:
            params[f"Parameter{i}"] = f"0x{match.group(1).upper()}"

    return params if params else None


def extract_dump_file(event):
    """Wyciąga ścieżkę do pliku dump z eventu."""
    message = event.get("message", "")

    import re
    patterns = [
        r'DumpFile:\s*([^\s]+)',
        r'C:\\Windows\\[^\\]+\.dmp',
        r'C:\\Windows\\Minidump\\[^\\]+\.dmp'
    ]
    for pattern in patterns:
        match = re.search(pattern, message, re.IGNORECASE)
        if match:
            return match.group(1) if match.groups() else match.group(0)

    return None


def analyze_minidumps(bsod_data):
    """
    Analizuje minidump files jeśli dostępne.

    Returns:
        dict: Informacje o minidumpach
    """
    if not bsod_data or not isinstance(bsod_data, dict):
        return None

    minidumps = bsod_data.get("minidumps", [])
    if not minidumps:
        return None

    # Znajdź najnowszy minidump
    latest_dump = None
    latest_time = None

    for dump in minidumps:
        modified = dump.get("modified", "")
        if modified:
            try:
                from datetime import datetime
                dump_time = datetime.fromisoformat(
                    modified.replace('Z', '+00:00'))
                if latest_time is None or dump_time > latest_time:
                    latest_time = dump_time
                    latest_dump = dump
            except BaseException:
                pass

    if latest_dump:
        return {
            "path": latest_dump.get("path", ""),
            "size": latest_dump.get("size", 0),
            "modified": latest_dump.get("modified", ""),
            "type": latest_dump.get("type", "MINIDUMP"),
            "note": "Minidump file found - detailed analysis requires WinDbg or similar tools"
        }

    return None


def analyze_bsod(
        system_logs_data,
        hardware_data,
        drivers_data,
        bsod_data=None,
        time_window_minutes=DEFAULT_TIME_WINDOW_MINUTES,
        use_new_correlation=False):
    """
    Analizuje ostatni BSOD i identyfikuje najbardziej prawdopodobne przyczyny.

    Args:
        system_logs_data (dict): Przetworzone logi systemowe
        hardware_data (dict): Dane sprzętowe (CPU, RAM, GPU, disks)
        drivers_data (list): Lista driverów z informacjami
        bsod_data (dict, optional): Dane z bsod_dumps collector
        time_window_minutes (int): Okno czasowe do analizy przed BSOD (domyślnie 15 min)
        use_new_correlation (bool): Jeśli True, używa nowego modułu correlation (domyślnie False)

    Returns:
        dict: Strukturyzowana analiza BSOD z confidence scores i rekomendacjami
    """
    logger = get_logger()
    logger.debug("[BSOD] Starting BSOD analysis")

    # Jeśli dostępny nowy moduł korelacji i użytkownik chce go użyć
    if use_new_correlation and NEW_CORRELATION_AVAILABLE:
        logger.info("[BSOD] Using new correlation module")
        try:
            correlator = BSODCorrelator(
                time_window_minutes=time_window_minutes)
            new_result = correlator.analyze_bsod()

            if new_result.get('bsod_found'):
                # Konwertuj wynik do formatu kompatybilnego z istniejącym kodem
                return _convert_new_correlation_result(
                    new_result, hardware_data, drivers_data)
            else:
                return {
                    "bsod_found": False,
                    "message": new_result.get('message', 'No BSOD found'),
                    "related_events": [],
                    "top_causes": [],
                    "recommendations": []
                }
        except Exception as e:
            logger.error(f"[BSOD] Error using new correlation module: {e}")
            logger.info("[BSOD] Falling back to legacy method")
            # Fallback do starej metody - kontynuuj poniżej

    result = {
        "bsod_found": False,
        "last_bsod_timestamp": None,
        "related_events": [],
        "top_causes": [],
        "recommendations": [],
        "hardware_correlations": [],
        "driver_correlations": []
    }

    # 1. Znajdź ostatni BSOD i wyciągnij bugcheck code
    last_bsod = find_last_bsod(system_logs_data, bsod_data)

    if not last_bsod:
        logger.info("[BSOD] No BSOD events found in logs")
        result["message"] = "No BSOD events found in logs"
        return result

    logger.info(
        f"[BSOD] BSOD found: Event ID {last_bsod.get('event_id', 'N/A')}, Timestamp: {last_bsod.get('timestamp', 'N/A')}")

    # Wyciągnij bugcheck code z Event 1001 lub 41
    bugcheck_code = extract_bugcheck_from_event(last_bsod)
    bugcheck_params = extract_bugcheck_parameters(last_bsod)
    dump_file = extract_dump_file(last_bsod)

    # Analizuj minidump files jeśli dostępne
    minidump_info = analyze_minidumps(bsod_data)

    # Sprawdź WHEA errors (hardware failures)
    whea_errors = bsod_data.get("whea_errors", []) if bsod_data else []
    has_whea_errors = len(whea_errors) > 0

    if has_whea_errors:
        logger.warning(
            f"[BSOD] Found {len(whea_errors)} WHEA hardware errors - indicating HARDWARE_FAILURE")

    result["bsod_found"] = True
    result["last_bsod_timestamp"] = last_bsod["timestamp"]
    result["bsod_details"] = {
        "event_id": last_bsod.get("event_id", "N/A"),
        "message": last_bsod.get("message", "")[:500],
        "level": last_bsod.get("level", "Critical"),
        "bugcheck_code": bugcheck_code,
        "bugcheck_parameters": bugcheck_params,
        "dump_file": dump_file,
        "minidump_info": minidump_info,
        "whea_errors": whea_errors,
        "has_hardware_failure": has_whea_errors
    }

    # 2. Parsuj timestamp BSOD
    bsod_time = parse_timestamp(last_bsod["timestamp"])
    if not bsod_time:
        result["message"] = "Could not parse BSOD timestamp"
        return result

    # 3. BSOD Analysis 2.0 - użyj primary i extended window
    primary_window = timedelta(minutes=PRIMARY_TIME_WINDOW_MINUTES)
    extended_window = timedelta(minutes=EXTENDED_TIME_WINDOW_MINUTES)

    primary_start = bsod_time - primary_window
    extended_start = bsod_time - extended_window

    logger.debug(
        f"[BSOD] Primary window: {primary_start} to {bsod_time} ({PRIMARY_TIME_WINDOW_MINUTES} minutes)")
    logger.debug(
        f"[BSOD] Extended window: {extended_start} to {bsod_time} ({EXTENDED_TIME_WINDOW_MINUTES} minutes)")

    # Zbierz wszystkie eventy z logów
    all_events = collect_all_events(system_logs_data)
    logger.debug(f"[BSOD] Collected {len(all_events)} total events from logs")

    # Filtruj eventy w primary window (krytyczne)
    primary_events = filter_events_by_time(
        all_events, primary_start, bsod_time)
    logger.info(
        f"[BSOD] Found {len(primary_events)} events in primary window ({PRIMARY_TIME_WINDOW_MINUTES} min)")

    # Filtruj eventy w extended window
    extended_events = filter_events_by_time(
        all_events, extended_start, bsod_time)
    logger.info(
        f"[BSOD] Found {len(extended_events)} events in extended window ({EXTENDED_TIME_WINDOW_MINUTES} min)")

    # Użyj extended events do analizy, ale priorytetyzuj primary events
    candidate_events = extended_events
    for event in primary_events:
        event['in_primary_window'] = True

    # 4. De-duplikuj eventy przed kategoryzacją
    logger.debug(
        f"[BSOD] Deduplicating {len(candidate_events)} candidate events")
    candidate_events = deduplicate_events(candidate_events)
    logger.info(
        f"[BSOD] After deduplication: {len(candidate_events)} unique events")

    # 5. Kategoryzuj i oblicz confidence scores
    categorized_events = categorize_events(candidate_events)
    scored_events = calculate_confidence_scores(
        categorized_events, bsod_time, time_window_minutes
    )

    # Normalizuj confidence scores do zakresu 0-100
    logger.debug("[BSOD] Normalizing confidence scores")
    for event in scored_events:
        if 'confidence_score' in event:
            original_score = event['confidence_score']
            normalized = normalize_confidence(original_score)
            event['confidence_score'] = normalized
            event['confidence_score_original'] = original_score
            logger.debug(
                f"[BSOD] Normalized confidence: {original_score} -> {normalized}")

    # 6. Koreluj z hardware i driver info
    logger.debug("[BSOD] Correlating with hardware and drivers")
    hardware_correlations = correlate_with_hardware(
        scored_events, hardware_data)
    driver_correlations = correlate_with_drivers(scored_events, drivers_data)
    logger.debug(
        f"[BSOD] Found {len(hardware_correlations)} hardware correlations, {len(driver_correlations)} driver correlations")

    # 7. Oblicz top causes (kumulatywny confidence) - z obsługą WHEA
    logger.debug("[BSOD] Calculating top causes")
    top_causes = calculate_top_causes(
        scored_events,
        hardware_correlations,
        driver_correlations,
        has_whea_errors,
        whea_errors)

    # Normalizuj confidence w top_causes
    for cause in top_causes:
        if 'confidence' in cause:
            original_confidence = cause['confidence']
            normalized = normalize_confidence(original_confidence)
            cause['confidence'] = normalized
            cause['confidence_original'] = original_confidence
            logger.debug(
                f"[BSOD] Normalized cause confidence: {original_confidence} -> {normalized}")

    # Jeśli brak top_causes, dodaj ogólne przyczyny na podstawie samego BSOD
    if not top_causes:
        # Event ID 41 (Unexpected shutdown) może mieć różne przyczyny
        bsod_event_id = result.get("bsod_details", {}).get("event_id", "")
        if bsod_event_id == "41":
            top_causes = [{"cause": "SYSTEM_CRITICAL",
                           "confidence": 60.0,
                           "related_events_count": 1,
                           "description": "Unexpected system shutdown - possible hardware failure, power loss, or critical system error"},
                          {"cause": "HARDWARE_FAILURE",
                           "confidence": 40.0,
                           "related_events_count": 0,
                           "description": "Hardware component failure (PSU, motherboard, RAM)"},
                          {"cause": "DRIVER_ERROR",
                           "confidence": 30.0,
                           "related_events_count": 0,
                           "description": "Driver crash or incompatibility"}]

    # 8. Generuj rekomendacje
    logger.debug("[BSOD] Generating recommendations")
    recommendations = generate_bsod_recommendations(
        top_causes, hardware_correlations, driver_correlations, scored_events
    )
    logger.debug(f"[BSOD] Generated {len(recommendations)} recommendations")

    # Jeśli brak rekomendacji, dodaj ogólne
    if not recommendations:
        recommendations = [{"priority": "CRITICAL",
                            "action": "Check minidump files in C:\\Windows\\Minidump",
                            "description": "Analyze crash dumps for specific error codes",
                            "confidence": 50},
                           {"priority": "HIGH",
                            "action": "Run Windows Memory Diagnostic",
                            "description": "Check for RAM issues",
                            "confidence": 40},
                           {"priority": "HIGH",
                            "action": "Check Event Viewer for errors before shutdown",
                            "description": "Review system logs for clues",
                            "confidence": 40},
                           {"priority": "MEDIUM",
                            "action": "Check power supply and connections",
                            "description": "Unexpected shutdowns can indicate power issues",
                            "confidence": 30}]

    # Sortuj eventy według confidence (najwyższe pierwsze)
    scored_events.sort(
        key=lambda x: x.get(
            "confidence_score",
            0),
        reverse=True)

    result["related_events"] = scored_events[:20]  # Top 20 eventów
    result["top_causes"] = top_causes[:5]  # Top 5 przyczyn
    result["recommendations"] = recommendations
    result["hardware_correlations"] = hardware_correlations
    result["driver_correlations"] = driver_correlations
    result["analysis_window"] = {
        "primary_start": primary_start.isoformat(),
        "extended_start": extended_start.isoformat(),
        "end": bsod_time.isoformat(),
        "primary_minutes": PRIMARY_TIME_WINDOW_MINUTES,
        "extended_minutes": EXTENDED_TIME_WINDOW_MINUTES
    }

    logger.info(
        f"[BSOD] Analysis complete: {len(result['related_events'])} related events, "
        f"{len(result['top_causes'])} top causes, {len(result['recommendations'])} recommendations")

    return result


def find_last_bsod(system_logs_data, bsod_data=None):
    """
    Znajduje ostatni BSOD w logach.

    Returns:
        dict: Ostatni BSOD event lub None
    """
    bsod_keywords = ["bugcheck", "stop error", "bsod", "blue screen",
                     "system crash", "unexpected shutdown"]

    all_bsod_events = []

    # Sprawdź system_logs_data
    if isinstance(system_logs_data, dict):
        for category, logs in system_logs_data.items():
            if isinstance(logs, list):
                for log in logs:
                    if isinstance(log, dict):
                        message = log.get("message", "").lower()
                        level = log.get("level", "").lower()
                        event_id = str(log.get("event_id", "")).lower()

                        # Sprawdź czy to BSOD
                        is_bsod = (
                            any(keyword in message for keyword in bsod_keywords)
                            or level in ["critical", "error"] and (
                                "1001" in event_id or "41" in event_id
                                or "6008" in event_id
                            )
                        )

                        if is_bsod:
                            all_bsod_events.append(log)

    # Sprawdź bsod_data jeśli dostępne
    if bsod_data and isinstance(bsod_data, dict):
        recent_crashes = bsod_data.get("recent_crashes", [])
        if recent_crashes:
            for crash in recent_crashes:
                if isinstance(crash, dict):
                    all_bsod_events.append({
                        "timestamp": crash.get("timestamp", ""),
                        "message": crash.get("message", "BSOD detected"),
                        "event_id": crash.get("event_id", "N/A"),
                        "level": "Critical"
                    })

    if not all_bsod_events:
        return None

    # Sortuj według timestamp (najnowsze pierwsze)
    all_bsod_events.sort(
        key=lambda x: parse_timestamp(x.get("timestamp", "")) or datetime.min,
        reverse=True
    )

    return all_bsod_events[0] if all_bsod_events else None


def collect_all_events(system_logs_data):
    """
    Zbiera wszystkie eventy z logów systemowych.

    Returns:
        list: Lista wszystkich eventów
    """
    logger = get_logger()
    all_events = []

    if isinstance(system_logs_data, dict):
        for category, logs in system_logs_data.items():
            if isinstance(logs, list):
                category_events = 0
                for log in logs:
                    if isinstance(log, dict):
                        # Pomiń błędy parsowania
                        if "error" in log:
                            logger.debug(
                                f"[BSOD] Skipping error entry in {category}: {log.get('error', 'N/A')}")
                            continue
                        all_events.append(log)
                        category_events += 1
                logger.debug(
                    f"[BSOD] Collected {category_events} events from {category} log")
            else:
                logger.warning(
                    f"[BSOD] {category} logs is not a list: {type(logs)}")
    else:
        logger.warning(
            f"[BSOD] system_logs_data is not a dict: {type(system_logs_data)}")

    logger.debug(f"[BSOD] Total events collected: {len(all_events)}")
    return all_events


def filter_events_by_time(events, window_start, window_end):
    """
    Filtruje eventy w oknie czasowym i wyklucza nieistotne.

    Args:
        events (list): Lista eventów
        window_start (datetime): Początek okna czasowego
        window_end (datetime): Koniec okna czasowego (BSOD time)

    Returns:
        list: Przefiltrowane eventy
    """
    filtered = []

    for event in events:
        # Pomiń jeśli brak timestamp
        event_time = parse_timestamp(event.get("timestamp", ""))
        if not event_time:
            continue

        # Sprawdź czy w oknie czasowym
        if window_start <= event_time <= window_end:
            # Wyklucz rutynowe/informacyjne eventy
            message = event.get("message", "").lower()
            if not should_exclude_event(message):
                filtered.append(event)

    return filtered


def should_exclude_event(message):
    """
    Sprawdza czy event powinien być wykluczony (rutynowy/informacyjny).
    Filtruje heartbeat, login/logout, Windows Update, backup, scheduled tasks, itp.

    Returns:
        bool: True jeśli wykluczyć, False jeśli uwzględnić
    """
    message_lower = message.lower()

    # Rozszerzona lista słów kluczowych do wykluczenia
    exclude_patterns = [
        # Heartbeat i rutynowe operacje
        "heartbeat", "health check", "status check",
        # Logowanie użytkowników
        "user logged on", "user logged off", "logon", "logoff", "login", "logout",
        "account logged on", "account logged off", "session", "authentication",
        # Windows Update
        "windows update", "update installed", "update downloaded", "wuauclt",
        # Backup i VSS
        "backup completed", "backup started", "backup finished", "vss", "shadow copy",
        # Scheduled tasks
        "task scheduler", "scheduled task", "task completed", "task started",
        # Rutynowe usługi
        "service started", "service stopped", "service is running", "service control",
        # Network rutynowe
        "dhcp", "dns query", "network adapter", "ip address assigned",
        # System rutynowe
        "system time", "time synchronization", "ntp", "time service",
        # Informacyjne
        "information", "informacje", "successful", "completed successfully",
        # Rutynowe operacje dysku
        "disk cleanup", "defrag", "disk check completed", "chkdsk completed",
    ]

    # Sprawdź czy zawiera słowa kluczowe do wykluczenia
    for pattern in exclude_patterns:
        if pattern in message_lower:
            return True

    # Sprawdź czy to tylko informacyjny event bez błędów
    if "error" not in message_lower and "fail" not in message_lower and "critical" not in message_lower:
        # Jeśli nie zawiera słów kluczowych błędów, sprawdź czy to rutynowy
        # event
        routine_keywords = [
            "started",
            "stopped",
            "completed",
            "initialized",
            "loaded"]
        if any(keyword in message_lower for keyword in routine_keywords):
            # Jeśli zawiera tylko rutynowe słowa, wyklucz
            if not any(keyword in message_lower for keyword in [
                       "error", "fail", "warn", "critical", "crash", "bsod"]):
                return True

    return False


def categorize_events(events):
    """
    Kategoryzuje eventy według typu problemu.

    Returns:
        list: Eventy z dodaną kategorią
    """
    categorized = []

    for event in events:
        message = event.get("message", "").lower()
        event_id = str(event.get("event_id", "")).lower()
        level = event.get("level", "").lower()

        category = "OTHER"

        # Sprawdź każdą kategorię
        for cat_name, keywords in KEYWORDS.items():
            if any(
                    keyword in message or keyword in event_id for keyword in keywords):
                category = cat_name
                break

        event["detected_category"] = category
        categorized.append(event)

    return categorized


def calculate_confidence_scores(events, bsod_time, time_window_minutes):
    """
    Oblicza confidence scores dla każdego eventu.

    Args:
        events (list): Kategoryzowane eventy
        bsod_time (datetime): Czas BSOD
        time_window_minutes (int): Okno czasowe w minutach

    Returns:
        list: Eventy z confidence scores
    """
    scored_events = []

    # Policz powtórzenia kategorii
    category_counts = defaultdict(int)
    for event in events:
        category = event.get("detected_category", "OTHER")
        category_counts[category] += 1

    for event in events:
        category = event.get("detected_category", "OTHER")
        base_score = CATEGORY_WEIGHTS.get(category, 10)

        # Zwiększ score jeśli kategoria się powtarza
        if category_counts[category] > 1:
            base_score *= 1.2  # +20% za powtórzenia

        # Oblicz czas od BSOD
        event_time = parse_timestamp(event.get("timestamp", ""))
        if event_time:
            time_diff = (bsod_time - event_time).total_seconds() / 60  # minuty

            # Zmniejsz score jeśli event jest daleko od BSOD
            if time_diff > 30:
                base_score *= 0.7  # -30% jeśli >30 min
            elif time_diff > 15:
                base_score *= 0.85  # -15% jeśli >15 min

        # Normalizuj do 0-100%
        confidence = min(100.0, base_score)

        event["confidence_score"] = round(confidence, 2)
        event["time_from_bsod_minutes"] = round(
            time_diff, 2) if event_time else None
        scored_events.append(event)

    return scored_events


def correlate_with_hardware(scored_events, hardware_data):
    """
    Koreluje eventy z danymi sprzętowymi.

    Returns:
        list: Korelacje hardware
    """
    correlations = []

    if not isinstance(hardware_data, dict):
        return correlations

    # Sprawdź GPU
    gpu_issues = []
    gpu_data = hardware_data.get("gpu", [])
    if gpu_data:
        for gpu in gpu_data:
            if isinstance(gpu, dict):
                temp = gpu.get("temperature", 0)
                if temp > 85:  # Wysoka temperatura GPU
                    gpu_issues.append(f"GPU temperature high: {temp}°C")

    # Sprawdź CPU
    cpu_issues = []
    cpu_data = hardware_data.get("cpu", {})
    if isinstance(cpu_data, dict):
        usage = cpu_data.get("usage_percent", 0)
        if usage > 95:
            cpu_issues.append(f"CPU usage very high: {usage}%")

    # Sprawdź RAM
    ram_issues = []
    ram_data = hardware_data.get("ram", {})
    if isinstance(ram_data, dict):
        percent = ram_data.get("percent", 0)
        if percent > 95:
            ram_issues.append(f"RAM usage very high: {percent}%")

    # Sprawdź dyski
    disk_issues = []
    disks_data = hardware_data.get("disks", [])
    if disks_data:
        for disk in disks_data:
            if isinstance(disk, dict):
                status = disk.get("status") or ""
                if status and isinstance(status, str):
                    status = status.lower()
                    if "fail" in status or "error" in status:
                        disk_issues.append(
                            f"Disk {disk.get('device', 'unknown')} status: {status}")

    # Znajdź eventy związane z hardware
    for event in scored_events:
        category = event.get("detected_category", "")
        message = event.get("message", "").lower()

        if category == "GPU_DRIVER" and gpu_issues:
            correlations.append({
                "event": event.get("event_id", "N/A"),
                "hardware_issue": gpu_issues[0],
                "correlation_type": "GPU"
            })

        if category == "DISK_ERROR" and disk_issues:
            correlations.append({
                "event": event.get("event_id", "N/A"),
                "hardware_issue": disk_issues[0],
                "correlation_type": "DISK"
            })

    return correlations


def correlate_with_drivers(scored_events, drivers_data):
    """
    Koreluje eventy z informacjami o driverach.

    Returns:
        list: Korelacje driverów
    """
    correlations = []

    if not isinstance(drivers_data, list):
        return correlations

    # Stwórz słownik driverów po nazwie
    drivers_dict = {}
    for driver in drivers_data:
        if isinstance(driver, dict):
            name = driver.get("name", "").lower()
            drivers_dict[name] = driver

    # Sprawdź eventy związane z driverami
    for event in scored_events:
        category = event.get("detected_category", "")
        message = event.get("message", "").lower()

        if category in ["GPU_DRIVER", "DRIVER_ERROR"]:
            # Znajdź driver w wiadomości
            for driver_name, driver_info in drivers_dict.items():
                if driver_name in message:
                    driver_status = driver_info.get("status", "").lower()
                    driver_version = driver_info.get("version", "unknown")

                    correlations.append({
                        "event": event.get("event_id", "N/A"),
                        "driver_name": driver_name,
                        "driver_status": driver_status,
                        "driver_version": driver_version,
                        "correlation_type": "DRIVER",
                        "is_problematic": "fail" in driver_status or "error" in driver_status
                    })
                    break

    return correlations


def calculate_top_causes(
        scored_events,
        hardware_correlations,
        driver_correlations,
        has_whea_errors=False,
        whea_errors=None):
    """
    Oblicza top causes na podstawie kumulatywnego confidence.
    Priorytety: WHEA > BugCheck > Kernel-Power > Disk > Driver

    Args:
        scored_events (list): Eventy z confidence scores
        hardware_correlations (list): Korelacje hardware
        driver_correlations (list): Korelacje driverów
        has_whea_errors (bool): Czy występują WHEA errors
        whea_errors (list): Lista WHEA errors

    Returns:
        list: Top causes z kumulatywnym confidence
    """
    logger = get_logger()  # Pobierz logger
    cause_scores = defaultdict(float)
    cause_details = defaultdict(list)

    # WHEA errors mają najwyższy priorytet - HARDWARE_FAILURE z high confidence
    if has_whea_errors and whea_errors:
        cause_scores["HARDWARE_FAILURE"] = 95.0  # Wysoki confidence dla WHEA
        cause_details["HARDWARE_FAILURE"] = whea_errors
        logger.warning(
            "[BSOD] WHEA errors detected - marking as HARDWARE_FAILURE with high confidence")

    # Zbierz scores według kategorii
    for event in scored_events:
        category = event.get("detected_category", "OTHER")
        confidence = event.get("confidence_score", 0)

        # Priorytetyzacja kategorii
        if category == "GPU_DRIVER":
            confidence *= 1.1  # +10%
        elif category == "DISK_ERROR":
            confidence *= 1.05  # +5%
        elif category == "DRIVER_ERROR":
            confidence *= 1.0  # Bez zmian

        cause_scores[category] += confidence
        cause_details[category].append(event)

    # Zwiększ score jeśli są korelacje hardware/driver
    for corr in hardware_correlations:
        corr_type = corr.get("correlation_type", "")
        if corr_type == "GPU":
            cause_scores["GPU_DRIVER"] += 15
        elif corr_type == "DISK":
            cause_scores["DISK_ERROR"] += 15

    for corr in driver_correlations:
        if corr.get("is_problematic", False):
            cause_scores["DRIVER_ERROR"] += 10

    # Normalizuj i sortuj
    top_causes = []
    for cause, total_score in cause_scores.items():
        # Normalizuj do 0-100%
        normalized_score = min(100.0, total_score)

        top_causes.append({
            "cause": cause,
            "confidence": round(normalized_score, 2),
            "related_events_count": len(cause_details.get(cause, [])),
            "description": get_cause_description(cause)
        })

    # Sortuj według priorytetów: WHEA > BugCheck > Kernel-Power > Disk > Driver
    priority_order = {
        "HARDWARE_FAILURE": 0,
        "GPU_DRIVER": 1,
        "DISK_ERROR": 2,
        "DRIVER_ERROR": 3,
        "MEMORY_ERROR": 4,
        "TXR_FAILURE": 5,
        "SERVICE_FAILURE": 6,
        "SYSTEM_CRITICAL": 7,
        "OTHER": 8
    }

    top_causes.sort(key=lambda x: (
        priority_order.get(x["cause"], 99),
        -x["confidence"]  # Wewnątrz tej samej kategorii sortuj po confidence
    ))

    return top_causes


def get_cause_description(cause):
    """Zwraca opis przyczyny."""
    descriptions = {
        "HARDWARE_FAILURE": "Hardware component failure detected by WHEA-Logger (EventID 18, 19, 20) - high confidence",
        "GPU_DRIVER": "Graphics driver issue or GPU hardware problem",
        "DISK_ERROR": "Disk I/O error, bad sectors, or storage controller issue",
        "MEMORY_ERROR": "RAM problem or memory management issue",
        "DRIVER_ERROR": "Driver failure or incompatibility",
        "TXR_FAILURE": "Registry transaction failure, possible disk corruption",
        "SERVICE_FAILURE": "Critical system service failure",
        "SYSTEM_CRITICAL": "Critical system error",
        "OTHER": "Other system issue"}
    return descriptions.get(cause, "Unknown issue")


def _get_cause_description(cause):
    """Zwraca opis przyczyny."""
    descriptions = {
        "GPU_DRIVER": "GPU driver issue - graphics driver crash or error",
        "DISK_ERROR": "Disk I/O error - storage device failure or corruption",
        "MEMORY_ERROR": "Memory management issue - RAM problems or page faults",
        "DRIVER_ERROR": "Driver failure - device driver failed to load or crashed",
        "TXR_FAILURE": "Registry transaction failure - system file corruption",
        "SERVICE_FAILURE": "Service failure - critical Windows service failed",
        "SYSTEM_CRITICAL": "Critical system error - fatal system error",
        "KERNEL_CRASH": "Kernel crash - system kernel error",
        "OTHER": "Other system issue"}
    return descriptions.get(cause, "Unknown issue")


def _convert_new_correlation_result(new_result, hardware_data, drivers_data):
    """
    Konwertuje wynik z nowego modułu korelacji do formatu kompatybilnego z istniejącym kodem.

    Args:
        new_result (dict): Wynik z BSODCorrelator.analyze_bsod()
        hardware_data (dict): Dane sprzętowe
        drivers_data (list): Dane driverów

    Returns:
        dict: Wynik w formacie kompatybilnym z analyze_bsod()
    """
    logger = get_logger()
    logger.debug("[BSOD] Converting new correlation result to legacy format")

    correlated_events = new_result.get('correlated_events', [])

    # Konwertuj correlated_events do formatu related_events
    related_events = []
    for event in correlated_events:
        related_events.append(
            {
                'timestamp': event.get('timestamp'),
                'level': event.get('level'),
                'event_id': event.get('event_id'),
                'message': event.get('message'),
                'category': event.get('category'),
                'confidence_score': event.get(
                    'correlation_score',
                    0),
                'time_from_bsod_minutes': event.get(
                    'time_from_bsod_seconds',
                    0) /
                60.0 if event.get('time_from_bsod_seconds') else None})

    # Oblicz top causes na podstawie kategorii i scores
    category_scores = defaultdict(float)
    for event in correlated_events:
        category = event.get('category', 'OTHER')
        score = event.get('correlation_score', 0)
        category_scores[category] += score

    # Sortuj kategorie po score
    sorted_categories = sorted(
        category_scores.items(),
        key=lambda x: x[1],
        reverse=True)

    top_causes = []
    for category, total_score in sorted_categories[:5]:  # Top 5
        top_causes.append({
            'cause': category,
            'confidence': min(100.0, total_score),
            'description': _get_cause_description(category)
        })

    # Generuj rekomendacje
    recommendations = generate_bsod_recommendations(
        top_causes,
        [],  # hardware_correlations
        [],  # driver_correlations
        related_events
    )

    # Parsuj timestamp BSOD
    bsod_timestamp_str = new_result.get('bsod_timestamp')
    bsod_timestamp = None
    if bsod_timestamp_str:
        try:
            # Próbuj parsować ISO format
            bsod_timestamp = datetime.fromisoformat(
                bsod_timestamp_str.replace('Z', '+00:00'))
        except Exception as e:
            logger.debug(
                f"[BSOD_ANALYZER] Error parsing timestamp: {e}")
            try:
                # Fallback - użyj istniejącej funkcji parse_timestamp
                bsod_timestamp = parse_timestamp(bsod_timestamp_str)
            except Exception as e2:
                logger.debug(
                    f"[BSOD_ANALYZER] Fallback timestamp parse failed: {e2}")

    return {
        "bsod_found": True,
        "last_bsod_timestamp": bsod_timestamp.isoformat() if bsod_timestamp else bsod_timestamp_str,
        "bsod_details": new_result.get(
            'bsod_details',
            {}),
        "related_events": related_events,
        "top_causes": top_causes,
        "recommendations": recommendations,
        "hardware_correlations": [],
        "driver_correlations": []}


def generate_bsod_recommendations(
        top_causes, hardware_correlations, driver_correlations, scored_events):
    """
    Generuje rekomendacje na podstawie analizy.

    Returns:
        list: Lista rekomendacji z priorytetami
    """
    recommendations = []
    seen_actions = set()

    # Rekomendacje na podstawie top causes
    for cause in top_causes[:3]:  # Top 3 causes
        cause_type = cause.get("cause", "")
        confidence = cause.get("confidence", 0)

        if cause_type == "GPU_DRIVER":
            if "Update GPU drivers" not in seen_actions:
                recommendations.append({
                    "priority": "CRITICAL" if confidence > 70 else "HIGH",
                    "action": "Update GPU drivers to latest version",
                    "description": "GPU driver issues are a common cause of BSODs",
                    "confidence": confidence
                })
                seen_actions.add("Update GPU drivers")

            if "Check GPU temperature" not in seen_actions:
                recommendations.append({
                    "priority": "HIGH",
                    "action": "Check GPU temperature and cooling",
                    "description": "Overheating can cause GPU driver crashes",
                    "confidence": confidence
                })
                seen_actions.add("Check GPU temperature")

        elif cause_type == "DISK_ERROR":
            if "Run chkdsk" not in seen_actions:
                recommendations.append({
                    "priority": "CRITICAL" if confidence > 70 else "HIGH",
                    "action": "Run chkdsk /f /r on affected drive",
                    "description": "Disk errors can cause system crashes",
                    "confidence": confidence
                })
                seen_actions.add("Run chkdsk")

            if "Check SMART status" not in seen_actions:
                recommendations.append({
                    "priority": "HIGH",
                    "action": "Check disk SMART status",
                    "description": "SMART errors indicate physical disk failure",
                    "confidence": confidence
                })
                seen_actions.add("Check SMART status")

        elif cause_type == "MEMORY_ERROR":
            if "Run memory diagnostic" not in seen_actions:
                recommendations.append({
                    "priority": "CRITICAL" if confidence > 70 else "HIGH",
                    "action": "Run Windows Memory Diagnostic",
                    "description": "Memory errors can cause BSODs",
                    "confidence": confidence
                })
                seen_actions.add("Run memory diagnostic")

        elif cause_type == "TXR_FAILURE":
            if "Run DISM" not in seen_actions:
                recommendations.append({
                    "priority": "CRITICAL",
                    "action": "Run DISM /Online /Cleanup-Image /RestoreHealth",
                    "description": "TxR failures indicate system file corruption",
                    "confidence": confidence
                })
                seen_actions.add("Run DISM")

            if "Run sfc" not in seen_actions:
                recommendations.append({
                    "priority": "HIGH",
                    "action": "Run sfc /scannow",
                    "description": "Scan and repair system files",
                    "confidence": confidence
                })
                seen_actions.add("Run sfc")

    # Dodaj ogólne rekomendacje
    if "Check minidump files" not in seen_actions:
        recommendations.append({
            "priority": "MEDIUM",
            "action": "Check minidump files in C:\\Windows\\Minidump",
            "description": "Analyze crash dumps for specific error codes",
            "confidence": 50
        })
        seen_actions.add("Check minidump files")

    # Sortuj według priorytetu
    priority_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    recommendations.sort(
        key=lambda x: priority_order.get(
            x.get(
                "priority",
                "MEDIUM"),
            99))

    return recommendations


def parse_timestamp(timestamp_str):
    """
    Parsuje timestamp z różnych formatów do datetime.

    Returns:
        datetime: Parsed timestamp lub None
    """
    if not timestamp_str:
        return None

    # Różne formaty timestampów
    formats = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y/%m/%d %H:%M:%S",
        "%m/%d/%Y %I:%M:%S %p",  # 11/29/2025 10:04:12 AM
        "%m/%d/%Y %H:%M:%S",     # 11/29/2025 10:04:12
        "%d/%m/%Y %H:%M:%S",     # 29/11/2025 10:04:12
        "%d.%m.%Y %H:%M:%S",     # 29.11.2025 10:04:12
    ]

    # Wyczyść timestamp
    timestamp_clean = timestamp_str.strip()

    # Usuń milisekundy jeśli są
    if '.' in timestamp_clean and len(timestamp_clean.split('.')) > 2:
        # Tylko jeśli to milisekundy, nie część daty
        parts = timestamp_clean.split('.')
        if len(parts[-1]) <= 3 and parts[-1].isdigit():
            timestamp_clean = '.'.join(parts[:-1])

    # Usuń 'Z' jeśli jest
    timestamp_clean = timestamp_clean.replace('Z', '')

    for fmt in formats:
        try:
            return datetime.strptime(timestamp_clean, fmt)
        except (ValueError, TypeError):
            continue

    # Próbuj parsować format z AM/PM (11/29/2025 10:04:12 AM)
    try:
        # Sprawdź czy zawiera AM/PM
        has_ampm = " AM" in timestamp_str or " PM" in timestamp_str
        if has_ampm:
            # Format: MM/DD/YYYY HH:MM:SS AM/PM
            # Próbuj bezpośrednio z AM/PM
            try:
                return datetime.strptime(
                    timestamp_str.strip(), "%m/%d/%Y %I:%M:%S %p")
            except ValueError:
                # Spróbuj bez AM/PM i dodaj godzinę
                timestamp_no_ampm = timestamp_str.replace(
                    " AM", "").replace(" PM", "").strip()
                parts = timestamp_no_ampm.split()
                if len(parts) >= 2:
                    date_part = parts[0]  # MM/DD/YYYY
                    time_part = parts[1]  # HH:MM:SS
                    # Konwertuj 12h na 24h jeśli potrzeba
                    time_obj = datetime.strptime(time_part, "%H:%M:%S").time()
                    # Jeśli było PM i godzina < 12, dodaj 12
                    if " PM" in timestamp_str and time_obj.hour < 12:
                        time_obj = time_obj.replace(hour=time_obj.hour + 12)
                    elif " AM" in timestamp_str and time_obj.hour == 12:
                        time_obj = time_obj.replace(hour=0)
                    return datetime.strptime(
                        f"{date_part} {time_obj.strftime('%H:%M:%S')}",
                        "%m/%d/%Y %H:%M:%S")
    except (ValueError, IndexError, AttributeError, TypeError) as e:
        logger = get_logger()
        logger.debug(
            f"[BSOD] Failed to parse AM/PM timestamp '{timestamp_str}': {e}")
        pass

    # Ostateczny fallback - próbuj podstawowe parsowanie
    try:
        # Usuń wszystko po spacji jeśli jest
        parts = timestamp_str.split()
        if parts:
            date_part = parts[0]
            time_part = parts[1] if len(parts) > 1 else "00:00:00"
            combined = f"{date_part} {time_part}"
            return datetime.strptime(combined, "%Y-%m-%d %H:%M:%S")
    except Exception as e:
        logger.error(
            f"[BSOD_ANALYZER] Error parsing timestamp: {e}",
            exc_info=True)

    return None


def generate_bsod_event_timeline(related_events, top_causes, max_events=30):
    """
    Generuje chronologiczną oś czasu eventów poprzedzających BSOD.
    Wyklucza eventy które nie miały wpływu na BSOD (niskie confidence, nieistotne kategorie).

    Args:
        related_events (list): Lista powiązanych eventów z confidence scores
        top_causes (list): Top przyczyny BSOD
        max_events (int): Maksymalna liczba eventów do timeline

    Returns:
        list: Chronologiczna lista eventów z opisami
    """
    if not related_events:
        return []

    # Pobierz top kategorie z top_causes (najbardziej prawdopodobne przyczyny)
    relevant_categories = set()
    for cause in top_causes[:3]:  # Top 3 przyczyny
        cause_name = cause.get("cause", "")
        if cause_name:
            relevant_categories.add(cause_name)

    # Filtruj eventy:
    # 1. Wyklucz eventy z confidence < 10% (za niskie)
    # 2. Priorytetyzuj eventy z kategorii które są w top_causes
    # 3. Wyklucz eventy typu "OTHER" jeśli nie są w top_causes
    filtered_events = []

    for event in related_events:
        confidence = event.get("confidence_score", 0)
        category = event.get("detected_category", "OTHER")

        # Wyklucz eventy z bardzo niskim confidence
        if confidence < 10:
            continue

        # Priorytetyzuj eventy z kategorii które są w top_causes
        is_relevant_category = category in relevant_categories

        # Wyklucz "OTHER" jeśli nie ma wysokiego confidence
        if category == "OTHER" and confidence < 30:
            continue

        # Dodaj event z flagą czy jest w relevant categories
        event_copy = event.copy()
        event_copy["is_relevant_category"] = is_relevant_category
        filtered_events.append(event_copy)

    # Sortuj chronologicznie (najstarsze pierwsze, do momentu BSOD)
    # Priorytetyzuj eventy z wysokim confidence i relevant categories

    def sort_key(event):
        timestamp = parse_timestamp(event.get("timestamp", ""))
        timestamp_sort = timestamp if timestamp else datetime.min

        # Sortuj chronologicznie (najstarsze pierwsze)
        # Negujemy confidence i is_relevant_category, żeby wyższe wartości były
        # pierwsze
        confidence = event.get("confidence_score", 0)
        is_relevant = 1 if event.get("is_relevant_category", False) else 0

        # Sortuj: timestamp (rosnąco), potem confidence (malejąco), potem
        # relevant (malejąco)
        return (timestamp_sort, -confidence, -is_relevant)

    filtered_events.sort(key=sort_key)

    # Ogranicz do max_events
    timeline_events = filtered_events[:max_events]

    # Formatuj dla timeline
    timeline = []
    for event in timeline_events:
        timestamp = event.get("timestamp", "N/A")
        category = event.get("detected_category", "OTHER")
        confidence = event.get("confidence_score", 0)
        event_id = event.get("event_id", "N/A")
        message = event.get("message", "")

        # Skróć długie wiadomości
        if len(message) > 150:
            message = message[:150] + "..."

        # Opis kategorii
        category_descriptions = {
            "GPU_DRIVER": "GPU driver issue",
            "DISK_ERROR": "Disk I/O error",
            "MEMORY_ERROR": "Memory management issue",
            "DRIVER_ERROR": "Driver failure",
            "TXR_FAILURE": "Registry transaction failure",
            "SERVICE_FAILURE": "Service failure",
            "SYSTEM_CRITICAL": "Critical system error",
            "OTHER": "Other system issue"
        }
        description = category_descriptions.get(category, "System event")

        timeline.append({
            "timestamp": timestamp,
            "category": category,
            "description": description,
            "confidence": round(confidence, 1),
            "event_id": event_id,
            "message": message,
            "time_from_bsod_minutes": event.get("time_from_bsod_minutes")
        })

    return timeline


def analyze_bsod_with_timeline(
        system_logs_data,
        hardware_data,
        drivers_data,
        bsod_data=None,
        time_window_minutes=DEFAULT_TIME_WINDOW_MINUTES,
        max_timeline_events=30,
        use_new_correlation=False):
    """
    Analizuje ostatni BSOD i identyfikuje najbardziej prawdopodobne przyczyny.
    Dodatkowo generuje chronologiczną listę eventów poprzedzających BSOD.

    Args:
        system_logs_data (dict): Przetworzone logi systemowe
        hardware_data (dict): Dane sprzętowe (CPU, RAM, GPU, disks)
        drivers_data (list): Lista driverów z informacjami
        bsod_data (dict, optional): Dane z bsod_dumps collector
        time_window_minutes (int, optional): Okno czasowe do analizy przed BSOD.
                                           Jeśli None, używa DEFAULT_TIME_WINDOW_MINUTES (15 min)
        max_timeline_events (int): Maksymalna liczba eventów do timeline

    Returns:
        dict: Strukturyzowana analiza BSOD z confidence scores, rekomendacjami i timeline
    """
    logger = get_logger()

    # Użyj domyślnego okna czasowego jeśli nie podano
    if time_window_minutes is None:
        time_window_minutes = DEFAULT_TIME_WINDOW_MINUTES

    logger.info(
        f"[BSOD] Starting BSOD analysis with timeline (time_window={time_window_minutes}min, use_new_correlation={use_new_correlation})")

    result = analyze_bsod(
        system_logs_data,
        hardware_data,
        drivers_data,
        bsod_data,
        time_window_minutes,
        use_new_correlation)

    if not result.get("bsod_found", False):
        return result  # brak BSOD

    # Generowanie chronologicznej osi eventów
    logger.debug(
        f"[BSOD] Generating timeline from {len(result.get('related_events', []))} related events")
    timeline = generate_bsod_event_timeline(
        result["related_events"],
        result["top_causes"],
        max_events=max_timeline_events)

    # Dodaj do wyniku
    result["event_timeline"] = timeline
    logger.info(f"[BSOD] Generated timeline with {len(timeline)} events")

    return result
