import re
import subprocess
import xml.etree.ElementTree as ET
from collections import defaultdict
from datetime import datetime

from utils.logger import get_logger
from utils.shadowcopy_helper import is_shadowcopy_path

logger = get_logger()


def collect(max_events=100, filter_levels=None):
    """
    Zbiera logi systemowe, aplikacyjne i bezpieczeństwa z Windows Event Logs.

    Args:
        max_events (int): Maksymalna liczba zdarzeń do pobrania z każdej kategorii (domyślnie 100)
        filter_levels (list): Lista poziomów do filtrowania (np. ['Error', 'Warning', 'Critical'])
                             Jeśli None, zwraca wszystkie poziomy

    Returns:
        dict: Słownik {kategoria: [log_entry, ...]}
    """
    log_categories = ["System", "Application", "Security"]
    all_logs = {}

    if filter_levels is None:
        filter_levels = []

    for category in log_categories:
        try:
            # Wywołanie PowerShell do pobrania logów w formacie XML (ukryte okno)
            # Użyj -ErrorAction SilentlyContinue żeby nie przerywać przy
            # błędach
            cmd = (
                f"Get-WinEvent -LogName {category} -MaxEvents {max_events} "
                "-ErrorAction SilentlyContinue | "
                "ConvertTo-Xml -As String -Depth 3"
            )

            # Użyj bezpiecznej funkcji z obsługą różnych kodowań
            from utils.subprocess_helper import run_powershell_hidden
            output = run_powershell_hidden(cmd)

            # Sprawdź czy output nie jest pusty
            logger = get_logger()
            if not output or len(output.strip()) < 50:
                logger.warning(
                    f"[SYSTEM_LOGS] Empty or invalid output from {category} log query (length: {len(output) if output else 0})")
                all_logs[category] = []
                continue

            logs = parse_xml_logs(output, filter_levels)
            all_logs[category] = logs

            # Policz eventy (bez błędów)
            valid_logs = [log for log in logs if "error" not in log]
            logger.info(
                f"[SYSTEM_LOGS] Collected {len(valid_logs)} valid events from {category} log (total parsed: {len(logs)})")
        except subprocess.CalledProcessError as e:
            error_msg = f"Error fetching {category} logs: {e}"
            all_logs[category] = [error_msg]
            logger = get_logger()
            logger.error(f"[SYSTEM_LOGS] {error_msg}")
        except Exception as e:
            error_msg = f"Unexpected error fetching {category} logs: {type(e).__name__}: {e}"
            all_logs[category] = [error_msg]
            logger = get_logger()
            logger.exception(
                f"[SYSTEM_LOGS] Exception in {category} log collection")

    return all_logs


def _validate_xml_data(xml_data):
    """
    Waliduje czy XML data jest poprawna i wystarczająco długa.

    Args:
        xml_data: Dane XML do walidacji

    Returns:
        bool: True jeśli XML jest poprawny
    """
    if not xml_data or len(xml_data.strip()) < 50:
        logger.warning("[SYSTEM_LOGS] XML data is empty or too short")
        return False
    return True


def _parse_xml_to_root(xml_data):
    """
    Parsuje XML do ElementTree root.

    Args:
        xml_data: Dane XML

    Returns:
        ElementTree.Element: Root element lub None
    """
    try:
        return ET.fromstring(xml_data)
    except ET.ParseError as e:
        logger.warning(f"[SYSTEM_LOGS] XML parse error: {e}")
        return None
    except Exception as e:
        logger.warning(f"[SYSTEM_LOGS] Unexpected error parsing XML: {e}")
        return None


def _extract_properties_from_xml_object(obj):
    """
    Wyciąga właściwości z obiektu XML, obsługując zagnieżdżone Property.

    Args:
        obj: Element XML reprezentujący Object

    Returns:
        dict: Słownik z właściwościami
    """
    record = {}
    for prop in obj.findall("Property"):
        name = prop.attrib.get("Name")
        if not name:
            continue

        text_content = prop.text if prop.text else ""
        nested_props = prop.findall("Property")

        if nested_props:
            for nested in nested_props:
                nested_name = nested.attrib.get("Name")
                if nested_name and nested.text:
                    record[f"{name}.{nested_name}"] = nested.text
        else:
            record[name] = text_content

    return record


def _get_event_timestamp(record):
    """
    Pobiera timestamp z rekordu event.

    Args:
        record: Słownik z właściwościami event

    Returns:
        str: Timestamp lub pusty string
    """
    return (
        record.get("TimeCreated") or
        record.get("Time") or
        record.get("TimeCreated.SystemTime") or
        ""
    )


def _get_event_message(record):
    """
    Pobiera message z rekordu event.

    Args:
        record: Słownik z właściwościami event

    Returns:
        str: Message lub pusty string
    """
    message = (
        record.get("Message") or
        record.get("Message.Message") or
        ""
    )
    # Skróć długie wiadomości
    if len(message) > 500:
        message = message[:500] + "..."
    return message


def _get_event_level(record):
    """
    Pobiera i konwertuje level event z rekordu.

    Args:
        record: Słownik z właściwościami event

    Returns:
        str: Znormalizowany level
    """
    level = (
        record.get("LevelDisplayName") or
        record.get("Level") or
        record.get("LevelName") or
        record.get("LevelId") or
        "Information"
    )

    return normalize_level(str(level))


def _get_event_id(record):
    """
    Pobiera event ID z rekordu.

    Args:
        record: Słownik z właściwościami event

    Returns:
        str: Event ID
    """
    return (
        record.get("Id") or
        record.get("EventID") or
        record.get("EventId") or
        "N/A"
    )


def _should_filter_event(level_normalized, filter_levels_lower):
    """
    Sprawdza czy event powinien być odfiltrowany.

    Args:
        level_normalized: Znormalizowany level event
        filter_levels_lower: Lista poziomów do filtrowania (lowercase)

    Returns:
        bool: True jeśli event powinien być odfiltrowany
    """
    if not filter_levels_lower:
        return False

    return level_normalized.lower() not in filter_levels_lower


def _create_log_entry(ts, level_normalized, event_id, message, is_shadowcopy):
    """
    Tworzy słownik log_entry z danymi event.

    Args:
        ts: Sformatowany timestamp
        level_normalized: Znormalizowany level
        event_id: Event ID
        message: Message event
        is_shadowcopy: Czy to ShadowCopy event

    Returns:
        dict: Log entry
    """
    log_entry = {
        "timestamp": ts,
        "level": level_normalized,
        "event_id": str(event_id),
        "message": message,
        "is_shadowcopy": is_shadowcopy,
        "category": "SHADOWCOPY_ERROR" if is_shadowcopy else None,
        "raw": f"[{ts}] [{level_normalized}] [ID:{event_id}] {message}"
    }

    if is_shadowcopy:
        logger.debug(
            f"[SYSTEM_LOGS] Detected ShadowCopy event: {event_id} - "
            f"{message[:100]}"
        )

    return log_entry


def _process_xml_objects(objects, filter_levels_lower):
    """
    Przetwarza listę obiektów XML i tworzy log entries.

    Args:
        objects: Lista elementów XML Object
        filter_levels_lower: Lista poziomów do filtrowania (lowercase)

    Returns:
        tuple: (logs, parsed_count, filtered_count)
    """
    logs = []
    parsed_count = 0
    filtered_count = 0

    for obj in objects:
        record = _extract_properties_from_xml_object(obj)

        timestamp = _get_event_timestamp(record)
        message = _get_event_message(record)
        level_normalized = _get_event_level(record)
        event_id = _get_event_id(record)

        parsed_count += 1

        # Loguj pierwsze kilka eventów dla debugowania
        if parsed_count <= 5:
            logger.debug(
                f"[SYSTEM_LOGS] Event {parsed_count}: "
                f"normalized='{level_normalized}', "
                f"event_id={event_id}, filter_levels={filter_levels_lower}"
            )

        # Filtrowanie po poziomie
        if _should_filter_event(level_normalized, filter_levels_lower):
            filtered_count += 1
            if filtered_count <= 5:
                logger.debug(
                    f"[SYSTEM_LOGS] Filtered event {filtered_count}: "
                    f"level='{level_normalized}' not in {filter_levels_lower}"
                )
            continue

        # Formatowanie timestampa
        ts = format_timestamp(timestamp)

        # Sprawdź czy to ShadowCopy event
        is_shadowcopy = is_shadowcopy_path(message)

        log_entry = _create_log_entry(
            ts,
            level_normalized,
            event_id,
            message,
            is_shadowcopy
        )

        logs.append(log_entry)

    return logs, parsed_count, filtered_count


def parse_xml_logs(xml_data, filter_levels=None):
    """
    Parsuje XML wygenerowany przez PowerShell i zwraca listę sformatowanych logów.
    """
    logs = []
    if filter_levels is None:
        filter_levels = []

    # Normalizuj filter_levels do małych liter
    filter_levels_lower = [
        f.lower() for f in filter_levels
    ] if filter_levels else []

    try:
        # Walidacja XML
        if not _validate_xml_data(xml_data):
            return logs

        # Parsowanie XML
        root = _parse_xml_to_root(xml_data)
        if not root:
            return logs

        objects = root.findall(".//Object")
        logger.debug(
            f"[SYSTEM_LOGS] Found {len(objects)} Object elements in XML"
        )

        # Przetwórz obiekty XML
        logs, parsed_count, filtered_count = _process_xml_objects(
            objects,
            filter_levels_lower
        )

        logger.debug(
            f"[SYSTEM_LOGS] Parsed {parsed_count} events, "
            f"filtered {filtered_count}, returned {len(logs)}"
        )

        # De-duplikuj eventy
        logger.debug(f"[SYSTEM_LOGS] Deduplicating {len(logs)} events")
        logs = deduplicate_events_advanced(logs)
        logger.info(
            f"[SYSTEM_LOGS] After deduplication: {len(logs)} unique events"
        )

    except ET.ParseError as e:
        error_msg = f"Failed to parse logs XML: {str(e)}"
        logger.exception(f"[SYSTEM_LOGS] XML ParseError: {error_msg}")
        logger.debug(
            f"[SYSTEM_LOGS] XML data sample (first 500 chars): "
            f"{xml_data[:500]}"
        )
        logs.append({"error": error_msg})
    except Exception as e:
        error_msg = f"Error parsing logs: {type(e).__name__}: {str(e)}"
        logger.exception(
            f"[SYSTEM_LOGS] Exception in parse_xml_logs: {error_msg}"
        )
        logs.append({"error": error_msg})

    return logs


def _check_encoding_issues(level_str, level_lower):
    """
    Sprawdza i naprawia problemy z kodowaniem w level string.

    Args:
        level_str: Level jako string
        level_lower: Level jako lowercase string

    Returns:
        str: Znormalizowany level lub None jeśli nie znaleziono
    """
    if not any(ord(c) > 127 and c not in 'ąćęłńóśźżĄĆĘŁŃÓŚŹŻ' for c in level_str):
        return None

    if 'ë' in level_lower or '©' in level_str or '†' in level_str or 'Â' in level_str:
        if any(x in level_lower for x in ['ë', '©', '†', 'bë', 'b©']):
            return "Error"
        if any(x in level_lower for x in ['ostrz', 'warn']):
            return "Warning"

    return None


def _check_error_keywords(level_lower):
    """
    Sprawdza czy level zawiera keywords dla Error.

    Args:
        level_lower: Level jako lowercase string

    Returns:
        bool: True jeśli to Error
    """
    error_keywords = ["error", "err", "2", "błąd", "błęd", "bled", "bledy"]
    return any(x in level_lower for x in error_keywords)


def _check_warning_keywords(level_lower):
    """
    Sprawdza czy level zawiera keywords dla Warning.

    Args:
        level_lower: Level jako lowercase string

    Returns:
        bool: True jeśli to Warning
    """
    warning_keywords = [
        "warning", "warn", "3", "ostrzeżenie", "ostrzeg", "ostrz"
    ]
    return any(x in level_lower for x in warning_keywords)


def _check_critical_keywords(level_lower):
    """
    Sprawdza czy level zawiera keywords dla Critical.

    Args:
        level_lower: Level jako lowercase string

    Returns:
        bool: True jeśli to Critical
    """
    critical_keywords = [
        "critical", "crit", "1", "krytyczny", "krytyczn", "kryt"
    ]
    return any(x in level_lower for x in critical_keywords)


def _check_information_keywords(level_lower):
    """
    Sprawdza czy level zawiera keywords dla Information.

    Args:
        level_lower: Level jako lowercase string

    Returns:
        bool: True jeśli to Information
    """
    info_keywords = [
        "information", "info", "informational", "4", "0",
        "informacje", "informacj", "inform"
    ]
    return any(x in level_lower for x in info_keywords)


def _convert_level_id_to_name(level_str):
    """
    Konwertuje level ID (liczba) na nazwę poziomu.

    Args:
        level_str: Level jako string reprezentujący liczbę

    Returns:
        str: Nazwa poziomu
    """
    if not level_str.isdigit():
        return None

    level_id = int(level_str)
    level_map = {
        1: "Critical",
        2: "Error",
        3: "Warning"
    }
    return level_map.get(level_id, "Information")


def normalize_level(level):
    """
    Normalizuje poziom logu do standardowych nazw.
    Obsługuje różne języki (angielski, polski, itp.) i problemy z kodowaniem.

    Args:
        level (str): Oryginalny poziom

    Returns:
        str: Znormalizowany poziom (Error, Warning, Critical, Information)
    """
    if not level:
        return "Information"

    level_str = str(level)
    level_lower = level_str.lower()

    # Sprawdź problemy z kodowaniem
    encoding_fix = _check_encoding_issues(level_str, level_lower)
    if encoding_fix:
        return encoding_fix

    # Sprawdź keywords
    if _check_error_keywords(level_lower):
        return "Error"
    if _check_warning_keywords(level_lower):
        return "Warning"
    if _check_critical_keywords(level_lower):
        return "Critical"
    if _check_information_keywords(level_lower):
        return "Information"

    # Sprawdź czy to Event ID jako poziom
    level_id_name = _convert_level_id_to_name(level_str)
    if level_id_name:
        return level_id_name

    # Domyślnie Information
    return "Information"


def format_timestamp(timestamp):
    """Formatuje timestamp z różnych formatów do czytelnego formatu."""
    if not timestamp:
        return "N/A"

    timestamp_clean = re.sub(r'\.\d+', '', timestamp.replace('Z', ''))
    timestamp_clean = timestamp_clean.strip()

    try:
        if len(timestamp_clean) >= 19:
            dt = datetime.strptime(timestamp_clean[:19], "%Y-%m-%dT%H:%M:%S")
            return dt.strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError):
        pass

    return timestamp[:19] if len(timestamp) >= 19 else timestamp


def deduplicate_events_advanced(events, time_window_seconds=1):
    """
    Zaawansowana deduplikacja eventów:
    - ten sam provider
    - ten sam event id
    - pierwsze 200 znaków message → jedna grupa
    - zlicz occurrences
    """
    if not events:
        return []

    # Sortuj według czasu
    events.sort(key=lambda x: x.get('timestamp', ''))

    # Grupuj według klucza: (provider, event_id, message_prefix)
    grouped = defaultdict(list)

    for event in events:
        provider = event.get(
            'provider',
            '') or event.get(
            'source',
            '') or 'Unknown'
        event_id = str(event.get('event_id', ''))
        message = event.get('message', '')
        message_prefix = message[:200] if len(message) > 200 else message

        key = (provider, event_id, message_prefix)
        grouped[key].append(event)

    # Deduplikuj w ramach grup (ten sam czas w oknie 1 sekundy)
    deduplicated = []

    for _, group_events in grouped.items():
        if len(group_events) == 1:
            group_events[0]['occurrences'] = 1
            deduplicated.append(group_events[0])
        else:
            # Grupuj według czasu (okno 1 sekundy)
            time_groups = defaultdict(list)
            for event in group_events:
                timestamp = event.get('timestamp', '')
                # Zaokrąglij timestamp do sekundy
                time_key = timestamp[:19] if len(
                    timestamp) >= 19 else timestamp
                time_groups[time_key].append(event)

            # Dla każdej grupy czasowej, weź pierwszy event i dodaj occurrences
            for _, time_group in time_groups.items():
                first_event = time_group[0]
                first_event['occurrences'] = len(time_group)
                deduplicated.append(first_event)

    logger.debug(
        f"[SYSTEM_LOGS] Advanced deduplication: {len(events)} -> {len(deduplicated)} events")
    return deduplicated
