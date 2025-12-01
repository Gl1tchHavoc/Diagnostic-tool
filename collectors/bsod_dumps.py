"""
Collector BSOD i Memory Dumps - zbiera informacje o crashach systemu.
Ulepszona wersja z pełnymi informacjami o minidumpach, filtrowaniem WHEA,
i korelacją między WHEA errors a bugchecks/minidumps.
"""
import json
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from pathlib import Path

from utils.logger import get_logger
from utils.minidump_parser import parse_minidump, STOP_CODES
from utils.subprocess_helper import run_powershell_hidden

logger = get_logger()

# Dozwolone Event IDs WHEA odpowiadające rzeczywistym błędom sprzętowym
WHEA_ALLOWED_EVENT_IDS = [17, 18, 19, 20, 21, 46]

# Wzorce regex do filtrowania aktualizacji i TPM
WHEA_FILTER_PATTERNS = [
    # Windows Update patterns
    r'(?i)(windows\s+update|update\s+installation|update\s+downloaded)',
    r'(?i)(wuauclt|trustedinstaller|component\s+update)',
    r'(?i)(servicing\s+stack\s+update|cumulative\s+update)',
    r'(?i)(instalacja\s+powiodła\s+się|installation\s+succeeded)',
    r'(?i)(instalacja\s+zakończona|installation\s+completed)',
    r'(?i)(system\s+windows\s+nie\s+mógł\s+zainstalować\s+aktualizacji)',
    r'(?i)(windows\s+could\s+not\s+install\s+update)',
    r'(?i)(update\s+install\s+success|update\s+install\s+failure)',
    r'(?i)(driver\s+install|driver\s+update|sterownik\s+zainstalowany)',
    r'(?i)(driver\s+installation\s+succeeded|driver\s+installation\s+failed)',
    # TPM patterns
    r'(?i)(tpm|trusted\s+platform\s+module|platform\s+configuration)',
    r'(?i)(tcg\s+event|firmware\s+update)',
    # Success/failure install patterns
    r'(?i)(success\s+install|failure\s+install|zainstalowano|nie\s+zainstalowano)',
    r'(?i)(install.*success|install.*failure|zakończono\s+instalację)'
]


def _parse_xml_record(obj):
    """
    Parsuje pojedynczy rekord XML z Event Log.

    Args:
        obj: Element XML reprezentujący rekord

    Returns:
        dict: Słownik z danymi rekordu
    """
    record = {}
    for prop in obj.findall("Property"):
        name = prop.attrib.get("Name")
        if name:
            record[name] = prop.text if prop.text else ""
    return record


def filter_whea_events(event_id, message):
    """
    Filtruje WHEA events - odrzuca eventy nie związane z rzeczywistymi błędami sprzętowymi.

    Zachowuje tylko faktyczne błędy sprzętowe (CPU, GPU, RAM, PCIe itp.).
    Odrzuca eventy o instalacjach Windows Update, sterownikach, czy innych komunikatach
    "success/failure install".

    Args:
        event_id: ID eventu jako string
        message: Treść wiadomości eventu

    Returns:
        bool: True jeśli event należy ODRZUCIĆ (aktualizacja/TPM/instalacja),
              False jeśli to faktyczny błąd sprzętowy (ZACHOWAJ)
    """
    if not message:
        return True  # Pomiń puste wiadomości

    try:
        event_id_int = int(event_id)
        if event_id_int not in WHEA_ALLOWED_EVENT_IDS:
            return True  # Pomiń niedozwolone Event IDs
    except (ValueError, TypeError):
        return True  # Pomiń nieprawidłowe Event IDs

    message_lower = message.lower()

    # Sprawdź wzorce regex - jeśli pasuje, odrzuć event
    for pattern in WHEA_FILTER_PATTERNS:
        if re.search(pattern, message_lower):
            return True  # Odrzuć - to nie jest faktyczny błąd sprzętowy

    return False  # Zachowaj - to może być faktyczny błąd sprzętowy


# Alias dla zgodności z istniejącym kodem
_is_whea_update_or_tpm_event = filter_whea_events


def _determine_whea_severity(event_id, message):
    """
    Określa severity błędu WHEA na podstawie event ID i wiadomości.

    Args:
        event_id: ID eventu (17, 18, 19, 20, 21, 46)
        message: Treść wiadomości

    Returns:
        str: 'High', 'Medium', 'Low'
    """
    try:
        event_id_int = int(event_id)
    except (ValueError, TypeError):
        return "Medium"

    message_lower = (message or "").lower()

    # Event 17, 19, 20, 21 = Fatal/Uncorrectable Errors (bardzo krytyczne)
    if event_id_int in [17, 19, 20, 21]:
        return "High"

    # Event 18 = Correctable Error (mniej krytyczne)
    if event_id_int == 18:
        # Ale niektóre mogą być poważne
        if any(keyword in message_lower for keyword in [
                "memory", "pcie", "cpu cache", "internal parity"]):
            return "Medium"
        return "Low"

    # Event 46 = Correctable Error (mniej krytyczne)
    if event_id_int == 46:
        return "Medium"

    return "Medium"


def _determine_whea_hardware_component(message):
    """
    Określa komponent sprzętowy związany z błędem WHEA.

    Args:
        message: Treść wiadomości

    Returns:
        str: Komponent (CPU, RAM, GPU, PCIe, Disk, Unknown)
    """
    if not message:
        return "Unknown"

    message_lower = message.lower()

    if any(keyword in message_lower for keyword in [
            "cpu", "processor", "cache", "microcode"]):
        return "CPU"

    if any(keyword in message_lower for keyword in [
            "memory", "ram", "ddr", "ecc"]):
        return "RAM"

    if any(keyword in message_lower for keyword in [
            "gpu", "graphics", "display", "video"]):
        return "GPU"

    if any(keyword in message_lower for keyword in [
            "pcie", "pci express", "pci-e", "pci bus"]):
        return "PCIe"

    if any(keyword in message_lower for keyword in [
            "disk", "storage", "nvme", "sata", "hard drive"]):
        return "Disk"

    return "Unknown"


def _format_timestamp_for_output(timestamp_str):
    """
    Konwertuje timestamp ISO na format wyjściowy (11/30/2025 9:15:00 PM).

    Args:
        timestamp_str: Timestamp w formacie ISO lub innym

    Returns:
        str: Sformatowany timestamp
    """
    if not timestamp_str:
        return None

    try:
        # Spróbuj różne formaty
        for fmt in [
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S",
            "%m/%d/%Y %I:%M:%S %p",
            "%m/%d/%Y %H:%M:%S"
        ]:
            try:
                dt = datetime.strptime(
                    timestamp_str.split("+")[0].split("Z")[0],
                    fmt
                )
                # Formatuj jako "11/30/2025 9:15:00 PM"
                return dt.strftime("%m/%d/%Y %I:%M:%S %p")
            except ValueError:
                continue

        # Jeśli nie udało się sparsować, zwróć oryginał
        return timestamp_str
    except Exception:
        return timestamp_str


def _get_bugcheck_description(stop_code):
    """
    Zwraca opis kodu bugcheck.

    Args:
        stop_code: Kod bugcheck (np. "0x0000007E")

    Returns:
        str: Opis błędu
    """
    try:
        # Konwertuj string na integer
        if stop_code.startswith("0x"):
            code_int = int(stop_code, 16)
        else:
            code_int = int(stop_code, 16)

        # Znajdź w mapowaniu
        if code_int in STOP_CODES:
            return STOP_CODES[code_int]

        return f"Unknown STOP code: {stop_code}"
    except (ValueError, TypeError):
        return f"Invalid STOP code: {stop_code}"


def _create_enhanced_dump_info(dump_path, dump_type):
    """
    Tworzy rozszerzone informacje o pliku dump z pełnymi danymi.

    Args:
        dump_path: Ścieżka do pliku dump
        dump_type: Typ dumpa ('MINIDUMP' lub 'FULL_DUMP')

    Returns:
        dict: Rozszerzone informacje o dumpie
    """
    stat = dump_path.stat()
    parsed_info = parse_minidump(str(dump_path))

    # Formatuj timestamp w formacie wyjściowym
    timestamp_iso = datetime.fromtimestamp(stat.st_mtime).isoformat()
    timestamp_formatted = _format_timestamp_for_output(timestamp_iso)

    dump_info = {
        "filename": dump_path.name,
        "path": str(dump_path),
        "size": stat.st_size,
        "timestamp": timestamp_formatted,
        "timestamp_iso": timestamp_iso,
        "type": dump_type,
        "source": "bugcheck_logger"
    }

    # Dodaj informacje z parsowania
    if parsed_info.get('success'):
        stop_code = parsed_info.get('stop_code')
        stop_code_name = parsed_info.get('stop_code_name')
        offending_driver = parsed_info.get('offending_driver')
        parameters = parsed_info.get('parameters', {})

        # Wyciągnij faulting_driver (może być None)
        faulting_driver = offending_driver or "Unknown"

        dump_info.update({
            "bugcheck_code": stop_code,
            "bugcheck_code_name": stop_code_name,
            "bugcheck_description": (
                _get_bugcheck_description(stop_code)
                if stop_code else None
            ),
            "faulting_driver": faulting_driver,
            "offending_driver": offending_driver,
            "parameter1": parameters.get("Parameter1"),
            "parameter2": parameters.get("Parameter2"),
            "parameter3": parameters.get("Parameter3"),
            "parameter4": parameters.get("Parameter4")
        })

        # Konwertuj parametry do listy dla zgodności z formatem
        params_list = []
        if dump_info.get("parameter1"):
            params_list.append(dump_info.get("parameter1"))
        if dump_info.get("parameter2"):
            params_list.append(dump_info.get("parameter2"))
        if dump_info.get("parameter3"):
            params_list.append(dump_info.get("parameter3"))
        if dump_info.get("parameter4"):
            params_list.append(dump_info.get("parameter4"))
        dump_info["parameters"] = params_list if params_list else None

        # Określ severity na podstawie stop code
        if stop_code and stop_code_name:
            if any(keyword in stop_code_name for keyword in [
                    "CRITICAL", "FATAL", "HARDWARE"]):
                dump_info["severity"] = "High"
            elif any(keyword in stop_code_name for keyword in [
                    "DRIVER", "SERVICE", "EXCEPTION"]):
                dump_info["severity"] = "Medium"
            else:
                dump_info["severity"] = "Low"
        else:
            dump_info["severity"] = "Unknown"

        if dump_type == "MINIDUMP":
            logger.info(
                f"[BSOD_DUMPS] Parsed minidump: {dump_path.name}, "
                f"STOP: {stop_code}, Driver: {faulting_driver}"
            )

    return dump_info


def _create_bugcheck_entry_from_dump(dump_info):
    """
    Tworzy oddzielny wpis bugcheck z informacji o dumpie.

    Format zgodny z przykładem:
    {
      "timestamp": "11/30/2025 9:15:00 PM",
      "bugcheck_code": "0x0000007E",
      "parameters": ["0xFFFFFFFFC0000005", ...],
      "faulting_driver": "ntfs.sys",
      "minidump_path": "C:\\Windows\\Minidump\\..."
    }

    Args:
        dump_info: Słownik z informacjami o dumpie

    Returns:
        dict: Wpis bugcheck z pełnymi danymi
    """
    bugcheck_entry = {
        "timestamp": dump_info.get("timestamp"),
        "bugcheck_code": dump_info.get("bugcheck_code"),
        "parameters": dump_info.get("parameters"),
        "faulting_driver": dump_info.get("faulting_driver"),
        "minidump_path": dump_info.get("path")
    }

    # Dodaj dodatkowe pola jeśli dostępne
    if dump_info.get("bugcheck_code_name"):
        bugcheck_entry["bugcheck_code_name"] = dump_info.get("bugcheck_code_name")
    if dump_info.get("bugcheck_description"):
        bugcheck_entry["bugcheck_description"] = dump_info.get("bugcheck_description")
    if dump_info.get("severity"):
        bugcheck_entry["severity"] = dump_info.get("severity")

    return bugcheck_entry


def _process_minidump_directory(dump_path, bsod_data):
    """
    Przetwarza katalog z minidumpami i tworzy rozszerzone informacje.

    Pobiera WSZYSTKIE pliki minidump z C:\\Windows\\Minidump\\*.dmp.

    Args:
        dump_path: Ścieżka do katalogu minidumpów
        bsod_data: Słownik z danymi BSOD do uzupełnienia
    """
    dump_files = sorted(
        dump_path.glob("*.dmp"),
        key=lambda p: p.stat().st_mtime,
        reverse=True
    )

    logger.info(
        f"[BSOD_DUMPS] Found {len(dump_files)} minidump files in "
        f"{dump_path}"
    )

    # Pobierz WSZYSTKIE pliki minidump (bez limitu)
    for dump_file in dump_files:
        try:
            dump_info = _create_enhanced_dump_info(dump_file, "MINIDUMP")
            bsod_data["minidumps"].append(dump_info)

            # Dodaj oddzielny wpis bugcheck dla każdego minidumpu
            if dump_info.get("bugcheck_code"):
                bugcheck_entry = _create_bugcheck_entry_from_dump(dump_info)
                bsod_data["bugchecks"].append(bugcheck_entry)

        except Exception as e:
            logger.warning(
                f"[BSOD_DUMPS] Error processing minidump {dump_file}: {e}"
            )


def _process_single_dump_file(dump_path, bsod_data):
    """
    Przetwarza pojedynczy plik dump (np. MEMORY.DMP).

    Args:
        dump_path: Ścieżka do pliku dump
        bsod_data: Słownik z danymi BSOD do uzupełnienia
    """
    try:
        dump_info = _create_enhanced_dump_info(dump_path, "FULL_DUMP")
        bsod_data["minidumps"].append(dump_info)

        # Dodaj oddzielny wpis bugcheck dla pełnego dumpa
        if dump_info.get("bugcheck_code"):
            bugcheck_entry = _create_bugcheck_entry_from_dump(dump_info)
            bsod_data["bugchecks"].append(bugcheck_entry)
    except Exception as e:
        logger.warning(
            f"[BSOD_DUMPS] Error processing MEMORY.DMP: {e}"
        )


def collect_minidumps(bsod_data):
    """
    Skanuje folder C:\\Windows\\Minidump\\ i zbiera informacje o plikach *.dmp.

    Dla każdego pliku minidump wyciąga:
    - bugcheck_code (np. 0x0000007E)
    - parameters (lista parametrów bugcheck)
    - faulting_driver (sterownik sprawczy)
    - timestamp (czas crashu)
    - minidump_path (ścieżka do pliku)

    Dodaje te dane do pola bugchecks w JSON.

    Args:
        bsod_data: Słownik z danymi BSOD do uzupełnienia
    """
    minidump_paths = [
        Path("C:/Windows/Minidump"),
        Path("C:/Windows/MEMORY.DMP")
    ]

    for dump_path in minidump_paths:
        if not dump_path.exists():
            logger.debug(
                f"[BSOD_DUMPS] Dump path does not exist: {dump_path}"
            )
            continue

        if dump_path.is_dir():
            _process_minidump_directory(dump_path, bsod_data)
        else:
            _process_single_dump_file(dump_path, bsod_data)


# Alias dla zgodności z istniejącym kodem
_collect_minidump_files = collect_minidumps


def _collect_bugcheck_events(bsod_data):
    """
    Zbiera eventy Bugcheck i Unexpected Shutdown z Event Log.

    Args:
        bsod_data: Słownik z danymi BSOD do uzupełnienia
    """
    cmd = (
        "Get-WinEvent -LogName System -MaxEvents 200 | "
        "Where-Object {$_.Id -in @(41,1001,6008,1074,1076) -or "
        "$_.Message -like '*bugcheck*' -or $_.Message -like '*blue screen*' "
        "-or $_.Message -like '*stop error*'} | "
        "ConvertTo-Xml -As String -Depth 3"
    )

    try:
        output = run_powershell_hidden(cmd)
        root = ET.fromstring(output)

        for obj in root.findall(".//Object"):
            record = _parse_xml_record(obj)
            _process_bugcheck_event(record, bsod_data)
            _process_shutdown_event(record, bsod_data)
    except (ET.ParseError, subprocess.CalledProcessError):
        pass
    except Exception as e:
        bsod_data["collection_error"] = f"Failed to collect BSOD events: {e}"


def _process_bugcheck_event(record, bsod_data):
    """
    Przetwarza event Bugcheck (ID 1001) i dodaje do bsod_data.

    Args:
        record: Słownik z danymi rekordu
        bsod_data: Słownik z danymi BSOD
    """
    event_id = record.get("Id") or record.get("EventID", "N/A")
    message = record.get("Message", "")
    timestamp = record.get("TimeCreated") or record.get("Time", "")

    if event_id == "1001" or "bugcheck" in message.lower():
        bugcheck_code = extract_bugcheck_code(message)
        bugcheck_params = extract_bugcheck_parameters(message)
        crashed_driver = extract_crashed_driver(message)
        dump_file = extract_dump_file_from_message(message)

        # Konwertuj parametry do listy
        params_list = []
        if bugcheck_params:
            for i in range(1, 5):
                param_key = f"Parameter{i}"
                if param_key in bugcheck_params:
                    params_list.append(bugcheck_params[param_key])

        # Formatuj timestamp
        timestamp_formatted = _format_timestamp_for_output(timestamp)

        # Format zgodny z przykładem - tylko podstawowe pola
        bugcheck_entry = {
            "timestamp": timestamp_formatted or timestamp,
            "bugcheck_code": bugcheck_code,
            "parameters": params_list if params_list else None,
            "faulting_driver": crashed_driver or "Unknown",
            "minidump_path": dump_file
        }

        bsod_data["bugchecks"].append(bugcheck_entry)


def _process_shutdown_event(record, bsod_data):
    """
    Przetwarza event Unexpected Shutdown (ID 41) i dodaje do bsod_data.

    Args:
        record: Słownik z danymi rekordu
        bsod_data: Słownik z danymi BSOD
    """
    event_id = record.get("Id") or record.get("EventID", "N/A")
    message = record.get("Message", "")
    timestamp = record.get("TimeCreated") or record.get("Time", "")

    if event_id == "41" or "unexpected shutdown" in message.lower():
        bsod_data["recent_crashes"].append({
            "event_id": str(event_id),
            "timestamp": timestamp,
            "message": message,
            "source": "bugcheck_logger",
            "severity": "High",
            "type": "UNEXPECTED_SHUTDOWN"
        })


def _correlate_whea_with_crashes(whea_event, bugchecks, minidumps):
    """
    Koreluje WHEA error z powiązanymi bugchecks i minidumps.

    Args:
        whea_event: Słownik z danymi WHEA event
        bugchecks: Lista bugchecks
        minidumps: Lista minidumps

    Returns:
        dict: Powiązania (related_bugcheck, related_minidump)
    """
    correlations = {
        "related_bugcheck": None,
        "related_minidump": None
    }

    if not whea_event.get("timestamp"):
        return correlations

    try:
        # Parsuj timestamp WHEA
        whea_time_str = whea_event.get("timestamp")
        whea_time = None
        if whea_time_str:
            # Spróbuj różne formaty timestampów
            for fmt in [
                "%Y-%m-%dT%H:%M:%S.%f",
                "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%d %H:%M:%S"
            ]:
                try:
                    whea_time = datetime.strptime(
                        whea_time_str.split("+")[0].split("Z")[0],
                        fmt
                    )
                    break
                except ValueError:
                    continue

        if not whea_time:
            return correlations

        # Szukaj bugcheck/minidump w oknie czasowym ±5 minut
        time_window = timedelta(minutes=5)

        # Szukaj powiązanego bugcheck
        for bugcheck in bugchecks:
            bugcheck_time_str = bugcheck.get("timestamp")
            if not bugcheck_time_str:
                continue

            try:
                for fmt in [
                    "%Y-%m-%dT%H:%M:%S.%f",
                    "%Y-%m-%dT%H:%M:%S",
                    "%Y-%m-%d %H:%M:%S"
                ]:
                    try:
                        bugcheck_time = datetime.strptime(
                            bugcheck_time_str.split("+")[0].split("Z")[0],
                            fmt
                        )
                        if abs((bugcheck_time - whea_time).total_seconds()) <= time_window.total_seconds():
                            correlations["related_bugcheck"] = {
                                "bugcheck_code": bugcheck.get("bugcheck_code"),
                                "timestamp": bugcheck_time_str,
                                "filename": bugcheck.get("filename")
                            }
                            break
                    except ValueError:
                        continue
            except (ValueError, TypeError):
                continue

        # Szukaj powiązanego minidump
        for minidump in minidumps:
            minidump_time_str = minidump.get("timestamp")
            if not minidump_time_str:
                continue

            try:
                for fmt in [
                    "%Y-%m-%dT%H:%M:%S.%f",
                    "%Y-%m-%dT%H:%M:%S",
                    "%Y-%m-%d %H:%M:%S"
                ]:
                    try:
                        minidump_time = datetime.strptime(
                            minidump_time_str.split("+")[0].split("Z")[0],
                            fmt
                        )
                        if abs((minidump_time - whea_time).total_seconds()) <= 300:
                            correlations["related_minidump"] = {
                                "filename": minidump.get("filename"),
                                "path": minidump.get("path"),
                                "bugcheck_code": minidump.get("bugcheck_code"),
                                "timestamp": minidump_time_str
                            }
                            break
                    except ValueError:
                        continue
            except (ValueError, TypeError):
                continue

    except Exception as e:
        logger.debug(
            f"[BSOD_DUMPS] Error correlating WHEA event: {e}"
        )

    return correlations


def _collect_whea_events(bsod_data):
    """
    Zbiera WHEA-Logger events z zaawansowanym filtrowaniem.

    Filtruje:
    - Tylko Event IDs odpowiadające rzeczywistym błędom sprzętowym (17-21, 46)
    - Logi aktualizacji Windows i TPM (regex patterns)
    - Puste wiadomości

    Args:
        bsod_data: Słownik z danymi BSOD do uzupełnienia
    """
    event_ids_str = ",".join(str(eid) for eid in WHEA_ALLOWED_EVENT_IDS)
    cmd = (
        f"Get-WinEvent -LogName System -MaxEvents 100 | "
        f"Where-Object {{$_.Id -in @({event_ids_str})}} | "
        f"ConvertTo-Xml -As String -Depth 3"
    )

    try:
        logger.debug("[BSOD_DUMPS] Checking WHEA-Logger events")
        output = run_powershell_hidden(cmd)
        root = ET.fromstring(output)
        whea_events = []

        for obj in root.findall(".//Object"):
            record = _parse_xml_record(obj)
            event_id = record.get("Id") or record.get("EventID", "N/A")
            message = record.get("Message", "")
            timestamp = record.get("TimeCreated") or record.get("Time", "")

            # Zaawansowane filtrowanie - tylko faktyczne błędy sprzętowe
            if _is_whea_update_or_tpm_event(event_id, message):
                logger.debug(
                    f"[BSOD_DUMPS] Filtered WHEA event (update/TPM/invalid): "
                    f"ID={event_id}"
                )
                continue

            # Formatuj timestamp
            timestamp_formatted = _format_timestamp_for_output(timestamp)

            # Tylko faktyczne błędy sprzętowe
            whea_event = {
                "event_id": str(event_id),
                "timestamp": timestamp_formatted or timestamp,
                "message": message,
                "type": "WHEA_HARDWARE_ERROR",
                "source": "whea_logger",
                "severity": _determine_whea_severity(event_id, message),
                "hardware_component": (
                    _determine_whea_hardware_component(message)
                )
            }

            whea_events.append(whea_event)

        # Koreluj WHEA events z bugchecks i minidumps
        for whea_event in whea_events:
            correlations = _correlate_whea_with_crashes(
                whea_event,
                bsod_data.get("bugchecks", []),
                bsod_data.get("minidumps", [])
            )
            if correlations.get("related_bugcheck"):
                whea_event["related_bugcheck"] = (
                    correlations["related_bugcheck"]
                )
            if correlations.get("related_minidump"):
                whea_event["related_minidump"] = (
                    correlations["related_minidump"]
                )

        if whea_events:
            bsod_data["whea_errors"] = whea_events
            logger.info(
                f"[BSOD_DUMPS] Found {len(whea_events)} "
                f"WHEA hardware errors (filtered and correlated)"
            )
    except ET.ParseError:
        pass
    except Exception as e:
        logger.debug(f"[BSOD_DUMPS] Could not collect WHEA events: {e}")


def _get_hardware_context_optional():
    """
    Pobiera opcjonalny kontekst sprzętowy (temperatury, SMART, RAM).

    Zbiera tylko podstawowe dane potrzebne do analizy crashy:
    - CPU temperature
    - GPU temperature
    - SMART status dysków
    - RAM info (ilość i użycie)

    Returns:
        dict: Dane sprzętowe lub None jeśli nie dostępne
    """
    hardware_context = {}

    try:
        # Pobierz temperaturę CPU
        cmd_temp = (
            "Get-WmiObject -Namespace 'root\\wmi' "
            "-Class MSAcpi_ThermalZoneTemperature | "
            "Select-Object -First 1 CurrentTemperature | "
            "ConvertTo-Json"
        )
        output = run_powershell_hidden(cmd_temp)
        if output and output.strip():
            temp_data = json.loads(output)
            if isinstance(temp_data, list) and temp_data:
                temp_data = temp_data[0]
            if isinstance(temp_data, dict):
                temp_raw = temp_data.get("CurrentTemperature")
                if temp_raw:
                    temp_celsius = (temp_raw / 10.0) - 273.15
                    hardware_context["cpu_temp"] = round(temp_celsius, 2)
    except Exception as e:
        logger.debug(f"[BSOD_DUMPS] Could not get CPU temperature: {e}")

    try:
        # Pobierz temperaturę GPU (GPUtil jeśli dostępny)
        try:
            import GPUtil
            gpus = GPUtil.getGPUs()
            if gpus and gpus[0].temperature:
                hardware_context["gpu_temp"] = gpus[0].temperature
        except ImportError:
            pass
        except Exception as e:
            logger.debug(f"[BSOD_DUMPS] Could not get GPU temp: {e}")
    except Exception:
        pass

    try:
        # Pobierz SMART status dysków
        cmd_smart = (
            "Get-PhysicalDisk | "
            "Get-StorageReliabilityCounter | "
            "Select-Object DeviceId, HealthStatus | "
            "ConvertTo-Json"
        )
        output = run_powershell_hidden(cmd_smart)
        if output and output.strip():
            smart_data = json.loads(output)
            if not isinstance(smart_data, list):
                smart_data = [smart_data]
            smart_disks = []
            for disk in smart_data:
                if isinstance(disk, dict):
                    device_id = disk.get("DeviceId")
                    health_status = disk.get("HealthStatus")
                    smart_disks.append({
                        "device_id": device_id if device_id is not None else "Unknown",
                        "health_status": (
                            health_status if health_status else "Unknown"
                        )
                    })
            if smart_disks:
                hardware_context["smart_disks"] = smart_disks
    except Exception as e:
        logger.debug(f"[BSOD_DUMPS] Could not get SMART data: {e}")

    try:
        # Pobierz informacje o RAM (ilość i użycie)
        import psutil
        ram_total = psutil.virtual_memory().total / (1024**3)  # GB
        ram_used = psutil.virtual_memory().used / (1024**3)  # GB
        ram_percent = psutil.virtual_memory().percent

        hardware_context["ram"] = {
            "total_gb": round(ram_total, 2),
            "used_gb": round(ram_used, 2),
            "usage_percent": round(ram_percent, 2)
        }
    except Exception as e:
        logger.debug(f"[BSOD_DUMPS] Could not get RAM info: {e}")

    # Zwróć tylko jeśli mamy jakieś dane
    return hardware_context if hardware_context else None


def collect():
    """
    Zbiera informacje o BSOD i memory dumps.

    Zwraca:
    - bugchecks: Lista bugcheck events z Event Log i minidumps
    - minidumps: Lista wszystkich minidump files z pełnymi informacjami
    - recent_crashes: Lista unexpected shutdown events
    - whea_errors: Lista WHEA hardware errors z korelacją do bugchecks
    - hardware_context: Opcjonalny kontekst sprzętowy (temp, SMART, RAM)

    Returns:
        dict: Dane BSOD z rozszerzonymi informacjami zgodne ze strukturą:
        {
            "source": "bsod_collector",
            "timestamp": "<aktualny_timestamp>",
            "bugchecks": [...],
            "whea_errors": [...],
            "hardware_context": {...}  # opcjonalnie
        }
    """
    bsod_data = {
        "source": "bsod_collector",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "bugchecks": [],
        "minidumps": [],
        "recent_crashes": [],
        "whea_errors": []
    }

    if sys.platform != "win32":
        bsod_data["error"] = "Windows only"
        return bsod_data

    # Zbierz wszystkie dane
    logger.info("[BSOD_DUMPS] Starting BSOD collection")
    _collect_bugcheck_events(bsod_data)
    collect_minidumps(bsod_data)
    _collect_whea_events(bsod_data)

    # Dodaj opcjonalny kontekst sprzętowy
    hardware_context = _get_hardware_context_optional()
    if hardware_context:
        bsod_data["hardware_context"] = hardware_context
        logger.info("[BSOD_DUMPS] Added hardware context")

    logger.info(
        f"[BSOD_DUMPS] Collection completed: "
        f"{len(bsod_data.get('bugchecks', []))} bugchecks, "
        f"{len(bsod_data.get('minidumps', []))} minidumps, "
        f"{len(bsod_data.get('whea_errors', []))} WHEA errors"
    )

    return bsod_data


def extract_bugcheck_code(message):
    """Wyciąga kod bugcheck z wiadomości."""
    if not message:
        return "Unknown"

    # Szukaj wzorców typu "0x0000007E" lub "0x7E"
    patterns = [
        r'BugCheckCode:\s*([0-9A-Fa-f]+)',
        r'BugCheck\s+([0-9A-Fa-f]+)',
        r'0x([0-9A-Fa-f]{8})',
        r'0x([0-9A-Fa-f]{1,8})',
        r'stop\s+code\s+([0-9A-Fa-f]+)'
    ]

    for pattern in patterns:
        match = re.search(pattern, message, re.IGNORECASE)
        if match:
            code = match.group(1).upper()
            # Upewnij się że ma format 0xXXXXXXXX
            if len(code) < 8:
                code = code.zfill(8)
            return f"0x{code}"

    return "Unknown"


def extract_bugcheck_parameters(message):
    """Wyciąga parametry bugcheck (Parameter1-4) z wiadomości."""
    if not message:
        return None

    params = {}

    for i in range(1, 5):
        patterns = [
            rf'Parameter{i}:\s*([0-9A-Fa-f]+)',
            rf'Param{i}:\s*([0-9A-Fa-f]+)',
            rf'P{i}:\s*([0-9A-Fa-f]+)'
        ]
        for pattern in patterns:
            match = re.search(pattern, message, re.IGNORECASE)
            if match:
                param_value = match.group(1).upper()
                if len(param_value) < 8:
                    param_value = param_value.zfill(8)
                params[f"Parameter{i}"] = f"0x{param_value}"
                break

    return params if params else None


def extract_crashed_driver(message):
    """Wyciąga nazwę sterownika który spowodował crash."""
    if not message:
        return None

    patterns = [
        r'Probably caused by:\s*([^\s]+\.(sys|dll))',
        r'Image name:\s*([^\s]+\.(sys|dll))',
        r'FAILURE_BUCKET_ID:\s*([^\s]+\.(sys|dll))',
        r'([a-zA-Z0-9_]+\.(sys|dll))\s+\([^)]+\)',
        r'Driver:\s*([^\s]+\.(sys|dll))'
    ]

    for pattern in patterns:
        match = re.search(pattern, message, re.IGNORECASE)
        if match:
            driver = match.group(1)
            # Typowe sterowniki kernel
            if driver.lower() in ['ntoskrnl.exe', 'hal.dll', 'win32k.sys']:
                continue  # Te są zbyt ogólne
            return driver

    return None


def extract_dump_file_from_message(message):
    """Wyciąga ścieżkę do pliku dump z wiadomości Event 1001."""
    if not message:
        return None

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
