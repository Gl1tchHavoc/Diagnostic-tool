"""
Collector BSOD i Memory Dumps - zbiera informacje o crashach systemu.
Ulepszona wersja z pełnymi informacjami o minidumpach, filtrowaniem WHEA,
i korelacją między WHEA errors a bugchecks/minidumps.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from pathlib import Path

if sys.platform == "win32":
    import winreg

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


def _determine_whea_hardware_component(message, component_details=None, description=None):
    """
    Określa komponent sprzętowy związany z błędem WHEA.
    Używa rozszerzonego algorytmu dopasowania i fallback do component_details.

    Args:
        message: Treść wiadomości
        component_details: Dict z component_details (opcjonalnie)
        description: Description z eventu WHEA (opcjonalnie)

    Returns:
        str: Komponent (CPU, RAM, GPU, PCIe, Disk, Motherboard, Unknown)
    """
    # Połącz wszystkie teksty do analizy
    all_text = ""
    if message:
        all_text += message.lower() + " "
    if description:
        all_text += description.lower() + " "
    if component_details:
        error_source = component_details.get("error_source", "").lower()
        component = component_details.get("component", "").lower()
        all_text += error_source + " " + component + " "

    if not all_text:
        return "Unknown"

    # CPU: "cpu", "processor"
    if any(keyword in all_text for keyword in [
            "cpu", "processor", "cache", "microcode", "core", "thread", "cpu core"]):
        return "CPU"

    # RAM: "memory", "ram"
    if any(keyword in all_text for keyword in [
            "memory", "ram", "ddr", "ecc", "dimm", "sodimm"]):
        return "RAM"

    # GPU: "gpu", "graphics"
    if any(keyword in all_text for keyword in [
            "gpu", "graphics", "display", "video", "nvidia", "amd", "intel graphics"]):
        return "GPU"

    # Płyta główna: "motherboard", "pci"
    if any(keyword in all_text for keyword in [
            "motherboard", "mainboard", "chipset", "southbridge", "northbridge", "pci"]):
        return "Motherboard"

    # Dyski NVMe/SATA: "nvme", "ssd", "disk"
    if any(keyword in all_text for keyword in [
            "nvme", "ssd", "disk", "storage", "sata", "hard drive", "hdd", "nvme controller"]):
        return "Disk"

    # Fallback: użyj Error Source z component_details
    if component_details and component_details.get("error_source"):
        error_source = component_details["error_source"].lower()
        if "cpu" in error_source or "processor" in error_source:
            return "CPU"
        elif "memory" in error_source or "ram" in error_source:
            return "RAM"
        elif "gpu" in error_source or "graphics" in error_source:
            return "GPU"
        elif "disk" in error_source or "storage" in error_source or "nvme" in error_source:
            return "Disk"
        elif "motherboard" in error_source or "pci" in error_source:
            return "Motherboard"

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
        "filepath": str(dump_path),
        "path": str(dump_path),  # Dla zgodności
        "size_bytes": stat.st_size,
        "size": stat.st_size,  # Dla zgodności
        "timestamp": timestamp_formatted,
        "timestamp_iso": timestamp_iso,
        "type": dump_type,
        "source": "bugcheck_logger"
    }

    # Fallback: jeśli parsowanie nie powiodło się, przynajmniej zapisz podstawowe info
    if not parsed_info.get('success'):
        logger.debug(
            f"[BSOD_DUMPS] Minidump parsing failed for {dump_path.name}, "
            f"using fallback info (filename, size)"
        )
        # Dodaj podstawowe informacje nawet bez parsowania
        dump_info["bugcheck_code"] = None
        dump_info["faulting_driver"] = None
        dump_info["parameters"] = None
        return dump_info

    # Dodaj informacje z parsowania
    if parsed_info.get('success'):
        stop_code = parsed_info.get('stop_code')
        stop_code_name = parsed_info.get('stop_code_name')
        offending_driver = parsed_info.get('offending_driver')
        parameters = parsed_info.get('parameters', {})

        # Wyciągnij faulting_driver (może być None)
        # Jeśli parse_minidump nie znalazło drivera, spróbuj WinDbg
        faulting_driver = offending_driver
        if not faulting_driver or faulting_driver == "Unknown":
            windbg_info = _parse_bugcheck_with_windbg(str(dump_path))
            if windbg_info and windbg_info.get('faulting_driver'):
                faulting_driver = windbg_info.get('faulting_driver')
                logger.debug(
                    f"[BSOD_DUMPS] Found driver via WinDbg: {faulting_driver} for {dump_path.name}")
        
        # Jeśli nadal nie ma drivera, ustaw "Unknown"
        if not faulting_driver:
            faulting_driver = "Unknown"

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
        # Używaj None dla brakujących parametrów zamiast pomijać
        params_list = []
        for i in range(1, 5):
            param_key = f"parameter{i}"
            param_value = dump_info.get(param_key)
            if param_value:
                params_list.append(param_value)
            else:
                params_list.append(None)  # Zawsze 4 parametry, None jeśli brakuje
        
        # Jeśli wszystkie są None, ustaw jako None zamiast listy z None
        if all(p is None for p in params_list):
            dump_info["parameters"] = None
        else:
            dump_info["parameters"] = params_list

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

    if len(dump_files) == 0:
        logger.info(
            f"[BSOD_DUMPS] Minidump directory exists but is empty: {dump_path}"
        )
    else:
        logger.info(
        f"[BSOD_DUMPS] Found {len(dump_files)} minidump files in "
        f"{dump_path}"
    )

    # Pobierz WSZYSTKIE pliki minidump (bez limitu)
    dump_file_paths = []
    for dump_file in dump_files:
        try:
            dump_info = _create_enhanced_dump_info(dump_file, "MINIDUMP")
            
            # Spróbuj parsować z WinDbg dla lepszych szczegółów
            windbg_info = _parse_bugcheck_with_windbg(dump_file)
            if windbg_info:
                # Uzupełnij dump_info danymi z WinDbg
                dump_info.update(windbg_info)
            
            bsod_data["minidumps"].append(dump_info)
            dump_file_paths.append(str(dump_file))

            # Dodaj oddzielny wpis bugcheck dla każdego minidumpu
            if dump_info.get("bugcheck_code"):
                bugcheck_entry = _create_bugcheck_entry_from_dump(dump_info)
                bsod_data["bugchecks"].append(bugcheck_entry)

        except Exception as e:
            logger.warning(
                f"[BSOD_DUMPS] Error processing minidump {dump_file}: {e}"
            )
    
    # Skopiuj minidumpy do centralnego folderu
    if dump_file_paths:
        copied = _copy_minidumps_to_central_folder(dump_file_paths)
        if copied:
            logger.info(
                f"[BSOD_DUMPS] Copied {len(copied)} minidumps to central folder"
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


def _get_dump_paths_from_registry():
    """
    Wykrywa ścieżki dumpów z rejestru Windows.
    
    Sprawdza klucz CrashControl w rejestrze:
    HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl
    
    Returns:
        list: Lista ścieżek do dumpów znalezionych w rejestrze
    """
    dump_paths = []
    
    if sys.platform != "win32":
        return dump_paths
    
    try:
        key_path = r"SYSTEM\CurrentControlSet\Control\CrashControl"
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            key_path,
            0,
            winreg.KEY_READ
        ) as key:
            # Odczytaj DumpFile (ścieżka do pełnego dumpa)
            try:
                dump_file, _ = winreg.QueryValueEx(key, "DumpFile")
                if dump_file:
                    dump_path = Path(dump_file)
                    if dump_path.exists():
                        dump_paths.append(dump_path)
                        logger.info(
                            f"[BSOD_DUMPS] Found dump file from registry: {dump_file}"
                        )
            except FileNotFoundError:
                pass
            
            # Odczytaj MinidumpDir (folder minidumpów)
            try:
                minidump_dir, _ = winreg.QueryValueEx(key, "MinidumpDir")
                if minidump_dir:
                    dump_path = Path(minidump_dir)
                    if dump_path.exists() and dump_path.is_dir():
                        dump_paths.append(dump_path)
                        logger.info(
                            f"[BSOD_DUMPS] Found minidump directory from registry: {minidump_dir}"
                        )
            except FileNotFoundError:
                pass
                
    except FileNotFoundError:
        logger.debug("[BSOD_DUMPS] CrashControl registry key not found")
    except PermissionError:
        logger.debug(
            "[BSOD_DUMPS] Cannot access registry - admin rights may be required"
        )
    except Exception as e:
        logger.debug(f"[BSOD_DUMPS] Error reading registry: {e}")
    
    return dump_paths


def _get_fallback_dump_paths():
    """
    Zwraca listę fallback ścieżek do dumpów.
    
    Returns:
        list: Lista ścieżek Path do sprawdzenia
    """
    fallback_paths = [
        Path("C:/Windows/Minidump"),
        Path("C:/Windows/MEMORY.DMP"),
    ]
    
    # Dodaj ścieżki z zmiennych środowiskowych
    try:
        localappdata = os.environ.get("LOCALAPPDATA")
        if localappdata:
            crashdumps_path = Path(localappdata) / "CrashDumps"
            if crashdumps_path.exists():
                fallback_paths.append(crashdumps_path)
    except Exception:
        pass
    
    # Rozwiń zmienne środowiskowe w ścieżkach
    expanded_paths = []
    for path in fallback_paths:
        try:
            expanded = Path(os.path.expandvars(str(path)))
            expanded_paths.append(expanded)
        except Exception:
            expanded_paths.append(path)
    
    return expanded_paths


def collect_minidumps(bsod_data):
    """
    Skanuje folder C:\\Windows\\Minidump\\ i zbiera informacje o plikach *.dmp.
    Obsługuje również custom folders z dumpami i ścieżki z rejestru.

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
    # Najpierw sprawdź rejestr dla ścieżek dumpów
    registry_paths = _get_dump_paths_from_registry()
    
    # Następnie fallback paths
    fallback_paths = _get_fallback_dump_paths()
    
    # Połącz wszystkie ścieżki (rejestr ma priorytet)
    minidump_paths = registry_paths + fallback_paths
    
    # Usuń duplikaty zachowując kolejność
    seen = set()
    unique_paths = []
    for path in minidump_paths:
        path_str = str(path)
        if path_str not in seen:
            seen.add(path_str)
            unique_paths.append(path)

    found_any = False
    paths_checked = []
    paths_not_found = []
    
    for dump_path in unique_paths:
        paths_checked.append(str(dump_path))
        if not dump_path.exists():
            paths_not_found.append(str(dump_path))
            logger.debug(
                f"[BSOD_DUMPS] Dump path does not exist: {dump_path}"
            )
            continue

        found_any = True
        if dump_path.is_dir():
            logger.info(f"[BSOD_DUMPS] Scanning directory: {dump_path}")
            _process_minidump_directory(dump_path, bsod_data)
        else:
            logger.info(f"[BSOD_DUMPS] Processing file: {dump_path}")
            _process_single_dump_file(dump_path, bsod_data)
    
    # Loguj informację o braku dumpów (info, nie warning)
    if not found_any:
        logger.info(
            "[BSOD_DUMPS] No minidump files found in any of the checked paths:"
        )
        for path in paths_checked:
            status = "✓ exists" if Path(path).exists() else "✗ not found"
            logger.info(f"  {status}: {path}")
        logger.info(
            "[BSOD_DUMPS] This is normal if no system crashes have occurred. "
            "Continuing with other data collection..."
        )


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

        # Szukaj bugcheck/minidump w oknie czasowym ±10 minut (rozszerzone dla lepszej korelacji)
        time_window = timedelta(minutes=10)

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
                        time_diff = abs((bugcheck_time - whea_time).total_seconds())
                        if time_diff <= time_window.total_seconds():
                            # Określ kierunek korelacji
                            correlation_direction = "WHEA→BSOD" if whea_time < bugcheck_time else "BSOD→WHEA"
                            correlations["related_bugcheck"] = {
                                "bugcheck_code": bugcheck.get("bugcheck_code"),
                                "timestamp": bugcheck_time_str,
                                "filename": bugcheck.get("filename"),
                                "correlation_direction": correlation_direction,
                                "time_difference_seconds": int(time_diff)
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
                        time_diff = abs((minidump_time - whea_time).total_seconds())
                        if time_diff <= time_window.total_seconds():
                            # Określ kierunek korelacji
                            correlation_direction = "WHEA→MINIDUMP" if whea_time < minidump_time else "MINIDUMP→WHEA"
                            correlations["related_minidump"] = {
                                "filename": minidump.get("filename"),
                                "path": minidump.get("path"),
                                "bugcheck_code": minidump.get("bugcheck_code"),
                                "timestamp": minidump_time_str,
                                "correlation_direction": correlation_direction,
                                "time_difference_seconds": int(time_diff)
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

            # Dodaj szczegółowe informacje o komponencie (najpierw, żeby użyć w _determine_whea_hardware_component)
            component_details = _get_enhanced_whea_component_details(record)
            description = record.get("Description", "") or record.get("Description", "")

            # Tylko faktyczne błędy sprzętowe
            whea_event = {
                "event_id": str(event_id),
                "timestamp": timestamp_formatted or timestamp,
                "message": message,
                "description": description,
                "type": "WHEA_HARDWARE_ERROR",
                "source": "whea_logger",
                "severity": _determine_whea_severity(event_id, message),
                "hardware_component": _determine_whea_hardware_component(
                    message, component_details, description
                )
            }
            
            # Dodaj szczegółowe informacje o komponencie
            if component_details:
                whea_event["component_details"] = component_details

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


def _parse_bugcheck_with_windbg(dump_file_path):
    """
    Parsuje minidump używając WinDbg w trybie skryptowym.

    Args:
        dump_file_path: Ścieżka do pliku minidump

    Returns:
        dict: Parsowane dane bugcheck lub None
    """
    try:
        # Sprawdź czy WinDbg jest dostępny
        windbg_paths = [
            r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\windbg.exe",
            r"C:\Program Files\Windows Kits\10\Debuggers\x64\windbg.exe",
            r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x86\windbg.exe"
        ]

        windbg_exe = None
        for path in windbg_paths:
            if Path(path).exists():
                windbg_exe = path
                break

        if not windbg_exe:
            logger.debug("[BSOD_DUMPS] WinDbg not found, skipping advanced parsing")
            return None

        # Uruchom WinDbg w trybie skryptowym
        # Zwiększony timeout dla dużych dumpów (60s)
        script = ".ecxr;!analyze -v;q"
        cmd = f'"{windbg_exe}" -z "{dump_file_path}" -c "{script}"'
        
        # Określ timeout na podstawie rozmiaru pliku
        dump_size = Path(dump_file_path).stat().st_size
        timeout = 60 if dump_size > 100 * 1024 * 1024 else 30  # 60s dla >100MB
        
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout
        )

        if result.returncode != 0:
            logger.debug(f"[BSOD_DUMPS] WinDbg analysis failed for {dump_file_path}")
            return None

        # Parsuj output WinDbg
        output = result.stdout
        bugcheck_info = {}

        # Wyciągnij bugcheck code
        bugcheck_match = re.search(r'Bugcheck\s+Code\s+:\s+([0-9a-fA-Fx]+)', output)
        if bugcheck_match:
            bugcheck_info["bugcheck_code"] = bugcheck_match.group(1)

        # Wyciągnij parametry
        params = []
        for i in range(1, 5):
            param_match = re.search(
                rf'Parameter\s+{i}\s+:\s+([0-9a-fA-Fx]+)',
                output
            )
            if param_match:
                params.append(param_match.group(1))
        if params:
            bugcheck_info["parameters"] = params

        # Wyciągnij faulting driver
        driver_match = re.search(
            r'Probably\s+caused\s+by\s+:\s+([^\s]+)',
            output
        )
        if driver_match:
            bugcheck_info["faulting_driver"] = driver_match.group(1)

        return bugcheck_info if bugcheck_info else None

    except subprocess.TimeoutExpired:
        logger.debug(f"[BSOD_DUMPS] WinDbg timeout for {dump_file_path}")
        return None
    except Exception as e:
        logger.debug(f"[BSOD_DUMPS] WinDbg parsing error: {e}")
        return None


def _copy_minidumps_to_central_folder(dump_files, central_folder=None):
    """
    Kopiuje minidumpy do centralnego folderu.

    Args:
        dump_files: Lista ścieżek do plików minidump
        central_folder: Ścieżka do centralnego folderu (opcjonalnie)

    Returns:
        list: Lista skopiowanych plików lub None
    """
    if not dump_files:
        return None

    try:
        # Domyślny folder centralny
        if not central_folder:
            central_folder = Path("C:/DiagnosticTool/Minidumps")
        else:
            central_folder = Path(central_folder)

        # Utwórz folder jeśli nie istnieje
        central_folder.mkdir(parents=True, exist_ok=True)

        copied_files = []
        for dump_file in dump_files:
            try:
                dump_path = Path(dump_file)
                if not dump_path.exists():
                    continue

                # Skopiuj z zachowaniem nazwy
                dest_path = central_folder / dump_path.name
                shutil.copy2(dump_path, dest_path)
                copied_files.append(str(dest_path))
                logger.debug(
                    f"[BSOD_DUMPS] Copied {dump_path.name} to {central_folder}"
                )
            except Exception as e:
                logger.warning(
                    f"[BSOD_DUMPS] Failed to copy {dump_file}: {e}"
                )

        return copied_files if copied_files else None

    except Exception as e:
        logger.debug(f"[BSOD_DUMPS] Failed to copy minidumps: {e}")
        return None


def _get_enhanced_whea_component_details(event_record):
    """
    Wyciąga szczegółowe informacje o komponencie sprzętowym z WHEA event.

    Args:
        event_record: Słownik z danymi eventu WHEA

    Returns:
        dict: Szczegóły komponentu (ErrorSource, Component, ProcessorId, MemoryId, DeviceId)
        Zawsze zwraca przynajmniej error_source i component (nawet jeśli "Unknown")
    """
    component_details = {
        "error_source": "Unknown",
        "component": "Unknown"
    }

    try:
        message = event_record.get("Message", "") or ""
        
        # Wyciągnij ErrorSource
        error_source_match = re.search(
            r'Error\s+Source\s*:\s*([^\n\r]+)',
            message,
            re.IGNORECASE
        )
        if error_source_match:
            component_details["error_source"] = error_source_match.group(1).strip()
        else:
            # Fallback: spróbuj z PowerShell
            try:
                cmd = (
                    "Get-WinEvent -ProviderName 'Microsoft-Windows-WHEA-Logger' "
                    "-MaxEvents 1 | Select-Object -ExpandProperty Properties | "
                    "Where-Object {$_.Value -like '*ErrorSource*'} | "
                    "Select-Object -First 1 -ExpandProperty Value"
                )
                output = run_powershell_hidden(cmd)
                if output and output.strip():
                    component_details["error_source"] = output.strip()
            except Exception:
                pass

        # Wyciągnij Component
        component_match = re.search(
            r'Component\s*:\s*([^\n\r]+)',
            message,
            re.IGNORECASE
        )
        if component_match:
            component_details["component"] = component_match.group(1).strip()
        else:
            # Fallback: użyj _determine_whea_hardware_component
            component_details["component"] = _determine_whea_hardware_component(message)

        # Wyciągnij ProcessorId
        processor_match = re.search(
            r'Processor\s+ID\s*:\s*([0-9a-fA-Fx]+)',
            message,
            re.IGNORECASE
        )
        if processor_match:
            component_details["processor_id"] = processor_match.group(1).strip()

        # Wyciągnij MemoryId
        memory_match = re.search(
            r'Memory\s+ID\s*:\s*([0-9a-fA-Fx]+)',
            message,
            re.IGNORECASE
        )
        if memory_match:
            component_details["memory_id"] = memory_match.group(1).strip()

        # Wyciągnij DeviceId
        device_match = re.search(
            r'Device\s+ID\s*:\s*([^\n\r]+)',
            message,
            re.IGNORECASE
        )
        if device_match:
            component_details["device_id"] = device_match.group(1).strip()

        # Alternatywnie użyj PowerShell do pobrania szczegółów
        if not component_details:
            cmd = (
                "Get-WinEvent -ProviderName 'Microsoft-Windows-WHEA-Logger' "
                "-MaxEvents 1 | Format-List * | Out-String"
            )
            try:
                output = run_powershell_hidden(cmd)
                if output:
                    # Parsuj output PowerShell
                    for line in output.split('\n'):
                        if 'ErrorSource' in line:
                            component_details["error_source"] = line.split(':', 1)[1].strip()
                        elif 'Component' in line and 'Component' not in component_details:
                            component_details["component"] = line.split(':', 1)[1].strip()
                        elif 'ProcessorId' in line:
                            component_details["processor_id"] = line.split(':', 1)[1].strip()
                        elif 'MemoryId' in line:
                            component_details["memory_id"] = line.split(':', 1)[1].strip()
                        elif 'DeviceId' in line:
                            component_details["device_id"] = line.split(':', 1)[1].strip()
            except Exception:
                pass

    except Exception as e:
        logger.debug(f"[BSOD_DUMPS] Error extracting WHEA component details: {e}")

    # Zawsze zwróć dict, nawet jeśli puste (przynajmniej error_source i component)
    return component_details


def _get_enhanced_smart_disk_health():
    """
    Zbiera szczegółowe dane SMART o zdrowiu dysków.
    Normalizuje wszystkie wpisy dysków używając device_id + serial jako klucza.

    Returns:
        list: Lista dysków z danymi SMART (znormalizowane, bez duplikatów)
    """
    smart_disks_dict = {}  # Używamy dict do normalizacji

    try:
        # Metoda 1: WMI MSStorageDriver_FailurePredictStatus
        try:
            cmd_wmi = (
                "Get-WmiObject -Namespace root\\wmi "
                "-Class MSStorageDriver_FailurePredictStatus | "
                "Select-Object InstanceName, PredictFailure, Reason | "
                "ConvertTo-Json"
            )
            output = run_powershell_hidden(cmd_wmi)
            if output and output.strip():
                try:
                    wmi_data = json.loads(output)
                    if not isinstance(wmi_data, list):
                        wmi_data = [wmi_data]
                    
                    for disk in wmi_data:
                        if isinstance(disk, dict):
                            instance_name = disk.get("InstanceName", "Unknown")
                            # Użyj instance_name jako klucza (może zawierać device info)
                            key = f"wmi_{instance_name}"
                            if key not in smart_disks_dict:
                                smart_disks_dict[key] = {}
                            smart_disks_dict[key].update({
                                "instance_name": instance_name,
                                "predict_failure": disk.get("PredictFailure", False),
                                "failure_reason": disk.get("Reason", "Unknown")
                            })
                except json.JSONDecodeError:
                    pass
        except (RuntimeError, Exception) as e:
            logger.debug(f"[BSOD_DUMPS] Failed to get SMART data via WMI: {e}")

        # Metoda 2: WMIC diskdrive
        try:
            cmd_wmic = (
                "wmic diskdrive get status,model,serialnumber,size /format:csv | "
                "ConvertFrom-Csv | ConvertTo-Json"
            )
            output = run_powershell_hidden(cmd_wmic)
            if output and output.strip():
                try:
                    wmic_data = json.loads(output)
                    if not isinstance(wmic_data, list):
                        wmic_data = [wmic_data]
                    
                    for disk in wmic_data:
                        if isinstance(disk, dict):
                            model = disk.get("Model", "Unknown")
                            serial = disk.get("SerialNumber", "Unknown")
                            # Użyj model + serial jako klucza do normalizacji
                            key = f"wmic_{model}_{serial}"
                            if key not in smart_disks_dict:
                                smart_disks_dict[key] = {}
                            smart_disks_dict[key].update({
                                "model": model,
                                "serial": serial,
                                "status": disk.get("Status", "Unknown"),
                                "size_bytes": disk.get("Size", "0")
                            })
                except json.JSONDecodeError:
                    pass
        except (RuntimeError, Exception) as e:
            logger.debug(f"[BSOD_DUMPS] Failed to get disk info via WMIC: {e}")

        # Metoda 3: Get-PhysicalDisk z StorageReliabilityCounter
        try:
            cmd_storage = (
                "Get-PhysicalDisk | Get-StorageReliabilityCounter | "
                "Select-Object DeviceId, HealthStatus, ReadErrorsTotal, "
                "WriteErrorsTotal, Wear | ConvertTo-Json"
            )
            output = run_powershell_hidden(cmd_storage)
            if output and output.strip():
                try:
                    storage_data = json.loads(output)
                    if not isinstance(storage_data, list):
                        storage_data = [storage_data]
                    
                    for disk in storage_data:
                        if isinstance(disk, dict):
                            device_id = disk.get("DeviceId")
                            # Użyj device_id jako klucza
                            key = f"storage_{device_id}"
                            if key not in smart_disks_dict:
                                smart_disks_dict[key] = {}
                            smart_disks_dict[key].update({
                                "device_id": device_id,
                                "health_status": disk.get("HealthStatus", "Unknown"),
                                "read_errors_total": disk.get("ReadErrorsTotal", 0),
                                "write_errors_total": disk.get("WriteErrorsTotal", 0),
                                "wear": disk.get("Wear", 0)
                            })
                except json.JSONDecodeError:
                    pass
        except (RuntimeError, Exception) as e:
            logger.debug(f"[BSOD_DUMPS] Failed to get storage reliability data: {e}")
        
        # Dodatkowe pola SMART przez WMI (ReallocatedSectors, PendingSectors, Temperature, PowerOnHours)
        try:
            cmd_smart_detailed = (
                "Get-WmiObject -Namespace root\\wmi "
                "-Class MSStorageDriver_ATAPISmartData | "
                "Select-Object InstanceName, VendorSpecific | "
                "ConvertTo-Json"
            )
            output = run_powershell_hidden(cmd_smart_detailed)
            if output and output.strip():
                try:
                    smart_detailed = json.loads(output)
                    if not isinstance(smart_detailed, list):
                        smart_detailed = [smart_detailed]
                    
                    for disk in smart_detailed:
                        if isinstance(disk, dict):
                            instance_name = disk.get("InstanceName", "")
                            # Znajdź odpowiedni wpis w smart_disks_dict
                            matching_key = None
                            for key, disk_data in smart_disks_dict.items():
                                if disk_data.get("instance_name") == instance_name:
                                    matching_key = key
                                    break
                            
                            if matching_key:
                                # Parsuj VendorSpecific (bajty SMART)
                                vendor_specific = disk.get("VendorSpecific", [])
                                if vendor_specific:
                                    # SMART Attribute 5 = Reallocated Sectors
                                    # SMART Attribute 197 = Pending Sectors
                                    # SMART Attribute 194 = Temperature
                                    # SMART Attribute 9 = Power On Hours
                                    smart_disks_dict[matching_key]["smart_attributes"] = {
                                        "reallocated_sectors": vendor_specific[5] if len(vendor_specific) > 5 else None,
                                        "pending_sectors": vendor_specific[197] if len(vendor_specific) > 197 else None,
                                        "temperature": vendor_specific[194] if len(vendor_specific) > 194 else None,
                                        "power_on_hours": vendor_specific[9] if len(vendor_specific) > 9 else None
                                    }
                except json.JSONDecodeError:
                    pass
        except (RuntimeError, Exception) as e:
            logger.debug(f"[BSOD_DUMPS] Failed to get detailed SMART attributes: {e}")

    except Exception as e:
        logger.debug(f"[BSOD_DUMPS] Error collecting SMART data: {e}")

    # Konwertuj dict na listę
    smart_disks = list(smart_disks_dict.values())
    return smart_disks if smart_disks else None


def _collect_system_events_and_driver_logs(crash_timestamp=None):
    """
    Zbiera eventy systemowe i logi sterowników wokół czasu crashu.

    Args:
        crash_timestamp: Timestamp crashu (opcjonalnie, do filtrowania)

    Returns:
        dict: Eventy systemowe i logi sterowników
    """
    events_data = {
        "system_events": [],
        "driver_events": [],
        "application_events": []
    }

    try:
        # Zbierz eventy systemowe
        if crash_timestamp:
            # Filtruj po czasie crashu (±10 minut)
            try:
                crash_dt = datetime.strptime(
                    crash_timestamp.split("+")[0].split("Z")[0],
                    "%Y-%m-%dT%H:%M:%S"
                )
                start_time = (crash_dt - timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%S")
                end_time = (crash_dt + timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%S")
                time_filter = f" | Where-Object {{$_.TimeCreated -ge '{start_time}' -and $_.TimeCreated -le '{end_time}'}}"
            except Exception:
                time_filter = ""
        else:
            time_filter = ""  # Usuń limit - zbierz wszystkie eventy

        # Zbierz eventy systemowe - wszystkie (bez limitu), z pełnym Message
        try:
            cmd_system = (
                f"Get-WinEvent -LogName System{time_filter} | "
                "Select-Object Id, LevelDisplayName, Message, TimeCreated, ProviderName | "
                "ConvertTo-Json -Depth 3"
            )
            output = run_powershell_hidden(cmd_system, timeout=60)
            if output and output.strip():
                try:
                    system_events = json.loads(output)
                    if not isinstance(system_events, list):
                        system_events = [system_events]
                    # Usuń limit - zapisz wszystkie
                    events_data["system_events"] = system_events
                    logger.debug(f"[BSOD_DUMPS] Collected {len(events_data['system_events'])} system events")
                except json.JSONDecodeError as e:
                    logger.debug(f"[BSOD_DUMPS] Failed to parse system events JSON: {e}")
        except (RuntimeError, Exception) as e:
            logger.debug(f"[BSOD_DUMPS] Failed to collect system events: {e}")

        # Zbierz eventy sterowników i crashy (rozszerzone Event IDs)
        # Event IDs: 1000, 1001 (bugcheck), 41 (unexpected shutdown), 6008, 1074, 1076, 20001-20003, 219, 10016
        try:
            driver_event_ids = [1000, 1001, 41, 6008, 1074, 1076, 20001, 20002, 20003, 219, 10016]
            event_ids_str = ",".join(str(eid) for eid in driver_event_ids)
            cmd_drivers = (
                f"Get-WinEvent -LogName System{time_filter} | "
                f"Where-Object {{$_.Id -in @({event_ids_str})}} | "
                "Select-Object Id, LevelDisplayName, Message, TimeCreated, ProviderName | "
                "ConvertTo-Json -Depth 3"
            )
            output = run_powershell_hidden(cmd_drivers, timeout=60)
            if output and output.strip():
                try:
                    driver_events = json.loads(output)
                    if not isinstance(driver_events, list):
                        driver_events = [driver_events]
                    # Nie ograniczaj - zapisz wszystkie
                    events_data["driver_events"] = driver_events
                    logger.debug(f"[BSOD_DUMPS] Collected {len(events_data['driver_events'])} driver events")
                except json.JSONDecodeError as e:
                    logger.debug(f"[BSOD_DUMPS] Failed to parse driver events JSON: {e}")
        except (RuntimeError, Exception) as e:
            logger.debug(f"[BSOD_DUMPS] Failed to collect driver events: {e}")

        # Zbierz eventy aplikacji - wszystkie Critical/Error (bez limitu)
        try:
            cmd_app = (
                f"Get-WinEvent -LogName Application{time_filter} | "
                "Where-Object {$_.LevelDisplayName -eq 'Error' -or $_.LevelDisplayName -eq 'Critical'} | "
                "Select-Object Id, LevelDisplayName, Message, TimeCreated, ProviderName | "
                "ConvertTo-Json -Depth 3"
            )
            output = run_powershell_hidden(cmd_app, timeout=60)
            if output and output.strip():
                try:
                    app_events = json.loads(output)
                    if not isinstance(app_events, list):
                        app_events = [app_events]
                    # Nie ograniczaj - zapisz wszystkie
                    events_data["application_events"] = app_events
                    logger.debug(f"[BSOD_DUMPS] Collected {len(events_data['application_events'])} application events")
                except json.JSONDecodeError as e:
                    logger.debug(f"[BSOD_DUMPS] Failed to parse application events JSON: {e}")
        except (RuntimeError, Exception) as e:
            logger.debug(f"[BSOD_DUMPS] Failed to collect application events: {e}")

    except Exception as e:
        logger.debug(f"[BSOD_DUMPS] Error collecting system events: {e}")

    return events_data if any(events_data.values()) else None


def _get_hardware_temperature_and_parameters():
    """
    Zbiera temperaturę i parametry sprzętu (CPU, GPU, voltage, fan speed).

    Returns:
        dict: Dane o temperaturze i parametrach sprzętu
    """
    hardware_params = {}

    try:
        # CPU Temperature - WMI
        try:
            cmd_cpu_temp = (
                "Get-WmiObject -Namespace 'root\\wmi' "
                "-Class MSAcpi_ThermalZoneTemperature | "
                "Select-Object CurrentTemperature | "
                "ConvertTo-Json"
            )
            output = run_powershell_hidden(cmd_cpu_temp)
            if output and output.strip():
                try:
                    temp_data = json.loads(output)
                    if not isinstance(temp_data, list):
                        temp_data = [temp_data]
                    if temp_data and isinstance(temp_data[0], dict):
                        temp_raw = temp_data[0].get("CurrentTemperature")
                        if temp_raw:
                            temp_celsius = (temp_raw / 10.0) - 273.15
                            hardware_params["cpu_temp_celsius"] = round(temp_celsius, 2)
                except json.JSONDecodeError:
                    pass
        except (RuntimeError, Exception) as e:
            logger.debug(f"[BSOD_DUMPS] Failed to get CPU temperature via WMI: {e}")

        # GPU Temperature - GPUtil lub WMI
        try:
            import GPUtil
            gpus = GPUtil.getGPUs()
            if gpus:
                gpu_temps = [gpu.temperature for gpu in gpus if gpu.temperature]
                if gpu_temps:
                    hardware_params["gpu_temp_celsius"] = gpu_temps[0]
        except ImportError:
            pass
        except Exception as e:
            logger.debug(f"[BSOD_DUMPS] Failed to get GPU temperature: {e}")

        # CPU Load i RAM Usage - psutil
        try:
            import psutil
            hardware_params["cpu_load_percent"] = round(psutil.cpu_percent(interval=1), 2)
            hardware_params["ram_total_gb"] = round(
                psutil.virtual_memory().total / (1024**3), 2
            )
            hardware_params["ram_used_gb"] = round(
                psutil.virtual_memory().used / (1024**3), 2
            )
            hardware_params["ram_usage_percent"] = round(
                psutil.virtual_memory().percent, 2
            )
        except ImportError:
            pass
        except Exception as e:
            logger.debug(f"[BSOD_DUMPS] Error getting CPU/RAM info: {e}")

        # Voltage i Fan Speed - WMI (jeśli dostępne)
        try:
            cmd_voltage = (
                "Get-WmiObject -Namespace 'root\\wmi' "
                "-Class Win32_VoltageProbe | "
                "Select-Object CurrentVoltage | "
                "ConvertTo-Json"
            )
            output = run_powershell_hidden(cmd_voltage)
            if output and output.strip():
                try:
                    voltage_data = json.loads(output)
                    if not isinstance(voltage_data, list):
                        voltage_data = [voltage_data]
                    if voltage_data and isinstance(voltage_data[0], dict):
                        voltage = voltage_data[0].get("CurrentVoltage")
                        if voltage:
                            hardware_params["voltage_mv"] = voltage
                except json.JSONDecodeError:
                    pass
        except (RuntimeError, Exception) as e:
            logger.debug(f"[BSOD_DUMPS] Failed to get voltage info: {e}")

    except Exception as e:
        logger.debug(f"[BSOD_DUMPS] Error collecting hardware parameters: {e}")

    return hardware_params if hardware_params else None


def _get_hardware_context_optional():
    """
    Pobiera opcjonalny kontekst sprzętowy (temperatury, SMART, RAM).

    Zbiera rozszerzone dane potrzebne do analizy crashy:
    - CPU temperature, load
    - GPU temperature
    - RAM usage (total, used, percent, swap)
    - SMART status dysków
    - CPU/GPU throttling info (jeśli dostępne)
    - Voltages / fan speeds (opcjonalnie)

    Returns:
        dict: Dane sprzętowe lub None jeśli nie dostępne
    """
    hardware_context = {}

    # Użyj nowej funkcji do pobrania temperatury i parametrów
    hardware_params = _get_hardware_temperature_and_parameters()
    if hardware_params:
        hardware_context.update(hardware_params)
    
    # Dodaj szczegółowe informacje o RAM (jeśli jeszcze nie ma)
    if "ram_used_gb" not in hardware_context:
        try:
            import psutil
            ram = psutil.virtual_memory()
            swap = psutil.swap_memory()
            hardware_context["ram"] = {
                "total_gb": round(ram.total / (1024**3), 2),
                "used_gb": round(ram.used / (1024**3), 2),
                "available_gb": round(ram.available / (1024**3), 2),
                "usage_percent": round(ram.percent, 2),
                "swap_total_gb": round(swap.total / (1024**3), 2),
                "swap_used_gb": round(swap.used / (1024**3), 2),
                "swap_usage_percent": round(swap.percent, 2) if swap.total > 0 else 0
            }
        except ImportError:
            pass
        except Exception as e:
            logger.debug(f"[BSOD_DUMPS] Error getting RAM info: {e}")

    # Użyj nowej funkcji do pobrania szczegółowych danych SMART
    smart_disks = _get_enhanced_smart_disk_health()
    if smart_disks:
        hardware_context["disks"] = smart_disks
        hardware_context["smart_disks"] = smart_disks  # Dla zgodności

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
    # Ujednolicona struktura JSON - zawsze obecne pola (nawet jeśli puste)
    bsod_data = {
        "source": "bsod_collector",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "bugchecks": [],
        "minidumps": [],
        "recent_crashes": [],
        "whea_errors": [],
        "system_events": {
            "system_events": [],
            "driver_events": [],
            "application_events": []
        },
        "hardware": {
            "cpu_temp": None,
            "gpu_temp": None,
            "cpu_load": None,
            "ram_used": None,
            "ram_total": None,
            "ram_usage_percent": None,
            "disks": []
        },
        "collection_error": None
    }

    if sys.platform != "win32":
        bsod_data["error"] = "Windows only"
        return bsod_data

    # Zbierz wszystkie dane
    logger.info("[BSOD_DUMPS] Starting BSOD collection")
    _collect_bugcheck_events(bsod_data)
    collect_minidumps(bsod_data)
    _collect_whea_events(bsod_data)

    # Dodaj opcjonalny kontekst sprzętowy - ujednolicona struktura
    hardware_context = _get_hardware_context_optional()
    if hardware_context:
        # Mapuj do ujednoliconej struktury hardware
        if hardware_context.get("cpu_temp_celsius") is not None:
            bsod_data["hardware"]["cpu_temp"] = hardware_context["cpu_temp_celsius"]
        if hardware_context.get("gpu_temp_celsius") is not None:
            bsod_data["hardware"]["gpu_temp"] = hardware_context["gpu_temp_celsius"]
        if hardware_context.get("cpu_load_percent") is not None:
            bsod_data["hardware"]["cpu_load"] = hardware_context["cpu_load_percent"]
        
        # RAM info
        if "ram" in hardware_context:
            ram = hardware_context["ram"]
            bsod_data["hardware"]["ram_used"] = ram.get("used_gb")
            bsod_data["hardware"]["ram_total"] = ram.get("total_gb")
            bsod_data["hardware"]["ram_usage_percent"] = ram.get("usage_percent")
        elif "ram_used_gb" in hardware_context:
            bsod_data["hardware"]["ram_used"] = hardware_context["ram_used_gb"]
            bsod_data["hardware"]["ram_total"] = hardware_context["ram_total_gb"]
            bsod_data["hardware"]["ram_usage_percent"] = hardware_context["ram_usage_percent"]
        
        # Dyski
        if "disks" in hardware_context:
            bsod_data["hardware"]["disks"] = hardware_context["disks"]
        elif "smart_disks" in hardware_context:
            bsod_data["hardware"]["disks"] = hardware_context["smart_disks"]
        
        # Zachowaj pełny hardware_context dla zgodności wstecznej
        bsod_data["hardware_context"] = hardware_context
        logger.info("[BSOD_DUMPS] Added hardware context")

    # Zbierz eventy systemowe i logi sterowników dla najnowszych crashy
    if bsod_data.get("bugchecks"):
        # Pobierz timestamp najnowszego bugcheck
        latest_bugcheck = max(
            bsod_data["bugchecks"],
            key=lambda x: x.get("timestamp", ""),
            default=None
        )
        if latest_bugcheck:
            crash_timestamp = latest_bugcheck.get("timestamp")
            system_events = _collect_system_events_and_driver_logs(crash_timestamp)
            if system_events:
                bsod_data["system_events"] = system_events
                logger.info("[BSOD_DUMPS] Added system events and driver logs")
    else:
        # Zbierz eventy systemowe bez filtrowania czasowego jeśli brak bugchecks
        system_events = _collect_system_events_and_driver_logs()
        if system_events:
            bsod_data["system_events"] = system_events

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
