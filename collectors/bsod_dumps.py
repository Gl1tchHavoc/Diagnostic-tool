"""
Collector BSOD i Memory Dumps - zbiera informacje o crashach systemu.
"""
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

from utils.logger import get_logger
from utils.minidump_parser import parse_minidump
from utils.subprocess_helper import run_powershell_hidden

logger = get_logger()


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

        bsod_data["bugchecks"].append({
            "event_id": str(event_id),
            "timestamp": timestamp,
            "message": message,
            "bugcheck_code": bugcheck_code,
            "bugcheck_parameters": bugcheck_params,
            "crashed_driver": crashed_driver,
            "dump_file": dump_file,
            "type": "BUGCHECK"
        })


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
            "type": "UNEXPECTED_SHUTDOWN"
        })


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


def _create_dump_info(dump_path, dump_type):
    """
    Tworzy informacje o pliku dump.

    Args:
        dump_path: Ścieżka do pliku dump
        dump_type: Typ dumpa ('MINIDUMP' lub 'FULL_DUMP')

    Returns:
        dict: Informacje o dumpie
    """
    stat = dump_path.stat()
    parsed_info = parse_minidump(str(dump_path))

    dump_info = {
        "path": str(dump_path),
        "size": stat.st_size,
        "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
        "type": dump_type
    }

    if parsed_info.get('success'):
        dump_info.update({
            "stop_code": parsed_info.get('stop_code'),
            "stop_code_name": parsed_info.get('stop_code_name'),
            "offending_driver": parsed_info.get('offending_driver'),
            "parameters": parsed_info.get('parameters', {})
        })

        if dump_type == "MINIDUMP":
            logger.info(
                f"[BSOD_DUMPS] Parsed minidump: {dump_path.name}, "
                f"STOP: {parsed_info.get('stop_code')}, "
                f"Driver: {parsed_info.get('offending_driver')}"
            )

    return dump_info


def _process_minidump_directory(dump_path, bsod_data):
    """
    Przetwarza katalog z minidumpami.

    Args:
        dump_path: Ścieżka do katalogu minidumpów
        bsod_data: Słownik z danymi BSOD do uzupełnienia
    """
    dump_files = sorted(
        dump_path.glob("*.dmp"),
        key=lambda p: p.stat().st_mtime,
        reverse=True
    )

    for dump_file in dump_files[:5]:  # Tylko 5 najnowszych
        try:
            dump_info = _create_dump_info(dump_file, "MINIDUMP")
            bsod_data["minidumps"].append(dump_info)
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
        dump_info = _create_dump_info(dump_path, "FULL_DUMP")
        bsod_data["minidumps"].append(dump_info)
    except Exception as e:
        logger.warning(
            f"[BSOD_DUMPS] Error processing MEMORY.DMP: {e}"
        )


def _collect_minidump_files(bsod_data):
    """
    Zbiera informacje o plikach minidump i MEMORY.DMP.

    Args:
        bsod_data: Słownik z danymi BSOD do uzupełnienia
    """
    minidump_paths = [
        Path("C:/Windows/Minidump"),
        Path("C:/Windows/MEMORY.DMP")
    ]

    for dump_path in minidump_paths:
        if not dump_path.exists():
            continue

        if dump_path.is_dir():
            _process_minidump_directory(dump_path, bsod_data)
        else:
            _process_single_dump_file(dump_path, bsod_data)


def _collect_whea_events(bsod_data):
    """
    Zbiera WHEA-Logger events (EventID 18, 19, 20).

    Args:
        bsod_data: Słownik z danymi BSOD do uzupełnienia
    """
    cmd = (
        "Get-WinEvent -LogName System -MaxEvents 100 | "
        "Where-Object {$_.Id -in @(18,19,20)} | "
        "ConvertTo-Xml -As String -Depth 3"
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

            whea_events.append({
                "event_id": str(event_id),
                "timestamp": timestamp,
                "message": message,
                "type": "WHEA_HARDWARE_ERROR"
            })

        if whea_events:
            bsod_data["whea_errors"] = whea_events
            logger.info(
                f"[BSOD_DUMPS] Found {len(whea_events)} WHEA hardware errors"
            )
    except ET.ParseError:
        pass
    except Exception as e:
        logger.debug(f"[BSOD_DUMPS] Could not collect WHEA events: {e}")


def collect():
    """
    Zbiera informacje o BSOD i memory dumps.
    Zwraca dane o crashach systemu, bugcheck codes i minidump files.
    """
    bsod_data = {
        "bugchecks": [],
        "minidumps": [],
        "recent_crashes": []
    }

    if sys.platform != "win32":
        bsod_data["error"] = "Windows only"
        return bsod_data

    _collect_bugcheck_events(bsod_data)
    _collect_minidump_files(bsod_data)
    _collect_whea_events(bsod_data)

    return bsod_data


def extract_bugcheck_code(message):
    """Wyciąga kod bugcheck z wiadomości."""
    import re

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
    import re
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
    import re
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
