"""
Collector BSOD i Memory Dumps - zbiera informacje o crashach systemu.
"""
import subprocess
import os
import sys
from pathlib import Path
from datetime import datetime


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

    try:
        # Sprawdź Event ID 1001 (Bugcheck) i 41 (Unexpected shutdown) - ukryte
        # okno
        cmd = "Get-WinEvent -LogName System -MaxEvents 200 | Where-Object {$_.Id -in @(41,1001,6008,1074,1076) -or $_.Message -like '*bugcheck*' -or $_.Message -like '*blue screen*' -or $_.Message -like '*stop error*'} | ConvertTo-Xml -As String -Depth 3"

        from utils.subprocess_helper import run_powershell_hidden
        output = run_powershell_hidden(cmd)

        import xml.etree.ElementTree as ET
        try:
            root = ET.fromstring(output)
            for obj in root.findall(".//Object"):
                record = {}
                for prop in obj.findall("Property"):
                    name = prop.attrib.get("Name")
                    if name:
                        record[name] = prop.text if prop.text else ""

                event_id = record.get("Id") or record.get("EventID", "N/A")
                message = record.get("Message", "")
                timestamp = record.get("TimeCreated") or record.get("Time", "")

                # Event ID 1001 - Bugcheck (szczegółowa analiza)
                if event_id == "1001" or "bugcheck" in message.lower():
                    # Wyciągnij szczegółowe informacje z Event 1001
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

                # Event ID 41 - Unexpected shutdown
                if event_id == "41" or "unexpected shutdown" in message.lower():
                    bsod_data["recent_crashes"].append({
                        "event_id": str(event_id),
                        "timestamp": timestamp,
                        "message": message,
                        "type": "UNEXPECTED_SHUTDOWN"
                    })
        except ET.ParseError:
            pass
    except subprocess.CalledProcessError:
        pass
    except Exception as e:
        bsod_data["collection_error"] = f"Failed to collect BSOD events: {e}"

    # Sprawdź minidump files i parsuj je
    from utils.logger import get_logger
    from utils.minidump_parser import parse_minidump

    logger = get_logger()
    minidump_paths = [
        Path("C:/Windows/Minidump"),
        Path("C:/Windows/MEMORY.DMP")
    ]

    for dump_path in minidump_paths:
        if dump_path.exists():
            if dump_path.is_dir():
                # Katalog z minidumpami - znajdź najnowszy
                dump_files = sorted(
                    dump_path.glob("*.dmp"),
                    key=lambda p: p.stat().st_mtime,
                    reverse=True)
                for dump_file in dump_files[:5]:  # Tylko 5 najnowszych
                    try:
                        stat = dump_file.stat()
                        # Parsuj minidump
                        parsed_info = parse_minidump(str(dump_file))

                        dump_info = {
                            "path": str(dump_file),
                            "size": stat.st_size,
                            "modified": datetime.fromtimestamp(
                                stat.st_mtime).isoformat(),
                            "type": "MINIDUMP"}

                        # Dodaj sparsowane informacje
                        if parsed_info.get('success'):
                            dump_info.update({
                                "stop_code": parsed_info.get('stop_code'),
                                "stop_code_name": parsed_info.get('stop_code_name'),
                                "offending_driver": parsed_info.get('offending_driver'),
                                "parameters": parsed_info.get('parameters', {})
                            })
                            logger.info(
                                f"[BSOD_DUMPS] Parsed minidump: {dump_file.name}, STOP: {parsed_info.get('stop_code')}, Driver: {parsed_info.get('offending_driver')}")

                        bsod_data["minidumps"].append(dump_info)
                    except Exception as e:
                        logger.warning(
                            f"[BSOD_DUMPS] Error processing minidump {dump_file}: {e}")
            else:
                # Pojedynczy plik MEMORY.DMP
                try:
                    stat = dump_path.stat()
                    parsed_info = parse_minidump(str(dump_path))

                    dump_info = {
                        "path": str(dump_path),
                        "size": stat.st_size,
                        "modified": datetime.fromtimestamp(
                            stat.st_mtime).isoformat(),
                        "type": "FULL_DUMP"}

                    if parsed_info.get('success'):
                        dump_info.update({
                            "stop_code": parsed_info.get('stop_code'),
                            "stop_code_name": parsed_info.get('stop_code_name'),
                            "offending_driver": parsed_info.get('offending_driver'),
                            "parameters": parsed_info.get('parameters', {})
                        })

                    bsod_data["minidumps"].append(dump_info)
                except Exception as e:
                    logger.warning(
                        f"[BSOD_DUMPS] Error processing MEMORY.DMP: {e}")

    # Sprawdź WHEA-Logger events (EventID 18, 19, 20)
    try:
        logger.debug("[BSOD_DUMPS] Checking WHEA-Logger events")
        cmd = "Get-WinEvent -LogName System -MaxEvents 100 | Where-Object {$_.Id -in @(18,19,20)} | ConvertTo-Xml -As String -Depth 3"
        from utils.subprocess_helper import run_powershell_hidden
        output = run_powershell_hidden(cmd)

        import xml.etree.ElementTree as ET
        try:
            root = ET.fromstring(output)
            whea_events = []
            for obj in root.findall(".//Object"):
                record = {}
                for prop in obj.findall("Property"):
                    name = prop.attrib.get("Name")
                    if name:
                        record[name] = prop.text if prop.text else ""

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
                    f"[BSOD_DUMPS] Found {len(whea_events)} WHEA hardware errors")
        except ET.ParseError:
            pass
    except Exception as e:
        logger.debug(f"[BSOD_DUMPS] Could not collect WHEA events: {e}")

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
