"""
Collector Windows Error Reporting (WER) - zbiera szczegółowe dane o crashach aplikacji i systemu.
Zbiera dane z Event Log oraz katalogów WER, grupuje powtarzające się crashy i integruje z golden rules.
"""
import subprocess
import sys
import os
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from datetime import datetime, timedelta
from collections import defaultdict
from utils.subprocess_helper import run_powershell_hidden
from utils.logger import get_logger

logger = get_logger()

# Event IDs do zbierania
WER_EVENT_IDS = [1000, 1001, 1002, 1005, 1008]

def collect():
    """
    Zbiera szczegółowe dane z Windows Error Reporting o crashach aplikacji i systemu.
    
    Returns:
        dict: {
            "recent_crashes": [list of crash events],
            "reports": [list of WER report directories],
            "grouped_crashes": [grouped crashes with occurrences],
            "statistics": {
                "total_crashes": int,
                "crashes_last_30min": int,
                "crashes_last_24h": int,
                "repeating_crashes": int
            }
        }
    """
    wer_data = {
        "recent_crashes": [],
        "reports": [],
        "grouped_crashes": [],
        "statistics": {
            "total_crashes": 0,
            "crashes_last_30min": 0,
            "crashes_last_24h": 0,
            "repeating_crashes": 0
        }
    }
    
    if sys.platform != "win32":
        wer_data["error"] = "Windows only"
        return wer_data
    
    try:
        # Krok 1: Zbieranie z Event Log
        logger.info("[WER] Collecting crash data from Event Log")
        event_crashes = collect_from_event_log()
        wer_data["recent_crashes"].extend(event_crashes)
        
        # Krok 2: Zbieranie z katalogów WER
        logger.info("[WER] Collecting crash data from WER directories")
        wer_reports = collect_from_wer_directories()
        wer_data["reports"].extend(wer_reports)
        
        # Krok 3: Grupowanie i analiza powtarzających się crashy
        logger.info("[WER] Grouping and analyzing repeating crashes")
        grouped = group_and_analyze_crashes(wer_data["recent_crashes"])
        wer_data["grouped_crashes"] = grouped
        
        # Krok 4: Oblicz statystyki
        now = datetime.now()
        last_30min = now - timedelta(minutes=30)
        last_24h = now - timedelta(hours=24)
        
        # Bezpieczne filtrowanie crashy z timestampami
        crashes_30min = []
        crashes_24h = []
        for c in wer_data["recent_crashes"]:
            if not isinstance(c, dict):
                continue
            timestamp = parse_timestamp(c.get("timestamp", ""))
            if timestamp is not None:
                if timestamp >= last_30min:
                    crashes_30min.append(c)
                if timestamp >= last_24h:
                    crashes_24h.append(c)
        
        # Bezpieczne filtrowanie powtarzających się crashy
        repeating = []
        for g in grouped:
            if isinstance(g, dict):
                occurrences_30min = g.get("occurrences_30min", 0)
                if isinstance(occurrences_30min, (int, float)) and occurrences_30min >= 3:
                    repeating.append(g)
        
        wer_data["statistics"] = {
            "total_crashes": len(wer_data["recent_crashes"]),
            "crashes_last_30min": len(crashes_30min),
            "crashes_last_24h": len(crashes_24h),
            "repeating_crashes": len(repeating)
        }
        
        logger.info(f"[WER] Collected {wer_data['statistics']['total_crashes']} crashes, "
                   f"{wer_data['statistics']['crashes_last_30min']} in last 30min, "
                   f"{wer_data['statistics']['repeating_crashes']} repeating")
        
    except Exception as e:
        logger.exception(f"[WER] Exception during collection: {e}")
        wer_data["collection_error"] = f"Failed to collect WER data: {e}"
    
    return wer_data


def collect_from_event_log():
    """
    Zbiera dane o crashach z Windows Event Log.
    
    Returns:
        list: Lista crash events z szczegółowymi danymi
    """
    crashes = []
    
    try:
        # Pobierz eventy z Event IDs: 1000, 1001, 1002, 1005, 1008
        event_ids_str = ",".join(str(eid) for eid in WER_EVENT_IDS)
        cmd = (
            f"Get-WinEvent -LogName Application -MaxEvents 500 -ErrorAction SilentlyContinue | "
            f"Where-Object {{$_.Id -in @({event_ids_str})}} | "
            f"ConvertTo-Xml -As String -Depth 5"
        )
        
        output = run_powershell_hidden(cmd)
        
        if not output or len(output.strip()) < 50:
            logger.warning("[WER] Empty or invalid output from Event Log")
            return crashes
        
        # Parsuj XML
        root = ET.fromstring(output)
        
        for obj in root.findall(".//Object"):
            record = {}
            for prop in obj.findall("Property"):
                name = prop.attrib.get("Name", "")
                if name:
                    # Pobierz wartość - może być w tekście lub w zagnieżdżonych właściwościach
                    value = prop.text if prop.text else ""
                    # Sprawdź zagnieżdżone właściwości
                    nested = prop.findall("Property")
                    if nested:
                        nested_dict = {}
                        for n in nested:
                            n_name = n.attrib.get("Name", "")
                            n_value = n.text if n.text else ""
                            nested_dict[n_name] = n_value
                        if nested_dict:
                            record[name] = nested_dict
                        else:
                            record[name] = value
                    else:
                        record[name] = value
            
            # Wyciągnij szczegółowe dane
            crash = extract_crash_details(record)
            if crash:
                crashes.append(crash)
        
        logger.info(f"[WER] Extracted {len(crashes)} crashes from Event Log")
        
    except ET.ParseError as e:
        logger.error(f"[WER] XML parse error: {e}")
    except subprocess.CalledProcessError as e:
        logger.error(f"[WER] PowerShell command failed: {e}")
    except Exception as e:
        logger.exception(f"[WER] Exception in collect_from_event_log: {e}")
    
    return crashes


def extract_crash_details(record):
    """
    Wyciąga szczegółowe dane o crashu z rekordu Event Log.
    
    Args:
        record (dict): Rekord z Event Log
        
    Returns:
        dict: Szczegółowe dane o crashu lub None
    """
    try:
        event_id = str(record.get("Id") or record.get("EventID", ""))
        if not event_id or event_id not in [str(eid) for eid in WER_EVENT_IDS]:
            return None
        
        message = record.get("Message", "") or ""
        timestamp = record.get("TimeCreated") or record.get("Time", "")
        provider = record.get("ProviderName", "") or ""
        
        # Wyciągnij szczegółowe informacje z message
        app_name = extract_field_from_message(message, [
            r'Application\s+Name:\s*([^\r\n]+)',
            r'Faulting\s+application\s+name:\s*([^\r\n]+)',
            r'Application:\s*([^\r\n,]+)'
        ])
        
        app_version = extract_field_from_message(message, [
            r'Application\s+Version:\s*([^\r\n]+)',
            r'Application\s+Version\s+String:\s*([^\r\n]+)'
        ])
        
        module_name = extract_field_from_message(message, [
            r'Faulting\s+module\s+name:\s*([^\r\n]+)',
            r'Module\s+Name:\s*([^\r\n]+)'
        ])
        
        module_version = extract_field_from_message(message, [
            r'Faulting\s+module\s+version:\s*([^\r\n]+)',
            r'Module\s+Version:\s*([^\r\n]+)'
        ])
        
        exception_code = extract_field_from_message(message, [
            r'Exception\s+Code:\s*([^\r\n]+)',
            r'Exception\s+code:\s*([^\r\n]+)',
            r'ExceptionCode:\s*([^\r\n]+)'
        ])
        
        process_id = extract_field_from_message(message, [
            r'Process\s+Id:\s*(\d+)',
            r'ProcessId:\s*(\d+)'
        ])
        
        thread_id = extract_field_from_message(message, [
            r'Thread\s+Id:\s*(\d+)',
            r'ThreadId:\s*(\d+)'
        ])
        
        # Wyciągnij wersję OS z message
        os_version = extract_field_from_message(message, [
            r'OS\s+Version:\s*([^\r\n]+)',
            r'Operating\s+System\s+Version:\s*([^\r\n]+)'
        ])
        
        crash = {
            "event_id": event_id,
            "timestamp": timestamp,
            "message": message[:500] if len(message) > 500 else message,  # Ogranicz długość
            "provider": provider,
            "application": app_name or "Unknown",
            "app_version": app_version or "",
            "module_name": module_name or "",
            "module_version": module_version or "",
            "exception_code": exception_code or "",
            "process_id": process_id or "",
            "thread_id": thread_id or "",
            "os_version": os_version or "",
            "type": determine_crash_type(app_name, module_name, exception_code)
        }
        
        return crash
        
    except Exception as e:
        logger.debug(f"[WER] Error extracting crash details: {e}")
        return None


def extract_field_from_message(message, patterns):
    """
    Wyciąga pole z wiadomości używając wzorców regex.
    
    Args:
        message (str): Wiadomość do przeszukania
        patterns (list): Lista wzorców regex
        
    Returns:
        str: Wyciągnięta wartość lub None
    """
    if not message:
        return None
    
    for pattern in patterns:
        match = re.search(pattern, message, re.IGNORECASE | re.MULTILINE)
        if match:
            value = match.group(1).strip()
            if value:
                return value
    
    return None


def determine_crash_type(app_name, module_name, exception_code):
    """
    Określa typ crashu na podstawie aplikacji, modułu i kodu wyjątku.
    
    Args:
        app_name (str): Nazwa aplikacji
        module_name (str): Nazwa modułu
        exception_code (str): Kod wyjątku
        
    Returns:
        str: Typ crashu
    """
    app_lower = (app_name or "").lower()
    module_lower = (module_name or "").lower()
    
    # Systemowe procesy
    system_processes = ["winlogon.exe", "csrss.exe", "lsass.exe", "services.exe", 
                        "smss.exe", "wininit.exe", "dwm.exe"]
    
    if any(proc in app_lower for proc in system_processes):
        return "SYSTEM_CRASH"
    
    # ntdll.dll crashy są często systemowe
    if "ntdll.dll" in module_lower:
        return "SYSTEM_CRASH"
    
    # Kernel mode exceptions
    if exception_code and any(code in exception_code.upper() for code in ["0xC0000005", "0xC0000409", "0xC000001D"]):
        return "KERNEL_CRASH"
    
    return "APPLICATION_CRASH"


def collect_from_wer_directories():
    """
    Zbiera dane z katalogów Windows Error Reporting.
    
    Returns:
        list: Lista raportów WER
    """
    reports = []
    
    # Ścieżki do katalogów WER
    wer_paths = [
        Path(os.environ.get("LOCALAPPDATA", "")) / "Microsoft" / "Windows" / "WER",
        Path("C:/ProgramData/Microsoft/Windows/WER")
    ]
    
    for wer_path in wer_paths:
        if not wer_path.exists():
            continue
        
        try:
            # Zlicz foldery i pliki *.wer
            report_dirs = [d for d in wer_path.iterdir() if d.is_dir()]
            wer_files = list(wer_path.rglob("*.wer"))
            
            logger.debug(f"[WER] Found {len(report_dirs)} report directories and {len(wer_files)} .wer files in {wer_path}")
            
            # Pobierz info o ostatnich raportach
            for report_dir in sorted(report_dirs, key=lambda x: x.stat().st_mtime, reverse=True)[:20]:
                try:
                    stat = report_dir.stat()
                    report_info = {
                        "path": str(report_dir),
                        "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                        "size": stat.st_size
                    }
                    
                    # Spróbuj wyciągnąć informacje z plików w katalogu
                    wer_file = report_dir / "Report.wer"
                    if wer_file.exists():
                        report_info["has_wer_file"] = True
                        # Można tutaj dodać parsowanie pliku .wer jeśli potrzeba
                    
                    reports.append(report_info)
                    
                except Exception as e:
                    logger.debug(f"[WER] Error processing report directory {report_dir}: {e}")
                    continue
            
            # Jeśli znaleziono raporty, nie sprawdzaj kolejnej ścieżki
            if reports:
                break
                
        except Exception as e:
            logger.debug(f"[WER] Error accessing WER directory {wer_path}: {e}")
            continue
    
    logger.info(f"[WER] Collected {len(reports)} WER reports from directories")
    return reports


def group_and_analyze_crashes(crashes):
    """
    Grupuje crashy po kombinacji: application + faulting_module + exception_code.
    Zlicza wystąpienia w ostatnich 30 minutach i 24 godzinach.
    
    Args:
        crashes (list): Lista crash events
        
    Returns:
        list: Zgrupowane crashy z occurrences
    """
    grouped = defaultdict(list)
    now = datetime.now()
    last_30min = now - timedelta(minutes=30)
    last_24h = now - timedelta(hours=24)
    
    # Grupuj crashy
    for crash in crashes:
        # Upewnij się, że crash jest słownikiem
        if not isinstance(crash, dict):
            logger.debug(f"[WER] Skipping non-dict crash: {type(crash)}")
            continue
        
        app = crash.get("application", "Unknown")
        module = crash.get("module_name", "")
        exception = crash.get("exception_code", "")
        
        # Klucz grupowania
        key = (app.lower(), module.lower() if module else "", exception.upper() if exception else "")
        
        crash_time = parse_timestamp(crash.get("timestamp", ""))
        if crash_time:
            grouped[key].append({
                "crash": crash,
                "timestamp": crash_time
            })
    
    # Utwórz zgrupowane wyniki
    grouped_results = []
    
    for key, crash_list in grouped.items():
        app, module, exception = key
        
        # Upewnij się, że crash_list nie jest puste
        if not crash_list:
            logger.debug(f"[WER] Skipping empty crash_list for key: {key}")
            continue
        
        # Sortuj po czasie (najnowsze pierwsze)
        try:
            crash_list.sort(key=lambda x: x.get("timestamp") if isinstance(x, dict) and "timestamp" in x else datetime.min, reverse=True)
        except Exception as e:
            logger.warning(f"[WER] Error sorting crash_list for {key}: {e}")
            continue
        
        # Zlicz wystąpienia w oknach czasowych
        crashes_30min = []
        crashes_24h = []
        for c in crash_list:
            if not isinstance(c, dict):
                continue
            timestamp = c.get("timestamp")
            if timestamp and isinstance(timestamp, datetime):
                if timestamp >= last_30min:
                    crashes_30min.append(c)
                if timestamp >= last_24h:
                    crashes_24h.append(c)
        
        # Określ czy to powtarzający się crash (≥3 w 30 min)
        is_repeating = len(crashes_30min) >= 3
        
        # Bezpieczne pobranie pierwszego i ostatniego crasha
        first_crash = crash_list[-1].get("crash", {}) if crash_list and isinstance(crash_list[-1], dict) else {}
        last_crash = crash_list[0].get("crash", {}) if crash_list and isinstance(crash_list[0], dict) else {}
        
        grouped_result = {
            "application": app,
            "module_name": module,
            "exception_code": exception,
            "total_occurrences": len(crash_list),
            "occurrences_30min": len(crashes_30min),
            "occurrences_24h": len(crashes_24h),
            "is_repeating": is_repeating,
            "first_occurrence": first_crash.get("timestamp", "") if isinstance(first_crash, dict) else "",
            "last_occurrence": last_crash.get("timestamp", "") if isinstance(last_crash, dict) else "",
            "latest_crash": last_crash if isinstance(last_crash, dict) else {}
        }
        
        grouped_results.append(grouped_result)
    
    # Sortuj po liczbie wystąpień (najczęstsze pierwsze)
    grouped_results.sort(key=lambda x: x["total_occurrences"], reverse=True)
    
    logger.info(f"[WER] Grouped {len(crashes)} crashes into {len(grouped_results)} groups")
    
    return grouped_results


def parse_timestamp(timestamp_str):
    """
    Parsuje timestamp string do datetime object.
    
    Args:
        timestamp_str (str): String timestamp
        
    Returns:
        datetime: Parsed timestamp lub None
    """
    if not timestamp_str:
        return None
    
    # Różne formaty timestampów z Event Log
    formats = [
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%m/%d/%Y %I:%M:%S %p",  # Format Windows Event Log
        "%m/%d/%Y %H:%M:%S"
    ]
    
    for fmt in formats:
        try:
            return datetime.strptime(timestamp_str[:19], fmt)
        except (ValueError, IndexError):
            continue
    
    # Spróbuj parsować jako ISO format
    try:
        return datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
    except:
        pass
    
    return None
