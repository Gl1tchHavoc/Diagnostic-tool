"""
Collector Windows Error Reporting (WER) - zbiera szczegółowe dane o crashach aplikacji i systemu.
Zbiera dane z Event Log oraz katalogów WER, grupuje powtarzające się crashy i integruje z golden rules.
"""
import configparser
import os
import re
import subprocess
import sys
import winreg
import xml.etree.ElementTree as ET
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

from utils.logger import get_logger
from utils.subprocess_helper import run_powershell_hidden

logger = get_logger()

# Event IDs do zbierania
WER_EVENT_IDS = [1000, 1001, 1002, 1005, 1008]


def _initialize_local_dumps_result():
    """
    Inicjalizuje strukturę wyniku check_local_dumps.

    Returns:
        dict: Pusta struktura wyniku
    """
    return {
        "enabled": False,
        "dump_count": None,
        "dump_type": None,
        "dump_folder": None,
        "folder_exists": False,
        "warnings": []
    }


def _read_registry_value(key, value_name, result):
    """
    Czyta wartość z klucza rejestru.

    Args:
        key: Klucz rejestru
        value_name: Nazwa wartości
        result: Słownik wyniku do uzupełnienia

    Returns:
        object: Wartość z rejestru lub None
    """
    try:
        value, _ = winreg.QueryValueEx(key, value_name)
        return value
    except FileNotFoundError:
        result["warnings"].append(f"{value_name} missing")
        return None


def _read_dump_folder(key, result):
    """
    Czyta DumpFolder z rejestru i sprawdza czy folder istnieje.

    Args:
        key: Klucz rejestru
        result: Słownik wyniku do uzupełnienia

    Returns:
        str: Ścieżka do folderu lub None
    """
    dump_folder = _read_registry_value(key, "DumpFolder", result)
    if dump_folder:
        dump_folder = os.path.expandvars(dump_folder)
        result["dump_folder"] = dump_folder
        result["folder_exists"] = os.path.isdir(dump_folder)
    return dump_folder


def _read_local_dumps_registry(result):
    """
    Czyta wartości LocalDumps z rejestru.

    Args:
        result: Słownik wyniku do uzupełnienia
    """
    key_path = (
        r"SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps"
    )

    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            key_path,
            0,
            winreg.KEY_READ
        ) as key:
            result["dump_type"] = _read_registry_value(key, "DumpType", result)
            result["dump_count"] = _read_registry_value(
                key, "DumpCount", result
            )
            _read_dump_folder(key, result)
    except FileNotFoundError:
        result["warnings"].append("LocalDumps registry key missing")
    except PermissionError:
        result["warnings"].append(
            "Cannot access registry - admin rights may be required"
        )
    except Exception as e:
        result["warnings"].append(f"Error checking LocalDumps: {e}")


def check_local_dumps():
    """
    ✅ 1. AUTODETEKCJA – sprawdza, czy LocalDumps jest włączone.

    Returns:
        dict: {
            "enabled": bool,
            "dump_count": int or None,
            "dump_type": int or None,
            "dump_folder": str or None,
            "folder_exists": bool,
            "warnings": list
        }
    """
    result = _initialize_local_dumps_result()
    _read_local_dumps_registry(result)

    # Enabled if DumpType exists
    if result["dump_type"] is not None:
        result["enabled"] = True

    return result


def enable_local_dumps(dump_folder=r"%LOCALAPPDATA%\CrashDumps"):
    """
    ✅ 2. AUTOKONFIGURACJA – włącza LocalDumps automatycznie.

    Args:
        dump_folder (str): Ścieżka do folderu z dumpami (może zawierać zmienne środowiskowe)

    Returns:
        bool: True jeśli udało się włączyć, False w przeciwnym razie
    """
    key_path = r"SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps"

    try:
        # Create/open key
        key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, key_path)

        # Set values
        winreg.SetValueEx(
            key,
            "DumpType",
            0,
            winreg.REG_DWORD,
            2)   # Full dump
        winreg.SetValueEx(key, "DumpCount", 0, winreg.REG_DWORD, 10)
        winreg.SetValueEx(
            key,
            "DumpFolder",
            0,
            winreg.REG_EXPAND_SZ,
            dump_folder)

        winreg.CloseKey(key)

        # Expand folder
        expanded_folder = os.path.expandvars(dump_folder)
        if not os.path.isdir(expanded_folder):
            os.makedirs(expanded_folder, exist_ok=True)

        logger.info(
            f"[WER] LocalDumps enabled successfully. Dump folder: {expanded_folder}")
        return True

    except PermissionError:
        logger.error("[WER] Cannot enable LocalDumps – admin rights required.")
        return False
    except Exception as e:
        logger.error(f"[WER] Error enabling LocalDumps: {e}")
        return False


def _initialize_wer_data():
    """Inicjalizuje strukturę danych WER."""
    return {
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


def _check_and_setup_local_dumps(wer_data):
    """Sprawdza i konfiguruje LocalDumps."""
    logger.info("[WER] Checking LocalDumps configuration...")
    ld = check_local_dumps()

    if not ld["enabled"]:
        logger.warning(
            "[WER] LocalDumps is DISABLED – crash diagnostics will be "
            "incomplete.")

        # Attempt auto-fix
        if enable_local_dumps():
            logger.info("[WER] LocalDumps was enabled automatically.")
            print(
                "⚠️ LocalDumps were disabled. Enabled now.\n"
                "Please trigger a crash and re-run the tool for full "
                "diagnostics.")
        else:
            logger.warning(
                "[WER] LocalDumps could not be enabled automatically.")
            print(
                "⚠️ LocalDumps are disabled and cannot be automatically "
                "enabled.\n"
                "Run the program as administrator or enable manually.")
    else:
        logger.info(
            f"[WER] LocalDumps is enabled. Dump folder: "
            f"{ld.get('dump_folder', 'N/A')}")
        if ld.get("warnings"):
            logger.warning(f"[WER] LocalDumps warnings: {ld['warnings']}")

    wer_data["local_dumps"] = ld
    return ld


def _collect_all_crashes(wer_data):
    """Zbiera crashy z Event Log i WER directories."""
    # Krok 1: Zbieranie z Event Log
    logger.info("[WER] Collecting crash data from Event Log")
    event_crashes = collect_from_event_log()
    wer_data["recent_crashes"].extend(event_crashes)

    # 2️⃣ Parsowanie .wer files z ReportQueue i ReportArchive
    logger.info(
        "[WER] Collecting crash data from WER directories "
        "(ReportQueue, ReportArchive)")
    wer_crashes = collect_from_wer_directories()
    wer_data["recent_crashes"].extend(wer_crashes)

    # Dla kompatybilności, zapisz informacje o liczbie sparsowanych plików
    if wer_crashes:
        wer_data["reports"].append({
            "source": "wer_file",
            "count": len(wer_crashes),
            "description": (
                f"Parsed {len(wer_crashes)} .wer files from "
                "ReportQueue/ReportArchive")
        })


def _validate_grouped_crashes(grouped):
    """Waliduje i normalizuje grouped_crashes - upewnia się, że to lista."""
    # DEBUG: Szczegółowe logowanie typu
    logger.debug(
        f"[WER] group_and_analyze_crashes() returned type: {type(grouped)}")
    logger.debug(
        f"[WER] group_and_analyze_crashes() is list: "
        f"{isinstance(grouped, list)}")
    logger.debug(
        f"[WER] group_and_analyze_crashes() is dict: "
        f"{isinstance(grouped, dict)}")

    if isinstance(grouped, list):
        logger.debug(f"[WER] group_and_analyze_crashes() length: {len(grouped)}")
        if len(grouped) > 0:
            logger.debug(
                f"[WER] group_and_analyze_crashes() first element type: "
                f"{type(grouped[0])}")
            logger.debug(
                f"[WER] group_and_analyze_crashes() first element is dict: "
                f"{isinstance(grouped[0], dict)}")
    elif isinstance(grouped, dict):
        logger.debug(
            f"[WER] group_and_analyze_crashes() dict keys: "
            f"{list(grouped.keys())[:10]}")
    sys.stdout.flush()

    # KRYTYCZNE: Upewnij się, że grouped jest ZAWSZE listą
    if not isinstance(grouped, list):
        logger.error(
            f"[WER] CRITICAL: group_and_analyze_crashes returned "
            f"{type(grouped)}, expected list! Converting...")
        if isinstance(grouped, dict):
            logger.warning(
                f"[WER] grouped is dict with keys: "
                f"{list(grouped.keys())[:5] if grouped else 'empty'}")
            grouped = [grouped] if grouped else []
        else:
            grouped = [grouped] if grouped is not None else []

    # DODATKOWA WALIDACJA: Upewnij się, że wszystkie elementy są dict
    if isinstance(grouped, list):
        validated_grouped = []
        for i, item in enumerate(grouped):
            logger.debug(
                f"[WER] grouped_crashes[{i}] type: {type(item)}, "
                f"is_dict: {isinstance(item, dict)}")
            if isinstance(item, dict):
                validated_grouped.append(item)
            else:
                logger.warning(
                    f"[WER] grouped_crashes[{i}] is not a dict: {type(item)}, "
                    f"value sample: {str(item)[:100]}, skipping")
        grouped = validated_grouped

    return grouped


def _simplify_crashes(wer_data, max_recent=50):
    """Upraszcza i ogranicza recent_crashes."""
    if not wer_data["recent_crashes"]:
        return

    original_count = len(wer_data["recent_crashes"])
    try:
        wer_data["recent_crashes"].sort(
            key=lambda x: parse_timestamp(x.get("timestamp", ""))
            if isinstance(x, dict) else datetime.min,
            reverse=True
        )
    except Exception as e:
        logger.warning(f"[WER] Error sorting recent_crashes: {e}")

    simplified = []
    for crash in wer_data["recent_crashes"][:max_recent]:
        if isinstance(crash, dict):
            simplified.append({
                "event_id": str(crash.get("event_id", ""))[:20],
                "timestamp": str(crash.get("timestamp", ""))[:50],
                "application": str(crash.get("application", ""))[:100],
                "module_name": str(crash.get("module_name", ""))[:100],
                "exception_code": str(crash.get("exception_code", ""))[:50],
                "type": str(crash.get("type", ""))[:50]
            })
        else:
            simplified.append(crash)

    wer_data["recent_crashes"] = simplified
    if original_count > max_recent:
        logger.info(
            f"[WER] Limited recent_crashes: {original_count} -> "
            f"{len(simplified)}")


def _simplify_grouped_crashes(wer_data, max_groups=20):
    """Upraszcza i ogranicza grouped_crashes."""
    if not wer_data.get("grouped_crashes"):
        return

    grouped_crashes = wer_data.get("grouped_crashes", [])
    if not isinstance(grouped_crashes, list):
        logger.error(
            f"[WER] CRITICAL: grouped_crashes is not a list! "
            f"Type: {type(grouped_crashes)}")
        from utils.error_analyzer import log_error_with_analysis
        log_error_with_analysis(
            TypeError(
                f"grouped_crashes is {type(grouped_crashes).__name__} "
                "instead of list"),
            grouped_crashes,
            {
                'variable_name': 'grouped_crashes',
                'location': 'wer.py:_simplify_grouped_crashes',
                'function': '_simplify_grouped_crashes'
            },
            continue_execution=True
        )
        grouped_crashes = []

    original_count = len(grouped_crashes)
    simplified_groups = []

    for idx, group in enumerate(grouped_crashes[:max_groups]):
        if not isinstance(group, dict):
            logger.warning(
                f"[WER] group[{idx}] is not a dict: {type(group)}, skipping")
            continue

        try:
            simplified = {
                "application": group.get("application", ""),
                "module_name": group.get("module_name", ""),
                "exception_code": group.get("exception_code", ""),
                "total_occurrences": group.get("total_occurrences", 0),
                "occurrences_30min": group.get("occurrences_30min", 0),
                "occurrences_24h": group.get("occurrences_24h", 0),
                "is_repeating": group.get("is_repeating", False),
                "first_occurrence": group.get("first_occurrence", ""),
                "last_occurrence": group.get("last_occurrence", "")
            }

            latest_crash = group.get("latest_crash", {})
            if latest_crash and isinstance(latest_crash, dict):
                simplified["latest_crash"] = {
                    "timestamp": latest_crash.get("timestamp", ""),
                    "application": latest_crash.get("application", ""),
                    "module_name": latest_crash.get("module_name", ""),
                    "exception_code": latest_crash.get("exception_code", "")
                }
            else:
                simplified["latest_crash"] = {}

            simplified_groups.append(simplified)
        except Exception as e:
            logger.error(f"[WER] Error processing group[{idx}]: {e}")
            from utils.error_analyzer import log_error_with_analysis
            log_error_with_analysis(
                e,
                group,
                {
                    'variable_name': f'grouped_crashes[{idx}]',
                    'location': 'wer.py:_simplify_grouped_crashes',
                    'function': '_simplify_grouped_crashes'
                },
                continue_execution=True
            )

    wer_data["grouped_crashes"] = simplified_groups
    if original_count > max_groups:
        logger.info(
            f"[WER] Limited grouped_crashes: {original_count} -> "
            f"{len(simplified_groups)}")


def _simplify_reports(wer_data, max_reports=20):
    """Upraszcza i ogranicza reports."""
    if not wer_data["reports"]:
        return

    original_count = len(wer_data["reports"])
    simplified_reports = []

    for report in wer_data["reports"][:max_reports]:
        if isinstance(report, dict):
            simplified_reports.append({
                "timestamp": report.get("timestamp", ""),
                "report_type": report.get("report_type", ""),
                "application": report.get("application", ""),
                "version": report.get("version", ""),
                "bucket": report.get("bucket", "")
            })
        else:
            simplified_reports.append(report)

    try:
        simplified_reports.sort(
            key=lambda x: parse_timestamp(x.get("timestamp", ""))
            if isinstance(x, dict) else datetime.min,
            reverse=True
        )
    except Exception:
        pass

    wer_data["reports"] = simplified_reports
    if original_count > max_reports:
        logger.info(
            f"[WER] Limited reports: {original_count} -> "
            f"{len(simplified_reports)}")


def _convert_single_datetime(dt_obj):
    """
    Konwertuje pojedynczy obiekt datetime na string.

    Args:
        dt_obj: Obiekt datetime

    Returns:
        str: ISO format string lub str(dt_obj) w przypadku błędu
    """
    try:
        return dt_obj.isoformat()
    except Exception as e:
        logger.warning(f"[WER] Error converting datetime to isoformat: {e}")
        return str(dt_obj)


def _convert_dict_datetime(obj_dict, depth, max_depth, convert_func):
    """
    Konwertuje słownik z datetime obiektami.

    Args:
        obj_dict: Słownik do konwersji
        depth: Obecna głębokość rekurencji
        max_depth: Maksymalna głębokość
        convert_func: Funkcja rekurencyjna do konwersji

    Returns:
        dict: Skonwertowany słownik
    """
    try:
        return {
            k: convert_func(v, depth + 1, max_depth)
            for k, v in obj_dict.items()
        }
    except Exception as e:
        logger.warning(f"[WER] Error converting dict at depth {depth}: {e}")
        return str(obj_dict)


def _convert_list_datetime(obj_list, depth, max_depth, convert_func):
    """
    Konwertuje listę z datetime obiektami.

    Args:
        obj_list: Lista do konwersji
        depth: Obecna głębokość rekurencji
        max_depth: Maksymalna głębokość
        convert_func: Funkcja rekurencyjna do konwersji

    Returns:
        list: Skonwertowana lista
    """
    try:
        return [
            convert_func(item, depth + 1, max_depth)
            for item in obj_list
        ]
    except Exception as e:
        logger.warning(f"[WER] Error converting list at depth {depth}: {e}")
        return str(obj_list)


def _convert_datetime_to_string_recursive(obj, depth=0, max_depth=50):
    """
    Rekurencyjnie konwertuje wszystkie obiekty datetime na stringi.

    Args:
        obj: Obiekt do konwersji
        depth: Obecna głębokość rekurencji
        max_depth: Maksymalna głębokość

    Returns:
        object: Skonwertowany obiekt
    """
    if depth > max_depth:
        logger.warning(
            f"[WER] Max depth {max_depth} reached in datetime conversion"
        )
        return str(obj) if obj is not None else None

    if obj is None:
        return None

    if isinstance(obj, datetime):
        return _convert_single_datetime(obj)

    if isinstance(obj, dict):
        return _convert_dict_datetime(obj, depth, max_depth, _convert_datetime_to_string_recursive)

    if isinstance(obj, list):
        return _convert_list_datetime(obj, depth, max_depth, _convert_datetime_to_string_recursive)

    return obj


def _count_total_items(wer_data):
    """
    Liczy całkowitą liczbę elementów w wer_data.

    Args:
        wer_data: Słownik z danymi WER

    Returns:
        int: Całkowita liczba elementów
    """
    return (
        len(wer_data.get('recent_crashes', [])) +
        len(wer_data.get('reports', [])) +
        len(wer_data.get('grouped_crashes', []))
    )


def _convert_datetime_to_strings(wer_data):
    """
    Konwertuje wszystkie obiekty datetime na stringi.

    Args:
        wer_data: Słownik z danymi WER

    Returns:
        dict: wer_data z skonwertowanymi datetime
    """
    logger.info(
        "[WER] Converting datetime objects to strings for serialization..."
    )
    sys.stdout.flush()

    try:
        total_items = _count_total_items(wer_data)

        if total_items > 200:
            logger.warning(
                f"[WER] Skipping datetime conversion - too many items "
                f"({total_items}), data already simplified"
            )
            sys.stdout.flush()
            return wer_data

        wer_data = _convert_datetime_to_string_recursive(wer_data)
        logger.info("[WER] Datetime conversion completed successfully")
        sys.stdout.flush()
    except Exception as e:
        logger.warning(f"[WER] Error converting datetime objects: {e}")
        sys.stdout.flush()

    return wer_data


def _collect_event_log_crashes(wer_data):
    """Zbiera crashy z Event Log."""
    logger.info("[WER] Collecting crash data from Event Log")
    event_crashes = collect_from_event_log()
    wer_data["recent_crashes"].extend(event_crashes)


def _collect_wer_files_and_reports(wer_data):
    """Zbiera crashy z plików WER."""
    logger.info(
        "[WER] Collecting crash data from WER directories "
        "(ReportQueue, ReportArchive)")
    wer_crashes = collect_from_wer_directories()
    wer_data["recent_crashes"].extend(wer_crashes)
    if wer_crashes:
        wer_data["reports"].append({
            "source": "wer_file",
            "count": len(wer_crashes),
            "description": (
                f"Parsed {len(wer_crashes)} .wer files from "
                "ReportQueue/ReportArchive"
            )
        })


def _log_debug_info(wer_data):
    """Loguje informacje debugowe o strukturze wer_data."""
    logger.debug(f"[WER] DEBUG: wer_data type: {type(wer_data)}")
    logger.debug(f"[WER] DEBUG: wer_data keys: {list(wer_data.keys())}")
    logger.debug(
        f"[WER] DEBUG: grouped_crashes type: "
        f"{type(wer_data.get('grouped_crashes'))}")
    logger.debug(
        f"[WER] DEBUG: grouped_crashes is list: "
        f"{isinstance(wer_data.get('grouped_crashes'), list)}")
    logger.debug(
        f"[WER] DEBUG: grouped_crashes length: "
        f"{len(wer_data.get('grouped_crashes', []))}")


def _log_return_info(wer_data):
    """Loguje informacje o zwracanych danych."""
    logger.debug(
        f"[WER] DEBUG: Returning wer_data, type: {type(wer_data)}")
    logger.debug(
        f"[WER] DEBUG: Returning wer_data keys: "
        f"{list(wer_data.keys()) if isinstance(wer_data, dict) else 'N/A'}")
    sys.stdout.flush()
    for handler in logger.handlers:
        if hasattr(handler, 'flush'):
            handler.flush()


def _warn_if_no_reports(wer_data):
    """Ostrzega, jeśli brak raportów."""
    if wer_data.get("statistics", {}).get("report_count", 0) == 0:
        logger.warning(
            "[WER] No WER reports found. LocalDumps might have been "
            "disabled previously. Now that they're enabled, crashes need "
            "time to accumulate. Re-run the tool after the next crash.")


def _write_debug_file(wer_data):
    """Zapisuje informacje debugowe do pliku."""
    try:
        debug_file = Path("logs/wer_debug.txt")
        with open(debug_file, "a", encoding="utf-8") as f:
            f.write(
                f"{datetime.now()} | [WER] Returning wer_data, "
                f"type: {type(wer_data)}\n")
            if isinstance(wer_data, dict):
                f.write(
                    f"{datetime.now()} | [WER] Keys: "
                    f"{list(wer_data.keys())}\n")
                if 'grouped_crashes' in wer_data:
                    f.write(
                        f"{datetime.now()} | [WER] grouped_crashes type: "
                        f"{type(wer_data['grouped_crashes'])}\n")
                    f.write(
                        f"{datetime.now()} | [WER] grouped_crashes is list: "
                        f"{isinstance(wer_data['grouped_crashes'], list)}\n")
            f.flush()
    except Exception as e:
        logger.warning(f"[WER] Failed to write debug file: {e}")


def _optimize_wer_data(wer_data):
    """Optymalizuje dane WER poprzez uproszczenie i ograniczenie ilości."""
    original_recent_count = len(wer_data["recent_crashes"])
    original_reports_count = len(wer_data["reports"])
    original_grouped_count = len(wer_data["grouped_crashes"])

    _simplify_crashes(wer_data, max_recent=50)
    _simplify_grouped_crashes(wer_data, max_groups=20)
    _simplify_reports(wer_data, max_reports=20)

    wer_data["statistics"]["original_recent_crashes_count"] = (
        original_recent_count
    )
    wer_data["statistics"]["original_reports_count"] = original_reports_count
    wer_data["statistics"]["original_grouped_crashes_count"] = (
        original_grouped_count
    )

    wer_data = _convert_datetime_to_strings(wer_data)

    logger.info(
        f"[WER] Optimized data: {original_recent_count}->"
        f"{len(wer_data.get('recent_crashes', []))} crashes, "
        f"{original_reports_count}->"
        f"{len(wer_data.get('reports', []))} reports, "
        f"{original_grouped_count}->"
        f"{len(wer_data.get('grouped_crashes', []))} groups")

    return wer_data


def _filter_crashes_by_time(wer_data, last_30min, last_24h):
    """
    Filtruje crashy według czasu (ostatnie 30 min i 24h).

    Args:
        wer_data: Słownik z danymi WER
        last_30min: Datetime dla ostatnich 30 minut
        last_24h: Datetime dla ostatnich 24 godzin

    Returns:
        tuple: (crashes_30min, crashes_24h)
    """
    crashes_30min = []
    crashes_24h = []

    for c in wer_data["recent_crashes"]:
        if not isinstance(c, dict):
            continue

        timestamp = parse_timestamp(c.get("timestamp", ""))
        if timestamp is None:
            continue

        if timestamp >= last_30min:
            crashes_30min.append(c)
        if timestamp >= last_24h:
            crashes_24h.append(c)

    return crashes_30min, crashes_24h


def _is_repeating_crash_group(group):
    """
    Sprawdza czy grupa crashy jest powtarzająca się (>=3 w ostatnich 30 min).

    Args:
        group: Słownik z danymi grupy crashy

    Returns:
        bool: True jeśli grupa jest powtarzająca się
    """
    if not isinstance(group, dict):
        return False

    try:
        occurrences_30min = group.get("occurrences_30min", 0)
        return isinstance(occurrences_30min, (int, float)) and occurrences_30min >= 3
    except Exception:
        return False


def _filter_repeating_crashes(grouped):
    """
    Filtruje powtarzające się crashy z grouped.

    Args:
        grouped: Lista grup crashy

    Returns:
        list: Lista powtarzających się grup
    """
    repeating = []

    if not isinstance(grouped, list):
        logger.warning(f"[WER] grouped is not a list: {type(grouped)}")
        return repeating

    logger.debug(
        f"[WER] Before filtering repeating - grouped type: {type(grouped)}, "
        f"is_list: {isinstance(grouped, list)}, length: {len(grouped)}"
    )

    for idx, g in enumerate(grouped):
        logger.debug(
            f"[WER] Processing group[{idx}] for repeating check: "
            f"type={type(g)}, is_dict={isinstance(g, dict)}"
        )

        if isinstance(g, dict):
            try:
                if _is_repeating_crash_group(g):
                    repeating.append(g)
            except Exception as e:
                logger.warning(
                    f"[WER] Error processing group[{idx}] for repeating "
                    f"check: {e}"
                )
                from utils.error_analyzer import log_error_with_analysis
                log_error_with_analysis(
                    e,
                    g,
                    {
                        'variable_name': f'grouped[{idx}]',
                        'location': 'wer.py:_calculate_statistics',
                        'function': '_calculate_statistics'
                    },
                    continue_execution=True
                )
        elif isinstance(g, list):
            logger.error(
                f"[WER] CRITICAL: group[{idx}] is list instead of dict "
                "in repeating check! Skipping..."
            )
            from utils.error_analyzer import log_error_with_analysis
            log_error_with_analysis(
                TypeError(f"group[{idx}] is list instead of dict"),
                g,
                {
                    'variable_name': f'grouped[{idx}]',
                    'location': 'wer.py:_calculate_statistics',
                    'function': '_calculate_statistics'
                },
                continue_execution=True
            )
        else:
            logger.warning(
                f"[WER] Unexpected type in grouped[{idx}] for repeating "
                f"check: {type(g)}"
            )

    return repeating


def _create_statistics_dict(total_crashes, crashes_30min, crashes_24h, repeating):
    """
    Tworzy słownik ze statystykami.

    Args:
        total_crashes: Całkowita liczba crashy
        crashes_30min: Liczba crashy w ostatnich 30 min
        crashes_24h: Liczba crashy w ostatnich 24h
        repeating: Liczba powtarzających się crashy

    Returns:
        dict: Słownik ze statystykami
    """
    return {
        "total_crashes": total_crashes,
        "crashes_last_30min": len(crashes_30min),
        "crashes_last_24h": len(crashes_24h),
        "repeating_crashes": len(repeating)
    }


def _calculate_statistics(wer_data, grouped):
    """
    Oblicza statystyki crashy.

    Args:
        wer_data: Słownik z danymi WER
        grouped: Lista zgrupowanych crashy
    """
    now = datetime.now()
    last_30min = now - timedelta(minutes=30)
    last_24h = now - timedelta(hours=24)

    crashes_30min, crashes_24h = _filter_crashes_by_time(
        wer_data,
        last_30min,
        last_24h
    )

    repeating = _filter_repeating_crashes(grouped)

    wer_data["statistics"] = _create_statistics_dict(
        len(wer_data["recent_crashes"]),
        crashes_30min,
        crashes_24h,
        repeating
    )

    logger.info(
        f"[WER] Collected {wer_data['statistics']['total_crashes']} crashes, "
        f"{wer_data['statistics']['crashes_last_30min']} in last 30min, "
        f"{wer_data['statistics']['repeating_crashes']} repeating"
    )


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
    wer_data = _initialize_wer_data()

    if sys.platform != "win32":
        wer_data["error"] = "Windows only"
        return wer_data

    # ✅ AUTODETEKCJA i AUTOKONFIGURACJA LocalDumps
    _check_and_setup_local_dumps(wer_data)

    try:
        _collect_event_log_crashes(wer_data)
        _collect_wer_files_and_reports(wer_data)

        # Korelacja Event Log → WER Files
        logger.info("[WER] Correlating Event Log crashes with WER files")
        wer_data["recent_crashes"] = correlate_event_log_with_wer_files(
            wer_data["recent_crashes"])

        # Krok 3: Grupowanie i walidacja
        logger.info("[WER] Grouping and analyzing repeating crashes")
        grouped = group_and_analyze_crashes(wer_data["recent_crashes"])
        wer_data["grouped_crashes"] = _validate_grouped_crashes(grouped)
        logger.debug(
            f"[WER] Final grouped_crashes type: "
            f"{type(wer_data['grouped_crashes'])}, "
            f"length: {len(wer_data['grouped_crashes'])}")
        sys.stdout.flush()

        # Krok 4: Oblicz statystyki
        _calculate_statistics(wer_data, grouped)

        # OPTYMALIZACJA: Ograniczamy ilość danych
        wer_data = _optimize_wer_data(wer_data)

        _log_debug_info(wer_data)

    except Exception as e:
        logger.exception(f"[WER] Exception during collection: {e}")
        wer_data["collection_error"] = f"Failed to collect WER data: {e}"

    _log_return_info(wer_data)
    _write_debug_file(wer_data)
    _warn_if_no_reports(wer_data)

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
            f"ConvertTo-Xml -As String -Depth 5")

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
                    # Pobierz wartość - może być w tekście lub w zagnieżdżonych
                    # właściwościach
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


def _validate_event_id(event_id):
    """
    Sprawdza czy event_id jest w liście obsługiwanych WER_EVENT_IDS.

    Args:
        event_id: Event ID jako string

    Returns:
        bool: True jeśli event_id jest obsługiwany
    """
    if not event_id:
        return False
    return event_id in [str(eid) for eid in WER_EVENT_IDS]


def _extract_basic_fields(record, message):
    """
    Wyciąga podstawowe pola z rekordu i message.

    Args:
        record: Słownik z rekordem Event Log
        message: Wiadomość z Event Log

    Returns:
        dict: Podstawowe pola
    """
    timestamp = (
        record.get("TimeCreated") or
        record.get("Time", "") or
        record.get("TimeCreated", "")
    )
    provider = (
        record.get("ProviderName", "") or
        record.get("Source", "") or
        ""
    )

    return {
        'timestamp': timestamp,
        'provider': provider,
        'message': message
    }


def _extract_application_fields(record, message):
    """
    Wyciąga pola związane z aplikacją.

    Args:
        record: Słownik z rekordem Event Log
        message: Wiadomość z Event Log

    Returns:
        dict: Pola aplikacji
    """
    app_name = (
        record.get("FaultingApplicationName") or
        extract_field_from_message(message, [
            r'Faulting\s+application\s+name:\s*([^\r\n]+)',
            r'Application\s+Name:\s*([^\r\n]+)',
            r'Application:\s*([^\r\n,]+)',
            r'AppName:\s*([^\r\n]+)',
            r'Faulting\s+Application\s+Name:\s*([^\r\n]+)'
        ])
    )

    app_path = (
        record.get("FaultingApplicationPath") or
        extract_field_from_message(message, [
            r'Faulting\s+application\s+path:\s*([^\r\n]+)',
            r'Application\s+Path:\s*([^\r\n]+)',
            r'Faulting\s+Application\s+Path:\s*([^\r\n]+)'
        ])
    )

    app_version = (
        record.get("FaultingApplicationVersion") or
        extract_field_from_message(message, [
            r'Faulting\s+application\s+version:\s*([^\r\n]+)',
            r'Application\s+Version:\s*([^\r\n]+)',
            r'Application\s+Version\s+String:\s*([^\r\n]+)'
        ])
    )

    return {
        'app_name': app_name,
        'app_path': app_path,
        'app_version': app_version
    }


def _extract_module_fields(record, message):
    """
    Wyciąga pola związane z modułem.

    Args:
        record: Słownik z rekordem Event Log
        message: Wiadomość z Event Log

    Returns:
        dict: Pola modułu
    """
    module_name = (
        record.get("FaultingModuleName") or
        extract_field_from_message(message, [
            r'Faulting\s+module\s+name:\s*([^\r\n]+)',
            r'Module\s+Name:\s*([^\r\n]+)',
            r'Faulting\s+Module\s+Name:\s*([^\r\n]+)',
            r'Module:\s*([^\r\n]+)'
        ])
    )

    module_path = (
        record.get("FaultingModulePath") or
        extract_field_from_message(message, [
            r'Faulting\s+module\s+path:\s*([^\r\n]+)',
            r'Module\s+Path:\s*([^\r\n]+)',
            r'Faulting\s+Module\s+Path:\s*([^\r\n]+)'
        ])
    )

    module_version = (
        record.get("FaultingModuleVersion") or
        extract_field_from_message(message, [
            r'Faulting\s+module\s+version:\s*([^\r\n]+)',
            r'Module\s+Version:\s*([^\r\n]+)'
        ])
    )

    return {
        'module_name': module_name,
        'module_path': module_path,
        'module_version': module_version
    }


def _extract_exception_fields(record, message):
    """
    Wyciąga pola związane z wyjątkiem.

    Args:
        record: Słownik z rekordem Event Log
        message: Wiadomość z Event Log

    Returns:
        dict: Pola wyjątku
    """
    exception_code = (
        record.get("ExceptionCode") or
        extract_field_from_message(message, [
            r'Exception\s+Code:\s*([^\r\n]+)',
            r'Exception\s+code:\s*([^\r\n]+)',
            r'ExceptionCode:\s*([^\r\n]+)'
        ])
    )

    fault_offset = (
        record.get("FaultOffset") or
        extract_field_from_message(message, [
            r'Fault\s+offset:\s*([^\r\n]+)',
            r'FaultOffset:\s*([^\r\n]+)',
            r'Offset:\s*([^\r\n]+)'
        ])
    )

    return {
        'exception_code': exception_code,
        'fault_offset': fault_offset
    }


def _extract_additional_fields(record, message):
    """
    Wyciąga dodatkowe pola z rekordu.

    Args:
        record: Słownik z rekordem Event Log
        message: Wiadomość z Event Log

    Returns:
        dict: Dodatkowe pola
    """
    activity_id = record.get("ActivityID") or record.get("ActivityId", "") or ""
    report_id = record.get("ReportID") or record.get("ReportId", "") or ""

    process_id = (
        record.get("ProcessId") or
        extract_field_from_message(message, [
            r'Process\s+Id:\s*(\d+)',
            r'ProcessId:\s*(\d+)'
        ])
    )

    thread_id = (
        record.get("ThreadId") or
        extract_field_from_message(message, [
            r'Thread\s+Id:\s*(\d+)',
            r'ThreadId:\s*(\d+)'
        ])
    )

    os_version = (
        record.get("OSVersion") or
        extract_field_from_message(message, [
            r'OS\s+Version:\s*([^\r\n]+)',
            r'Operating\s+System\s+Version:\s*([^\r\n]+)'
        ])
    )

    return {
        'activity_id': activity_id,
        'report_id': report_id,
        'process_id': process_id,
        'thread_id': thread_id,
        'os_version': os_version
    }


def _handle_application_hang(event_id, message, app_name):
    """
    Obsługuje Application Hang (EventID 1002).

    Args:
        event_id: Event ID
        message: Wiadomość z Event Log
        app_name: Obecna nazwa aplikacji

    Returns:
        tuple: (is_hang, hang_type, app_name)
    """
    is_hang = (event_id == "1002")
    hang_type = None

    if not is_hang:
        return False, None, app_name

    hang_type = extract_field_from_message(message, [
        r'Application\s+hang:\s*([^\r\n]+)',
        r'Hang\s+type:\s*([^\r\n]+)',
        r'Application\s+stopped\s+responding:\s*([^\r\n]+)'
    ])

    if not app_name:
        app_name = extract_field_from_message(message, [
            r'Application\s+Name:\s*([^\r\n]+)',
            r'Program:\s*([^\r\n]+)'
        ])

    return True, hang_type, app_name


def _normalize_app_name(app_name, module_name, provider):
    """
    Normalizuje nazwę aplikacji z fallbackami.

    Args:
        app_name: Nazwa aplikacji
        module_name: Nazwa modułu
        provider: Provider z Event Log

    Returns:
        str: Znormalizowana nazwa aplikacji
    """
    if app_name and app_name != "Unknown":
        return app_name

    if module_name:
        logger.debug(
            f"[WER] AppName is None/Unknown, using module_name as fallback: "
            f"{module_name}"
        )
        return module_name

    if provider and provider != "Application Error":
        return provider

    return "Unknown"


def _normalize_paths(app_name, app_path, module_name, module_path):
    """
    Normalizuje ścieżki aplikacji i modułu.

    Args:
        app_name: Nazwa aplikacji
        app_path: Ścieżka aplikacji
        module_name: Nazwa modułu
        module_path: Ścieżka modułu

    Returns:
        tuple: (app_name, app_path, module_name, module_path)
    """
    app_name = normalize_path(app_name)
    module_name = normalize_path(module_name) if module_name else ""

    if app_path:
        app_path = normalize_path(app_path)
    elif app_name:
        app_path = normalize_path(app_name)

    if module_path:
        module_path = normalize_path(module_path)
    elif module_name:
        module_path = normalize_path(module_name)

    return app_name, app_path, module_name, module_path


def _normalize_timestamp(timestamp):
    """
    Normalizuje timestamp do string.

    Args:
        timestamp: Timestamp jako string lub datetime

    Returns:
        str: Znormalizowany timestamp
    """
    if not timestamp:
        return ""

    timestamp_parsed = parse_timestamp(timestamp)
    if timestamp_parsed:
        return timestamp_parsed.isoformat()

    return timestamp


def _build_crash_dict_from_fields(
    event_id,
    timestamp_str,
    message,
    provider,
    app_name,
    app_path,
    app_version,
    module_name,
    module_path,
    module_version,
    exception_code,
    fault_offset,
    activity_id,
    report_id,
    process_id,
    thread_id,
    os_version,
    is_hang,
    hang_type
):
    """
    Tworzy słownik z danymi crash z wyciągniętych pól.

    Args:
        event_id: Event ID
        timestamp_str: Timestamp jako string
        message: Wiadomość
        provider: Provider
        app_name: Nazwa aplikacji
        app_path: Ścieżka aplikacji
        app_version: Wersja aplikacji
        module_name: Nazwa modułu
        module_path: Ścieżka modułu
        module_version: Wersja modułu
        exception_code: Kod wyjątku
        fault_offset: Offset wyjątku
        activity_id: Activity ID
        report_id: Report ID
        process_id: Process ID
        thread_id: Thread ID
        os_version: OS Version
        is_hang: Czy to Application Hang
        hang_type: Typ hang

    Returns:
        dict: Słownik z danymi crash
    """
    crash = {
        "event_id": event_id,
        "timestamp": timestamp_str,
        "time_created": timestamp_str,
        "message": message[:500] if len(message) > 500 else message,
        "source": provider,
        "provider": provider,
        "application": app_name or "Unknown",
        "faulting_application_name": app_name or "Unknown",
        "faulting_application_path": app_path or "",
        "app_version": app_version or "",
        "faulting_application_version": app_version or "",
        "module_name": module_name or "",
        "faulting_module_name": module_name or "",
        "faulting_module_path": module_path or "",
        "module_version": module_version or "",
        "faulting_module_version": module_version or "",
        "exception_code": exception_code or "",
        "fault_offset": fault_offset or "",
        "activity_id": activity_id,
        "report_id": report_id,
        "process_id": process_id or "",
        "thread_id": thread_id or "",
        "os_version": os_version or "",
        "type": determine_crash_type(app_name, module_name, exception_code),
        "severity": get_exception_severity(exception_code),
        "is_hang": is_hang,
        "hang_type": hang_type or ""
    }

    crash["criticality"] = calculate_crash_criticality(crash)
    return crash


def extract_crash_details(record):
    """
    🔷 1.1. Event Log — Crash Reports
    Wyciąga szczegółowe dane o crashu z rekordu Event Log.

    Minimalne wymagane pola:
    - TimeCreated: czas wystąpienia
    - EventID: typ błędu
    - Source: Windows Error Reporting / Application Error
    - Message: szczegóły crasha
    - FaultingApplicationName: EXE
    - FaultingApplicationVersion: wersja aplikacji
    - FaultingModuleName: moduł (DLL / driver)
    - FaultingModuleVersion: wersja modułu
    - ExceptionCode: kod błędu (0xc0000005 → access violation)
    - FaultOffset: offset wyjątku
    - ActivityID: korelacja
    - ReportID: ID raportu w Microsoft telemetry

    Reguła: ✔ rekord uznajemy za crash tylko jeśli ma FaultingApplicationName lub Application Error.

    Args:
        record (dict): Rekord z Event Log

    Returns:
        dict: Szczegółowe dane o crashu lub None
    """
    try:
        event_id = str(record.get("Id") or record.get("EventID", ""))
        if not _validate_event_id(event_id):
            return None

        message = record.get("Message", "") or ""

        basic = _extract_basic_fields(record, message)
        app_fields = _extract_application_fields(record, message)
        module_fields = _extract_module_fields(record, message)
        exception_fields = _extract_exception_fields(record, message)
        additional = _extract_additional_fields(record, message)

        is_hang, hang_type, app_name = _handle_application_hang(
            event_id,
            message,
            app_fields['app_name']
        )

        app_name = _normalize_app_name(
            app_name,
            module_fields['module_name'],
            basic['provider']
        )

        app_name, app_path, module_name, module_path = _normalize_paths(
            app_name,
            app_fields['app_path'],
            module_fields['module_name'],
            module_fields['module_path']
        )

        timestamp_str = _normalize_timestamp(basic['timestamp'])

        crash = _build_crash_dict_from_fields(
            event_id,
            timestamp_str,
            basic['message'],
            basic['provider'],
            app_name,
            app_path,
            app_fields['app_version'],
            module_name,
            module_path,
            module_fields['module_version'],
            exception_fields['exception_code'],
            exception_fields['fault_offset'],
            additional['activity_id'],
            additional['report_id'],
            additional['process_id'],
            additional['thread_id'],
            additional['os_version'],
            is_hang,
            hang_type
        )

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


def normalize_path(path_str):
    """
    ✅ 3.2. Wszystkie ścieżki → absolutne
    Konwertuje ścieżkę na absolutną. Jeśli tylko nazwa pliku, próbuje znaleźć pełną ścieżkę.

    Args:
        path_str (str): Ścieżka do normalizacji

    Returns:
        str: Znormalizowana ścieżka
    """
    if not path_str or path_str == "Unknown":
        return path_str

    try:
        # Jeśli już jest absolutna ścieżka, zwróć ją
        if os.path.isabs(path_str):
            return os.path.normpath(path_str)

        # Jeśli tylko nazwa pliku (np. "steam.exe"), spróbuj znaleźć w PATH
        if os.path.sep not in path_str:
            # Można tutaj dodać mapowanie z Event Log, ale na razie zwróć jak
            # jest
            return path_str

        # Względna ścieżka - spróbuj zrobić absolutną
        abs_path = os.path.abspath(path_str)
        if os.path.exists(abs_path):
            return abs_path

        return path_str
    except Exception:
        return path_str


def get_exception_severity(exception_code):
    """
    ✅ 6. Reguły analizy - system priorytetów dla exception codes

    High severity:
    - 0xc0000005 (access violation)
    - 0xc0000409 (stack buffer overflow)
    - 0xc000001d (illegal instruction)
    - 0xe06d7363 (C++ exception)
    - 0xc00000fd (stack overflow)
    - 0xc0000374 (heap corruption)

    Medium:
    - 0xc0000142 (DLL init failed)
    - 0xc0150004 (side-by-side)
    - 0xc000022 (invalid image)

    Low:
    - "Stopped responding"
    - "BEX" (DEP)

    Args:
        exception_code (str): Kod wyjątku

    Returns:
        str: "High", "Medium", "Low", lub "Unknown"
    """
    if not exception_code:
        return "Unknown"

    exc_upper = str(exception_code).upper().strip()

    # High severity
    high_codes = [
        "0XC0000005", "C0000005",  # access violation
        "0XC0000409", "C0000409",  # stack buffer overflow
        "0XC000001D", "C000001D",  # illegal instruction
        "0XE06D7363", "E06D7363",  # C++ exception
        "0XC00000FD", "C00000FD",  # stack overflow
        "0XC0000374", "C0000374",  # heap corruption
    ]

    if any(code in exc_upper for code in high_codes):
        return "High"

    # Medium severity
    medium_codes = [
        "0XC0000142", "C0000142",  # DLL init failed
        "0XC0150004", "C0150004",  # side-by-side
        "0XC000022", "C000022",    # invalid image
    ]

    if any(code in exc_upper for code in medium_codes):
        return "Medium"

    # Low severity
    if "STOPPED RESPONDING" in exc_upper or "BEX" in exc_upper:
        return "Low"

    return "Unknown"


def calculate_crash_criticality(crash):
    """
    3️⃣ Severity / Criticality - automatyczna ocena ważności crasha

    Ocena na podstawie:
    - aplikacja systemowa vs użytkownika
    - exception code znany jako krytyczny (np. 0xC0000005)
    - typ crasha (SYSTEM_CRASH, KERNEL_CRASH, APPLICATION_CRASH)

    Args:
        crash (dict): Crash event

    Returns:
        str: "Critical", "High", "Medium", "Low"
    """
    if not isinstance(crash, dict):
        return "Unknown"

    app_name = (crash.get("application") or crash.get(
        "faulting_application_name") or "").lower()
    crash_type = crash.get("type", "")
    severity = crash.get("severity", "Unknown")

    # Systemowe procesy = Critical
    system_processes = [
        "winlogon.exe", "csrss.exe", "lsass.exe", "services.exe",
        "smss.exe", "wininit.exe", "dwm.exe", "svchost.exe",
        "explorer.exe", "ntoskrnl.exe", "hal.dll"
    ]

    if any(proc in app_name for proc in system_processes):
        return "Critical"

    # Kernel crash = Critical
    if crash_type == "KERNEL_CRASH" or crash_type == "SYSTEM_CRASH":
        return "Critical"

    # High severity exception codes = High
    if severity == "High":
        return "High"

    # Medium severity = Medium
    if severity == "Medium":
        return "Medium"

    # Low severity = Low
    if severity == "Low":
        return "Low"

    # Domyślnie Medium dla aplikacji użytkownika
    return "Medium"


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
    system_processes = [
        "winlogon.exe",
        "csrss.exe",
        "lsass.exe",
        "services.exe",
        "smss.exe",
        "wininit.exe",
        "dwm.exe"]

    if any(proc in app_lower for proc in system_processes):
        return "SYSTEM_CRASH"

    # ntdll.dll crashy są często systemowe
    if "ntdll.dll" in module_lower:
        return "SYSTEM_CRASH"

    # Kernel mode exceptions
    if exception_code and any(code in exception_code.upper() for code in [
                              "0xC0000005", "0xC0000409", "0xC000001D"]):
        return "KERNEL_CRASH"

    return "APPLICATION_CRASH"


def parse_wer_file(wer_file_path):
    """
    ✅ 2. Reguły parsowania plików WER (.wer)

    Plik .wer to format klucz=wartość.

    Parsuje sekcje (case-insensitive):
    - [ReportMetadata]
    - [AppCompat]
    - [ProblemSignatures]
    - [DynamicSignatures]
    - [UserMetadata]
    - [SystemInformation]

    Wyciąga pola:
    - ReportMetadata: ReportType, CreationTime, ReportStatus
    - ProblemSignatures: P1 (EXE), P2 (wersja EXE), P3 (moduł), P4 (wersja modułu), P5 (offset), P9 (Exception Code)
    - SystemInformation: OSVersion, LocaleID, BIOSVersion
    - AppCompat: AppCompatFlags
    - DynamicSignatures: DynamicSig[1..10]

    Args:
        wer_file_path (Path): Ścieżka do pliku .wer

    Returns:
        dict: Wyciągnięte dane o crashu lub None jeśli nie można sparsować
    """
    try:
        if not wer_file_path.exists():
            return None

        # Pliki .wer mogą zawierać null bytes - czytaj binarnie i filtruj
        try:
            with open(wer_file_path, 'rb') as f:
                raw_content = f.read()

            # Filtruj null bytes i inne nieprawidłowe znaki
            # Konwertuj na string, usuwając null bytes i inne problematyczne
            # znaki
            content = raw_content.decode('utf-8', errors='ignore')
            # Usuń wszystkie null bytes
            content = content.replace('\x00', '')
            # Usuń inne problematyczne znaki kontrolne (zostaw tylko \r, \n,
            # \t)
            content = ''.join(c for c in content if ord(c)
                              >= 32 or c in '\r\n\t')

        except Exception as e:
            logger.debug(f"[WER] Error reading .wer file {wer_file_path}: {e}")
            return None

        if not content or len(content.strip()) < 10:
            logger.debug(
                f"[WER] .wer file {wer_file_path} is empty or too short")
            return None

        # Sprawdź czy to XML (zaczyna się od <?xml lub <)
        content_stripped = content.strip()
        if content_stripped.startswith(
                '<?xml') or content_stripped.startswith('<'):
            return parse_wer_xml(wer_file_path, content)
        else:
            # To jest INI-like format - użyj configparser
            return parse_wer_ini_with_sections(wer_file_path, content)

    except Exception as e:
        logger.debug(f"[WER] Error parsing .wer file {wer_file_path}: {e}")
        return None


def _clean_wer_content(content):
    """
    Czyści zawartość pliku .wer z null bytes i problematycznych znaków.

    Args:
        content: Zawartość pliku

    Returns:
        str: Oczyszczona zawartość
    """
    clean_content = content.replace('\x00', '').replace('\x01', '').replace('\x02', '')
    lines = [line for line in clean_content.split('\n') if line.strip()]
    return '\n'.join(lines)


def _setup_config_parser(content, wer_file_path):
    """
    Przygotowuje configparser i parsuje zawartość.

    Args:
        content: Zawartość pliku
        wer_file_path: Ścieżka do pliku

    Returns:
        ConfigParser: Sparsowany config lub None
    """
    config = configparser.ConfigParser()
    config.optionxform = str  # Zachowaj oryginalną wielkość liter

    try:
        clean_content = _clean_wer_content(content)
        config.read_string(clean_content)
        return config
    except configparser.MissingSectionHeaderError:
        clean_content = _clean_wer_content(content)
        config.read_string(f"[DEFAULT]\n{clean_content}")
        return config
    except Exception as e:
        logger.debug(
            f"[WER] configparser failed for {wer_file_path}, using fallback: {e}"
        )
        return None


def _extract_report_metadata(section):
    """
    Wyciąga dane z sekcji ReportMetadata.

    Args:
        section: Sekcja configparser

    Returns:
        dict: Wyciągnięte dane
    """
    return {
        'report_type': get_config_value(section, 'ReportType'),
        'timestamp': get_config_value(section, 'CreationTime'),
        'report_status': get_config_value(section, 'ReportStatus'),
        'report_guid': get_config_value(section, 'ReportGUID')
    }


def _extract_problem_signatures(section):
    """
    Wyciąga dane z sekcji ProblemSignatures.

    Args:
        section: Sekcja configparser

    Returns:
        dict: Wyciągnięte dane
    """
    return {
        'app_name': get_config_value(section, 'P1'),
        'app_version': get_config_value(section, 'P2'),
        'module_name': get_config_value(section, 'P3'),
        'module_version': get_config_value(section, 'P4'),
        'fault_offset': get_config_value(section, 'P5'),
        'exception_code': get_config_value(section, 'P9')
    }


def _extract_system_information(section):
    """
    Wyciąga dane z sekcji SystemInformation.

    Args:
        section: Sekcja configparser

    Returns:
        dict: Wyciągnięte dane
    """
    return {
        'os_version': get_config_value(section, 'OSVersion'),
        'locale_id': get_config_value(section, 'LocaleID'),
        'bios_version': get_config_value(section, 'BIOSVersion')
    }


def _extract_appcompat_data(section):
    """
    Wyciąga dane z sekcji AppCompat.

    Args:
        section: Sekcja configparser

    Returns:
        str: AppCompat flags lub None
    """
    return get_config_value(section, 'AppCompatFlags')


def _extract_dynamic_signatures(section):
    """
    Wyciąga dane z sekcji DynamicSignatures.

    Args:
        section: Sekcja configparser

    Returns:
        dict: Dynamic signatures
    """
    dynamic_sigs = {}
    for key in section:
        if key.lower().startswith('dynamicsig'):
            dynamic_sigs[key] = section[key]
    return dynamic_sigs


def _extract_from_default_section(default_section, extracted_data):
    """
    Wyciąga dane z sekcji DEFAULT jako fallback.

    Args:
        default_section: Sekcja DEFAULT
        extracted_data: Słownik z już wyciągniętymi danymi

    Returns:
        dict: Zaktualizowane dane
    """
    if not extracted_data.get('app_name'):
        extracted_data['app_name'] = (
            get_config_value(default_section, 'P1') or
            get_config_value(default_section, 'FaultingApplicationName')
        )

    if not extracted_data.get('module_name'):
        extracted_data['module_name'] = (
            get_config_value(default_section, 'P3') or
            get_config_value(default_section, 'FaultingModuleName')
        )

    if not extracted_data.get('exception_code'):
        extracted_data['exception_code'] = (
            get_config_value(default_section, 'P9') or
            get_config_value(default_section, 'ExceptionCode')
        )

    if not extracted_data.get('timestamp'):
        extracted_data['timestamp'] = (
            get_config_value(default_section, 'CreationTime') or
            get_config_value(default_section, 'Time')
        )

    extracted_data['dump_count'] = (
        get_config_value(default_section, 'DumpCount') or
        extracted_data.get('dump_count')
    )

    extracted_data['parent_process_name'] = (
        get_config_value(default_section, 'ParentProcessName') or
        extracted_data.get('parent_process_name')
    )

    extracted_data['parent_process_version'] = (
        get_config_value(default_section, 'ParentProcessVersion') or
        extracted_data.get('parent_process_version')
    )

    return extracted_data


def _parse_wer_timestamp(timestamp, wer_file_path):
    """
    Parsuje timestamp z WER file lub używa daty modyfikacji pliku.

    Args:
        timestamp: Timestamp string lub None
        wer_file_path: Ścieżka do pliku

    Returns:
        datetime: Sparsowany timestamp
    """
    if not timestamp:
        return datetime.fromtimestamp(wer_file_path.stat().st_mtime)

    timestamp_parsed = parse_timestamp(timestamp)
    if not timestamp_parsed:
        return datetime.fromtimestamp(wer_file_path.stat().st_mtime)

    return timestamp_parsed


def _build_crash_dict(extracted_data, wer_file_path):
    """
    Tworzy słownik z danymi crash z wyciągniętych danych.

    Args:
        extracted_data: Słownik z wyciągniętymi danymi
        wer_file_path: Ścieżka do pliku

    Returns:
        dict: Słownik z danymi crash
    """
    timestamp = extracted_data.get('timestamp')
    if isinstance(timestamp, datetime):
        timestamp_str = timestamp.isoformat()
    else:
        timestamp_str = str(timestamp) if timestamp else ""

    app_name = extracted_data.get('app_name') or "Unknown"
    module_name = extracted_data.get('module_name') or ""
    app_version = extracted_data.get('app_version') or ""
    module_version = extracted_data.get('module_version') or ""

    return {
        "event_id": "WER_FILE",
        "timestamp": timestamp_str,
        "time_created": timestamp_str,
        "message": f"WER file: {wer_file_path.name}",
        "source": "wer_file",
        "provider": "Windows Error Reporting",
        "application": app_name,
        "faulting_application_name": app_name,
        "app_version": app_version,
        "faulting_application_version": app_version,
        "module_name": module_name,
        "faulting_module_name": module_name,
        "module_version": module_version,
        "faulting_module_version": module_version,
        "exception_code": extracted_data.get('exception_code') or "",
        "fault_offset": extracted_data.get('fault_offset') or "",
        "os_version": extracted_data.get('os_version') or "",
        "type": determine_crash_type(
            app_name if app_name != "Unknown" else None,
            module_name if module_name else None,
            extracted_data.get('exception_code')
        ),
        "severity": get_exception_severity(extracted_data.get('exception_code')),
        "wer_file_path": str(wer_file_path),
        "report_type": extracted_data.get('report_type') or "",
        "report_status": extracted_data.get('report_status') or "",
        "report_guid": extracted_data.get('report_guid') or "",
        "dump_count": extracted_data.get('dump_count') or "",
        "parent_process_name": extracted_data.get('parent_process_name') or "",
        "parent_process_version": extracted_data.get('parent_process_version') or "",
        "locale_id": extracted_data.get('locale_id') or "",
        "bios_version": extracted_data.get('bios_version') or "",
        "app_compat_flags": extracted_data.get('app_compat_flags') or "",
        "dynamic_signatures": extracted_data.get('dynamic_signatures', {})
    }


def _process_config_section(section_name, section, extracted_data, config):
    """
    Przetwarza pojedynczą sekcję config i aktualizuje extracted_data.

    Args:
        section_name: Nazwa sekcji
        section: Sekcja configparser
        extracted_data: Słownik z wyciągniętymi danymi
        config: Obiekt ConfigParser

    Returns:
        dict: Zaktualizowany extracted_data
    """
    section_lower = section_name.lower()

    if 'reportmetadata' in section_lower or 'metadata' in section_lower:
        metadata = _extract_report_metadata(section)
        extracted_data.update(metadata)
    elif 'problemsignatures' in section_lower or 'signature' in section_lower:
        signatures = _extract_problem_signatures(section)
        extracted_data.update(signatures)
    elif 'systeminformation' in section_lower or 'system' in section_lower:
        sys_info = _extract_system_information(section)
        extracted_data.update(sys_info)
    elif 'appcompat' in section_lower:
        extracted_data['app_compat_flags'] = _extract_appcompat_data(section)
    elif 'dynamicsignatures' in section_lower or 'dynamic' in section_lower:
        extracted_data['dynamic_signatures'] = _extract_dynamic_signatures(section)

    # Sprawdź sekcję DEFAULT jako fallback
    if 'default' in config:
        default_section = config['DEFAULT']
        extracted_data = _extract_from_default_section(
            default_section,
            extracted_data
        )

    return extracted_data


def _initialize_extracted_data():
    """
    Inicjalizuje strukturę extracted_data.

    Returns:
        dict: Pusta struktura extracted_data
    """
    return {
        'app_name': None,
        'app_version': None,
        'module_name': None,
        'module_version': None,
        'exception_code': None,
        'fault_offset': None,
        'timestamp': None,
        'report_type': None,
        'report_status': None,
        'os_version': None,
        'locale_id': None,
        'bios_version': None,
        'app_compat_flags': None,
        'dynamic_signatures': {},
        'dump_count': None,
        'parent_process_name': None,
        'parent_process_version': None,
        'report_guid': None
    }


def parse_wer_ini_with_sections(wer_file_path, content):
    """
    ✅ 2.1. Parsuj sekcje i klucze (case-insensitive)

    Parsuje plik .wer w formacie INI z sekcjami używając configparser.
    Sekcje: ReportMetadata, ProblemSignatures, SystemInformation, AppCompat, DynamicSignatures

    Args:
        wer_file_path (Path): Ścieżka do pliku
        content (str): Zawartość pliku

    Returns:
        dict: Wyciągnięte dane o crashu lub None
    """
    try:
        config = _setup_config_parser(content, wer_file_path)
        if not config:
            return parse_wer_ini_fallback(wer_file_path, content)

        extracted_data = _initialize_extracted_data()

        # Przetwórz wszystkie sekcje
        for section_name in config.sections():
            section = config[section_name]
            extracted_data = _process_config_section(
                section_name,
                section,
                extracted_data,
                config
            )

        # Parsuj timestamp
        extracted_data['timestamp'] = _parse_wer_timestamp(
            extracted_data.get('timestamp'),
            wer_file_path
        )

        # Normalizuj ścieżki
        app_name = normalize_path(extracted_data.get('app_name'))
        module_name = normalize_path(extracted_data.get('module_name'))

        # Zwróć tylko jeśli znaleziono przynajmniej AppName lub Module
        if not app_name and not module_name:
            return None

        extracted_data['app_name'] = app_name
        extracted_data['module_name'] = module_name

        crash = _build_crash_dict(extracted_data, wer_file_path)
        logger.debug(
            f"[WER] Parsed .wer file - AppName: {app_name}, "
            f"Module: {module_name}, "
            f"ExceptionCode: {extracted_data.get('exception_code')}"
        )
        return crash

    except Exception as e:
        logger.debug(
            f"[WER] Error parsing INI .wer file {wer_file_path}: {e}"
        )
        return parse_wer_ini_fallback(wer_file_path, content)


def get_config_value(section, key, default=None):
    """
    Pobiera wartość z sekcji configparser (case-insensitive).

    Args:
        section: Sekcja configparser
        key (str): Klucz do pobrania
        default: Wartość domyślna

    Returns:
        str: Wartość lub None
    """
    try:
        # Spróbuj dokładne dopasowanie
        if key in section:
            return section[key]

        # Spróbuj case-insensitive
        key_lower = key.lower()
        for k in section:
            if k.lower() == key_lower:
                return section[k]

        return default
    except Exception:
        return default


def _clean_wer_content_fallback(content):
    """
    Czyści zawartość pliku .wer z null bytes i znaków kontrolnych.

    Args:
        content: Zawartość pliku

    Returns:
        str: Oczyszczona zawartość
    """
    clean_content = content.replace('\x00', '').replace('\x01', '').replace('\x02', '')
    return ''.join(c for c in clean_content if ord(c) >= 32 or c in '\r\n\t')


def _extract_with_multiple_patterns(content, patterns):
    """
    Wyciąga wartość używając wielu wzorców regex.

    Args:
        content: Zawartość do przeszukania
        patterns: Lista wzorców regex do wypróbowania

    Returns:
        str: Wyciągnięta wartość lub None
    """
    for pattern in patterns:
        match = re.search(pattern, content, re.IGNORECASE)
        if match:
            return match.group(1).strip()
    return None


def _extract_app_name_fallback(content):
    """
    Wyciąga nazwę aplikacji z zawartości pliku .wer.

    Args:
        content: Zawartość pliku

    Returns:
        str: Nazwa aplikacji lub None
    """
    patterns = [
        r'Faulting\s+application[:\s]+([^\r\n]+)',
        r'AppName[:\s]+([^\r\n]+)',
        r'P1[:\s=]+([^\r\n]+)'
    ]
    return _extract_with_multiple_patterns(content, patterns)


def _extract_module_fallback(content):
    """
    Wyciąga nazwę modułu z zawartości pliku .wer.

    Args:
        content: Zawartość pliku

    Returns:
        str: Nazwa modułu lub None
    """
    patterns = [
        r'Faulting\s+module[:\s]+([^\r\n]+)',
        r'Module[:\s]+([^\r\n]+)',
        r'P3[:\s=]+([^\r\n]+)'
    ]
    return _extract_with_multiple_patterns(content, patterns)


def _extract_exception_code_fallback(content):
    """
    Wyciąga kod wyjątku z zawartości pliku .wer.

    Args:
        content: Zawartość pliku

    Returns:
        str: Kod wyjątku lub None
    """
    patterns = [
        r'Exception\s+code[:\s]+([^\r\n]+)',
        r'ExceptionCode[:\s]+([^\r\n]+)',
        r'P9[:\s=]+([^\r\n]+)'
    ]
    return _extract_with_multiple_patterns(content, patterns)


def _extract_timestamp_fallback(content, wer_file_path):
    """
    Wyciąga timestamp z zawartości pliku .wer lub używa daty modyfikacji.

    Args:
        content: Zawartość pliku
        wer_file_path: Ścieżka do pliku

    Returns:
        datetime: Timestamp
    """
    patterns = [
        r'CreationTime[:\s=]+([^\r\n]+)',
        r'Time[:\s]+([^\r\n]+)'
    ]

    timestamp_str = _extract_with_multiple_patterns(content, patterns)
    if timestamp_str:
        timestamp = parse_timestamp(timestamp_str)
        if timestamp:
            return timestamp

    return datetime.fromtimestamp(wer_file_path.stat().st_mtime)


def _build_fallback_crash_dict(app_name, module, exception_code, timestamp, wer_file_path):
    """
    Tworzy słownik z danymi crash dla fallback parsera.

    Args:
        app_name: Nazwa aplikacji
        module: Nazwa modułu
        exception_code: Kod wyjątku
        timestamp: Timestamp
        wer_file_path: Ścieżka do pliku

    Returns:
        dict: Słownik z danymi crash
    """
    timestamp_str = (
        timestamp.isoformat() if isinstance(timestamp, datetime) else str(timestamp)
    )

    return {
        "event_id": "WER_FILE",
        "timestamp": timestamp_str,
        "time_created": timestamp_str,
        "message": f"WER file: {wer_file_path.name}",
        "provider": "Windows Error Reporting",
        "application": app_name or "Unknown",
        "faulting_application_name": app_name or "Unknown",
        "module_name": module or "",
        "faulting_module_name": module or "",
        "exception_code": exception_code or "",
        "type": determine_crash_type(app_name, module, exception_code),
        "severity": get_exception_severity(exception_code),
        "source": "wer_file",
        "wer_file_path": str(wer_file_path)
    }


def parse_wer_ini_fallback(wer_file_path, content):
    """
    Fallback - ręczne parsowanie pliku .wer gdy configparser nie działa.
    Obsługuje pliki z null bytes i innymi problematycznymi znakami.

    Args:
        wer_file_path (Path): Ścieżka do pliku
        content (str): Zawartość pliku

    Returns:
        dict: Wyciągnięte dane o crashu lub None
    """
    try:
        _clean_wer_content_fallback(content)

        app_name = _extract_app_name_fallback(content)
        module = _extract_module_fallback(content)
        exception_code = _extract_exception_code_fallback(content)
        timestamp = _extract_timestamp_fallback(content, wer_file_path)

        app_name = normalize_path(app_name) if app_name else None
        module = normalize_path(module) if module else None

        if not app_name and not module:
            return None

        return _build_fallback_crash_dict(
            app_name,
            module,
            exception_code,
            timestamp,
            wer_file_path
        )

    except Exception as e:
        logger.debug(f"[WER] Error in fallback parsing: {e}")
        return None


def _extract_value_from_xml_elem(elem):
    """
    Wyciąga wartość z elementu XML (text lub atrybut value).

    Args:
        elem: Element XML

    Returns:
        str: Wartość lub pusty string
    """
    text = (elem.text or "").strip()
    attrib_value = elem.attrib.get('value', '').strip()
    return text or attrib_value


def _check_app_name_tag(tag, elem, app_name):
    """
    Sprawdza czy tag XML zawiera informacje o nazwie aplikacji.

    Args:
        tag: Tag elementu (lowercase)
        elem: Element XML
        app_name: Obecna wartość app_name (może być None)

    Returns:
        str: Nowa wartość app_name lub None
    """
    if app_name:
        return app_name

    if 'faulting' in tag and 'application' in tag:
        return _extract_value_from_xml_elem(elem)
    if 'appname' in tag:
        return _extract_value_from_xml_elem(elem)
    if 'application' in tag and elem.text and elem.text.strip():
        return elem.text.strip()

    return None


def _check_module_tag(tag, elem, module):
    """
    Sprawdza czy tag XML zawiera informacje o module.

    Args:
        tag: Tag elementu (lowercase)
        elem: Element XML
        module: Obecna wartość module (może być None)

    Returns:
        str: Nowa wartość module lub None
    """
    if module:
        return module

    if 'faulting' in tag and 'module' in tag:
        return _extract_value_from_xml_elem(elem)
    if 'module' in tag and 'name' in tag:
        return _extract_value_from_xml_elem(elem)

    return None


def _check_exception_code_tag(tag, elem, exception_code):
    """
    Sprawdza czy tag XML zawiera kod wyjątku.

    Args:
        tag: Tag elementu (lowercase)
        elem: Element XML
        exception_code: Obecna wartość exception_code (może być None)

    Returns:
        str: Nowa wartość exception_code lub None
    """
    if exception_code:
        return exception_code

    if 'exception' in tag and 'code' in tag:
        return _extract_value_from_xml_elem(elem)
    if 'exceptioncode' in tag:
        return _extract_value_from_xml_elem(elem)

    return None


def _check_timestamp_tag(tag, elem, timestamp):
    """
    Sprawdza czy tag XML zawiera timestamp.

    Args:
        tag: Tag elementu (lowercase)
        elem: Element XML
        timestamp: Obecna wartość timestamp (może być None)

    Returns:
        datetime: Nowa wartość timestamp lub None
    """
    if timestamp:
        return timestamp

    if 'time' in tag or 'timestamp' in tag:
        timestamp_str = _extract_value_from_xml_elem(elem)
        if timestamp_str:
            parsed = parse_timestamp(timestamp_str)
            if parsed:
                return parsed

    return None


def _extract_data_from_xml(root):
    """
    Wyciąga dane z XML root element.

    Args:
        root: ElementTree root element

    Returns:
        dict: Wyciągnięte dane (app_name, module, exception_code, timestamp)
    """
    app_name = None
    module = None
    exception_code = None
    timestamp = None

    for elem in root.iter():
        tag = elem.tag.lower()

        app_name = _check_app_name_tag(tag, elem, app_name)
        module = _check_module_tag(tag, elem, module)
        exception_code = _check_exception_code_tag(tag, elem, exception_code)
        timestamp = _check_timestamp_tag(tag, elem, timestamp)

    return {
        'app_name': app_name,
        'module': module,
        'exception_code': exception_code,
        'timestamp': timestamp
    }


def _build_xml_crash_dict(app_name, module, exception_code, timestamp, wer_file_path):
    """
    Tworzy słownik z danymi crash dla XML parsera.

    Args:
        app_name: Nazwa aplikacji
        module: Nazwa modułu
        exception_code: Kod wyjątku
        timestamp: Timestamp
        wer_file_path: Ścieżka do pliku

    Returns:
        dict: Słownik z danymi crash
    """
    timestamp_str = (
        timestamp.isoformat() if isinstance(timestamp, datetime) else str(timestamp)
    )

    return {
        "event_id": "WER_FILE",
        "timestamp": timestamp_str,
        "message": f"WER file: {wer_file_path.name}",
        "provider": "Windows Error Reporting",
        "application": app_name or "Unknown",
        "app_version": "",
        "module_name": module or "",
        "module_version": "",
        "exception_code": exception_code or "",
        "process_id": "",
        "thread_id": "",
        "os_version": "",
        "type": determine_crash_type(app_name, module, exception_code),
        "severity": get_exception_severity(exception_code),
        "source": "wer_file",
        "wer_file_path": str(wer_file_path)
    }


def parse_wer_xml(wer_file_path, content):
    """
    Parsuje plik .wer w formacie XML.

    Args:
        wer_file_path (Path): Ścieżka do pliku
        content (str): Zawartość pliku

    Returns:
        dict: Wyciągnięte dane o crashu lub None
    """
    try:
        root = ET.fromstring(content)
        extracted = _extract_data_from_xml(root)

        app_name = extracted['app_name']
        module = extracted['module']
        exception_code = extracted['exception_code']
        timestamp = extracted['timestamp']

        # Jeśli nie znaleziono timestamp, użyj daty modyfikacji pliku
        if not timestamp:
            timestamp = datetime.fromtimestamp(wer_file_path.stat().st_mtime)

        # Zwróć tylko jeśli znaleziono przynajmniej AppName lub Module
        if not app_name and not module:
            return None

        crash = _build_xml_crash_dict(
            app_name,
            module,
            exception_code,
            timestamp,
            wer_file_path
        )

        logger.debug(
            f"[WER] Parsed .wer XML file - AppName: {app_name}, "
            f"Module: {module}, ExceptionCode: {exception_code}"
        )
        return crash

    except ET.ParseError as e:
        logger.debug(f"[WER] XML parse error in {wer_file_path}: {e}")
        return None
    except Exception as e:
        logger.debug(f"[WER] Error parsing XML .wer file {wer_file_path}: {e}")
        return None


def _get_wer_directory_paths():
    """
    Przygotowuje listę ścieżek do katalogów WER.

    Returns:
        list: Lista ścieżek Path do katalogów WER
    """
    programdata = os.environ.get("ProgramData", "C:/ProgramData")
    localappdata = os.environ.get("LOCALAPPDATA", "")

    wer_paths = [
        Path(programdata) / "Microsoft" / "Windows" / "WER" / "ReportQueue",
        Path(programdata) / "Microsoft" / "Windows" / "WER" / "ReportArchive",
    ]

    if localappdata:
        wer_paths.extend([
            Path(localappdata) / "Microsoft" / "Windows" / "WER" / "ReportQueue",
            Path(localappdata) / "Microsoft" / "Windows" / "WER" / "ReportArchive",
        ])

    return wer_paths


def _get_sorted_report_directories(wer_path, max_count=50):
    """
    Znajduje i sortuje katalogi raportów w katalogu WER.

    Args:
        wer_path: Ścieżka do katalogu WER
        max_count: Maksymalna liczba katalogów do zwrócenia

    Returns:
        list: Lista katalogów raportów posortowanych według czasu modyfikacji
    """
    if not wer_path.exists():
        return []

    try:
        report_dirs = [d for d in wer_path.iterdir() if d.is_dir()]
        if not report_dirs:
            return []

        sorted_dirs = sorted(
            report_dirs,
            key=lambda x: x.stat().st_mtime,
            reverse=True
        )[:max_count]

        return sorted_dirs
    except Exception as e:
        logger.debug(f"[WER] Error listing report directories: {e}")
        return []


def _parse_single_dump_file(dump_file, dump_type):
    """
    Parsuje pojedynczy plik dump (mdmp lub hdmp).

    Args:
        dump_file: Ścieżka do pliku dump
        dump_type: Typ dumpa ('minidump' lub 'fulldump')

    Returns:
        dict: Informacje o dumpie lub None
    """
    try:
        from utils.minidump_parser import parse_minidump
        dump_info = parse_minidump(str(dump_file))
        if not dump_info.get("success"):
            return None

        return {
            "file": str(dump_file),
            "type": dump_type,
            "stop_code": dump_info.get("stop_code"),
            "stop_code_name": dump_info.get("stop_code_name"),
            "offending_driver": dump_info.get("offending_driver")
        }
    except Exception as e:
        logger.debug(f"[WER] Error parsing {dump_type} {dump_file}: {e}")
        return None


def _update_crash_from_dump_info(crash, dump_info):
    """
    Aktualizuje obiekt crash danymi z dumpa, jeśli brakuje kluczowych pól.

    Args:
        crash: Słownik z danymi crasha
        dump_info: Słownik z danymi dumpa
    """
    stop_code = dump_info.get("stop_code")
    offending_driver = dump_info.get("offending_driver")

    if not crash.get("exception_code") and stop_code:
        crash["exception_code"] = stop_code
        crash["severity"] = get_exception_severity(stop_code)

    if not crash.get("module_name") and offending_driver:
        crash["module_name"] = offending_driver
        crash["faulting_module_name"] = offending_driver


def _parse_dump_files(report_dir, crash):
    """
    Parsuje wszystkie pliki dump w katalogu raportu.

    Args:
        report_dir: Katalog raportu
        crash: Słownik z danymi crasha do uzupełnienia

    Returns:
        list: Lista danych o dumpach
    """
    dump_data = []
    mdmp_files = list(report_dir.glob("*.mdmp"))
    hdmp_files = list(report_dir.glob("*.hdmp"))

    for dump_file in mdmp_files:
        dump_info = _parse_single_dump_file(dump_file, "minidump")
        if dump_info:
            dump_data.append(dump_info)
            _update_crash_from_dump_info(crash, dump_info)

    for dump_file in hdmp_files:
        dump_info = _parse_single_dump_file(dump_file, "fulldump")
        if dump_info:
            dump_data.append(dump_info)
            _update_crash_from_dump_info(crash, dump_info)

    if mdmp_files:
        crash["wer_files"].extend([str(f) for f in mdmp_files])
    if hdmp_files:
        crash["wer_files"].extend([str(f) for f in hdmp_files])
    if dump_data:
        crash["dump_analysis"] = dump_data

    return dump_data


def _parse_memory_info_file(report_dir, crash):
    """
    Parsuje plik MemoryInfo.txt z katalogu raportu.

    Args:
        report_dir: Katalog raportu
        crash: Słownik z danymi crasha do uzupełnienia
    """
    memory_info = report_dir / "MemoryInfo.txt"
    if not memory_info.exists():
        return

    crash["has_memory_info"] = True
    crash["wer_files"].append(str(memory_info))

    try:
        with open(
            memory_info, 'r', encoding='utf-8', errors='ignore'
        ) as f:
            mem_content = f.read()
            mem_match = re.search(
                r'Memory\s+Usage:\s*([^\r\n]+)',
                mem_content,
                re.IGNORECASE
            )
            if mem_match:
                crash["memory_usage"] = mem_match.group(1).strip()
    except Exception:
        pass


def _parse_appcompat_file(report_dir, crash):
    """
    Parsuje plik AppCompat.txt z katalogu raportu.

    Args:
        report_dir: Katalog raportu
        crash: Słownik z danymi crasha do uzupełnienia
    """
    appcompat = report_dir / "AppCompat.txt"
    if not appcompat.exists():
        return

    crash["has_appcompat"] = True
    crash["wer_files"].append(str(appcompat))


def _process_single_report_directory(report_dir):
    """
    Przetwarza pojedynczy katalog raportu WER.

    Args:
        report_dir: Katalog raportu

    Returns:
        dict: Dane crasha lub None
    """
    report_wer = report_dir / "Report.wer"
    if not report_wer.exists():
        return None

    crash = parse_wer_file(report_wer)
    if not crash:
        return None

    crash["wer_directory"] = str(report_dir)
    crash["wer_files"] = []

    _parse_dump_files(report_dir, crash)
    _parse_memory_info_file(report_dir, crash)
    _parse_appcompat_file(report_dir, crash)

    return crash


def _process_wer_directory(wer_path):
    """
    Przetwarza wszystkie katalogi raportów w katalogu WER.

    Args:
        wer_path: Ścieżka do katalogu WER

    Returns:
        list: Lista crash events z tego katalogu
    """
    crashes = []
    report_dirs = _get_sorted_report_directories(wer_path, max_count=50)

    if not report_dirs:
        return crashes

    logger.info(
        f"[WER] Found {len(report_dirs)} report directories in {wer_path}"
    )

    for report_dir in report_dirs:
        try:
            crash = _process_single_report_directory(report_dir)
            if crash:
                crashes.append(crash)
        except Exception as e:
            logger.debug(
                f"[WER] Error processing report directory {report_dir}: {e}"
            )
            continue

    logger.info(
        f"[WER] Parsed {len(crashes)} report directories from {wer_path}"
    )

    return crashes


def collect_from_wer_directories():
    """
    3️⃣ Pełne parsowanie katalogów WER

    Parsuje:
    - Report.wer (główny manifest w każdym katalogu)
    - *.mdmp / *.hdmp (minidump / full dump)
    - MemoryInfo.txt (zużycie RAM)
    - AppCompat.txt (zgodność)

    Returns:
        list: Lista crash events wyciągniętych z plików .wer
    """
    crashes = []
    wer_paths = _get_wer_directory_paths()

    logger.info(f"[WER] Checking {len(wer_paths)} WER directory locations")

    for wer_path in wer_paths:
        if not wer_path.exists():
            logger.debug(f"[WER] WER directory does not exist: {wer_path}")
            continue

        logger.info(f"[WER] Processing WER directory: {wer_path}")

        try:
            dir_crashes = _process_wer_directory(wer_path)
            crashes.extend(dir_crashes)
        except Exception as e:
            logger.warning(
                f"[WER] Error accessing WER directory {wer_path}: {e}"
            )
            continue

    logger.info(
        f"[WER] Collected {len(crashes)} crashes "
        f"from {len(wer_paths)} WER directory locations"
    )

    return crashes


def correlate_event_log_with_wer_files(crashes):
    """
    4️⃣ Powiązanie Event Log → WER Files

    Korelacja po:
    - ReportId (z Event Log) → ReportGUID (z WER file)
    - CreationTime (z Event Log) → CreationTime (z WER file) ± 5 sekund
    - P1/P2 z signatures (AppName + Version)

    Args:
        crashes (list): Lista crash events z Event Log i WER files

    Returns:
        list: Lista crash events z dodanymi korelacjami
    """
    # Podziel crashy na Event Log i WER files
    event_log_crashes = [
        c for c in crashes if isinstance(
            c, dict) and c.get("source") != "wer_file"]
    wer_file_crashes = [
        c for c in crashes if isinstance(
            c, dict) and c.get("source") == "wer_file"]

    if not event_log_crashes or not wer_file_crashes:
        return crashes

    # Utwórz mapę WER files po różnych kluczach
    wer_by_report_id = {}
    wer_by_time = {}
    wer_by_app = {}

    for wer_crash in wer_file_crashes:
        report_guid = wer_crash.get("report_guid", "")
        if report_guid:
            wer_by_report_id[report_guid.lower()] = wer_crash

        timestamp = parse_timestamp(wer_crash.get("timestamp", ""))
        if timestamp:
            # Klucz: timestamp zaokrąglony do 5 sekund
            time_key = timestamp.replace(
                second=(
                    timestamp.second // 5) * 5,
                microsecond=0)
            if time_key not in wer_by_time:
                wer_by_time[time_key] = []
            wer_by_time[time_key].append(wer_crash)

        app_name = (wer_crash.get("application") or "").lower()
        app_version = (wer_crash.get("app_version") or "").lower()
        if app_name:
            key = (app_name, app_version)
            if key not in wer_by_app:
                wer_by_app[key] = []
            wer_by_app[key].append(wer_crash)

    # Koreluj Event Log crashes z WER files
    correlated_crashes = []
    for event_crash in event_log_crashes:
        report_id = event_crash.get("report_id", "")
        timestamp = parse_timestamp(event_crash.get("timestamp", ""))
        app_name = (event_crash.get("application") or "").lower()
        app_version = (event_crash.get("app_version") or "").lower()

        # Spróbuj znaleźć odpowiadający WER file
        matched_wer = None

        # 1. Po ReportId
        if report_id:
            matched_wer = wer_by_report_id.get(report_id.lower())

        # 2. Po CreationTime (± 5 sekund)
        if not matched_wer and timestamp:
            time_key = timestamp.replace(
                second=(
                    timestamp.second // 5) * 5,
                microsecond=0)
            candidates = wer_by_time.get(time_key, [])
            if len(candidates) == 1:
                matched_wer = candidates[0]
            elif len(candidates) > 1:
                # Jeśli wiele, wybierz najbliższy czasowo
                matched_wer = min(candidates, key=lambda w: abs(
                    (parse_timestamp(w.get("timestamp", ""))
                     or datetime.min) - timestamp
                ))

        # 3. Po P1/P2 (AppName + Version)
        if not matched_wer and app_name:
            key = (app_name, app_version)
            candidates = wer_by_app.get(key, [])
            if len(candidates) == 1:
                matched_wer = candidates[0]
            elif len(candidates) > 1 and timestamp:
                # Jeśli wiele, wybierz najbliższy czasowo
                matched_wer = min(candidates, key=lambda w: abs(
                    (parse_timestamp(w.get("timestamp", ""))
                     or datetime.min) - timestamp
                ))

        # Jeśli znaleziono dopasowanie, połącz dane
        if matched_wer:
            # Uzupełnij brakujące pola z WER file
            if not event_crash.get("faulting_application_path") and matched_wer.get(
                    "faulting_application_path"):
                event_crash["faulting_application_path"] = matched_wer["faulting_application_path"]
            if not event_crash.get("faulting_module_path") and matched_wer.get(
                    "faulting_module_path"):
                event_crash["faulting_module_path"] = matched_wer["faulting_module_path"]
            if not event_crash.get(
                    "exception_code") and matched_wer.get("exception_code"):
                event_crash["exception_code"] = matched_wer["exception_code"]
                event_crash["severity"] = get_exception_severity(
                    matched_wer["exception_code"])
            if not event_crash.get(
                    "fault_offset") and matched_wer.get("fault_offset"):
                event_crash["fault_offset"] = matched_wer["fault_offset"]

            # Dodaj informacje o WER file
            event_crash["correlated_wer_file"] = matched_wer.get(
                "wer_file_path", "")
            event_crash["correlated_wer_directory"] = matched_wer.get(
                "wer_directory", "")
            if matched_wer.get("wer_files"):
                event_crash["correlated_wer_files"] = matched_wer["wer_files"]

        correlated_crashes.append(event_crash)

    # Dodaj WER file crashes, które nie zostały skorelowane
    correlated_report_ids = {c.get("report_id", "").lower()
                             for c in correlated_crashes if c.get("report_id")}
    for wer_crash in wer_file_crashes:
        report_guid = (wer_crash.get("report_guid", "") or "").lower()
        if not report_guid or report_guid not in correlated_report_ids:
            correlated_crashes.append(wer_crash)

    logger.info(
        f"[WER] Correlated {len(correlated_crashes)} crashes (Event Log + WER files)")
    return correlated_crashes


def normalize_fault_offset(offset_str):
    """
    ✅ 4. ASLR-aware grouping - normalizuje offset modulo page alignment (0x1000)
    Pozwala wykryć takie same crashy mimo różnych ASLR!

    Args:
        offset_str (str): Offset jako string (hex lub dec)

    Returns:
        int: Znormalizowany offset (offset % 0x1000) lub 0
    """
    if not offset_str:
        return 0

    try:
        # Spróbuj sparsować jako hex
        if isinstance(offset_str, str):
            offset_str = offset_str.strip()
            if offset_str.startswith('0x') or offset_str.startswith('0X'):
                offset = int(offset_str, 16)
            else:
                # Spróbuj jako hex bez prefiksu
                try:
                    offset = int(offset_str, 16)
                except ValueError:
                    # Spróbuj jako decimal
                    offset = int(offset_str, 10)
        else:
            offset = int(offset_str)

        # Normalizuj modulo 0x1000 (page alignment)
        return offset % 0x1000
    except (ValueError, TypeError):
        return 0


def filter_and_deduplicate_crashes(crashes):
    """
    ✅ 5. Reguły filtrowania i deduplikacji

    5.1. Crash'e systemowe z pustymi polami - oznacz jako Unknown, ale NIE USUWAJ (statystyka)
    5.2. Powtarzające się identyczne crash'e w ciągu 5 sekund - łącz w jeden

    Args:
        crashes (list): Lista crash events

    Returns:
        list: Filtrowane i deduplikowane crashy
    """
    if not crashes:
        return []

    filtered = []
    seen_recent = {}  # {(app, module, exception): last_timestamp}
    dedup_window = timedelta(seconds=5)  # 5 sekund okno deduplikacji

    for crash in crashes:
        if not isinstance(crash, dict):
            continue

        # 5.1. Oznacz jako Unknown dla pustych pól, ale NIE USUWAJ
        app = crash.get("application") or crash.get(
            "faulting_application_name") or "Unknown"
        module = crash.get("module_name") or crash.get(
            "faulting_module_name") or ""
        exception = crash.get("exception_code") or ""

        if not app or app == "Unknown":
            if not module and not exception:
                # Oznacz jako Unknown dla statystyki
                crash["application"] = "Unknown"
                crash["faulting_application_name"] = "Unknown"

        # 5.2. Deduplikacja - powtarzające się identyczne crash'e w ciągu 5
        # sekund
        crash_time = parse_timestamp(crash.get("timestamp", ""))
        if crash_time:
            key = (app.lower(), module.lower(), exception.upper())
            last_seen = seen_recent.get(key)

            if last_seen and (crash_time - last_seen) < dedup_window:
                # Ten sam crash w ciągu 5 sekund - pomiń (lub zwiększ licznik)
                # Można tutaj dodać licznik, ale na razie pomijamy
                continue

            seen_recent[key] = crash_time

        filtered.append(crash)

    return filtered


def group_and_analyze_crashes(crashes):
    """
    ✅ 4. Reguły grupowania crashy - ASLR-aware grouping

    Twórz GroupID wg:
    (faulting_app, faulting_module, exception_code, fault_offset_normalized)

    Gdzie:
    fault_offset_normalized to offset modulo page alignment (0x1000)
    Pozwala wykryć takie same crashy mimo różnych ASLR!

    ASLR-aware grouping = MUST HAVE

    Args:
        crashes (list): Lista crash events

    Returns:
        list: Zgrupowane crashy z occurrences
    """
    # 5. Filtrowanie i deduplikacja
    crashes = filter_and_deduplicate_crashes(crashes)

    grouped = defaultdict(list)
    now = datetime.now()
    last_30min = now - timedelta(minutes=30)
    last_24h = now - timedelta(hours=24)

    # ✅ 4. ASLR-aware grouping
    for crash in crashes:
        # Upewnij się, że crash jest słownikiem
        if not isinstance(crash, dict):
            logger.debug(f"[WER] Skipping non-dict crash: {type(crash)}")
            continue

        app = crash.get("application") or crash.get(
            "faulting_application_name") or "Unknown"
        module = crash.get("module_name") or crash.get(
            "faulting_module_name") or ""
        exception = crash.get("exception_code") or ""
        fault_offset = crash.get("fault_offset") or ""

        # Normalizuj wartości dla lepszego grupowania
        app_normalized = app.lower().strip() if app else "unknown"
        # Usuwanie .exe, .dll dla grupowania, ale przechowanie w oryginale
        app_normalized = app_normalized.replace(
            '.exe', '').replace(
            '.dll', '').strip()
        module_normalized = module.lower().strip() if module else ""
        module_normalized = module_normalized.replace(
            '.exe', '').replace('.dll', '').strip()
        exception_normalized = exception.upper().strip() if exception else ""

        # ✅ 4. ASLR-aware: normalizuj offset modulo 0x1000
        offset_normalized = normalize_fault_offset(fault_offset)

        # Klucz grupowania: (AppName, Module, ExceptionCode, OffsetNormalized)
        key = (
            app_normalized,
            module_normalized,
            exception_normalized,
            offset_normalized)

        crash_time = parse_timestamp(crash.get("timestamp", ""))
        # Dodaj do grupy nawet jeśli timestamp jest None
        grouped[key].append({
            "crash": crash,
            "timestamp": crash_time if crash_time is not None else None
        })

    # Utwórz zgrupowane wyniki
    grouped_results = []

    for key, crash_list in grouped.items():
        app, module, exception, offset_normalized = key

        # Upewnij się, że crash_list nie jest puste
        if not crash_list:
            logger.debug(f"[WER] Skipping empty crash_list for key: {key}")
            continue

        # Sortuj po czasie (najnowsze pierwsze)
        try:
            crash_list.sort(key=lambda x: x.get("timestamp") if isinstance(
                x, dict) and "timestamp" in x else datetime.min, reverse=True)
        except Exception as e:
            logger.warning(f"[WER] Error sorting crash_list for {key}: {e}")
            continue

        # Zlicz wystąpienia w oknach czasowych
        crashes_30min = []
        crashes_24h = []
        crashes_1h = []
        crashes_6h = []
        timestamps = []

        for c in crash_list:
            if not isinstance(c, dict):
                continue
            timestamp = c.get("timestamp")
            if timestamp and isinstance(timestamp, datetime):
                timestamps.append(timestamp)
                if timestamp >= last_30min:
                    crashes_30min.append(c)
                if timestamp >= (now - timedelta(hours=1)):
                    crashes_1h.append(c)
                if timestamp >= (now - timedelta(hours=6)):
                    crashes_6h.append(c)
                if timestamp >= last_24h:
                    crashes_24h.append(c)

        # 2️⃣ Analiza powtarzalności - lepsze liczenie z rozróżnieniem czasu
        # Powtarzający się crash: ≥3 w 30 min LUB ≥5 w 1h LUB ≥10 w 24h
        is_repeating_30min = len(crashes_30min) >= 3
        is_repeating_1h = len(crashes_1h) >= 5
        is_repeating_24h = len(crashes_24h) >= 10
        is_repeating = is_repeating_30min or is_repeating_1h or is_repeating_24h

        # 4️⃣ Czasy między crashami - średni interwał
        avg_interval_seconds = None
        avg_interval_hours = None
        if len(timestamps) > 1:
            # Sortuj timestamps
            timestamps_sorted = sorted(timestamps)
            intervals = []
            for i in range(1, len(timestamps_sorted)):
                interval = (
                    timestamps_sorted[i] - timestamps_sorted[i - 1]).total_seconds()
                intervals.append(interval)
            if intervals:
                avg_interval_seconds = sum(intervals) / len(intervals)
                avg_interval_hours = avg_interval_seconds / 3600

        # Bezpieczne pobranie pierwszego i ostatniego crasha
        first_crash = crash_list[-1].get("crash",
                                         {}) if crash_list and isinstance(crash_list[-1],
                                                                          dict) else {}
        last_crash = crash_list[0].get(
            "crash", {}) if crash_list and isinstance(
            crash_list[0], dict) else {}

        # 3️⃣ Severity / Criticality - automatyczna ocena
        severity = last_crash.get(
            "severity",
            "Unknown") if isinstance(
            last_crash,
            dict) else "Unknown"
        criticality = calculate_crash_criticality(
            last_crash) if isinstance(last_crash, dict) else "Unknown"

        grouped_result = {
            "application": app,
            "module_name": module,
            "exception_code": exception,
            "fault_offset_normalized": offset_normalized,
            "total_occurrences": len(crash_list),
            "occurrences_30min": len(crashes_30min),
            "occurrences_1h": len(crashes_1h),
            "occurrences_6h": len(crashes_6h),
            "occurrences_24h": len(crashes_24h),
            "is_repeating": is_repeating,
            "is_repeating_30min": is_repeating_30min,
            "is_repeating_1h": is_repeating_1h,
            "is_repeating_24h": is_repeating_24h,
            "severity": severity,
            "criticality": criticality,
            "avg_interval_seconds": avg_interval_seconds,
            "avg_interval_hours": avg_interval_hours,
            "first_occurrence": first_crash.get(
                "timestamp",
                "") if isinstance(
                first_crash,
                dict) else "",
            "last_occurrence": last_crash.get(
                "timestamp",
                "") if isinstance(
                    last_crash,
                    dict) else "",
            "latest_crash": last_crash if isinstance(
                last_crash,
                dict) else {}}

        grouped_results.append(grouped_result)

    # Sortuj po liczbie wystąpień (najczęstsze pierwsze)
    # DEBUG: Sprawdź typ każdego elementu przed sortowaniem
    logger.debug(
        f"[WER] Before sorting - grouped_results type: {type(grouped_results)}, length: {len(grouped_results)}")
    for idx, result in enumerate(
            grouped_results[:3]):  # Tylko pierwsze 3 dla logowania
        logger.debug(
            f"[WER] grouped_results[{idx}] type: {type(result)}, is_dict: {isinstance(result, dict)}")
        if isinstance(result, dict):
            logger.debug(
                f"[WER] grouped_results[{idx}] keys: {list(result.keys())[:10]}")
    sys.stdout.flush()

    try:
        grouped_results.sort(
            key=lambda x: x.get(
                "total_occurrences",
                0) if isinstance(
                x,
                dict) else 0,
            reverse=True)
    except Exception as e:
        logger.warning(f"[WER] Error sorting grouped_results: {e}")
        from utils.error_analyzer import log_error_with_analysis
        log_error_with_analysis(
            e,
            grouped_results,
            {
                'variable_name': 'grouped_results',
                'location': 'wer.py:868',
                'function': 'group_and_analyze_crashes'
            },
            continue_execution=True
        )
        # Kontynuuj mimo błędu

    # DEBUG: Szczegółowe logowanie zwracanego wyniku
    logger.debug(
        f"[WER] group_and_analyze_crashes() returning type: {type(grouped_results)}")
    logger.debug(
        f"[WER] group_and_analyze_crashes() returning is list: {isinstance(grouped_results, list)}")
    logger.debug(
        f"[WER] group_and_analyze_crashes() returning length: {len(grouped_results)}")
    if len(grouped_results) > 0:
        logger.debug(
            f"[WER] group_and_analyze_crashes() first result type: {type(grouped_results[0])}")
        logger.debug(
            f"[WER] group_and_analyze_crashes() first result is dict: {isinstance(grouped_results[0], dict)}")
        if isinstance(grouped_results[0], dict):
            logger.debug(
                f"[WER] group_and_analyze_crashes() first result keys: {list(grouped_results[0].keys())}")
    sys.stdout.flush()

    logger.info(
        f"[WER] Grouped {len(crashes)} crashes into {len(grouped_results)} groups")

    return grouped_results


def parse_timestamp(timestamp_str):
    """
    Parsuje timestamp string do datetime object.
    Obsługuje różne formaty timestampów z Windows Event Log i WER.

    Args:
        timestamp_str (str): String timestamp (może być None, pusty string, lub różne formaty)

    Returns:
        datetime: Parsed datetime object lub None jeśli nie można sparsować
    """
    # Obsługa None i pustych stringów
    if not timestamp_str:
        return None

    # Konwersja na string i usunięcie białych znaków
    try:
        timestamp_str = str(timestamp_str).strip()
    except Exception:
        return None

    if not timestamp_str or timestamp_str.lower() in ['none', 'null', '']:
        return None

    # Różne formaty timestampów z Windows Event Log i WER
    formats = [
        "%Y-%m-%d %H:%M:%S",                    # 2025-11-29 12:22:15
        "%Y-%m-%dT%H:%M:%S",                    # 2025-11-29T12:22:15
        "%Y-%m-%dT%H:%M:%S.%f",                 # 2025-11-29T12:22:15.123456
        "%Y-%m-%dT%H:%M:%S.%fZ",                # 2025-11-29T12:22:15.123456Z
        "%Y-%m-%dT%H:%M:%SZ",                   # 2025-11-29T12:22:15Z
        "%Y/%m/%d %H:%M:%S",                    # 2025/11/29 12:22:15
        "%m/%d/%Y %H:%M:%S",                    # 11/29/2025 12:22:15
        "%m/%d/%Y %I:%M:%S %p",                 # 11/29/2025 12:22:15 PM
        "%d.%m.%Y %H:%M:%S",                    # 29.11.2025 12:22:15
        "%Y-%m-%d %H:%M:%S.%f",                 # 2025-11-29 12:22:15.123456
    ]

    # Spróbuj każdy format
    for fmt in formats:
        try:
            # Dla formatów z mikrosekundami, spróbuj pełnego stringa
            if '.%f' in fmt or 'Z' in fmt:
                return datetime.strptime(timestamp_str, fmt)
            else:
                # Dla innych formatów, weź pierwsze 19 znaków (bez mikrosekund)
                return datetime.strptime(timestamp_str[:19], fmt)
        except (ValueError, IndexError, TypeError):
            continue

    # Spróbuj ISO format z Z (UTC) - obsługa różnych wariantów
    try:
        # Usuń Z i dodaj +00:00 dla UTC
        if timestamp_str.endswith('Z'):
            timestamp_str = timestamp_str[:-1] + '+00:00'
        return datetime.fromisoformat(timestamp_str)
    except (ValueError, TypeError):
        pass

    # Ostatnia próba - użyj parsera daty z biblioteki standardowej (jeśli
    # dostępny)
    try:
        from dateutil import parser
        return parser.parse(timestamp_str)
    except (ImportError, ValueError, TypeError):
        pass

    # Jeśli wszystko zawiodło, zwróć None (nie loguj - może być dużo takich
    # przypadków)
    return None
