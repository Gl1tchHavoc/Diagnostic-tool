"""
Collector Windows Error Reporting (WER) - zbiera szczegółowe dane o crashach aplikacji i systemu.
Zbiera dane z Event Log oraz katalogów WER, grupuje powtarzające się crashy i integruje z golden rules.
"""
import subprocess
import sys
import os
import re
import xml.etree.ElementTree as ET
import configparser
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
        
        # 2️⃣ Parsowanie .wer files z ReportQueue i ReportArchive
        logger.info("[WER] Collecting crash data from WER directories (ReportQueue, ReportArchive)")
        wer_crashes = collect_from_wer_directories()
        # wer_crashes to lista crash events wyciągniętych z plików .wer
        wer_data["recent_crashes"].extend(wer_crashes)
        # Dla kompatybilności, zapisz informacje o liczbie sparsowanych plików .wer
        # reports jest listą, więc dodajemy dict z informacjami
        if wer_crashes:
            wer_data["reports"].append({
                "source": "wer_file",
                "count": len(wer_crashes),
                "description": f"Parsed {len(wer_crashes)} .wer files from ReportQueue/ReportArchive"
            })
        
        # Krok 3: Grupowanie i analiza powtarzających się crashy
        logger.info("[WER] Grouping and analyzing repeating crashes")
        grouped = group_and_analyze_crashes(wer_data["recent_crashes"])
        
        # DEBUG: Szczegółowe logowanie typu zwracanego przez group_and_analyze_crashes()
        logger.debug(f"[WER] group_and_analyze_crashes() returned type: {type(grouped)}")
        logger.debug(f"[WER] group_and_analyze_crashes() is list: {isinstance(grouped, list)}")
        logger.debug(f"[WER] group_and_analyze_crashes() is dict: {isinstance(grouped, dict)}")
        if isinstance(grouped, list):
            logger.debug(f"[WER] group_and_analyze_crashes() length: {len(grouped)}")
            if len(grouped) > 0:
                logger.debug(f"[WER] group_and_analyze_crashes() first element type: {type(grouped[0])}")
                logger.debug(f"[WER] group_and_analyze_crashes() first element is dict: {isinstance(grouped[0], dict)}")
                if isinstance(grouped[0], dict):
                    logger.debug(f"[WER] group_and_analyze_crashes() first element keys: {list(grouped[0].keys())[:10]}")
                logger.debug(f"[WER] group_and_analyze_crashes() content sample (first 3): {grouped[:3]}")
        elif isinstance(grouped, dict):
            logger.debug(f"[WER] group_and_analyze_crashes() dict keys: {list(grouped.keys())[:10]}")
        sys.stdout.flush()
        
        # KRYTYCZNE: Upewnij się, że grouped jest ZAWSZE listą (group_and_analyze_crashes zwraca listę)
        # Konsumenci oczekują listy i iterują po niej - NIE słownika!
        if not isinstance(grouped, list):
            logger.error(f"[WER] CRITICAL: group_and_analyze_crashes returned {type(grouped)}, expected list! Converting...")
            if isinstance(grouped, dict):
                # Jeśli to dict, zamień na listę z jednym elementem
                logger.warning(f"[WER] grouped is dict with keys: {list(grouped.keys())[:5] if grouped else 'empty'}")
                grouped = [grouped] if grouped else []
            else:
                grouped = [grouped] if grouped is not None else []
        
        # DODATKOWA WALIDACJA: Upewnij się, że wszystkie elementy są dict
        if isinstance(grouped, list):
            validated_grouped = []
            for i, item in enumerate(grouped):
                # DEBUG: Logowanie typu każdego elementu
                logger.debug(f"[WER] grouped_crashes[{i}] type: {type(item)}, is_dict: {isinstance(item, dict)}")
                if isinstance(item, dict):
                    validated_grouped.append(item)
                else:
                    logger.warning(f"[WER] grouped_crashes[{i}] is not a dict: {type(item)}, value sample: {str(item)[:100]}, skipping")
            grouped = validated_grouped
        
        wer_data["grouped_crashes"] = grouped
        logger.debug(f"[WER] Final grouped_crashes type: {type(wer_data['grouped_crashes'])}, length: {len(wer_data['grouped_crashes'])}")
        sys.stdout.flush()
        
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
        # grouped to LISTA, więc iterujemy po niej
        repeating = []
        # DEBUG: Sprawdź typ grouped przed iteracją
        logger.debug(f"[WER] Before filtering repeating - grouped type: {type(grouped)}, is_list: {isinstance(grouped, list)}")
        if isinstance(grouped, list):
            logger.debug(f"[WER] Before filtering repeating - grouped length: {len(grouped)}")
            for idx, g in enumerate(grouped):
                # DEBUG: Logowanie typu każdego elementu
                logger.debug(f"[WER] Processing group[{idx}] for repeating check: type={type(g)}, is_dict={isinstance(g, dict)}")
                
                if isinstance(g, dict):
                    # Bezpieczne użycie .get() - g jest dict
                    try:
                        occurrences_30min = g.get("occurrences_30min", 0)
                        if isinstance(occurrences_30min, (int, float)) and occurrences_30min >= 3:
                            repeating.append(g)
                    except Exception as e:
                        logger.warning(f"[WER] Error processing group[{idx}] for repeating check: {e}")
                        from utils.error_analyzer import log_error_with_analysis
                        log_error_with_analysis(
                            e,
                            g,
                            {
                                'variable_name': f'grouped[{idx}]',
                                'location': 'wer.py:134',
                                'function': 'collect'
                            },
                            continue_execution=True
                        )
                        continue
                elif isinstance(g, list):
                    # BŁĄD: g jest listą zamiast dict
                    logger.error(f"[WER] CRITICAL: group[{idx}] is list instead of dict in repeating check! Skipping...")
                    from utils.error_analyzer import log_error_with_analysis
                    log_error_with_analysis(
                        TypeError(f"group[{idx}] is list instead of dict"),
                        g,
                        {
                            'variable_name': f'grouped[{idx}]',
                            'location': 'wer.py:134',
                            'function': 'collect'
                        },
                        continue_execution=True
                    )
                    continue
                else:
                    logger.warning(f"[WER] Unexpected type in grouped[{idx}] for repeating check: {type(g)}")
                    continue
        else:
            logger.warning(f"[WER] grouped is not a list: {type(grouped)}")
        
        wer_data["statistics"] = {
            "total_crashes": len(wer_data["recent_crashes"]),
            "crashes_last_30min": len(crashes_30min),
            "crashes_last_24h": len(crashes_24h),
            "repeating_crashes": len(repeating)
        }
        
        logger.info(f"[WER] Collected {wer_data['statistics']['total_crashes']} crashes, "
                   f"{wer_data['statistics']['crashes_last_30min']} in last 30min, "
                   f"{wer_data['statistics']['repeating_crashes']} repeating")
        
        # OPTYMALIZACJA: Ograniczamy ilość danych, aby uniknąć problemów z pamięcią i serializacją
        # Problem: 348 crashy powodowały zawieszenie aplikacji podczas zwracania danych
        # Rozwiązanie: Zwracamy tylko ostatnie N crashy i uproszczone grouped_crashes
        
        MAX_RECENT_CRASHES = 50  # Zmniejszone z 100 do 50 - mniej danych
        MAX_GROUPED_CRASHES_DETAIL = 20  # Zmniejszone z 50 do 20 - mniej grup
        
        original_recent_count = len(wer_data["recent_crashes"])
        original_reports_count = len(wer_data["reports"])
        original_grouped_count = len(wer_data["grouped_crashes"])
        
        # 1. Ogranicz recent_crashes - tylko ostatnie N (najnowsze) + uprość strukturę
        if wer_data["recent_crashes"]:
            # Sortuj po timestamp (najnowsze pierwsze)
            try:
                wer_data["recent_crashes"].sort(
                    key=lambda x: parse_timestamp(x.get("timestamp", "")) if isinstance(x, dict) else datetime.min,
                    reverse=True
                )
            except Exception as e:
                logger.warning(f"[WER] Error sorting recent_crashes: {e}")
            
            # Uprość strukturę - usuń zbędne pola z każdego crasha
            simplified_crashes = []
            for crash in wer_data["recent_crashes"][:MAX_RECENT_CRASHES]:
                if isinstance(crash, dict):
                    # Zachowaj tylko kluczowe pola potrzebne do analizy
                    simplified = {
                        "event_id": str(crash.get("event_id", ""))[:20],
                        "timestamp": str(crash.get("timestamp", ""))[:50],
                        "application": str(crash.get("application", ""))[:100],
                        "module_name": str(crash.get("module_name", ""))[:100],
                        "exception_code": str(crash.get("exception_code", ""))[:50],
                        "type": str(crash.get("type", ""))[:50]
                    }
                    simplified_crashes.append(simplified)
                else:
                    simplified_crashes.append(crash)
            
            wer_data["recent_crashes"] = simplified_crashes
            logger.info(f"[WER] Limited and simplified recent_crashes: {original_recent_count} -> {len(simplified_crashes)}")
        
        # 2. Uprość grouped_crashes - usuń pełne obiekty crash, zostaw tylko statystyki
        # DEBUG: Sprawdź typ grouped_crashes przed iteracją
        logger.debug(f"[WER] Before simplification - grouped_crashes type: {type(wer_data.get('grouped_crashes'))}")
        logger.debug(f"[WER] Before simplification - grouped_crashes is list: {isinstance(wer_data.get('grouped_crashes'), list)}")
        if isinstance(wer_data.get('grouped_crashes'), list):
            logger.debug(f"[WER] Before simplification - grouped_crashes length: {len(wer_data.get('grouped_crashes', []))}")
        sys.stdout.flush()
        
        if wer_data.get("grouped_crashes"):
            # ZABEZPIECZENIE: Upewnij się, że grouped_crashes jest listą przed iteracją
            grouped_crashes = wer_data.get("grouped_crashes", [])
            if not isinstance(grouped_crashes, list):
                logger.error(f"[WER] CRITICAL: grouped_crashes is not a list before simplification! Type: {type(grouped_crashes)}")
                # Użyj error_analyzer do kompleksowej analizy
                from utils.error_analyzer import log_error_with_analysis
                log_error_with_analysis(
                    TypeError(f"grouped_crashes is {type(grouped_crashes).__name__} instead of list"),
                    grouped_crashes,
                    {
                        'variable_name': 'grouped_crashes',
                        'location': 'wer.py:177',
                        'function': 'collect'
                    },
                    continue_execution=True
                )
                grouped_crashes = []
            
            simplified_groups = []
            for idx, group in enumerate(grouped_crashes[:MAX_GROUPED_CRASHES_DETAIL]):
                # DEBUG: Logowanie typu każdego elementu przed użyciem .get()
                logger.debug(f"[WER] Processing group[{idx}]: type={type(group)}, is_dict={isinstance(group, dict)}")
                
                if isinstance(group, dict):
                    # Bezpieczne użycie .get() - group jest dict
                    try:
                        # Zachowaj tylko kluczowe pola, usuń pełne obiekty crash
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
                        # Usuń latest_crash - może zawierać duże obiekty
                        # Jeśli latest_crash istnieje, wyciągnij tylko podstawowe pola (bez pełnego obiektu)
                        latest_crash = group.get("latest_crash", {})
                        if latest_crash and isinstance(latest_crash, dict):
                            # Zachowaj tylko podstawowe pola z latest_crash (bez zagnieżdżonych obiektów)
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
                                'location': 'wer.py:179',
                                'function': 'collect'
                            },
                            continue_execution=True
                        )
                        # Pomiń ten element, kontynuuj z następnym
                        continue
                elif isinstance(group, list):
                    # BŁĄD: group jest listą zamiast dict - to nie powinno się zdarzyć
                    logger.error(f"[WER] CRITICAL: group[{idx}] is list (length: {len(group)}) instead of dict! Skipping...")
                    from utils.error_analyzer import log_error_with_analysis
                    log_error_with_analysis(
                        TypeError(f"group[{idx}] is list instead of dict"),
                        group,
                        {
                            'variable_name': f'grouped_crashes[{idx}]',
                            'location': 'wer.py:179',
                            'function': 'collect'
                        },
                        continue_execution=True
                    )
                    # Pomiń ten element
                    continue
                else:
                    logger.warning(f"[WER] Unexpected type in grouped_crashes[{idx}]: {type(group)}, value sample: {str(group)[:100]}")
                    # Pomiń ten element
                    continue
            
            wer_data["grouped_crashes"] = simplified_groups
            if original_grouped_count > MAX_GROUPED_CRASHES_DETAIL:
                logger.info(f"[WER] Limited grouped_crashes: {original_grouped_count} -> {len(simplified_groups)}")
        
        # 3. Uprość reports - zostaw tylko podstawowe informacje (bez pełnych ścieżek i dużych danych)
        if wer_data["reports"]:
            simplified_reports = []
            for report in wer_data["reports"][:20]:  # Limit do 20
                if isinstance(report, dict):
                    # Zachowaj tylko podstawowe pola, usuń duże obiekty
                    simplified = {
                        "timestamp": report.get("timestamp", ""),
                        "report_type": report.get("report_type", ""),
                        "application": report.get("application", ""),
                        "version": report.get("version", ""),
                        "bucket": report.get("bucket", "")
                    }
                    # Usuń pełne ścieżki i duże dane
                    simplified_reports.append(simplified)
                else:
                    simplified_reports.append(report)
            
            # Sortuj po czasie (najnowsze pierwsze)
            try:
                simplified_reports.sort(
                    key=lambda x: parse_timestamp(x.get("timestamp", "")) if isinstance(x, dict) else datetime.min,
                    reverse=True
                )
            except Exception:
                pass
            
            wer_data["reports"] = simplified_reports
            if original_reports_count > 20:
                logger.info(f"[WER] Limited reports: {original_reports_count} -> {len(simplified_reports)}")
            elif len(simplified_reports) < original_reports_count:
                logger.info(f"[WER] Simplified reports: {original_reports_count} -> {len(simplified_reports)}")
        
        # Dodaj informację o oryginalnych rozmiarach do statystyk (dla debugowania)
        wer_data["statistics"]["original_recent_crashes_count"] = original_recent_count
        wer_data["statistics"]["original_reports_count"] = original_reports_count
        wer_data["statistics"]["original_grouped_crashes_count"] = original_grouped_count
        
        # KONWERSJA DATETIME NA STRINGI - kluczowe dla serializacji!
        # Problem: obiekty datetime nie są serializowalne do JSON i mogą powodować zawieszenie
        def convert_datetime_to_string(obj, depth=0, max_depth=50):
            """Rekurencyjnie konwertuje wszystkie obiekty datetime na stringi."""
            # Zabezpieczenie przed nieskończoną rekurencją
            if depth > max_depth:
                logger.warning(f"[WER] Max depth {max_depth} reached in datetime conversion")
                return str(obj) if obj is not None else None
            
            # Obsługa None - zwróć None zamiast próbować konwertować
            if obj is None:
                return None
            
            # Obsługa datetime
            if isinstance(obj, datetime):
                try:
                    return obj.isoformat()
                except Exception as e:
                    logger.warning(f"[WER] Error converting datetime to isoformat: {e}")
                    return str(obj)
            
            # Obsługa dict
            elif isinstance(obj, dict):
                try:
                    return {k: convert_datetime_to_string(v, depth + 1, max_depth) for k, v in obj.items()}
                except Exception as e:
                    logger.warning(f"[WER] Error converting dict at depth {depth}: {e}")
                    return str(obj)
            
            # Obsługa list
            elif isinstance(obj, list):
                try:
                    return [convert_datetime_to_string(item, depth + 1, max_depth) for item in obj]
                except Exception as e:
                    logger.warning(f"[WER] Error converting list at depth {depth}: {e}")
                    return str(obj)
            
            # Wszystko inne - zwróć jak jest
            else:
                return obj
        
        logger.info("[WER] Converting datetime objects to strings for serialization...")
        sys.stdout.flush()
        try:
            # ZABEZPIECZENIE: Konwersja może być wolna - wykonaj tylko jeśli dane nie są zbyt duże
            # Sprawdź rozmiar danych przed konwersją
            total_items = len(wer_data.get('recent_crashes', [])) + len(wer_data.get('reports', [])) + len(wer_data.get('grouped_crashes', []))
            if total_items > 200:  # Jeśli więcej niż 200 elementów, pomin konwersję (może być wolna)
                logger.warning(f"[WER] Skipping datetime conversion - too many items ({total_items}), data already simplified")
                sys.stdout.flush()
            else:
                wer_data = convert_datetime_to_string(wer_data)
                logger.info("[WER] Datetime conversion completed successfully")
                sys.stdout.flush()
        except Exception as e:
            logger.warning(f"[WER] Error converting datetime objects: {e}")
            sys.stdout.flush()
            # Nie przerywaj - kontynuuj z oryginalnymi danymi (które są już uproszczone)
        
        logger.info(f"[WER] Optimized data: {original_recent_count}->{len(wer_data.get('recent_crashes', []))} crashes, "
                   f"{original_reports_count}->{len(wer_data.get('reports', []))} reports, "
                   f"{original_grouped_count}->{len(wer_data.get('grouped_crashes', []))} groups")
        
        # DEBUG: Sprawdź strukturę przed zwróceniem
        logger.debug(f"[WER] DEBUG: wer_data type: {type(wer_data)}")
        logger.debug(f"[WER] DEBUG: wer_data keys: {list(wer_data.keys())}")
        logger.debug(f"[WER] DEBUG: grouped_crashes type: {type(wer_data.get('grouped_crashes'))}")
        logger.debug(f"[WER] DEBUG: grouped_crashes is list: {isinstance(wer_data.get('grouped_crashes'), list)}")
        logger.debug(f"[WER] DEBUG: grouped_crashes length: {len(wer_data.get('grouped_crashes', []))}")
        
    except Exception as e:
        logger.exception(f"[WER] Exception during collection: {e}")
        wer_data["collection_error"] = f"Failed to collect WER data: {e}"
    
    # DEBUG: Sprawdź strukturę przed zwróceniem (nawet po błędzie)
    logger.debug(f"[WER] DEBUG: Returning wer_data, type: {type(wer_data)}")
    logger.debug(f"[WER] DEBUG: Returning wer_data keys: {list(wer_data.keys()) if isinstance(wer_data, dict) else 'N/A'}")
    
    # FORCE FLUSH - upewnij się, że logi są zapisane
    # sys jest już zaimportowany na początku pliku (linia 6)
    sys.stdout.flush()
    for handler in logger.handlers:
        if hasattr(handler, 'flush'):
            handler.flush()
    
    # Dodatkowy log do pliku bezpośrednio (na wypadek problemów z loggerem)
    try:
        debug_file = Path("logs/wer_debug.txt")
        with open(debug_file, "a", encoding="utf-8") as f:
            f.write(f"{datetime.now()} | [WER] Returning wer_data, type: {type(wer_data)}\n")
            if isinstance(wer_data, dict):
                f.write(f"{datetime.now()} | [WER] Keys: {list(wer_data.keys())}\n")
                if 'grouped_crashes' in wer_data:
                    f.write(f"{datetime.now()} | [WER] grouped_crashes type: {type(wer_data['grouped_crashes'])}\n")
                    f.write(f"{datetime.now()} | [WER] grouped_crashes is list: {isinstance(wer_data['grouped_crashes'], list)}\n")
            f.flush()
    except Exception as e:
        logger.warning(f"[WER] Failed to write debug file: {e}")
    
    logger.info("[WER] DEBUG: About to RETURN wer_data - LAST LINE IN collect()")
    sys.stdout.flush()
    
    # Dodatkowy zapis do pliku przed return
    try:
        debug_file = Path("logs/wer_return_debug.txt")
        with open(debug_file, "a", encoding="utf-8") as f:
            f.write(f"{datetime.now()} | [WER] RETURNING wer_data\n")
            f.write(f"{datetime.now()} | [WER] Type: {type(wer_data)}\n")
            if isinstance(wer_data, dict):
                f.write(f"{datetime.now()} | [WER] Keys: {list(wer_data.keys())}\n")
                if 'grouped_crashes' in wer_data:
                    f.write(f"{datetime.now()} | [WER] grouped_crashes type: {type(wer_data['grouped_crashes'])}\n")
                    f.write(f"{datetime.now()} | [WER] grouped_crashes is list: {isinstance(wer_data['grouped_crashes'], list)}\n")
            f.flush()
    except Exception as e:
        logger.warning(f"[WER] Failed to write return debug file: {e}")
    
    logger.info("[WER] DEBUG: ACTUALLY RETURNING NOW")
    sys.stdout.flush()
    
    # Próba zwrócenia z dodatkowym logowaniem
    try:
        result = wer_data
        logger.info("[WER] DEBUG: wer_data assigned to result variable")
        sys.stdout.flush()
        logger.info("[WER] DEBUG: About to execute return statement")
        sys.stdout.flush()
        return result
    except Exception as e:
        logger.exception(f"[WER] DEBUG: Exception during return: {e}")
        sys.stdout.flush()
        raise


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
        
        # 1️⃣ Pobranie crashy z Event Log - Event ID 1000, 1001
        # Wyciągnij AppName z różnych formatów
        app_name = extract_field_from_message(message, [
            r'Application\s+Name:\s*([^\r\n]+)',
            r'Faulting\s+application\s+name:\s*([^\r\n]+)',
            r'Application:\s*([^\r\n,]+)',
            r'AppName:\s*([^\r\n]+)',
            r'Faulting\s+Application\s+Name:\s*([^\r\n]+)'
        ])
        
        app_version = extract_field_from_message(message, [
            r'Application\s+Version:\s*([^\r\n]+)',
            r'Application\s+Version\s+String:\s*([^\r\n]+)'
        ])
        
        module_name = extract_field_from_message(message, [
            r'Faulting\s+module\s+name:\s*([^\r\n]+)',
            r'Module\s+Name:\s*([^\r\n]+)',
            r'Faulting\s+Module\s+Name:\s*([^\r\n]+)',
            r'Module:\s*([^\r\n]+)'
        ])
        
        # 6️⃣ Dodatkowe usprawnienia: Jeśli AppName == None → spróbuj Faulting module name
        if not app_name or app_name == "Unknown":
            if module_name:
                logger.debug(f"[WER] AppName is None/Unknown, using module_name as fallback: {module_name}")
                app_name = module_name
            else:
                # Jeśli nadal Unknown → spróbuj wyciągnąć z ProviderName
                if provider and provider != "Application Error":
                    app_name = provider
                else:
                    app_name = "Unknown"
        
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
        
        # 6️⃣ Dodatkowe usprawnienia: Walidacja i logowanie
        logger.debug(f"[WER] Extracted crash - AppName: {app_name}, Module: {module_name}, ExceptionCode: {exception_code}")
        
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


def parse_wer_file(wer_file_path):
    """
    Parsuje plik .wer (może być w formacie INI lub XML).
    Wyciąga: AppName, Module, ExceptionCode, Timestamp.
    
    Args:
        wer_file_path (Path): Ścieżka do pliku .wer
        
    Returns:
        dict: Wyciągnięte dane o crashu lub None jeśli nie można sparsować
    """
    try:
        if not wer_file_path.exists():
            return None
        
        # Spróbuj najpierw jako INI
        try:
            config = configparser.ConfigParser()
            # configparser wymaga sekcji, więc musimy obsłużyć pliki bez sekcji
            with open(wer_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Sprawdź czy to XML (zaczyna się od <?xml lub <)
            if content.strip().startswith('<?xml') or content.strip().startswith('<'):
                return parse_wer_xml(wer_file_path, content)
            else:
                # To jest INI-like format
                return parse_wer_ini(wer_file_path, content)
                
        except Exception as e:
            logger.debug(f"[WER] Error parsing .wer file {wer_file_path}: {e}")
            return None
            
    except Exception as e:
        logger.debug(f"[WER] Error reading .wer file {wer_file_path}: {e}")
        return None


def parse_wer_ini(wer_file_path, content):
    """
    Parsuje plik .wer w formacie INI.
    
    Args:
        wer_file_path (Path): Ścieżka do pliku
        content (str): Zawartość pliku
        
    Returns:
        dict: Wyciągnięte dane o crashu lub None
    """
    try:
        # Pliki .wer w formacie INI często nie mają sekcji, więc parsujemy ręcznie
        app_name = None
        module = None
        exception_code = None
        timestamp = None
        
        # Wyciągnij wartości używając regex
        # AppName → Faulting application
        app_match = re.search(r'Faulting\s+application[:\s]+([^\r\n]+)', content, re.IGNORECASE)
        if not app_match:
            app_match = re.search(r'AppName[:\s]+([^\r\n]+)', content, re.IGNORECASE)
        if app_match:
            app_name = app_match.group(1).strip()
        
        # Module → Faulting module
        module_match = re.search(r'Faulting\s+module[:\s]+([^\r\n]+)', content, re.IGNORECASE)
        if not module_match:
            module_match = re.search(r'Module[:\s]+([^\r\n]+)', content, re.IGNORECASE)
        if module_match:
            module = module_match.group(1).strip()
        
        # ExceptionCode → Exception code
        exception_match = re.search(r'Exception\s+code[:\s]+([^\r\n]+)', content, re.IGNORECASE)
        if not exception_match:
            exception_match = re.search(r'ExceptionCode[:\s]+([^\r\n]+)', content, re.IGNORECASE)
        if exception_match:
            exception_code = exception_match.group(1).strip()
        
        # Timestamp → czas crasha
        timestamp_match = re.search(r'Time[:\s]+([^\r\n]+)', content, re.IGNORECASE)
        if not timestamp_match:
            timestamp_match = re.search(r'Timestamp[:\s]+([^\r\n]+)', content, re.IGNORECASE)
        if not timestamp_match:
            # Spróbuj wyciągnąć z nazwy pliku lub daty modyfikacji
            timestamp = datetime.fromtimestamp(wer_file_path.stat().st_mtime)
        else:
            timestamp_str = timestamp_match.group(1).strip()
            timestamp = parse_timestamp(timestamp_str)
            if not timestamp:
                # Fallback do daty modyfikacji pliku
                timestamp = datetime.fromtimestamp(wer_file_path.stat().st_mtime)
        
        # Jeśli nie znaleziono timestamp, użyj daty modyfikacji pliku
        if not timestamp:
            timestamp = datetime.fromtimestamp(wer_file_path.stat().st_mtime)
        
        # Zwróć tylko jeśli znaleziono przynajmniej AppName lub Module
        if app_name or module:
            crash = {
                "event_id": "WER_FILE",
                "timestamp": timestamp.isoformat() if isinstance(timestamp, datetime) else str(timestamp),
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
                "source": "wer_file",
                "wer_file_path": str(wer_file_path)
            }
            logger.debug(f"[WER] Parsed .wer file - AppName: {app_name}, Module: {module}, ExceptionCode: {exception_code}")
            return crash
        
        return None
        
    except Exception as e:
        logger.debug(f"[WER] Error parsing INI .wer file {wer_file_path}: {e}")
        return None


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
        
        app_name = None
        module = None
        exception_code = None
        timestamp = None
        
        # Szukaj w różnych miejscach w XML
        # AppName → Faulting application
        for elem in root.iter():
            text = elem.text or ""
            tag = elem.tag.lower()
            attrib = elem.attrib
            
            # Sprawdź różne możliwe lokalizacje
            if 'faulting' in tag and 'application' in tag:
                app_name = text.strip() or attrib.get('value', '').strip()
            elif 'appname' in tag:
                app_name = text.strip() or attrib.get('value', '').strip()
            elif 'application' in tag and text.strip():
                app_name = text.strip()
            
            # Module → Faulting module
            if 'faulting' in tag and 'module' in tag:
                module = text.strip() or attrib.get('value', '').strip()
            elif 'module' in tag and 'name' in tag:
                module = text.strip() or attrib.get('value', '').strip()
            
            # ExceptionCode → Exception code
            if 'exception' in tag and 'code' in tag:
                exception_code = text.strip() or attrib.get('value', '').strip()
            elif 'exceptioncode' in tag:
                exception_code = text.strip() or attrib.get('value', '').strip()
            
            # Timestamp
            if 'time' in tag or 'timestamp' in tag:
                timestamp_str = text.strip() or attrib.get('value', '').strip()
                if timestamp_str:
                    timestamp = parse_timestamp(timestamp_str)
        
        # Jeśli nie znaleziono timestamp, użyj daty modyfikacji pliku
        if not timestamp:
            timestamp = datetime.fromtimestamp(wer_file_path.stat().st_mtime)
        
        # Zwróć tylko jeśli znaleziono przynajmniej AppName lub Module
        if app_name or module:
            crash = {
                "event_id": "WER_FILE",
                "timestamp": timestamp.isoformat() if isinstance(timestamp, datetime) else str(timestamp),
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
                "source": "wer_file",
                "wer_file_path": str(wer_file_path)
            }
            logger.debug(f"[WER] Parsed .wer XML file - AppName: {app_name}, Module: {module}, ExceptionCode: {exception_code}")
            return crash
        
        return None
        
    except ET.ParseError as e:
        logger.debug(f"[WER] XML parse error in {wer_file_path}: {e}")
        return None
    except Exception as e:
        logger.debug(f"[WER] Error parsing XML .wer file {wer_file_path}: {e}")
        return None


def collect_from_wer_directories():
    """
    2️⃣ Parsowanie .wer files z ReportQueue i ReportArchive.
    Zbiera dane z katalogów Windows Error Reporting i parsuje pliki .wer.
    
    Returns:
        list: Lista crash events wyciągniętych z plików .wer
    """
    crashes = []
    reports = []
    
    # 2️⃣ Parsowanie .wer files - lokalizacje:
    # C:\ProgramData\Microsoft\Windows\WER\ReportQueue
    # C:\ProgramData\Microsoft\Windows\WER\ReportArchive
    wer_paths = [
        Path("C:/ProgramData/Microsoft/Windows/WER/ReportQueue"),
        Path("C:/ProgramData/Microsoft/Windows/WER/ReportArchive"),
        Path(os.environ.get("LOCALAPPDATA", "")) / "Microsoft" / "Windows" / "WER",
        Path("C:/ProgramData/Microsoft/Windows/WER")
    ]
    
    for wer_path in wer_paths:
        if not wer_path.exists():
            continue
        
        try:
            # Znajdź wszystkie pliki *.wer
            wer_files = list(wer_path.rglob("*.wer"))
            logger.debug(f"[WER] Found {len(wer_files)} .wer files in {wer_path}")
            
            # Parsuj pliki .wer (maksymalnie 50 najnowszych)
            parsed_count = 0
            for wer_file in sorted(wer_files, key=lambda x: x.stat().st_mtime, reverse=True)[:50]:
                try:
                    crash = parse_wer_file(wer_file)
                    if crash:
                        crashes.append(crash)
                        parsed_count += 1
                except Exception as e:
                    logger.debug(f"[WER] Error parsing .wer file {wer_file}: {e}")
                    continue
            
            logger.info(f"[WER] Parsed {parsed_count} .wer files from {wer_path}")
            
            # Zbierz też informacje o katalogach raportów (dla kompatybilności)
            report_dirs = [d for d in wer_path.iterdir() if d.is_dir()]
            for report_dir in sorted(report_dirs, key=lambda x: x.stat().st_mtime, reverse=True)[:20]:
                try:
                    stat = report_dir.stat()
                    report_info = {
                        "path": str(report_dir),
                        "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                        "size": stat.st_size
                    }
                    
                    # Sprawdź czy jest plik .wer w katalogu
                    wer_file = report_dir / "Report.wer"
                    if wer_file.exists():
                        report_info["has_wer_file"] = True
                        # Plik już został sparsowany powyżej
                    
                    reports.append(report_info)
                    
                except Exception as e:
                    logger.debug(f"[WER] Error processing report directory {report_dir}: {e}")
                    continue
            
            # Jeśli znaleziono crashy, nie sprawdzaj kolejnej ścieżki
            if crashes:
                break
                
        except Exception as e:
            logger.debug(f"[WER] Error accessing WER directory {wer_path}: {e}")
            continue
    
    logger.info(f"[WER] Collected {len(crashes)} crashes from .wer files and {len(reports)} WER report directories")
    
    # Zwróć crashy (będą dodane do recent_crashes) oraz informacje o raportach
    # Dla kompatybilności zwracamy listę, ale crashy są już w crashes
    return crashes


def group_and_analyze_crashes(crashes):
    """
    3️⃣ Grupowanie crashy - zgrupuj po AppName, ExceptionCode, Module.
    Zlicza wystąpienia w ostatnich 30 minutach i 24 godzinach.
    
    Grupowanie po:
    - AppName (application)
    - ExceptionCode
    - Module (module_name) - opcjonalnie
    
    Args:
        crashes (list): Lista crash events
        
    Returns:
        list: Zgrupowane crashy z occurrences
    """
    grouped = defaultdict(list)
    now = datetime.now()
    last_30min = now - timedelta(minutes=30)
    last_24h = now - timedelta(hours=24)
    
    # 3️⃣ Grupuj crashy - po AppName, ExceptionCode, Module
    for crash in crashes:
        # Upewnij się, że crash jest słownikiem
        if not isinstance(crash, dict):
            logger.debug(f"[WER] Skipping non-dict crash: {type(crash)}")
            continue
        
        app = crash.get("application", "Unknown")
        module = crash.get("module_name", "")
        exception = crash.get("exception_code", "")
        
        # Klucz grupowania: (AppName, Module, ExceptionCode)
        # Normalizuj wartości dla lepszego grupowania
        app_normalized = app.lower().strip() if app else "unknown"
        module_normalized = module.lower().strip() if module else ""
        exception_normalized = exception.upper().strip() if exception else ""
        
        key = (app_normalized, module_normalized, exception_normalized)
        
        crash_time = parse_timestamp(crash.get("timestamp", ""))
        # Dodaj do grupy nawet jeśli timestamp jest None - użyj pustego stringa jako fallback
        grouped[key].append({
            "crash": crash,
            "timestamp": crash_time if crash_time is not None else None  # None jest OK, będzie konwertowane później
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
    # DEBUG: Sprawdź typ każdego elementu przed sortowaniem
    logger.debug(f"[WER] Before sorting - grouped_results type: {type(grouped_results)}, length: {len(grouped_results)}")
    for idx, result in enumerate(grouped_results[:3]):  # Tylko pierwsze 3 dla logowania
        logger.debug(f"[WER] grouped_results[{idx}] type: {type(result)}, is_dict: {isinstance(result, dict)}")
        if isinstance(result, dict):
            logger.debug(f"[WER] grouped_results[{idx}] keys: {list(result.keys())[:10]}")
    sys.stdout.flush()
    
    try:
        grouped_results.sort(key=lambda x: x.get("total_occurrences", 0) if isinstance(x, dict) else 0, reverse=True)
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
    logger.debug(f"[WER] group_and_analyze_crashes() returning type: {type(grouped_results)}")
    logger.debug(f"[WER] group_and_analyze_crashes() returning is list: {isinstance(grouped_results, list)}")
    logger.debug(f"[WER] group_and_analyze_crashes() returning length: {len(grouped_results)}")
    if len(grouped_results) > 0:
        logger.debug(f"[WER] group_and_analyze_crashes() first result type: {type(grouped_results[0])}")
        logger.debug(f"[WER] group_and_analyze_crashes() first result is dict: {isinstance(grouped_results[0], dict)}")
        if isinstance(grouped_results[0], dict):
            logger.debug(f"[WER] group_and_analyze_crashes() first result keys: {list(grouped_results[0].keys())}")
    sys.stdout.flush()
    
    logger.info(f"[WER] Grouped {len(crashes)} crashes into {len(grouped_results)} groups")
    
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
    
    # Ostatnia próba - użyj parsera daty z biblioteki standardowej (jeśli dostępny)
    try:
        from dateutil import parser
        return parser.parse(timestamp_str)
    except (ImportError, ValueError, TypeError):
        pass
    
    # Jeśli wszystko zawiodło, zwróć None (nie loguj - może być dużo takich przypadków)
    return None
