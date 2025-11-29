import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import datetime
import re
from utils.logger import get_logger

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
            # Użyj -ErrorAction SilentlyContinue żeby nie przerywać przy błędach
            cmd = f"Get-WinEvent -LogName {category} -MaxEvents {max_events} -ErrorAction SilentlyContinue | ConvertTo-Xml -As String -Depth 3"
            
            # Użyj bezpiecznej funkcji z obsługą różnych kodowań
            from utils.subprocess_helper import run_powershell_hidden
            output = run_powershell_hidden(cmd)
            
            # Sprawdź czy output nie jest pusty
            logger = get_logger()
            if not output or len(output.strip()) < 50:
                logger.warning(f"[SYSTEM_LOGS] Empty or invalid output from {category} log query (length: {len(output) if output else 0})")
                all_logs[category] = []
                continue
            
            logs = parse_xml_logs(output, filter_levels)
            all_logs[category] = logs
            
            # Policz eventy (bez błędów)
            valid_logs = [log for log in logs if "error" not in log]
            logger.info(f"[SYSTEM_LOGS] Collected {len(valid_logs)} valid events from {category} log (total parsed: {len(logs)})")
        except subprocess.CalledProcessError as e:
            error_msg = f"Error fetching {category} logs: {e}"
            all_logs[category] = [error_msg]
            logger = get_logger()
            logger.error(f"[SYSTEM_LOGS] {error_msg}")
        except Exception as e:
            error_msg = f"Unexpected error fetching {category} logs: {type(e).__name__}: {e}"
            all_logs[category] = [error_msg]
            logger = get_logger()
            logger.exception(f"[SYSTEM_LOGS] Exception in {category} log collection")
    
    return all_logs

def parse_xml_logs(xml_data, filter_levels=None):
    """
    Parsuje XML wygenerowany przez PowerShell i zwraca listę sformatowanych logów.
    """
    logger = get_logger()
    logs = []
    if filter_levels is None:
        filter_levels = []
    
    # Normalizuj filter_levels do małych liter
    filter_levels_lower = [f.lower() for f in filter_levels] if filter_levels else []
    
    try:
        # Sprawdź czy XML nie jest pusty
        if not xml_data or len(xml_data.strip()) < 50:
            logger.warning("[SYSTEM_LOGS] XML data is empty or too short")
            return logs
        
        root = ET.fromstring(xml_data)
        objects = root.findall(".//Object")
        logger.debug(f"[SYSTEM_LOGS] Found {len(objects)} Object elements in XML")
        
        parsed_count = 0
        filtered_count = 0
        
        for obj in objects:
            record = {}
            for prop in obj.findall("Property"):
                name = prop.attrib.get("Name")
                if name:
                    text_content = prop.text if prop.text else ""
                    nested_props = prop.findall("Property")
                    if nested_props:
                        for nested in nested_props:
                            nested_name = nested.attrib.get("Name")
                            if nested_name and nested.text:
                                record[f"{name}.{nested_name}"] = nested.text
                    else:
                        record[name] = text_content
            
            # Pobierz dane eventu
            timestamp = record.get("TimeCreated") or record.get("Time") or record.get("TimeCreated.SystemTime") or ""
            message = record.get("Message") or record.get("Message.Message") or ""
            
            # Pobierz level - sprawdź różne możliwe nazwy (sprawdź wszystkie możliwe klucze)
            level = (record.get("LevelDisplayName") or 
                    record.get("Level") or 
                    record.get("LevelName") or
                    record.get("LevelId") or  # Czasami level jest jako ID (1=Critical, 2=Error, 3=Warning, 4=Information)
                    "Information")
            
            # Jeśli level jest liczbą, przekonwertuj na nazwę
            if isinstance(level, (int, str)) and str(level).isdigit():
                level_id = int(level)
                level_map = {1: "Critical", 2: "Error", 3: "Warning", 4: "Information", 0: "Information"}
                level = level_map.get(level_id, "Information")
            
            # Normalizuj level do standardowych nazw
            level_normalized = normalize_level(str(level))
            
            event_id = record.get("Id") or record.get("EventID") or record.get("EventId") or "N/A"
            
            parsed_count += 1
            
            # Loguj pierwsze kilka eventów dla debugowania
            if parsed_count <= 5:
                logger.debug(f"[SYSTEM_LOGS] Event {parsed_count}: raw_level='{level}', normalized='{level_normalized}', event_id={event_id}, filter_levels={filter_levels_lower}")
            
            # Filtrowanie po poziomie (sprawdź znormalizowany level)
            if filter_levels_lower and level_normalized.lower() not in filter_levels_lower:
                filtered_count += 1
                # Loguj pierwsze kilka odfiltrowanych eventów
                if filtered_count <= 5:
                    logger.debug(f"[SYSTEM_LOGS] Filtered event {filtered_count}: level='{level_normalized}' not in {filter_levels_lower}")
                continue

            # Formatowanie timestampa
            ts = format_timestamp(timestamp)
            
            # Skrócenie długich wiadomości
            if len(message) > 500:
                message = message[:500] + "..."
            
            logs.append({
                "timestamp": ts,
                "level": level_normalized,
                "event_id": str(event_id),
                "message": message,
                "raw": f"[{ts}] [{level_normalized}] [ID:{event_id}] {message}"
            })
        
        logger.debug(f"[SYSTEM_LOGS] Parsed {parsed_count} events, filtered {filtered_count}, returned {len(logs)}")
            
    except ET.ParseError as e:
        error_msg = f"Failed to parse logs XML: {str(e)}"
        logger.exception(f"[SYSTEM_LOGS] XML ParseError: {error_msg}")
        logger.debug(f"[SYSTEM_LOGS] XML data sample (first 500 chars): {xml_data[:500]}")
        logs.append({"error": error_msg})
    except Exception as e:
        error_msg = f"Error parsing logs: {type(e).__name__}: {str(e)}"
        logger.exception(f"[SYSTEM_LOGS] Exception in parse_xml_logs: {error_msg}")
        logs.append({"error": error_msg})
    
    return logs


def normalize_level(level):
    """
    Normalizuje poziom logu do standardowych nazw.
    Obsługuje różne języki (angielski, polski, itp.)
    
    Args:
        level (str): Oryginalny poziom
    
    Returns:
        str: Znormalizowany poziom (Error, Warning, Critical, Information)
    """
    if not level:
        return "Information"
    
    level_lower = level.lower()
    
    # Mapowanie różnych nazw poziomów (angielski)
    if level_lower in ["error", "err", "2", "błąd", "błęd"]:
        return "Error"
    elif level_lower in ["warning", "warn", "3", "ostrzeżenie", "ostrzeg"]:
        return "Warning"
    elif level_lower in ["critical", "crit", "1", "krytyczny", "krytyczn"]:
        return "Critical"
    elif level_lower in ["information", "info", "informational", "4", "0", "informacje", "informacj"]:
        return "Information"
    else:
        # Jeśli nie rozpoznano, zwróć oryginalny z pierwszą wielką literą
        return level.capitalize()

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

