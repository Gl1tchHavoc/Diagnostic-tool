import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import datetime
import re

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
            cmd = f"Get-WinEvent -LogName {category} -MaxEvents {max_events} | ConvertTo-Xml -As String -Depth 3"
            
            # Ukryj okno PowerShell
            from utils.subprocess_helper import get_hidden_startupinfo
            startupinfo = get_hidden_startupinfo()
            
            output = subprocess.check_output(
                ["powershell", "-Command", cmd],
                text=True,
                encoding="utf-8",
                stderr=subprocess.DEVNULL,
                startupinfo=startupinfo
            )
            logs = parse_xml_logs(output, filter_levels)
            all_logs[category] = logs
        except subprocess.CalledProcessError as e:
            all_logs[category] = [f"Error fetching {category} logs: {e}"]
        except Exception as e:
            all_logs[category] = [f"Unexpected error fetching {category} logs: {type(e).__name__}: {e}"]
    
    return all_logs

def parse_xml_logs(xml_data, filter_levels=None):
    """
    Parsuje XML wygenerowany przez PowerShell i zwraca listę sformatowanych logów.
    """
    logs = []
    if filter_levels is None:
        filter_levels = []
    
    try:
        root = ET.fromstring(xml_data)
        for obj in root.findall(".//Object"):
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
            
            timestamp = record.get("TimeCreated") or record.get("Time") or record.get("TimeCreated.SystemTime")
            message = record.get("Message") or record.get("Message.Message") or ""
            level = record.get("LevelDisplayName") or record.get("Level") or "Info"
            event_id = record.get("Id") or record.get("EventID") or "N/A"
            
            # Filtrowanie po poziomie
            if filter_levels and level not in filter_levels:
                continue

            # Formatowanie timestampa
            ts = format_timestamp(timestamp)
            
            # Skrócenie długich wiadomości
            if len(message) > 500:
                message = message[:500] + "..."
            
            logs.append({
                "timestamp": ts,
                "level": level,
                "event_id": str(event_id),
                "message": message,
                "raw": f"[{ts}] [{level}] [ID:{event_id}] {message}"
            })
            
    except ET.ParseError as e:
        logs.append({"error": f"Failed to parse logs XML: {str(e)}"})
    except Exception as e:
        logs.append({"error": f"Error parsing logs: {type(e).__name__}: {str(e)}"})
    
    return logs

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

