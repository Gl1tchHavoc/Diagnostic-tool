"""
Collector WHEA (Windows Hardware Error Architecture) - zbiera szczegółowe dane o błędach sprzętowych.
Zbiera Event IDs: 18, 19, 20, 46 z Windows Event Log i dekoduje szczegółowe informacje o błędach.
"""
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from collections import defaultdict
from utils.subprocess_helper import run_powershell_hidden
from utils.logger import get_logger

logger = get_logger()

# Event IDs WHEA do zbierania
WHEA_EVENT_IDS = [18, 19, 20, 46]

def collect():
    """
    Zbiera szczegółowe dane WHEA z Windows Event Log.
    
    Returns:
        dict: {
            "whea_events": [list of WHEA events with decoded data],
            "statistics": {
                "total_events": int,
                "events_by_id": dict,
                "events_last_10min": int,
                "events_last_24h": int
            },
            "raw_events": [list of raw event data]
        }
    """
    whea_data = {
        "whea_events": [],
        "statistics": {
            "total_events": 0,
            "events_by_id": {},
            "events_last_10min": 0,
            "events_last_24h": 0
        },
        "raw_events": []
    }
    
    if sys.platform != "win32":
        whea_data["error"] = "Windows only"
        return whea_data
    
    try:
        logger.info("[WHEA] Collecting WHEA events from System Event Log")
        events = collect_whea_events()
        
        # Dekoduj każdy event
        for event in events:
            decoded = decode_whea_event(event)
            if decoded:
                whea_data["whea_events"].append(decoded)
                whea_data["raw_events"].append(event)
        
        # Oblicz statystyki
        now = datetime.now()
        last_10min = now - timedelta(minutes=10)
        last_24h = now - timedelta(hours=24)
        
        events_by_id = defaultdict(int)
        events_10min = 0
        events_24h = 0
        
        for event in whea_data["whea_events"]:
            # Upewnij się, że event jest słownikiem
            if not isinstance(event, dict):
                logger.debug(f"[WHEA] Skipping non-dict event: {type(event)}")
                continue
            event_id = event.get("event_id", "")
            events_by_id[event_id] += 1
            
            timestamp = parse_timestamp(event.get("timestamp", ""))
            if timestamp:
                if timestamp >= last_10min:
                    events_10min += 1
                if timestamp >= last_24h:
                    events_24h += 1
        
        whea_data["statistics"] = {
            "total_events": len(whea_data["whea_events"]),
            "events_by_id": dict(events_by_id),
            "events_last_10min": events_10min,
            "events_last_24h": events_24h
        }
        
        logger.info(f"[WHEA] Collected {whea_data['statistics']['total_events']} WHEA events "
                   f"({events_10min} in last 10min, {events_24h} in last 24h)")
        
    except Exception as e:
        logger.exception(f"[WHEA] Exception during collection: {e}")
        whea_data["collection_error"] = f"Failed to collect WHEA data: {e}"
    
    return whea_data


def collect_whea_events():
    """
    Zbiera surowe eventy WHEA z Windows Event Log.
    
    Returns:
        list: Lista surowych eventów WHEA
    """
    events = []
    
    try:
        event_ids_str = ",".join(str(eid) for eid in WHEA_EVENT_IDS)
        cmd = (
            f"Get-WinEvent -LogName System -MaxEvents 500 -ErrorAction SilentlyContinue | "
            f"Where-Object {{$_.Id -in @({event_ids_str})}} | "
            f"ConvertTo-Xml -As String -Depth 10"
        )
        
        output = run_powershell_hidden(cmd)
        
        if not output or len(output.strip()) < 50:
            logger.warning("[WHEA] Empty or invalid output from System Event Log")
            return events
        
        # Parsuj XML
        root = ET.fromstring(output)
        
        for obj in root.findall(".//Object"):
            record = {}
            for prop in obj.findall("Property"):
                name = prop.attrib.get("Name", "")
                if name:
                    value = prop.text if prop.text else ""
                    # Sprawdź zagnieżdżone właściwości
                    nested = prop.findall("Property")
                    if nested:
                        nested_dict = {}
                        for n in nested:
                            n_name = n.attrib.get("Name", "")
                            n_value = n.text if n.text else ""
                            if n_name:
                                nested_dict[n_name] = n_value
                        if nested_dict:
                            record[name] = nested_dict
                        else:
                            record[name] = value
                    else:
                        record[name] = value
            
            if record:
                events.append(record)
        
        logger.info(f"[WHEA] Extracted {len(events)} raw WHEA events from Event Log")
        
    except ET.ParseError as e:
        logger.error(f"[WHEA] XML parse error: {e}")
    except Exception as e:
        logger.exception(f"[WHEA] Exception in collect_whea_events: {e}")
    
    return events


def decode_whea_event(event_record):
    """
    Dekoduje event WHEA i wyciąga szczegółowe dane.
    
    Args:
        event_record (dict): Surowe dane eventu z Event Log
        
    Returns:
        dict: Zdekodowane dane WHEA lub None
    """
    try:
        event_id = str(event_record.get("Id") or event_record.get("EventID", ""))
        if not event_id or event_id not in [str(eid) for eid in WHEA_EVENT_IDS]:
            return None
        
        message = event_record.get("Message", "") or ""
        timestamp = event_record.get("TimeCreated") or event_record.get("Time", "")
        
        # Wyciągnij dane z message i XML
        decoded = {
            "event_id": event_id,
            "timestamp": timestamp,
            "message": message[:1000] if len(message) > 1000 else message,  # Ogranicz długość
            "error_source": extract_error_source(message),
            "mca_cod": extract_mca_cod(message),
            "mcg_status": extract_mcg_status(message),
            "processor_apic_id": extract_apic_id(message),
            "bank": extract_bank(message),
            "msr_status": extract_msr_status(message),
            "error_type": determine_error_type(event_id, message)
        }
        
        return decoded
        
    except Exception as e:
        logger.debug(f"[WHEA] Error decoding WHEA event: {e}")
        return None


def extract_error_source(message):
    """Wyciąga ErrorSource z message."""
    import re
    patterns = [
        r'Error\s+Source:\s*([^\r\n]+)',
        r'ErrorSource:\s*([^\r\n]+)',
        r'Source:\s*([^\r\n]+)'
    ]
    
    for pattern in patterns:
        match = re.search(pattern, message, re.IGNORECASE)
        if match:
            return match.group(1).strip()
    
    # Sprawdź typy błędów w message
    message_lower = message.lower()
    if "machine check exception" in message_lower or "mce" in message_lower:
        return "Machine Check Exception"
    elif "pci express" in message_lower or "pcie" in message_lower:
        return "PCI Express Error"
    elif "memory" in message_lower and "controller" in message_lower:
        return "Memory Controller"
    elif "cache" in message_lower:
        return "Cache Hierarchy"
    elif "bus" in message_lower or "interconnect" in message_lower or "fabric" in message_lower:
        return "Bus/Interconnect"
    
    return "Unknown"


def extract_mca_cod(message):
    """Wyciąga MCACOD z message."""
    import re
    patterns = [
        r'MCACOD:\s*([^\r\n]+)',
        r'MCA\s+Code:\s*([^\r\n]+)',
        r'MCACOD\s*=\s*([^\r\n]+)',
        r'0x([0-9A-Fa-f]+).*MCACOD',
        r'MCACOD.*0x([0-9A-Fa-f]+)'
    ]
    
    for pattern in patterns:
        match = re.search(pattern, message, re.IGNORECASE)
        if match:
            cod = match.group(1).strip()
            # Normalizuj format (dodaj 0x jeśli brakuje)
            if not cod.startswith("0x"):
                if cod.startswith("0"):
                    cod = "0x" + cod
                else:
                    cod = "0x" + cod
            return cod.upper()
    
    return None


def extract_mcg_status(message):
    """Wyciąga MCGSTATUS z message."""
    import re
    patterns = [
        r'MCGSTATUS:\s*([^\r\n]+)',
        r'MCG\s+Status:\s*([^\r\n]+)',
        r'MCGSTATUS\s*=\s*([^\r\n]+)'
    ]
    
    for pattern in patterns:
        match = re.search(pattern, message, re.IGNORECASE)
        if match:
            return match.group(1).strip()
    
    return None


def extract_apic_id(message):
    """Wyciąga APIC ID (ProcessorAPICID) z message."""
    import re
    patterns = [
        r'ProcessorAPICID:\s*(\d+)',
        r'APIC\s+ID:\s*(\d+)',
        r'APICID:\s*(\d+)',
        r'Processor\s+APIC\s+ID:\s*(\d+)'
    ]
    
    for pattern in patterns:
        match = re.search(pattern, message, re.IGNORECASE)
        if match:
            return int(match.group(1))
    
    return None


def extract_bank(message):
    """Wyciąga Bank z message."""
    import re
    patterns = [
        r'Bank:\s*([^\r\n]+)',
        r'Bank\s*=\s*([^\r\n]+)',
        r'L(\d+)',  # L0, L1, L2, L3
        r'MC\s+Bank',
        r'Memory\s+Controller'
    ]
    
    for pattern in patterns:
        match = re.search(pattern, message, re.IGNORECASE)
        if match:
            bank = match.group(1) if match.lastindex else match.group(0)
            return bank.strip()
    
    # Sprawdź czy message zawiera informacje o banku
    message_lower = message.lower()
    if "l0" in message_lower or "l1" in message_lower or "l2" in message_lower or "l3" in message_lower:
        for level in ["L0", "L1", "L2", "L3"]:
            if level.lower() in message_lower:
                return level
    if "mc" in message_lower and "bank" in message_lower:
        return "MC"
    if "memory controller" in message_lower:
        return "MC"
    
    return None


def extract_msr_status(message):
    """Wyciąga MSR Status z message."""
    import re
    patterns = [
        r'MSR\s+Status:\s*([^\r\n]+)',
        r'MSR:\s*([^\r\n]+)',
        r'MSR\s*=\s*([^\r\n]+)'
    ]
    
    for pattern in patterns:
        match = re.search(pattern, message, re.IGNORECASE)
        if match:
            return match.group(1).strip()
    
    return None


def determine_error_type(event_id, message):
    """Określa typ błędu na podstawie Event ID i message."""
    event_id = str(event_id)
    message_lower = message.lower()
    
    if event_id == "18":
        return "Uncorrectable Hardware Error"
    elif event_id == "19":
        return "Correctable Hardware Error"
    elif event_id == "20":
        return "Fatal Hardware Error"
    elif event_id == "46":
        return "Hardware Error (Generic)"
    
    return "Unknown"


def parse_timestamp(timestamp_str):
    """Parsuje timestamp string do datetime object."""
    if not timestamp_str:
        return None
    
    formats = [
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%m/%d/%Y %I:%M:%S %p",
        "%m/%d/%Y %H:%M:%S"
    ]
    
    for fmt in formats:
        try:
            return datetime.strptime(timestamp_str[:19], fmt)
        except (ValueError, IndexError):
            continue
    
    try:
        return datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
    except:
        pass
    
    return None

