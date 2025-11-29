import subprocess
import sys
from datetime import datetime

def collect(max_events=200):
    """
    Zbiera błędy związane z Registry Transaction (TxR) - bardzo poważne błędy systemowe.
    TxR błędy wskazują na problemy z transakcjami rejestru, często związane z uszkodzeniem dysku.
    
    Args:
        max_events (int): Maksymalna liczba zdarzeń do sprawdzenia
    
    Returns:
        list: Lista błędów TxR z szczegółami
    """
    txr_errors = []
    
    try:
        # Szukamy błędów TxR w logach System (ukryte okno)
        cmd = f"Get-WinEvent -LogName System -MaxEvents {max_events} | Where-Object {{$_.Message -like '*TxR*' -or $_.Message -like '*0xc00000a2*' -or $_.Id -eq 8193}} | ConvertTo-Xml -As String -Depth 3"
        
        from utils.subprocess_helper import run_powershell_hidden
        output = run_powershell_hidden(cmd)
        
        # Parsowanie XML
        import xml.etree.ElementTree as ET
        try:
            root = ET.fromstring(output)
            for obj in root.findall(".//Object"):
                record = {}
                for prop in obj.findall("Property"):
                    name = prop.attrib.get("Name")
                    if name:
                        record[name] = prop.text if prop.text else ""
                
                message = record.get("Message", "")
                event_id = record.get("Id") or record.get("EventID", "N/A")
                timestamp = record.get("TimeCreated") or record.get("Time", "")
                
                if "txr" in message.lower() or "0xc00000a2" in message.lower():
                    txr_errors.append({
                        "event_id": str(event_id),
                        "timestamp": timestamp,
                        "message": message,
                        "severity": "CRITICAL"
                    })
        except ET.ParseError:
            pass
            
    except subprocess.CalledProcessError:
        pass
    except Exception as e:
        txr_errors.append({
            "error": f"Failed to collect TxR errors: {type(e).__name__}: {e}"
        })
    
    # Dodatkowo sprawdzamy Event ID 8193 (Registry TxR failure)
    try:
        cmd = "Get-WinEvent -FilterHashtable @{LogName='System'; ID=8193} -MaxEvents 50 | ConvertTo-Xml -As String -Depth 3"
        
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
                
                message = record.get("Message", "")
                timestamp = record.get("TimeCreated") or record.get("Time", "")
                
                txr_errors.append({
                    "event_id": "8193",
                    "timestamp": timestamp,
                    "message": message,
                    "severity": "CRITICAL"
                })
        except ET.ParseError:
            pass
    except:
        pass
    
    return txr_errors

