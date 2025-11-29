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
        # Sprawdź Event ID 1001 (Bugcheck) i 41 (Unexpected shutdown)
        cmd = [
            "powershell",
            "-Command",
            "Get-WinEvent -LogName System -MaxEvents 200 | Where-Object {$_.Id -in @(41,1001,6008,1074,1076) -or $_.Message -like '*bugcheck*' -or $_.Message -like '*blue screen*' -or $_.Message -like '*stop error*'} | ConvertTo-Xml -As String -Depth 3"
        ]
        output = subprocess.check_output(cmd, text=True, encoding="utf-8", stderr=subprocess.DEVNULL)
        
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
                
                # Event ID 1001 - Bugcheck
                if event_id == "1001" or "bugcheck" in message.lower():
                    # Wyciągnij bugcheck code z message
                    bugcheck_code = extract_bugcheck_code(message)
                    bsod_data["bugchecks"].append({
                        "event_id": str(event_id),
                        "timestamp": timestamp,
                        "message": message,
                        "bugcheck_code": bugcheck_code,
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
    
    # Sprawdź minidump files
    minidump_paths = [
        Path("C:/Windows/Minidump"),
        Path("C:/Windows/MEMORY.DMP")
    ]
    
    for dump_path in minidump_paths:
        if dump_path.exists():
            if dump_path.is_dir():
                # Katalog z minidumpami
                for dump_file in dump_path.glob("*.dmp"):
                    try:
                        stat = dump_file.stat()
                        bsod_data["minidumps"].append({
                            "path": str(dump_file),
                            "size": stat.st_size,
                            "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                            "type": "MINIDUMP"
                        })
                    except Exception:
                        pass
            else:
                # Pojedynczy plik MEMORY.DMP
                try:
                    stat = dump_path.stat()
                    bsod_data["minidumps"].append({
                        "path": str(dump_path),
                        "size": stat.st_size,
                        "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                        "type": "FULL_DUMP"
                    })
                except Exception:
                    pass
    
    return bsod_data

def extract_bugcheck_code(message):
    """Wyciąga kod bugcheck z wiadomości."""
    import re
    # Szukaj wzorców typu "0x0000007E" lub "0x7E"
    patterns = [
        r'0x([0-9A-Fa-f]{8})',
        r'0x([0-9A-Fa-f]{1,8})',
        r'BugCheck\s+([0-9A-Fa-f]+)',
        r'stop\s+code\s+([0-9A-Fa-f]+)'
    ]
    
    for pattern in patterns:
        match = re.search(pattern, message, re.IGNORECASE)
        if match:
            return f"0x{match.group(1).upper()}"
    
    return "Unknown"

