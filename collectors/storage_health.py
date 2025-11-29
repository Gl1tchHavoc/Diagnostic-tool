import subprocess
import sys

# WMI dla Windows
if sys.platform == "win32":
    try:
        import wmi
    except ImportError:
        wmi = None

def collect():
    """
    Zbiera informacje o zdrowiu dysków (SMART, błędy I/O, wydajność).
    Zwraca szczegółowe dane o stanie dysków.
    """
    storage_data = {
        "disks": [],
        "smart_errors": [],
        "io_errors": [],
        "disk_errors": []
    }
    
    if sys.platform != "win32" or not wmi:
        storage_data["error"] = "WMI not available - Windows only"
        return storage_data
    
    try:
        c = wmi.WMI()
        
        # Pobierz informacje o dyskach
        for disk in c.Win32_DiskDrive():
            disk_info = {
                "model": disk.Model.strip() if disk.Model else "Unknown",
                "serial": disk.SerialNumber.strip() if disk.SerialNumber else "Unknown",
                "status": disk.Status if disk.Status else "Unknown",
                "size": int(disk.Size) if disk.Size else 0,
                "interface": disk.InterfaceType if disk.InterfaceType else "Unknown",
                "media_type": disk.MediaType if disk.MediaType else "Unknown"
            }
            storage_data["disks"].append(disk_info)
        
        # Sprawdź błędy dysków w Event Logs (ukryte okno)
        try:
            cmd = "Get-WinEvent -LogName System -MaxEvents 200 | Where-Object {$_.Id -in @(7,51,52,55,57,129) -or $_.Message -like '*disk*' -or $_.Message -like '*ntfs*' -or $_.Message -like '*bad block*'} | ConvertTo-Xml -As String -Depth 3"
            
            from utils.subprocess_helper import get_hidden_startupinfo
            startupinfo = get_hidden_startupinfo()
            
            output = subprocess.check_output(
                ["powershell", "-Command", cmd],
                text=True,
                encoding="utf-8",
                stderr=subprocess.DEVNULL,
                startupinfo=startupinfo
            )
            
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
                    
                    # Klasyfikacja błędów
                    if any(keyword in message.lower() for keyword in ["bad block", "bad sector", "reallocated"]):
                        storage_data["smart_errors"].append({
                            "event_id": str(event_id),
                            "timestamp": timestamp,
                            "message": message,
                            "type": "SMART_ERROR"
                        })
                    elif any(keyword in message.lower() for keyword in ["io error", "i/o error", "read error", "write error"]):
                        storage_data["io_errors"].append({
                            "event_id": str(event_id),
                            "timestamp": timestamp,
                            "message": message,
                            "type": "IO_ERROR"
                        })
                    elif any(keyword in message.lower() for keyword in ["disk", "ntfs", "volsnap"]):
                        storage_data["disk_errors"].append({
                            "event_id": str(event_id),
                            "timestamp": timestamp,
                            "message": message,
                            "type": "DISK_ERROR"
                        })
            except ET.ParseError:
                pass
        except subprocess.CalledProcessError:
            pass
        
        # Pobierz SMART attributes przez WMI (jeśli dostępne)
        try:
            for disk in c.Win32_DiskDrive():
                try:
                    # Próba pobrania SMART data
                    smart_data = {}
                    # WMI nie zawsze ma bezpośredni dostęp do SMART, więc używamy Event Logs
                    storage_data["smart_available"] = False
                except:
                    pass
        except:
            pass
            
    except Exception as e:
        storage_data["error"] = f"Failed to collect storage health: {type(e).__name__}: {e}"
    
    return storage_data

