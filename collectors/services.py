"""
Collector statusu usług Windows - zbiera informacje o wszystkich usługach i ich statusie.
"""
import subprocess
import sys

if sys.platform == "win32":
    try:
        import wmi
    except ImportError:
        wmi = None

def collect():
    """
    Zbiera informacje o wszystkich usługach Windows.
    Zwraca listę usług z ich statusem, typem startu i błędami.
    """
    services_data = {
        "services": [],
        "failed_services": [],
        "stopped_services": [],
        "errors": []
    }
    
    if sys.platform != "win32" or not wmi:
        services_data["error"] = "WMI not available - Windows only"
        return services_data
    
    try:
        c = wmi.WMI()
        
        # Pobierz wszystkie usługi
        for service in c.Win32_Service():
            service_info = {
                "name": service.Name,
                "display_name": service.DisplayName,
                "state": service.State,  # Running, Stopped, etc.
                "start_mode": service.StartMode,  # Auto, Manual, Disabled
                "status": service.Status,
                "process_id": service.ProcessId if service.ProcessId else None,
                "path_name": service.PathName if service.PathName else None,
                "description": service.Description if service.Description else ""
            }
            
            services_data["services"].append(service_info)
            
            # Zidentyfikuj problematyczne usługi
            if service.State == "Stopped" and service.StartMode in ["Auto", "Automatic"]:
                services_data["stopped_services"].append({
                    "name": service.Name,
                    "display_name": service.DisplayName,
                    "start_mode": service.StartMode,
                    "issue": "Service should be running but is stopped"
                })
            
            if service.Status and "error" in service.Status.lower():
                services_data["failed_services"].append({
                    "name": service.Name,
                    "display_name": service.DisplayName,
                    "status": service.Status,
                    "issue": "Service has error status"
                })
        
        # Sprawdź błędy usług w Event Logs (ukryte okno)
        try:
            cmd = "Get-WinEvent -LogName System -MaxEvents 500 | Where-Object {$_.Id -in @(7000,7001,7009,7011,7022,7023,7024,7031,7032,7034) -or $_.Message -like '*service*' -and ($_.Message -like '*fail*' -or $_.Message -like '*error*' -or $_.Message -like '*timeout*')} | ConvertTo-Xml -As String -Depth 3"
            
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
                    
                    # Event ID 7000, 7001, 7009, 7011 - service failures
                    if event_id in ["7000", "7001", "7009", "7011", "7022", "7023", "7024", "7031", "7032", "7034"]:
                        services_data["errors"].append({
                            "event_id": str(event_id),
                            "timestamp": timestamp,
                            "message": message,
                            "type": "SERVICE_ERROR"
                        })
            except ET.ParseError:
                pass
        except subprocess.CalledProcessError:
            pass
        except Exception as e:
            services_data["collection_errors"] = f"Failed to collect service errors from Event Log: {e}"
            
    except Exception as e:
        services_data["error"] = f"Failed to collect services: {type(e).__name__}: {e}"
    
    return services_data

