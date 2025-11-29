"""
Collector Windows Error Reporting (WER) - zbiera dane o crashach aplikacji.
"""
import subprocess
import sys
import os
from pathlib import Path
from datetime import datetime

def collect():
    """
    Zbiera dane z Windows Error Reporting o crashach aplikacji.
    """
    wer_data = {
        "reports": [],
        "recent_crashes": []
    }
    
    if sys.platform != "win32":
        wer_data["error"] = "Windows only"
        return wer_data
    
    # Sprawdź Event Logs dla WER (ukryte okno)
    try:
        # Event ID 1000, 1001 - Application crashes
        cmd = "Get-WinEvent -LogName Application -MaxEvents 200 | Where-Object {$_.Id -in @(1000,1001,1002) -or $_.ProviderName -eq 'Application Error' -or $_.ProviderName -eq 'Windows Error Reporting'} | ConvertTo-Xml -As String -Depth 3"
        
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
                
                event_id = record.get("Id") or record.get("EventID", "N/A")
                message = record.get("Message", "")
                timestamp = record.get("TimeCreated") or record.get("Time", "")
                provider = record.get("ProviderName", "")
                
                # Wyciągnij nazwę aplikacji z message
                app_name = extract_app_name(message)
                
                wer_data["recent_crashes"].append({
                    "event_id": str(event_id),
                    "timestamp": timestamp,
                    "message": message,
                    "provider": provider,
                    "application": app_name,
                    "type": "APPLICATION_CRASH"
                })
        except ET.ParseError:
            pass
    except subprocess.CalledProcessError:
        pass
    except Exception as e:
        wer_data["collection_error"] = f"Failed to collect WER data: {e}"
    
    # Sprawdź katalog WER reports (jeśli dostępny)
    wer_paths = [
        Path(os.environ.get("LOCALAPPDATA", "")) / "Microsoft" / "Windows" / "WER",
        Path("C:/ProgramData/Microsoft/Windows/WER")
    ]
    
    for wer_path in wer_paths:
        if wer_path.exists():
            try:
                # Zlicz raporty (nie czytamy ich bezpośrednio - mogą być duże)
                report_dirs = [d for d in wer_path.iterdir() if d.is_dir()]
                wer_data["reports"] = {
                    "path": str(wer_path),
                    "report_count": len(report_dirs),
                    "recent_reports": []
                }
                
                # Pobierz info o ostatnich raportach
                for report_dir in sorted(report_dirs, key=lambda x: x.stat().st_mtime, reverse=True)[:10]:
                    try:
                        stat = report_dir.stat()
                        wer_data["reports"]["recent_reports"].append({
                            "path": str(report_dir),
                            "modified": datetime.fromtimestamp(stat.st_mtime).isoformat()
                        })
                    except Exception:
                        pass
                break
            except Exception:
                pass
    
    return wer_data

def extract_app_name(message):
    """Wyciąga nazwę aplikacji z wiadomości WER."""
    import re
    # Szukaj wzorców typu "Application: app.exe"
    patterns = [
        r'Application:\s*([^\s,]+)',
        r'Faulting\s+application\s+name:\s*([^\s,]+)',
        r'([A-Za-z0-9_\-]+\.exe)'
    ]
    
    for pattern in patterns:
        match = re.search(pattern, message, re.IGNORECASE)
        if match:
            return match.group(1)
    
    return "Unknown"

