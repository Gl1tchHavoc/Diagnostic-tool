import platform
import sys
import os
import subprocess
from datetime import datetime

def collect():
    """
    Zbiera podstawowe informacje o systemie operacyjnym.
    Zwraca szczegółowe dane o konfiguracji systemu.
    """
    system_data = {
        "os": {},
        "windows_version": {},
        "boot_time": None,
        "uptime": None,
        "system_paths": {},
        "environment": {}
    }
    
    # Podstawowe informacje OS
    system_data["os"] = {
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "architecture": platform.architecture()[0]
    }
    
    # Windows-specific info (ukryte okna)
    if sys.platform == "win32":
        try:
            from utils.subprocess_helper import run_powershell_hidden
            
            # Wersja Windows
            version = run_powershell_hidden('(Get-CimInstance Win32_OperatingSystem).Version').strip()
            system_data["windows_version"]["version"] = version
            
            caption = run_powershell_hidden('(Get-CimInstance Win32_OperatingSystem).Caption').strip()
            system_data["windows_version"]["caption"] = caption
            
            build = run_powershell_hidden('(Get-CimInstance Win32_OperatingSystem).BuildNumber').strip()
            system_data["windows_version"]["build"] = build
            
            # Boot time
            boot_str = run_powershell_hidden('(Get-CimInstance Win32_OperatingSystem).LastBootUpTime').strip()
            if boot_str:
                system_data["boot_time"] = boot_str
            
            # Uptime
            import psutil
            boot_time = psutil.boot_time()
            boot_dt = datetime.fromtimestamp(boot_time)
            uptime_seconds = (datetime.now() - boot_dt).total_seconds()
            hours = int(uptime_seconds // 3600)
            minutes = int((uptime_seconds % 3600) // 60)
            system_data["uptime"] = f"{hours}h {minutes}m"
            
        except Exception as e:
            system_data["error"] = f"Failed to collect Windows info: {type(e).__name__}: {e}"
    
    # System paths
    system_data["system_paths"] = {
        "system32": sys.executable if hasattr(sys, 'executable') else "N/A",
        "python_version": sys.version,
        "python_path": sys.executable
    }
    
    # Environment variables (ważne dla diagnostyki)
    important_env = ["PATH", "TEMP", "TMP", "USERPROFILE", "SYSTEMROOT", "WINDIR"]
    for env_var in important_env:
        if env_var in os.environ:
            system_data["environment"][env_var] = os.environ[env_var]
    
    return system_data

