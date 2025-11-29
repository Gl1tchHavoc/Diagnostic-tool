"""
Procesor danych hardware - analizuje i wykrywa problemy w sprzęcie.
"""
from utils.disk_helper import drive_exists, get_existing_drives
from utils.logger import get_logger

logger = get_logger()

def process(hardware_data):
    """
    Przetwarza dane hardware i wykrywa potencjalne problemy.
    
    Args:
        hardware_data (dict): Dane z collectors.hardware
    
    Returns:
        dict: Przetworzone dane z wykrytymi problemami
    """
    issues = []
    warnings = []
    
    # Sprawdź CPU
    cpu = hardware_data.get("cpu", {})
    cpu_usage = cpu.get("usage_percent", 0)
    if cpu_usage > 90:
        issues.append({
            "type": "CPU_HIGH_USAGE",
            "severity": "WARNING",
            "message": f"CPU usage is very high: {cpu_usage}%",
            "component": "CPU"
        })
    
    # Sprawdź RAM
    ram = hardware_data.get("ram", {})
    ram_percent = ram.get("percent", 0)
    if ram_percent > 90:
        issues.append({
            "type": "RAM_HIGH_USAGE",
            "severity": "WARNING",
            "message": f"RAM usage is very high: {ram_percent}%",
            "component": "RAM"
        })
    
    # Sprawdź RAM slots layout
    ram_slots = hardware_data.get("ram_slots", [])
    if len(ram_slots) >= 2:
        occupied_slots = []
        for slot in ram_slots:
            label = slot.get('bank_label') or ''
            label = label.upper().replace("BANK ", "").replace("DIMM", "").strip()
            if label.isdigit():
                occupied_slots.append(int(label))
        
        occupied_slots.sort()
        if len(occupied_slots) == 2:
            if not (occupied_slots == [0, 2] or occupied_slots == [1, 3]):
                warnings.append({
                    "type": "RAM_SUBOPTIMAL_LAYOUT",
                    "severity": "INFO",
                    "message": f"RAM not in optimal dual-channel layout: slots {occupied_slots}",
                    "component": "RAM"
                })
    
    # Sprawdź dyski - filtruj tylko istniejące dyski
    disks = hardware_data.get("disks", [])
    existing_drives = get_existing_drives()
    logger.debug(f"[HARDWARE] Processing {len(disks)} disks, {len(existing_drives)} existing drives: {existing_drives}")
    
    for disk in disks:
        device = disk.get('device', '')
        
        # Sprawdź czy dysk faktycznie istnieje przed raportowaniem błędu
        if "error" in disk:
            # Wyciągnij literę dysku z device (np. "E:\" -> "E:")
            drive_letter = None
            if device and len(device) >= 2:
                if device[1] == ':':
                    drive_letter = device[:2].upper()
                elif ':' in device:
                    drive_letter = device.split(':')[0] + ':'
            
            # Sprawdź czy dysk istnieje
            if drive_letter:
                if not drive_exists(drive_letter):
                    logger.debug(f"[HARDWARE] Skipping error for non-existent drive {drive_letter}: {disk.get('error')}")
                    continue  # Pomiń błędy dla nieistniejących dysków
            
            # Jeśli dysk istnieje lub nie można określić litery, raportuj błąd
            issues.append({
                "type": "DISK_ACCESS_ERROR",
                "severity": "ERROR",
                "message": f"Disk {device} access error: {disk.get('error')}",
                "component": "Storage"
            })
        else:
            # Sprawdź czy dysk istnieje przed raportowaniem innych problemów
            device = disk.get('device', '')
            drive_letter = None
            if device and len(device) >= 2:
                if device[1] == ':':
                    drive_letter = device[:2].upper()
                elif ':' in device:
                    drive_letter = device.split(':')[0] + ':'
            
            # Jeśli można określić literę dysku, sprawdź czy istnieje
            if drive_letter and not drive_exists(drive_letter):
                logger.debug(f"[HARDWARE] Skipping warnings for non-existent drive {drive_letter}")
                continue  # Pomiń ostrzeżenia dla nieistniejących dysków
            
            disk_percent = disk.get("percent", 0)
            if disk_percent > 90:
                warnings.append({
                    "type": "DISK_HIGH_USAGE",
                    "severity": "WARNING",
                    "message": f"Disk {device} is {disk_percent}% full",
                    "component": "Storage"
                })
            
            status = disk.get("status", "").lower()
            if "error" in status or "fail" in status:
                issues.append({
                    "type": "DISK_STATUS_ERROR",
                    "severity": "ERROR",
                    "message": f"Disk {device} has status: {status}",
                    "component": "Storage"
                })
    
    # Sprawdź temperaturę CPU
    sensors = hardware_data.get("sensors", {})
    cpu_temp = sensors.get("cpu_temp")
    if isinstance(cpu_temp, (int, float)):
        if cpu_temp > 80:
            issues.append({
                "type": "CPU_HIGH_TEMP",
                "severity": "WARNING",
                "message": f"CPU temperature is high: {cpu_temp}°C",
                "component": "CPU"
            })
    
    # Sprawdź GPU
    gpus = hardware_data.get("gpu", [])
    for gpu in gpus:
        if "error" not in gpu and "info" not in gpu:
            gpu_temp = gpu.get("temperature", 0)
            if gpu_temp > 85:
                warnings.append({
                    "type": "GPU_HIGH_TEMP",
                    "severity": "WARNING",
                    "message": f"GPU {gpu.get('name')} temperature is high: {gpu_temp}°C",
                    "component": "GPU"
                })
    
    return {
        "data": hardware_data,
        "issues": issues,
        "warnings": warnings,
        "summary": {
            "total_issues": len(issues),
            "total_warnings": len(warnings)
        }
    }

