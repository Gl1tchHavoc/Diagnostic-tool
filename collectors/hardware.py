import psutil
import platform
import sys

# GPU
try:
    import GPUtil
except ImportError:
    GPUtil = None

# WMI dla Windows
if sys.platform == "win32":
    try:
        import wmi
    except ImportError:
        wmi = None

def collect():
    """
    Zbiera informacje o sprzęcie systemowym.
    Zwraca słownik z danymi hardware.
    """
    data = {}

    # CPU
    data['cpu'] = {
        'physical_cores': psutil.cpu_count(logical=False),
        'logical_cores': psutil.cpu_count(logical=True),
        'usage_percent': psutil.cpu_percent(interval=1),
        'model': platform.processor()
    }

    # RAM
    mem = psutil.virtual_memory()
    data['ram'] = {
        'total': mem.total,
        'used': mem.used,
        'available': mem.available,
        'percent': mem.percent
    }

    # RAM per slot
    data['ram_slots'] = []
    if sys.platform == "win32" and wmi:
        try:
            c = wmi.WMI()
            for mem_slot in c.Win32_PhysicalMemory():
                data['ram_slots'].append({
                    'capacity': int(mem_slot.Capacity),
                    'manufacturer': mem_slot.Manufacturer.strip(),
                    'speed': int(mem_slot.Speed) if mem_slot.Speed else None,
                    'part_number': mem_slot.PartNumber.strip(),
                    'bank_label': mem_slot.BankLabel.strip()
                })
        except Exception as e:
            data['ram_slots'].append({'error': f'Unable to read RAM slots: {e}'})

    # Dyski - zbieramy informacje o wszystkich wykrytych dyskach
    from utils.disk_helper import get_existing_drives
    from utils.logger import get_logger
    logger = get_logger()
    
    disks = []
    existing_drives = get_existing_drives()
    logger.debug(f"[HARDWARE] Found {len(existing_drives)} accessible drives: {existing_drives}")
    
    # Zbieramy informacje o wszystkich dyskach wykrytych przez psutil
    for part in psutil.disk_partitions():
        device = part.device
        mountpoint = part.mountpoint
        
        # Wyciągnij literę dysku (dla Windows)
        drive_letter = None
        if sys.platform == "win32" and device and len(device) >= 2:
            if device[1] == ':':
                drive_letter = device[:2].upper()
            elif ':' in device:
                drive_letter = device.split(':')[0] + ':'
        
        # Próbuj zebrać informacje o dysku
        try:
            usage = psutil.disk_usage(mountpoint)
            disk_info = {
                'device': device,
                'mountpoint': mountpoint,
                'fstype': part.fstype,
                'total': usage.total,
                'used': usage.used,
                'free': usage.free,
                'percent': usage.percent
            }
            if sys.platform == "win32" and wmi:
                try:
                    c = wmi.WMI()
                    for disk in c.Win32_DiskDrive():
                        if disk.DeviceID == device or disk.Caption in device:
                            disk_info['serial'] = disk.SerialNumber.strip()
                            disk_info['model'] = disk.Model.strip()
                            disk_info['status'] = disk.Status
                except Exception as e:
                    disk_info['status'] = f"SMART info unavailable: {e}"
            disks.append(disk_info)
            logger.debug(f"[HARDWARE] Successfully collected info for drive {device}")
        except PermissionError as e:
            # Dysk jest wykryty, ale niedostępny - dodaj z informacją o błędzie
            logger.warning(f"[HARDWARE] PermissionError accessing drive {device}: {e}")
            disk_info = {
                'device': device,
                'mountpoint': mountpoint,
                'fstype': part.fstype,
                'error': 'Permission denied - not accessible',
                'error_type': 'PermissionError'
            }
            # Spróbuj pobrać podstawowe informacje z WMI (jeśli dostępne)
            if sys.platform == "win32" and wmi and drive_letter:
                try:
                    c = wmi.WMI()
                    for disk in c.Win32_DiskDrive():
                        # Próbuj dopasować dysk po literze
                        for logical_disk in c.Win32_LogicalDisk():
                            if logical_disk.DeviceID == drive_letter:
                                disk_info['drive_letter'] = drive_letter
                                disk_info['drive_type'] = logical_disk.DriveType
                                disk_info['description'] = logical_disk.Description if logical_disk.Description else None
                                break
                except Exception as wmi_error:
                    logger.debug(f"[HARDWARE] Could not get WMI info for {device}: {wmi_error}")
            disks.append(disk_info)
        except OSError as e:
            # Błąd systemowy (np. dysk nie jest zamontowany)
            logger.warning(f"[HARDWARE] OSError accessing drive {device}: {e}")
            disks.append({
                'device': device,
                'mountpoint': mountpoint,
                'fstype': part.fstype,
                'error': f'OS Error: {str(e)}',
                'error_type': 'OSError'
            })
        except Exception as e:
            # Inne błędy - dodaj z informacją o błędzie
            logger.warning(f"[HARDWARE] Error accessing drive {device}: {type(e).__name__}: {e}")
            disks.append({
                'device': device,
                'mountpoint': mountpoint,
                'fstype': part.fstype,
                'error': f'Error: {type(e).__name__} - {str(e)}',
                'error_type': type(e).__name__
            })
    
    logger.info(f"[HARDWARE] Collected info for {len(disks)} drives (including inaccessible ones)")
    data['disks'] = disks

    # GPU
    data['gpu'] = []
    if GPUtil:
        try:
            gpus = GPUtil.getGPUs()
            for gpu in gpus:
                data['gpu'].append({
                    'name': gpu.name,
                    'load': gpu.load,
                    'memoryTotal': gpu.memoryTotal,
                    'memoryUsed': gpu.memoryUsed,
                    'temperature': gpu.temperature,
                    'driver': gpu.driver
                })
            if not data['gpu']:
                data['gpu'].append({'info': 'No GPU detected'})
        except Exception as e:
            data['gpu'].append({'error': f'GPU detection failed: {e}'})
    else:
        data['gpu'].append({'info': 'GPUtil not installed'})

    # Network
    netcards = []
    for iface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == psutil.AF_LINK:
                netcards.append({
                    'interface': iface,
                    'mac': addr.address
                })
    data['network'] = netcards

    # Motherboard
    data['motherboard'] = []
    if sys.platform == "win32" and wmi:
        try:
            c = wmi.WMI()
            for board in c.Win32_BaseBoard():
                data['motherboard'].append({
                    'manufacturer': board.Manufacturer,
                    'product': board.Product,
                    'serial': board.SerialNumber
                })
            if not data['motherboard']:
                data['motherboard'].append({'info': 'Motherboard not found'})
        except Exception as e:
            data['motherboard'].append({'error': f'Unable to read motherboard info: {e}'})

    # Sensors (CPU temp)
    data['sensors'] = {}
    if sys.platform == "win32" and wmi:
        try:
            c = wmi.WMI(namespace="root\\wmi")
            for sensor in c.MSAcpi_ThermalZoneTemperature():
                data['sensors']['cpu_temp'] = (sensor.CurrentTemperature / 10.0 - 273.15)
        except Exception as e:
            data['sensors']['cpu_temp'] = f'Unavailable: {e}'

    # Battery
    try:
        battery = psutil.sensors_battery()
        if battery:
            data['battery'] = {
                'percent': battery.percent,
                'plugged_in': battery.power_plugged
            }
        else:
            data['battery'] = {'info': 'No battery detected'}
    except Exception as e:
        data['battery'] = {'error': f'Battery info unavailable: {e}'}

    return data

