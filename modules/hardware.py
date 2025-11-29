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

def scan():
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
        except:
            data['ram_slots'].append({'info': 'Unable to read RAM slots'})

    # Dyski
    disks = []
    for part in psutil.disk_partitions():
        try:
            usage = psutil.disk_usage(part.mountpoint)
            disk_info = {
                'device': part.device,
                'mountpoint': part.mountpoint,
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
                        if disk.DeviceID == part.device or disk.Caption in part.device:
                            disk_info['serial'] = disk.SerialNumber.strip()
                            disk_info['model'] = disk.Model.strip()
                            disk_info['status'] = disk.Status
                except:
                    disk_info['status'] = "SMART info unavailable"
            disks.append(disk_info)
        except PermissionError:
            disks.append({
                'device': part.device,
                'mountpoint': part.mountpoint,
                'fstype': part.fstype,
                'error': 'Not accessible'
            })
    data['disks'] = disks

    # GPU
    data['gpu'] = []
    if GPUtil:
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
        except:
            data['motherboard'].append({'info': 'Unable to read motherboard info'})

    # Sensors (CPU temp)
    data['sensors'] = {}
    if sys.platform == "win32" and wmi:
        try:
            c = wmi.WMI(namespace="root\\wmi")
            for sensor in c.MSAcpi_ThermalZoneTemperature():
                data['sensors']['cpu_temp'] = (sensor.CurrentTemperature / 10.0 - 273.15)
        except:
            data['sensors']['cpu_temp'] = 'Unavailable'

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
    except:
        data['battery'] = {'info': 'Battery info unavailable'}

    return data

# ===== RAM slot layout check =====
def check_ram_slot_layout(ram_slots):
    warnings = []

    if not ram_slots or len(ram_slots) < 2:
        return warnings

    occupied_slots = []
    for slot in ram_slots:
        label = slot.get('bank_label') or ''
        label = label.upper().replace("BANK ", "").replace("DIMM", "").strip()
        if label.isdigit():
            occupied_slots.append(int(label))

    occupied_slots.sort()

    if len(occupied_slots) == 2:
        if not (occupied_slots == [0, 2] or occupied_slots == [1, 3]):
            warnings.append(f"RAM nie jest w optymalnym układzie dla dual-channel: zajęte sloty {occupied_slots}")
    elif len(occupied_slots) == 4:
        if occupied_slots != [0, 1, 2, 3]:
            warnings.append(f"RAM w pełnym zestawie, ale sloty nie są w standardowym porządku: {occupied_slots}")
    else:
        warnings.append(f"Nieznany lub nietypowy układ RAM: zajęte sloty {occupied_slots}")

    return warnings

# ===== Formatowanie wyników =====
def format_results(results):
    lines = []

    # CPU
    cpu = results.get("cpu", {})
    lines.append("=== CPU ===")
    lines.append(f"Model: {cpu.get('model', 'N/A')}")
    lines.append(f"Physical cores: {cpu.get('physical_cores', 'N/A')}")
    lines.append(f"Logical cores: {cpu.get('logical_cores', 'N/A')}")
    lines.append(f"Usage: {cpu.get('usage_percent', 'N/A')}%")
    lines.append("")

    # RAM
    ram = results.get("ram", {})
    lines.append("=== RAM ===")
    lines.append(f"Total: {ram.get('total', 0)//(1024**3)} GB")
    lines.append(f"Used: {ram.get('used', 0)//(1024**3)} GB")
    lines.append(f"Available: {ram.get('available', 0)//(1024**3)} GB")
    lines.append(f"Usage: {ram.get('percent', 0)}%")
    lines.append("RAM Slots:")

    ram_slots = results.get("ram_slots", [])
    for slot in ram_slots:
        if 'info' in slot:
            lines.append(f"  {slot['info']}")
        else:
            lines.append(f"  {slot['manufacturer']} {slot.get('capacity',0)//(1024**3)}GB @ {slot.get('speed','N/A')}MHz Part#: {slot.get('part_number','N/A')}")

    # Ostrzeżenia o złym układzie RAM
    ram_warnings = check_ram_slot_layout(ram_slots)
    for warn in ram_warnings:
        lines.append(f"  ⚠️ {warn}")

    lines.append("")

    # Dyski
    lines.append("=== Disks ===")
    for disk in results.get("disks", []):
        lines.append(f"Device: {disk.get('device')}")
        if 'error' in disk:
            lines.append(f"  Error: {disk['error']}")
        else:
            lines.append(f"  Mountpoint: {disk.get('mountpoint')}")
            lines.append(f"  Filesystem: {disk.get('fstype')}")
            lines.append(f"  Total: {disk.get('total')//(1024**3)} GB")
            lines.append(f"  Used: {disk.get('used')//(1024**3)} GB")
            lines.append(f"  Free: {disk.get('free')//(1024**3)} GB")
            lines.append(f"  Usage: {disk.get('percent')}%")
            lines.append(f"  Model: {disk.get('model','N/A')}")
            lines.append(f"  Serial: {disk.get('serial','N/A')}")
            lines.append(f"  Status: {disk.get('status','N/A')}")
        lines.append("")

    # GPU
    lines.append("=== GPU ===")
    for gpu in results.get("gpu", []):
        if 'info' in gpu:
            lines.append(f"  {gpu['info']}")
        else:
            lines.append(f"  Name: {gpu.get('name')}")
            lines.append(f"  Load: {gpu.get('load')*100:.1f}%")
            lines.append(f"  Memory: {gpu.get('memoryUsed')}/{gpu.get('memoryTotal')} MB")
            lines.append(f"  Temp: {gpu.get('temperature','N/A')}°C")
            lines.append(f"  Driver: {gpu.get('driver')}")
    lines.append("")

    # Network
    lines.append("=== Network ===")
    for iface in results.get("network", []):
        lines.append(f"  Interface: {iface.get('interface')} MAC: {iface.get('mac')}")
    lines.append("")

    # Motherboard
    lines.append("=== Motherboard ===")
    for board in results.get("motherboard", []):
        if 'info' in board:
            lines.append(f"  {board['info']}")
        elif 'error' in board:
            lines.append(f"  Error: {board['error']}")
        else:
            lines.append(f"  Manufacturer: {board.get('manufacturer')}")
            lines.append(f"  Product: {board.get('product')}")
            lines.append(f"  Serial: {board.get('serial')}")
    lines.append("")

    # Sensors
    lines.append("=== Sensors ===")
    sensors = results.get("sensors", {})
    if 'cpu_temp' in sensors:
        lines.append(f"CPU Temp: {sensors['cpu_temp']}°C")
    lines.append("")

    # Battery
    lines.append("=== Battery ===")
    battery = results.get("battery", {})
    if 'percent' in battery:
        lines.append(f"Charge: {battery['percent']}% Plugged in: {battery['plugged_in']}")
    else:
        lines.append(f"  {battery.get('info','N/A')}")
    lines.append("")

    return "\n".join(lines)
