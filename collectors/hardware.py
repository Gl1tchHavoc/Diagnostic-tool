"""
Collector Hardware - REFAKTORYZOWANA WERSJA.
Podzielony na mniejsze funkcje dla zmniejszenia złożoności cyklomatycznej.
"""
import platform
import sys

import psutil

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

from utils.logger import get_logger

logger = get_logger()


def _collect_cpu():
    """Zbiera informacje o CPU."""
    cpu_data = {}
    try:
        cpu_freq = psutil.cpu_freq()
        cpu_times = psutil.cpu_times()
        cpu_per_core = psutil.cpu_percent(interval=0.1, percpu=True)

        cpu_data = {
            'physical_cores': psutil.cpu_count(logical=False),
            'logical_cores': psutil.cpu_count(logical=True),
            'usage_percent': psutil.cpu_percent(interval=1),
            'usage_per_core': cpu_per_core,
            'model': platform.processor(),
            'frequency': {
                'current': cpu_freq.current if cpu_freq else None,
                'min': cpu_freq.min if cpu_freq else None,
                'max': cpu_freq.max if cpu_freq else None
            },
            'times': {
                'user': cpu_times.user,
                'system': cpu_times.system,
                'idle': cpu_times.idle,
                'nice': getattr(cpu_times, 'nice', None),
                'iowait': getattr(cpu_times, 'iowait', None),
                'irq': getattr(cpu_times, 'irq', None),
                'softirq': getattr(cpu_times, 'softirq', None)
            }
        }

        # Dodatkowe informacje o CPU z WMI (Windows)
        if sys.platform == "win32" and wmi:
            try:
                c = wmi.WMI()
                for processor in c.Win32_Processor():
                    cpu_data.update({
                        'name': processor.Name.strip()
                        if processor.Name else None,
                        'manufacturer': processor.Manufacturer.strip()
                        if processor.Manufacturer else None,
                        'family': processor.Family,
                        'architecture': processor.Architecture,
                        'address_width': processor.AddressWidth,
                        'data_width': processor.DataWidth,
                        'number_of_cores': processor.NumberOfCores,
                        'number_of_logical_processors':
                            processor.NumberOfLogicalProcessors,
                        'max_clock_speed': processor.MaxClockSpeed,
                        'current_clock_speed': processor.CurrentClockSpeed,
                        'l2_cache_size': processor.L2CacheSize,
                        'l3_cache_size': processor.L3CacheSize,
                        'voltage': processor.Voltage,
                        'load_percentage': processor.LoadPercentage,
                        'status': processor.Status,
                        'stepping': processor.Stepping,
                        'revision': processor.Revision,
                        'processor_id': processor.ProcessorId
                    })
                    break  # Tylko pierwszy procesor
            except Exception as e:
                logger.debug(
                    f"[HARDWARE] Could not get detailed CPU info from WMI: {e}")
    except Exception as e:
        logger.warning(f"[HARDWARE] Error collecting CPU info: {e}")
        cpu_data = {'error': str(e)}
    return cpu_data


def _collect_ram():
    """Zbiera informacje o RAM."""
    ram_data = {}
    try:
        mem = psutil.virtual_memory()
        swap = psutil.swap_memory()

        ram_data = {
            'total': mem.total,
            'used': mem.used,
            'available': mem.available,
            'free': mem.free,
            'percent': mem.percent,
            'active': getattr(mem, 'active', None),
            'inactive': getattr(mem, 'inactive', None),
            'buffers': getattr(mem, 'buffers', None),
            'cached': getattr(mem, 'cached', None),
            'shared': getattr(mem, 'shared', None),
            'swap': {
                'total': swap.total,
                'used': swap.used,
                'free': swap.free,
                'percent': swap.percent,
                'sin': swap.sin,
                'sout': swap.sout
            }
        }
    except Exception as e:
        logger.warning(f"[HARDWARE] Error collecting RAM info: {e}")
        ram_data = {'error': str(e)}
    return ram_data


def _collect_ram_slots():
    """Zbiera informacje o slotach RAM."""
    ram_slots = []
    if sys.platform == "win32" and wmi:
        try:
            c = wmi.WMI()
            for mem_slot in c.Win32_PhysicalMemory():
                slot_info = {
                    'capacity': int(mem_slot.Capacity)
                    if mem_slot.Capacity else None,
                    'manufacturer': mem_slot.Manufacturer.strip()
                    if mem_slot.Manufacturer else None,
                    'speed': int(mem_slot.Speed) if mem_slot.Speed else None,
                    'part_number': mem_slot.PartNumber.strip()
                    if mem_slot.PartNumber else None,
                    'bank_label': mem_slot.BankLabel.strip()
                    if mem_slot.BankLabel else None,
                    'serial_number': mem_slot.SerialNumber.strip()
                    if mem_slot.SerialNumber else None,
                    'form_factor': mem_slot.FormFactor,
                    'memory_type': mem_slot.MemoryType,
                    'configured_clock_speed': mem_slot.ConfiguredClockSpeed,
                    'configured_voltage': mem_slot.ConfiguredVoltage,
                    'device_locator': mem_slot.DeviceLocator.strip()
                    if mem_slot.DeviceLocator else None,
                    'status': mem_slot.Status,
                    'tag': mem_slot.Tag.strip() if mem_slot.Tag else None
                }
                ram_slots.append(slot_info)
        except Exception as e:
            logger.warning(f"[HARDWARE] Error reading RAM slots: {e}")
            ram_slots.append({'error': f'Unable to read RAM slots: {e}'})
    return ram_slots


def _collect_disks():
    """Zbiera informacje o dyskach."""
    from utils.disk_helper import get_existing_drives, get_logical_volumes

    disks = []
    logical_volumes = get_logical_volumes()
    existing_drives = get_existing_drives()
    logger.debug(
        f"[HARDWARE] Found {len(logical_volumes)} logical volumes, "
        f"{len(existing_drives)} accessible drives")

    # Użyj get_logical_volumes() jako głównego źródła danych
    for volume in logical_volumes:
        drive_letter = volume.get('device_id', '')

        # Pomiń shadowcopy i wirtualne dyski
        if volume.get('is_shadowcopy', False):
            logger.debug(
                f"[HARDWARE] Skipping ShadowCopy volume {drive_letter}")
            continue

        if volume.get('is_virtual', False):
            logger.debug(f"[HARDWARE] Skipping virtual volume {drive_letter}")
            continue

        disk_info = _build_disk_info(volume, drive_letter)
        disks.append(disk_info)

    # Fallback: jeśli get_logical_volumes() nie zwróciło wyników
    if not disks:
        logger.warning(
            "[HARDWARE] get_logical_volumes() returned no volumes, "
            "falling back to psutil")
        disks = _collect_disks_fallback()

    logger.info(
        f"[HARDWARE] Collected info for {len(disks)} drives "
        f"(including inaccessible ones)")
    return disks


def _build_disk_info(volume, drive_letter):
    """Buduje informacje o dysku z volume."""
    disk_info = {
        'device': drive_letter,
        'mountpoint': drive_letter,
        'fstype': volume.get('file_system', 'Unknown'),
        'volume_name': volume.get('volume_name'),
        'volume_serial': volume.get('volume_serial'),
        'drive_type': volume.get('drive_type_desc', 'Unknown'),
        'description': volume.get('description'),
        'status': volume.get('status'),
        'accessible': volume.get('accessible', False)
    }

    # Dodaj informacje o użyciu
    if volume.get('psutil_usage'):
        usage = volume['psutil_usage']
        disk_info.update({
            'total': usage['total'],
            'used': usage['used'],
            'free': usage['free'],
            'percent': usage['percent']
        })
    elif volume.get('size'):
        disk_info['total'] = volume['size']
        disk_info['free'] = volume.get('free_space', 0)
        if disk_info['total'] and disk_info['total'] > 0:
            disk_info['used'] = disk_info['total'] - disk_info['free']
            disk_info['percent'] = (
                disk_info['used'] / disk_info['total']) * 100
        else:
            disk_info['used'] = None
            disk_info['percent'] = None

    # Jeśli nie jest dostępny, dodaj informację o błędzie
    if not volume.get('accessible', False):
        disk_info['error'] = volume.get('access_error', 'Not accessible')
        disk_info['error_type'] = 'AccessError'

    # Dodaj informacje o dysku fizycznym z WMI
    if sys.platform == "win32" and wmi and drive_letter:
        _add_physical_disk_info(disk_info, drive_letter)

    logger.debug(
        f"[HARDWARE] Added volume {drive_letter}: "
        f"{disk_info.get('volume_name', 'N/A')} "
        f"({disk_info.get('total', 0)} bytes)")
    return disk_info


def _add_physical_disk_info(disk_info, drive_letter):
    """Dodaje informacje o dysku fizycznym z WMI."""
    try:
        c = wmi.WMI()
        # Znajdź powiązany dysk fizyczny
        for partition in c.Win32_DiskPartition():
            for logical_disk in c.Win32_LogicalDisk():
                if logical_disk.DeviceID == drive_letter:
                    # Znajdź dysk fizyczny
                    for physical_disk in c.Win32_DiskDrive():
                        if str(physical_disk.Index) == str(partition.DiskIndex):
                            disk_info['physical_disk'] = {
                                'model': physical_disk.Model.strip()
                                if physical_disk.Model else None,
                                'serial': physical_disk.SerialNumber.strip()
                                if physical_disk.SerialNumber else None,
                                'manufacturer':
                                    physical_disk.Manufacturer.strip()
                                    if physical_disk.Manufacturer else None,
                                'interface_type': physical_disk.InterfaceType,
                                'media_type': physical_disk.MediaType,
                                'size': int(physical_disk.Size)
                                if physical_disk.Size else None,
                                'status': physical_disk.Status,
                                'firmware_revision':
                                    physical_disk.FirmwareRevision.strip()
                                    if physical_disk.FirmwareRevision
                                    else None
                            }
                            break
                    break
    except Exception as e:
        logger.debug(
            f"[HARDWARE] Could not get physical disk info for "
            f"{drive_letter}: {e}")


def _collect_disks_fallback():
    """Fallback - używa psutil do zbierania informacji o dyskach."""
    disks = []
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
            # Szczegółowe informacje z WMI o dysku fizycznym
            if sys.platform == "win32" and wmi:
                _add_wmi_disk_info(disk_info, drive_letter)
            disks.append(disk_info)
            logger.debug(
                f"[HARDWARE] Successfully collected info for drive {device}")
        except PermissionError as e:
            logger.warning(
                f"[HARDWARE] PermissionError accessing drive {device}: {e}")
            disk_info = {
                'device': device,
                'mountpoint': mountpoint,
                'fstype': part.fstype,
                'error': 'Permission denied - not accessible',
                'error_type': 'PermissionError'
            }
            if sys.platform == "win32" and wmi and drive_letter:
                _add_wmi_disk_info(disk_info, drive_letter)
            disks.append(disk_info)
        except OSError as e:
            logger.warning(f"[HARDWARE] OSError accessing drive {device}: {e}")
            disks.append({
                'device': device,
                'mountpoint': mountpoint,
                'fstype': part.fstype,
                'error': f'OS Error: {str(e)}',
                'error_type': 'OSError'
            })
        except Exception as e:
            logger.warning(
                f"[HARDWARE] Error accessing drive {device}: "
                f"{type(e).__name__}: {e}")
            disks.append({
                'device': device,
                'mountpoint': mountpoint,
                'fstype': part.fstype,
                'error': f'Error: {type(e).__name__} - {str(e)}',
                'error_type': type(e).__name__
            })
    return disks


def _add_wmi_disk_info(disk_info, drive_letter):
    """Dodaje szczegółowe informacje o dysku z WMI."""
    if not drive_letter:
        return
    try:
        c = wmi.WMI()
        for logical_disk in c.Win32_LogicalDisk():
            if logical_disk.DeviceID == drive_letter:
                disk_info.update({
                    'volume_name': logical_disk.VolumeName.strip()
                    if logical_disk.VolumeName else None,
                    'volume_serial':
                        logical_disk.VolumeSerialNumber.strip()
                        if logical_disk.VolumeSerialNumber else None,
                    'file_system': logical_disk.FileSystem,
                    'drive_type': logical_disk.DriveType,
                    'compressed': logical_disk.Compressed,
                    'supports_disk_quota': logical_disk.SupportsDiskQuotas,
                    'quotas_incomplete': logical_disk.QuotasIncomplete,
                    'quotas_rebuild': logical_disk.QuotasRebuilding
                })
                _add_physical_disk_details(disk_info, logical_disk)
                break
    except Exception as e:
        logger.debug(
            f"[HARDWARE] Could not get detailed disk info from WMI: {e}")
        disk_info['wmi_error'] = str(e)


def _add_physical_disk_details(disk_info, logical_disk):
    """Dodaje szczegóły dysku fizycznego."""
    try:
        c = wmi.WMI()
        drive_letter = logical_disk.DeviceID
        for partition in c.Win32_DiskPartition():
            if (partition.DeviceID in logical_disk.DeviceID or
                    drive_letter in partition.DeviceID):
                for physical_disk in c.Win32_DiskDrive():
                    if (physical_disk.DeviceID == partition.DiskIndex or
                            physical_disk.Index == partition.DiskIndex):
                        disk_info.update({
                            'physical_disk': {
                                'model': physical_disk.Model.strip()
                                if physical_disk.Model else None,
                                'serial': physical_disk.SerialNumber.strip()
                                if physical_disk.SerialNumber else None,
                                'manufacturer':
                                    physical_disk.Manufacturer.strip()
                                    if physical_disk.Manufacturer else None,
                                'interface_type': physical_disk.InterfaceType,
                                'media_type': physical_disk.MediaType,
                                'size': int(physical_disk.Size)
                                if physical_disk.Size else None,
                                'status': physical_disk.Status,
                                'firmware_revision':
                                    physical_disk.FirmwareRevision.strip()
                                    if physical_disk.FirmwareRevision
                                    else None,
                                'partitions': physical_disk.Partitions,
                                'total_cylinders': physical_disk.TotalCylinders,
                                'total_heads': physical_disk.TotalHeads,
                                'total_sectors': physical_disk.TotalSectors,
                                'total_tracks': physical_disk.TotalTracks,
                                'sectors_per_track':
                                    physical_disk.SectorsPerTrack,
                                'bytes_per_sector':
                                    physical_disk.BytesPerSector,
                                'scsi_bus': physical_disk.SCSIBus,
                                'scsi_logical_unit':
                                    physical_disk.SCSILogicalUnit,
                                'scsi_port': physical_disk.SCSIPort,
                                'scsi_target_id': physical_disk.SCSITargetId
                            }
                        })
                        break
                break
    except Exception as e:
        logger.debug(f"[HARDWARE] Error adding physical disk details: {e}")


def _create_gputil_gpu_info(gpu):
    """
    Tworzy słownik z informacjami o GPU z GPUtil.

    Args:
        gpu: Obiekt GPU z GPUtil

    Returns:
        dict: Informacje o GPU
    """
    return {
        'name': gpu.name,
        'load': gpu.load,
        'memoryTotal': gpu.memoryTotal,
        'memoryUsed': gpu.memoryUsed,
        'memoryFree': gpu.memoryFree,
        'temperature': gpu.temperature,
        'driver': gpu.driver,
        'uuid': gpu.uuid,
        'display_mode': gpu.display_mode,
        'display_active': gpu.display_active,
        'source': 'GPUtil'
    }


def _collect_gpu_from_gputil(gpu_list):
    """
    Zbiera informacje o GPU z GPUtil.

    Args:
        gpu_list: Lista GPU do uzupełnienia
    """
    if not GPUtil:
        return

    try:
        gpus = GPUtil.getGPUs()
        for gpu in gpus:
            gpu_info = _create_gputil_gpu_info(gpu)
            gpu_list.append(gpu_info)

        if not gpu_list:
            gpu_list.append({'info': 'No GPU detected by GPUtil'})
    except Exception as e:
        logger.debug(f"[HARDWARE] GPUtil detection failed: {e}")


def _create_wmi_gpu_info(gpu):
    """
    Tworzy słownik z informacjami o GPU z WMI.

    Args:
        gpu: Obiekt GPU z WMI

    Returns:
        dict: Informacje o GPU
    """
    return {
        'name': gpu.Name.strip() if gpu.Name else None,
        'adapter_ram': int(gpu.AdapterRAM) if gpu.AdapterRAM else None,
        'driver_version': gpu.DriverVersion.strip() if gpu.DriverVersion else None,
        'driver_date': gpu.DriverDate.strip() if gpu.DriverDate else None,
        'video_mode_description': (
            gpu.VideoModeDescription.strip()
            if gpu.VideoModeDescription else None
        ),
        'video_processor': (
            gpu.VideoProcessor.strip() if gpu.VideoProcessor else None
        ),
        'status': gpu.Status,
        'availability': gpu.Availability,
        'pnp_device_id': (
            gpu.PNPDeviceID.strip() if gpu.PNPDeviceID else None
        ),
        'device_id': gpu.DeviceID.strip() if gpu.DeviceID else None,
        'adapter_dac_type': (
            gpu.AdapterDACType.strip() if gpu.AdapterDACType else None
        ),
        'max_memory_supported': (
            int(gpu.MaxMemorySupported) if gpu.MaxMemorySupported else None
        ),
        'max_refresh_rate': (
            int(gpu.MaxRefreshRate) if gpu.MaxRefreshRate else None
        ),
        'min_refresh_rate': (
            int(gpu.MinRefreshRate) if gpu.MinRefreshRate else None
        ),
        'current_refresh_rate': (
            int(gpu.CurrentRefreshRate) if gpu.CurrentRefreshRate else None
        ),
        'current_horizontal_resolution': (
            int(gpu.CurrentHorizontalResolution)
            if gpu.CurrentHorizontalResolution else None
        ),
        'current_vertical_resolution': (
            int(gpu.CurrentVerticalResolution)
            if gpu.CurrentVerticalResolution else None
        ),
        'source': 'WMI'
    }


def _merge_or_add_gpu(gpu_list, gpu_info):
    """
    Łączy informacje o GPU z istniejącym wpisem lub dodaje nowy.

    Args:
        gpu_list: Lista GPU
        gpu_info: Informacje o GPU do dodania/połączenia
    """
    for existing_gpu in gpu_list:
        if existing_gpu.get('name') == gpu_info['name']:
            existing_gpu.update(gpu_info)
            return

    gpu_list.append(gpu_info)


def _collect_gpu_from_wmi(gpu_list):
    """
    Zbiera informacje o GPU z WMI (Windows).

    Args:
        gpu_list: Lista GPU do uzupełnienia
    """
    if sys.platform != "win32" or not wmi:
        return

    try:
        c = wmi.WMI()
        for gpu in c.Win32_VideoController():
            gpu_info = _create_wmi_gpu_info(gpu)
            _merge_or_add_gpu(gpu_list, gpu_info)
    except Exception as e:
        logger.debug(f"[HARDWARE] WMI GPU detection failed: {e}")


def _collect_gpu():
    """
    Zbiera informacje o GPU.

    Returns:
        list: Lista informacji o GPU
    """
    gpu_list = []

    _collect_gpu_from_gputil(gpu_list)
    _collect_gpu_from_wmi(gpu_list)

    if not gpu_list:
        gpu_list.append({'info': 'No GPU detected'})

    return gpu_list


def _create_address_info(addr):
    """
    Tworzy słownik z informacjami o adresie sieciowym.

    Args:
        addr: Obiekt adresu z psutil

    Returns:
        dict: Informacje o adresie
    """
    return {
        'family': str(addr.family),
        'address': addr.address,
        'netmask': addr.netmask if hasattr(addr, 'netmask') else None,
        'broadcast': addr.broadcast if hasattr(addr, 'broadcast') else None,
        'ptp': addr.ptp if hasattr(addr, 'ptp') else None
    }


def _process_network_address(addr, interface_info):
    """
    Przetwarza adres sieciowy i dodaje do interface_info.

    Args:
        addr: Obiekt adresu z psutil
        interface_info: Słownik z informacjami o interfejsie
    """
    addr_info = _create_address_info(addr)
    interface_info['addresses'].append(addr_info)

    if addr.family == psutil.AF_LINK:
        interface_info['mac'] = addr.address
    elif addr.family == 2:  # IPv4
        interface_info['ipv4'].append(addr.address)
    elif addr.family == 23:  # IPv6
        interface_info['ipv6'].append(addr.address)


def _add_interface_stats(iface, net_stats, interface_info):
    """
    Dodaje statystyki interfejsu do interface_info.

    Args:
        iface: Nazwa interfejsu
        net_stats: Słownik ze statystykami interfejsów
        interface_info: Słownik z informacjami o interfejsie
    """
    if iface not in net_stats:
        return

    stats = net_stats[iface]
    interface_info['stats'] = {
        'isup': stats.isup,
        'speed': stats.speed,
        'mtu': stats.mtu,
        'duplex': str(stats.duplex) if hasattr(stats, 'duplex') else None
    }


def _add_interface_io(iface, net_io, interface_info):
    """
    Dodaje statystyki I/O interfejsu do interface_info.

    Args:
        iface: Nazwa interfejsu
        net_io: Słownik ze statystykami I/O interfejsów
        interface_info: Słownik z informacjami o interfejsie
    """
    if iface not in net_io:
        return

    io = net_io[iface]
    interface_info['io'] = {
        'bytes_sent': io.bytes_sent,
        'bytes_recv': io.bytes_recv,
        'packets_sent': io.packets_sent,
        'packets_recv': io.packets_recv,
        'errin': io.errin,
        'errout': io.errout,
        'dropin': io.dropin,
        'dropout': io.dropout
    }


def _create_network_summary(netcards):
    """
    Tworzy podsumowanie sieci.

    Args:
        netcards: Lista interfejsów sieciowych

    Returns:
        dict: Podsumowanie sieci
    """
    active_interfaces = [
        n for n in netcards
        if n.get('stats', {}).get('isup', False)
    ]

    return {
        'total_interfaces': len(netcards),
        'active_interfaces': len(active_interfaces),
        'total_bytes_sent': sum(
            n.get('io', {}).get('bytes_sent', 0) for n in netcards
        ),
        'total_bytes_recv': sum(
            n.get('io', {}).get('bytes_recv', 0) for n in netcards
        )
    }


def _collect_network():
    """
    Zbiera informacje o sieci.

    Returns:
        dict: Dane sieci
    """
    try:
        netcards = []
        net_stats = psutil.net_if_stats()
        net_io = psutil.net_io_counters(pernic=True)

        for iface, addrs in psutil.net_if_addrs().items():
            interface_info = {
                'interface': iface,
                'addresses': [],
                'mac': None,
                'ipv4': [],
                'ipv6': []
            }

            for addr in addrs:
                _process_network_address(addr, interface_info)

            _add_interface_stats(iface, net_stats, interface_info)
            _add_interface_io(iface, net_io, interface_info)

            netcards.append(interface_info)

        if sys.platform == "win32" and wmi:
            _add_wmi_network_info(netcards)

        network_summary = _create_network_summary(netcards)

        return {'interfaces': netcards, 'summary': network_summary}
    except Exception as e:
        logger.warning(f"[HARDWARE] Error collecting network info: {e}")
        return {'error': str(e)}


def _add_wmi_network_info(netcards):
    """Dodaje szczegółowe informacje o sieci z WMI."""
    try:
        c = wmi.WMI()
        for adapter in c.Win32_NetworkAdapter():
            if adapter.NetEnabled:
                # Znajdź odpowiedni interfejs
                for netcard in netcards:
                    if (adapter.Name in netcard['interface'] or
                            netcard['interface'] in adapter.Name):
                        netcard.update({
                            'adapter_type': adapter.AdapterType,
                            'adapter_type_id': adapter.AdapterTypeID,
                            'manufacturer': adapter.Manufacturer.strip()
                            if adapter.Manufacturer else None,
                            'product_name': adapter.ProductName.strip()
                            if adapter.ProductName else None,
                            'description': adapter.Description.strip()
                            if adapter.Description else None,
                            'pnp_device_id': adapter.PNPDeviceID.strip()
                            if adapter.PNPDeviceID else None,
                            'speed': adapter.Speed if adapter.Speed else None,
                            'mac_address': adapter.MACAddress.strip()
                            if adapter.MACAddress else None,
                            'status': adapter.Status,
                            'availability': adapter.Availability
                        })
                        break
    except Exception as e:
        logger.debug(
            f"[HARDWARE] Could not get detailed network info from WMI: {e}")


def _create_board_info(board):
    """
    Tworzy słownik z informacjami o płycie głównej.

    Args:
        board: Obiekt WMI Win32_BaseBoard

    Returns:
        dict: Informacje o płycie głównej
    """
    return {
        'manufacturer': board.Manufacturer.strip() if board.Manufacturer else None,
        'product': board.Product.strip() if board.Product else None,
        'serial': board.SerialNumber.strip() if board.SerialNumber else None,
        'version': board.Version.strip() if board.Version else None,
        'tag': board.Tag.strip() if board.Tag else None,
        'part_number': board.PartNumber.strip() if board.PartNumber else None,
        'status': board.Status,
        'hosting_board': board.HostingBoard,
        'removable': board.Removable,
        'replaceable': board.Replaceable,
        'requires_daughter_board': board.RequiresDaughterBoard
    }


def _collect_boards_wmi(motherboard_data):
    """
    Zbiera informacje o płytach głównych z WMI.

    Args:
        motherboard_data: Słownik z danymi płyty głównej do uzupełnienia
    """
    try:
        c = wmi.WMI()
        for board in c.Win32_BaseBoard():
            board_info = _create_board_info(board)
            motherboard_data['boards'].append(board_info)
    except Exception as e:
        logger.warning(f"[HARDWARE] Error reading motherboard info: {e}")
        motherboard_data['boards'].append(
            {'error': f'Unable to read motherboard info: {e}'}
        )


def _create_bios_info(bios):
    """
    Tworzy słownik z informacjami o BIOS.

    Args:
        bios: Obiekt WMI Win32_BIOS

    Returns:
        dict: Informacje o BIOS
    """
    return {
        'manufacturer': bios.Manufacturer.strip() if bios.Manufacturer else None,
        'version': bios.Version.strip() if bios.Version else None,
        'release_date': bios.ReleaseDate.strip() if bios.ReleaseDate else None,
        'serial_number': bios.SerialNumber.strip() if bios.SerialNumber else None,
        'smbios_version': (
            bios.SMBIOSBIOSVersion.strip()
            if bios.SMBIOSBIOSVersion else None
        ),
        'smbios_major_version': bios.SMBIOSMajorVersion,
        'smbios_minor_version': bios.SMBIOSMinorVersion,
        'bios_characteristics': (
            bios.BIOSCharacteristics
            if hasattr(bios, 'BIOSCharacteristics') else None
        )
    }


def _collect_bios_wmi(motherboard_data):
    """
    Zbiera informacje o BIOS z WMI.

    Args:
        motherboard_data: Słownik z danymi płyty głównej do uzupełnienia
    """
    try:
        c = wmi.WMI()
        for bios in c.Win32_BIOS():
            bios_info = _create_bios_info(bios)
            motherboard_data['bios'].append(bios_info)
    except Exception as e:
        logger.debug(f"[HARDWARE] Could not get BIOS info: {e}")


def _create_chipset_info(chipset):
    """
    Tworzy słownik z informacjami o chipsecie.

    Args:
        chipset: Obiekt WMI Win32_IDEController

    Returns:
        dict: Informacje o chipsecie
    """
    return {
        'name': chipset.Name.strip() if chipset.Name else None,
        'manufacturer': (
            chipset.Manufacturer.strip() if chipset.Manufacturer else None
        ),
        'device_id': chipset.DeviceID.strip() if chipset.DeviceID else None,
        'status': chipset.Status
    }


def _collect_chipset_wmi(motherboard_data):
    """
    Zbiera informacje o chipsecie z WMI.

    Args:
        motherboard_data: Słownik z danymi płyty głównej do uzupełnienia
    """
    try:
        c = wmi.WMI()
        for chipset in c.Win32_IDEController():
            chipset_info = _create_chipset_info(chipset)
            motherboard_data['chipset'].append(chipset_info)
    except Exception as e:
        logger.debug(f"[HARDWARE] Could not get chipset info: {e}")


def _collect_motherboard():
    """
    Zbiera informacje o płycie głównej.

    Returns:
        dict: Dane płyty głównej
    """
    motherboard_data = {
        'boards': [],
        'bios': [],
        'chipset': []
    }

    if sys.platform == "win32" and wmi:
        _collect_boards_wmi(motherboard_data)
        _collect_bios_wmi(motherboard_data)
        _collect_chipset_wmi(motherboard_data)

        if not motherboard_data['boards']:
            motherboard_data['boards'].append(
                {'info': 'Motherboard not found'}
            )

    return motherboard_data


def _collect_cpu_temperature_wmi(sensors_data):
    """
    Zbiera temperaturę CPU z WMI.

    Args:
        sensors_data: Słownik z danymi czujników do uzupełnienia
    """
    try:
        c = wmi.WMI(namespace="root\\wmi")
        for sensor in c.MSAcpi_ThermalZoneTemperature():
            temp_celsius = (sensor.CurrentTemperature / 10.0 - 273.15)
            sensors_data['cpu_temp'] = round(temp_celsius, 2)
            sensors_data['cpu_temp_raw'] = sensor.CurrentTemperature
            sensors_data['thermal_zone'] = (
                sensor.InstanceName.strip()
                if sensor.InstanceName else None
            )
    except Exception as e:
        logger.debug(f"[HARDWARE] Could not get CPU temperature: {e}")
        sensors_data['cpu_temp'] = f'Unavailable: {e}'


def _collect_fan_speeds_wmi(sensors_data):
    """
    Zbiera informacje o wentylatorach z WMI.

    Args:
        sensors_data: Słownik z danymi czujników do uzupełnienia
    """
    try:
        c = wmi.WMI(namespace="root\\wmi")
        fans = []
        for fan in c.MSAcpi_Fan():
            fans.append({
                'active': fan.Active,
                'desired_speed': (
                    fan.DesiredSpeed
                    if hasattr(fan, 'DesiredSpeed') else None
                )
            })
        if fans:
            sensors_data['fans'] = fans
    except Exception as e:
        logger.debug(f"[HARDWARE] Could not get fan info: {e}")


def _collect_psutil_sensors(sensors_data):
    """
    Zbiera informacje o czujnikach z psutil.

    Args:
        sensors_data: Słownik z danymi czujników do uzupełnienia
    """
    try:
        if hasattr(psutil, "sensors_temperatures"):
            temps = psutil.sensors_temperatures()
            if temps:
                sensors_data['psutil_temperatures'] = temps
        if hasattr(psutil, "sensors_fans"):
            fans = psutil.sensors_fans()
            if fans:
                sensors_data['psutil_fans'] = fans
    except Exception as e:
        logger.debug(f"[HARDWARE] Could not get psutil sensors: {e}")


def _collect_sensors():
    """
    Zbiera informacje o czujnikach.

    Returns:
        dict: Dane czujników
    """
    sensors_data = {}

    if sys.platform == "win32" and wmi:
        _collect_cpu_temperature_wmi(sensors_data)
        _collect_fan_speeds_wmi(sensors_data)

    _collect_psutil_sensors(sensors_data)

    return sensors_data


def _collect_battery():
    """Zbiera informacje o baterii."""
    try:
        battery = psutil.sensors_battery()
        if battery:
            battery_data = {
                'percent': battery.percent,
                'plugged_in': battery.power_plugged,
                'seconds_left': battery.secsleft
                if hasattr(battery, 'secsleft') else None
            }

            # Dodatkowe informacje z WMI (Windows)
            if sys.platform == "win32" and wmi:
                _add_wmi_battery_info(battery_data)
            return battery_data
        else:
            return {'info': 'No battery detected'}
    except Exception as e:
        logger.warning(f"[HARDWARE] Error collecting battery info: {e}")
        return {'error': f'Battery info unavailable: {e}'}


def _add_wmi_battery_info(battery_data):
    """Dodaje szczegółowe informacje o baterii z WMI."""
    try:
        c = wmi.WMI()
        for battery_wmi in c.Win32_Battery():
            battery_data.update({
                'name': battery_wmi.Name.strip()
                if battery_wmi.Name else None,
                'manufacturer': battery_wmi.Manufacturer.strip()
                if battery_wmi.Manufacturer else None,
                'chemistry': battery_wmi.Chemistry.strip()
                if battery_wmi.Chemistry else None,
                'design_capacity': battery_wmi.DesignCapacity
                if battery_wmi.DesignCapacity else None,
                'full_charge_capacity': battery_wmi.FullChargeCapacity
                if battery_wmi.FullChargeCapacity else None,
                'estimated_charge_remaining':
                    battery_wmi.EstimatedChargeRemaining
                    if battery_wmi.EstimatedChargeRemaining else None,
                'expected_life': battery_wmi.ExpectedLife
                if battery_wmi.ExpectedLife else None,
                'expected_battery_life': battery_wmi.ExpectedBatteryLife
                if battery_wmi.ExpectedBatteryLife else None,
                'max_recharge_capacity': battery_wmi.MaxRechargeCapacity
                if battery_wmi.MaxRechargeCapacity else None,
                'time_on_battery': battery_wmi.TimeOnBattery
                if battery_wmi.TimeOnBattery else None,
                'time_to_full_charge': battery_wmi.TimeToFullCharge
                if battery_wmi.TimeToFullCharge else None,
                'status': battery_wmi.Status,
                'availability': battery_wmi.Availability,
                'battery_status': battery_wmi.BatteryStatus,
                'battery_recharge_time': battery_wmi.BatteryRechargeTime
                if battery_wmi.BatteryRechargeTime else None
            })
            break
    except Exception as e:
        logger.debug(
            f"[HARDWARE] Could not get detailed battery info from WMI: {e}")


def _collect_usb():
    """Zbiera informacje o urządzeniach USB."""
    usb_devices = []
    if sys.platform == "win32" and wmi:
        try:
            c = wmi.WMI()
            for usb in c.Win32_USBControllerDevice():
                try:
                    device = usb.Dependent
                    usb_devices.append({
                        'device_id': device.DeviceID.strip()
                        if device.DeviceID else None,
                        'description': device.Description.strip()
                        if device.Description else None,
                        'name': device.Name.strip() if device.Name else None,
                        'manufacturer': device.Manufacturer.strip()
                        if device.Manufacturer else None,
                        'service': device.Service.strip()
                        if device.Service else None,
                        'status': device.Status,
                        'pnp_class': device.PNPClass.strip()
                        if device.PNPClass else None
                    })
                except (AttributeError, TypeError, ValueError):
                    # USB device może mieć brakujące atrybuty
                    pass
        except Exception as e:
            logger.debug(f"[HARDWARE] Could not get USB devices info: {e}")
    return usb_devices


def _collect_pci():
    """Zbiera informacje o urządzeniach PCI."""
    pci_devices = []
    if sys.platform == "win32" and wmi:
        try:
            c = wmi.WMI()
            for pci in c.Win32_PnPEntity():
                try:
                    # Bezpieczny dostęp do właściwości WMI - mogą powodować access violation
                    pnp_class = getattr(pci, 'PNPClass', None) or ''
                    if 'PCI' in str(pnp_class):
                        pci_devices.append({
                            'name': (
                                pci.Name.strip()
                                if getattr(pci, 'Name', None) else None
                            ),
                            'device_id': (
                                pci.DeviceID.strip()
                                if getattr(pci, 'DeviceID', None) else None
                            ),
                            'manufacturer': (
                                pci.Manufacturer.strip()
                                if getattr(pci, 'Manufacturer', None) else None
                            ),
                            'description': (
                                pci.Description.strip()
                                if getattr(pci, 'Description', None) else None
                            ),
                            'status': getattr(pci, 'Status', None),
                            'pnp_class': (
                                str(pnp_class).strip() if pnp_class else None
                            ),
                            'service': (
                                pci.Service.strip()
                                if getattr(pci, 'Service', None) else None
                            )
                        })
                except Exception as device_error:
                    # Pomiń problematyczne urządzenie i kontynuuj
                    logger.debug(
                        f"[HARDWARE] Error reading PCI device: {device_error}"
                    )
                    continue
        except Exception as e:
            logger.debug(f"[HARDWARE] Could not get PCI devices info: {e}")
    return pci_devices


def _collect_chassis():
    """Zbiera informacje o obudowie systemu."""
    chassis_list = []
    if sys.platform == "win32" and wmi:
        try:
            c = wmi.WMI()
            for chassis in c.Win32_SystemEnclosure():
                chassis_list.append({
                    'manufacturer': chassis.Manufacturer.strip()
                    if chassis.Manufacturer else None,
                    'model': chassis.Model.strip()
                    if chassis.Model else None,
                    'serial_number': chassis.SerialNumber.strip()
                    if chassis.SerialNumber else None,
                    'chassis_types': chassis.ChassisTypes,
                    'tag': chassis.Tag.strip() if chassis.Tag else None,
                    'sku': chassis.SKU.strip() if chassis.SKU else None,
                    'height': chassis.Height if chassis.Height else None,
                    'depth': chassis.Depth if chassis.Depth else None,
                    'width': chassis.Width if chassis.Width else None,
                    'weight': chassis.Weight if chassis.Weight else None,
                    'lock_present': chassis.LockPresent,
                    'security_status': chassis.SecurityStatus,
                    'smbios_asset_tag': chassis.SMBIOSAssetTag.strip()
                    if chassis.SMBIOSAssetTag else None
                })
        except Exception as e:
            logger.debug(f"[HARDWARE] Could not get chassis info: {e}")
    return chassis_list


def _collect_memory_spd():
    """Zbiera informacje o pamięci SPD."""
    memory_spd = []
    if sys.platform == "win32" and wmi:
        try:
            c = wmi.WMI()
            for mem in c.Win32_PhysicalMemory():
                spd_data = {
                    'manufacturer': mem.Manufacturer.strip()
                    if mem.Manufacturer else None,
                    'part_number': mem.PartNumber.strip()
                    if mem.PartNumber else None,
                    'serial_number': mem.SerialNumber.strip()
                    if mem.SerialNumber else None,
                    'speed': mem.Speed if mem.Speed else None,
                    'capacity': int(mem.Capacity) if mem.Capacity else None,
                    'form_factor': mem.FormFactor if mem.FormFactor else None,
                    'memory_type': mem.MemoryType if mem.MemoryType else None,
                    'configured_clock_speed':
                        mem.ConfiguredClockSpeed
                        if mem.ConfiguredClockSpeed else None,
                    'configured_voltage': mem.ConfiguredVoltage
                    if mem.ConfiguredVoltage else None,
                    'max_voltage': mem.MaxVoltage if mem.MaxVoltage else None,
                    'min_voltage': mem.MinVoltage if mem.MinVoltage else None,
                    'bank_label': mem.BankLabel.strip()
                    if mem.BankLabel else None,
                    'device_locator': mem.DeviceLocator.strip()
                    if mem.DeviceLocator else None,
                    'tag': mem.Tag.strip() if mem.Tag else None
                }
                memory_spd.append(spd_data)
        except Exception as e:
            logger.debug(f"[HARDWARE] Could not get memory SPD info: {e}")
    return memory_spd


def _collect_psu():
    """Zbiera informacje o zasilaczu."""
    psu_data = {}
    if sys.platform == "win32" and wmi:
        try:
            c = wmi.WMI(namespace="root\\wmi")
            # MSAcpi_ThermalZoneTemperature może zawierać info o PSU
            for thermal in c.MSAcpi_ThermalZoneTemperature():
                if 'PSU' in str(thermal) or 'Power' in str(thermal):
                    psu_data['thermal_zone'] = {
                        'current_temperature':
                            thermal.CurrentTemperature
                            if hasattr(thermal, 'CurrentTemperature')
                            else None,
                        'critical_trip_point':
                            thermal.CriticalTripPoint
                            if hasattr(thermal, 'CriticalTripPoint')
                            else None
                    }
        except Exception as e:
            logger.debug(f"[HARDWARE] Could not get PSU info: {e}")
    return psu_data


def collect():
    """
    Zbiera szczegółowe informacje o sprzęcie systemowym.
    Zwraca kompleksowy słownik z danymi hardware.

    Refaktoryzowana wersja - używa mniejszych funkcji dla zmniejszenia
    złożoności cyklomatycznej.
    """
    logger.debug("[HARDWARE] Starting hardware collection")

    data = {
        'cpu': _collect_cpu(),
        'ram': _collect_ram(),
        'ram_slots': _collect_ram_slots(),
        'disks': _collect_disks(),
        'gpu': _collect_gpu(),
        'network': _collect_network(),
        'motherboard': _collect_motherboard(),
        'sensors': _collect_sensors(),
        'battery': _collect_battery(),
        'usb_devices': _collect_usb(),
        'pci_devices': _collect_pci(),
        'chassis': _collect_chassis(),
        'memory_spd': _collect_memory_spd(),
        'psu': _collect_psu()
    }

    logger.info("[HARDWARE] Hardware collection completed")
    return data


# Zachowaj funkcje pomocnicze z oryginalnego pliku
def get_smart_data(device_id):
    """Pobiera SMART data dla dysku (CrystalDiskInfo-like)."""
    import json
    from utils.subprocess_helper import run_powershell_hidden

    try:
        cmd = f"""
        $disk = Get-PhysicalDisk | Where-Object {{ $_.DeviceID -eq '{device_id}' -or $_.FriendlyName -like '*{device_id}*' }}
        if ($disk) {{
            $smart = Get-StorageReliabilityCounter -PhysicalDisk $disk
            @{{
                'HealthStatus' = $smart.HealthStatus
                'Temperature' = $smart.Temperature
                'ReadErrorsTotal' = $smart.ReadErrorsTotal
                'WriteErrorsTotal' = $smart.WriteErrorsTotal
                'Wear' = $smart.Wear
            }} | ConvertTo-Json
        }}
        """
        output = run_powershell_hidden(cmd)
        if output and output.strip():
            return json.loads(output)
    except Exception as e:
        logger.debug(f"[HARDWARE] Error getting SMART data: {e}")
    return None


def get_nvme_health(device_id):
    """Pobiera NVMe health status."""
    import json
    from utils.subprocess_helper import run_powershell_hidden

    try:
        cmd = f"""
        $disk = Get-PhysicalDisk | Where-Object {{ $_.DeviceID -eq '{device_id}' -or $_.FriendlyName -like '*{device_id}*' }}
        if ($disk -and $disk.PhysicalLocation -like '*NVMe*') {{
            $health = Get-StorageReliabilityCounter -PhysicalDisk $disk
            @{{
                'HealthStatus' = $health.HealthStatus
                'Temperature' = $health.Temperature
                'Wear' = $health.Wear
                'MediaType' = $disk.MediaType
            }} | ConvertTo-Json
        }}
        """
        output = run_powershell_hidden(cmd)
        if output and output.strip():
            return json.loads(output)
    except Exception as e:
        logger.debug(f"[HARDWARE] Error getting NVMe health: {e}")
    return None


def get_pcie_info(device_id):
    """Pobiera informacje o PCIe link width i speed."""
    import json
    from utils.subprocess_helper import run_powershell_hidden

    try:
        cmd = f"""
        $disk = Get-PhysicalDisk | Where-Object {{ $_.DeviceID -eq '{device_id}' -or $_.FriendlyName -like '*{device_id}*' }}
        if ($disk) {{
            $pcie = Get-PnpDevice | Where-Object {{ $_.InstanceId -like '*{device_id}*' -or $_.FriendlyName -like '*{device_id}*' }}
            if ($pcie) {{
                @{{
                    'Status' = $pcie.Status
                    'Class' = $pcie.Class
                    'FriendlyName' = $pcie.FriendlyName
                }} | ConvertTo-Json
            }}
        }}
        """
        output = run_powershell_hidden(cmd)
        if output and output.strip():
            return json.loads(output)
    except Exception as e:
        logger.debug(f"[HARDWARE] Error getting PCIe info: {e}")
    return None
