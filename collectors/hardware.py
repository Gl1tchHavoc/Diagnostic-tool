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


def collect():
    """
    Zbiera szczegółowe informacje o sprzęcie systemowym.
    Zwraca kompleksowy słownik z danymi hardware.
    """
    from utils.logger import get_logger
    logger = get_logger()

    data = {}

    # CPU - szczegółowe informacje
    logger.debug("[HARDWARE] Collecting CPU information")
    try:
        cpu_freq = psutil.cpu_freq()
        cpu_times = psutil.cpu_times()
        cpu_per_core = psutil.cpu_percent(interval=0.1, percpu=True)

        data['cpu'] = {
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
                    data['cpu'].update({
                        'name': processor.Name.strip() if processor.Name else None,
                        'manufacturer': processor.Manufacturer.strip() if processor.Manufacturer else None,
                        'family': processor.Family,
                        'architecture': processor.Architecture,
                        'address_width': processor.AddressWidth,
                        'data_width': processor.DataWidth,
                        'number_of_cores': processor.NumberOfCores,
                        'number_of_logical_processors': processor.NumberOfLogicalProcessors,
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
        data['cpu'] = {'error': str(e)}

    # RAM - szczegółowe informacje
    logger.debug("[HARDWARE] Collecting RAM information")
    try:
        mem = psutil.virtual_memory()
        swap = psutil.swap_memory()

        data['ram'] = {
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
        data['ram'] = {'error': str(e)}

    # RAM per slot - szczegółowe informacje
    logger.debug("[HARDWARE] Collecting RAM slots information")
    data['ram_slots'] = []
    if sys.platform == "win32" and wmi:
        try:
            c = wmi.WMI()
            for mem_slot in c.Win32_PhysicalMemory():
                slot_info = {
                    'capacity': int(
                        mem_slot.Capacity) if mem_slot.Capacity else None,
                    'manufacturer': mem_slot.Manufacturer.strip() if mem_slot.Manufacturer else None,
                    'speed': int(
                        mem_slot.Speed) if mem_slot.Speed else None,
                    'part_number': mem_slot.PartNumber.strip() if mem_slot.PartNumber else None,
                    'bank_label': mem_slot.BankLabel.strip() if mem_slot.BankLabel else None,
                    'serial_number': mem_slot.SerialNumber.strip() if mem_slot.SerialNumber else None,
                    'form_factor': mem_slot.FormFactor,
                    'memory_type': mem_slot.MemoryType,
                    'configured_clock_speed': mem_slot.ConfiguredClockSpeed,
                    'configured_voltage': mem_slot.ConfiguredVoltage,
                    'device_locator': mem_slot.DeviceLocator.strip() if mem_slot.DeviceLocator else None,
                    'status': mem_slot.Status,
                    'tag': mem_slot.Tag.strip() if mem_slot.Tag else None}
                data['ram_slots'].append(slot_info)
        except Exception as e:
            logger.warning(f"[HARDWARE] Error reading RAM slots: {e}")
            data['ram_slots'].append(
                {'error': f'Unable to read RAM slots: {e}'})

    # Dyski - używamy get_logical_volumes() dla pełnych informacji
    logger.debug(
        "[HARDWARE] Collecting disk information using get_logical_volumes()")
    from utils.disk_helper import get_existing_drives, get_logical_volumes

    disks = []
    logical_volumes = get_logical_volumes()
    existing_drives = get_existing_drives()
    logger.debug(
        f"[HARDWARE] Found {len(logical_volumes)} logical volumes, {len(existing_drives)} accessible drives")

    # Użyj get_logical_volumes() jako głównego źródła danych
    for volume in logical_volumes:
        drive_letter = volume.get('device_id', '')

        # Pomiń shadowcopy i wirtualne dyski (chyba że użytkownik chce je
        # widzieć)
        if volume.get('is_shadowcopy', False):
            logger.debug(
                f"[HARDWARE] Skipping ShadowCopy volume {drive_letter}")
            continue

        if volume.get('is_virtual', False):
            logger.debug(f"[HARDWARE] Skipping virtual volume {drive_letter}")
            continue

        # Buduj informacje o dysku
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

        # Dodaj informacje o użyciu (z psutil jeśli dostępne)
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
            try:
                c = wmi.WMI()
                # Znajdź powiązany dysk fizyczny
                for partition in c.Win32_DiskPartition():
                    for logical_disk in c.Win32_LogicalDisk():
                        if logical_disk.DeviceID == drive_letter:
                            # Znajdź dysk fizyczny
                            for physical_disk in c.Win32_DiskDrive():
                                if str(
                                        physical_disk.Index) == str(
                                        partition.DiskIndex):
                                    disk_info['physical_disk'] = {
                                        'model': physical_disk.Model.strip() if physical_disk.Model else None,
                                        'serial': physical_disk.SerialNumber.strip() if physical_disk.SerialNumber else None,
                                        'manufacturer': physical_disk.Manufacturer.strip() if physical_disk.Manufacturer else None,
                                        'interface_type': physical_disk.InterfaceType,
                                        'media_type': physical_disk.MediaType,
                                        'size': int(physical_disk.Size) if physical_disk.Size else None,
                                        'status': physical_disk.Status,
                                        'firmware_revision': physical_disk.FirmwareRevision.strip() if physical_disk.FirmwareRevision else None
                                    }
                                    break
                            break
                    break
            except Exception as e:
                logger.debug(
                    f"[HARDWARE] Could not get physical disk info for {drive_letter}: {e}")

        # Dodaj SMART data i NVMe health
        if sys.platform == "win32" and wmi:
            try:
                c = wmi.WMI()
                # Znajdź powiązany dysk fizyczny dla SMART
                for physical_disk in c.Win32_DiskDrive():
                    if physical_disk.DeviceID in str(
                        disk_info.get(
                            'physical_disk',
                            {}).get(
                            'model',
                            '')) or (
                        drive_letter and physical_disk.Index == disk_info.get(
                            'physical_disk',
                            {}).get('index')):
                        # SMART attributes (jeśli dostępne)
                        try:
                            smart_data = get_smart_data(physical_disk.DeviceID)
                            if smart_data:
                                disk_info['smart'] = smart_data
                        except Exception as e:
                            logger.debug(
                                f"[HARDWARE] Could not get SMART data for {drive_letter}: {e}")

                        # NVMe health (jeśli to NVMe)
                        if 'NVMe' in (
                                physical_disk.InterfaceType or '') or 'nvme' in (
                                physical_disk.Model or '').lower():
                            try:
                                nvme_health = get_nvme_health(
                                    physical_disk.DeviceID)
                                if nvme_health:
                                    disk_info['nvme_health'] = nvme_health
                            except Exception as e:
                                logger.debug(
                                    f"[HARDWARE] Could not get NVMe health for {drive_letter}: {e}")

                        # PCIe link info (jeśli dostępne)
                        try:
                            pcie_info = get_pcie_info(physical_disk.DeviceID)
                            if pcie_info:
                                disk_info['pcie'] = pcie_info
                        except Exception as e:
                            logger.debug(
                                f"[HARDWARE] Could not get PCIe info for {drive_letter}: {e}")

                        break
            except Exception as e:
                logger.debug(
                    f"[HARDWARE] Could not get extended disk info: {e}")

        disks.append(disk_info)
        logger.debug(
            f"[HARDWARE] Added volume {drive_letter}: {disk_info.get('volume_name', 'N/A')} ({disk_info.get('total', 0)} bytes)")

    # Fallback: jeśli get_logical_volumes() nie zwróciło wyników, użyj psutil
    if not disks:
        logger.warning(
            "[HARDWARE] get_logical_volumes() returned no volumes, falling back to psutil")
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
                    try:
                        c = wmi.WMI()
                        # Znajdź fizyczny dysk powiązany z tym wolumenem
                        for logical_disk in c.Win32_LogicalDisk():
                            if logical_disk.DeviceID == drive_letter:
                                disk_info.update({
                                    'volume_name': logical_disk.VolumeName.strip() if logical_disk.VolumeName else None,
                                    'volume_serial': logical_disk.VolumeSerialNumber.strip() if logical_disk.VolumeSerialNumber else None,
                                    'file_system': logical_disk.FileSystem,
                                    'drive_type': logical_disk.DriveType,
                                    'compressed': logical_disk.Compressed,
                                    'supports_disk_quota': logical_disk.SupportsDiskQuotas,
                                    'quotas_incomplete': logical_disk.QuotasIncomplete,
                                    'quotas_rebuild': logical_disk.QuotasRebuilding
                                })

                                # Znajdź powiązany dysk fizyczny
                                for partition in c.Win32_DiskPartition():
                                    if partition.DeviceID in logical_disk.DeviceID or drive_letter in partition.DeviceID:
                                        for physical_disk in c.Win32_DiskDrive():
                                            if physical_disk.DeviceID == partition.DiskIndex or physical_disk.Index == partition.DiskIndex:
                                                disk_info.update({
                                                    'physical_disk': {
                                                        'model': physical_disk.Model.strip() if physical_disk.Model else None,
                                                        'serial': physical_disk.SerialNumber.strip() if physical_disk.SerialNumber else None,
                                                        'manufacturer': physical_disk.Manufacturer.strip() if physical_disk.Manufacturer else None,
                                                        'interface_type': physical_disk.InterfaceType,
                                                        'media_type': physical_disk.MediaType,
                                                        'size': int(physical_disk.Size) if physical_disk.Size else None,
                                                        'status': physical_disk.Status,
                                                        'firmware_revision': physical_disk.FirmwareRevision.strip() if physical_disk.FirmwareRevision else None,
                                                        'partitions': physical_disk.Partitions,
                                                        'total_cylinders': physical_disk.TotalCylinders,
                                                        'total_heads': physical_disk.TotalHeads,
                                                        'total_sectors': physical_disk.TotalSectors,
                                                        'total_tracks': physical_disk.TotalTracks,
                                                        'sectors_per_track': physical_disk.SectorsPerTrack,
                                                        'bytes_per_sector': physical_disk.BytesPerSector,
                                                        'scsi_bus': physical_disk.SCSIBus,
                                                        'scsi_logical_unit': physical_disk.SCSILogicalUnit,
                                                        'scsi_port': physical_disk.SCSIPort,
                                                        'scsi_target_id': physical_disk.SCSITargetId
                                                    }
                                                })
                                                break
                                        break
                                break
                    except Exception as e:
                        logger.debug(
                            f"[HARDWARE] Could not get detailed disk info from WMI: {e}")
                        disk_info['wmi_error'] = str(e)
                disks.append(disk_info)
                logger.debug(
                    f"[HARDWARE] Successfully collected info for drive {device}")
            except PermissionError as e:
                # Dysk jest wykryty, ale niedostępny - dodaj z informacją o
                # błędzie
                logger.warning(
                    f"[HARDWARE] PermissionError accessing drive {device}: {e}")
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
                        logger.debug(
                            f"[HARDWARE] Could not get WMI info for {device}: {wmi_error}")
                disks.append(disk_info)
            except OSError as e:
                # Błąd systemowy (np. dysk nie jest zamontowany)
                logger.warning(
                    f"[HARDWARE] OSError accessing drive {device}: {e}")
                disks.append({
                    'device': device,
                    'mountpoint': mountpoint,
                    'fstype': part.fstype,
                    'error': f'OS Error: {str(e)}',
                    'error_type': 'OSError'
                })
            except Exception as e:
                # Inne błędy - dodaj z informacją o błędzie
                logger.warning(
                    f"[HARDWARE] Error accessing drive {device}: {type(e).__name__}: {e}")
                disks.append({
                    'device': device,
                    'mountpoint': mountpoint,
                    'fstype': part.fstype,
                    'error': f'Error: {type(e).__name__} - {str(e)}',
                    'error_type': type(e).__name__
                })

    logger.info(
        f"[HARDWARE] Collected info for {len(disks)} drives (including inaccessible ones)")
    data['disks'] = disks

    # GPU - szczegółowe informacje
    logger.debug("[HARDWARE] Collecting GPU information")
    data['gpu'] = []

    # GPUtil (jeśli dostępny)
    if GPUtil:
        try:
            gpus = GPUtil.getGPUs()
            for gpu in gpus:
                data['gpu'].append({
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
                })
            if not data['gpu']:
                data['gpu'].append({'info': 'No GPU detected by GPUtil'})
        except Exception as e:
            logger.debug(f"[HARDWARE] GPUtil detection failed: {e}")

    # WMI dla Windows (dodatkowe informacje o GPU)
    if sys.platform == "win32" and wmi:
        try:
            c = wmi.WMI()
            for gpu in c.Win32_VideoController():
                gpu_info = {
                    'name': gpu.Name.strip() if gpu.Name else None,
                    'adapter_ram': int(
                        gpu.AdapterRAM) if gpu.AdapterRAM else None,
                    'driver_version': gpu.DriverVersion.strip() if gpu.DriverVersion else None,
                    'driver_date': gpu.DriverDate.strip() if gpu.DriverDate else None,
                    'video_mode_description': gpu.VideoModeDescription.strip() if gpu.VideoModeDescription else None,
                    'video_processor': gpu.VideoProcessor.strip() if gpu.VideoProcessor else None,
                    'status': gpu.Status,
                    'availability': gpu.Availability,
                    'pnp_device_id': gpu.PNPDeviceID.strip() if gpu.PNPDeviceID else None,
                    'device_id': gpu.DeviceID.strip() if gpu.DeviceID else None,
                    'adapter_dac_type': gpu.AdapterDACType.strip() if gpu.AdapterDACType else None,
                    'max_memory_supported': int(
                        gpu.MaxMemorySupported) if gpu.MaxMemorySupported else None,
                    'max_refresh_rate': int(
                        gpu.MaxRefreshRate) if gpu.MaxRefreshRate else None,
                    'min_refresh_rate': int(
                        gpu.MinRefreshRate) if gpu.MinRefreshRate else None,
                    'current_refresh_rate': int(
                        gpu.CurrentRefreshRate) if gpu.CurrentRefreshRate else None,
                    'current_horizontal_resolution': int(
                        gpu.CurrentHorizontalResolution) if gpu.CurrentHorizontalResolution else None,
                    'current_vertical_resolution': int(
                        gpu.CurrentVerticalResolution) if gpu.CurrentVerticalResolution else None,
                    'source': 'WMI'}

                # Sprawdź czy to już istnieje w liście (z GPUtil)
                existing = False
                for existing_gpu in data['gpu']:
                    if existing_gpu.get('name') == gpu_info['name']:
                        existing_gpu.update(gpu_info)
                        existing = True
                        break

                if not existing:
                    data['gpu'].append(gpu_info)
        except Exception as e:
            logger.debug(f"[HARDWARE] WMI GPU detection failed: {e}")

    if not data['gpu']:
        data['gpu'].append({'info': 'No GPU detected'})

    # Network - szczegółowe informacje
    logger.debug("[HARDWARE] Collecting network information")
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

            # Adresy sieciowe
            for addr in addrs:
                addr_info = {
                    'family': str(
                        addr.family), 'address': addr.address, 'netmask': addr.netmask if hasattr(
                        addr, 'netmask') else None, 'broadcast': addr.broadcast if hasattr(
                        addr, 'broadcast') else None, 'ptp': addr.ptp if hasattr(
                        addr, 'ptp') else None}
                interface_info['addresses'].append(addr_info)

                if addr.family == psutil.AF_LINK:
                    interface_info['mac'] = addr.address
                elif addr.family == 2:  # IPv4
                    interface_info['ipv4'].append(addr.address)
                elif addr.family == 23:  # IPv6
                    interface_info['ipv6'].append(addr.address)

            # Statystyki interfejsu
            if iface in net_stats:
                stats = net_stats[iface]
                interface_info['stats'] = {
                    'isup': stats.isup,
                    'speed': stats.speed,
                    'mtu': stats.mtu,
                    'duplex': str(
                        stats.duplex) if hasattr(
                        stats,
                        'duplex') else None}

            # I/O statystyki
            if iface in net_io:
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

            netcards.append(interface_info)

        # Dodatkowe informacje z WMI (Windows)
        if sys.platform == "win32" and wmi:
            try:
                c = wmi.WMI()
                for adapter in c.Win32_NetworkAdapter():
                    if adapter.NetEnabled:
                        # Znajdź odpowiedni interfejs
                        for netcard in netcards:
                            if adapter.Name in netcard['interface'] or netcard['interface'] in adapter.Name:
                                netcard.update({
                                    'adapter_type': adapter.AdapterType,
                                    'adapter_type_id': adapter.AdapterTypeID,
                                    'manufacturer': adapter.Manufacturer.strip() if adapter.Manufacturer else None,
                                    'product_name': adapter.ProductName.strip() if adapter.ProductName else None,
                                    'description': adapter.Description.strip() if adapter.Description else None,
                                    'pnp_device_id': adapter.PNPDeviceID.strip() if adapter.PNPDeviceID else None,
                                    'speed': adapter.Speed if adapter.Speed else None,
                                    'mac_address': adapter.MACAddress.strip() if adapter.MACAddress else None,
                                    'status': adapter.Status,
                                    'availability': adapter.Availability
                                })
                                break
            except Exception as e:
                logger.debug(
                    f"[HARDWARE] Could not get detailed network info from WMI: {e}")

        data['network'] = netcards
        data['network_summary'] = {
            'total_interfaces': len(netcards), 'active_interfaces': len(
                [
                    n for n in netcards if n.get(
                        'stats', {}).get(
                        'isup', False)]), 'total_bytes_sent': sum(
                n.get(
                    'io', {}).get(
                    'bytes_sent', 0) for n in netcards), 'total_bytes_recv': sum(
                n.get(
                    'io', {}).get(
                    'bytes_recv', 0) for n in netcards)}
    except Exception as e:
        logger.warning(f"[HARDWARE] Error collecting network info: {e}")
        data['network'] = {'error': str(e)}

    # Motherboard - szczegółowe informacje
    logger.debug("[HARDWARE] Collecting motherboard information")
    data['motherboard'] = []
    if sys.platform == "win32" and wmi:
        try:
            c = wmi.WMI()
            for board in c.Win32_BaseBoard():
                data['motherboard'].append({
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
                })

            # BIOS informacje
            data['bios'] = []
            try:
                for bios in c.Win32_BIOS():
                    data['bios'].append({
                        'manufacturer': bios.Manufacturer.strip() if bios.Manufacturer else None,
                        'version': bios.Version.strip() if bios.Version else None,
                        'release_date': bios.ReleaseDate.strip() if bios.ReleaseDate else None,
                        'serial_number': bios.SerialNumber.strip() if bios.SerialNumber else None,
                        'smbios_version': bios.SMBIOSBIOSVersion.strip() if bios.SMBIOSBIOSVersion else None,
                        'smbios_major_version': bios.SMBIOSMajorVersion,
                        'smbios_minor_version': bios.SMBIOSMinorVersion,
                        'bios_characteristics': bios.BIOSCharacteristics if hasattr(bios, 'BIOSCharacteristics') else None
                    })
            except Exception as e:
                logger.debug(f"[HARDWARE] Could not get BIOS info: {e}")

            # Chipset informacje
            data['chipset'] = []
            try:
                for chipset in c.Win32_IDEController():
                    data['chipset'].append({
                        'name': chipset.Name.strip() if chipset.Name else None,
                        'manufacturer': chipset.Manufacturer.strip() if chipset.Manufacturer else None,
                        'device_id': chipset.DeviceID.strip() if chipset.DeviceID else None,
                        'status': chipset.Status
                    })
            except Exception as e:
                logger.debug(f"[HARDWARE] Could not get chipset info: {e}")

            if not data['motherboard']:
                data['motherboard'].append({'info': 'Motherboard not found'})
        except Exception as e:
            logger.warning(f"[HARDWARE] Error reading motherboard info: {e}")
            data['motherboard'].append(
                {'error': f'Unable to read motherboard info: {e}'})

    # Sensors - temperatury i inne czujniki
    logger.debug("[HARDWARE] Collecting sensor information")
    data['sensors'] = {}
    if sys.platform == "win32" and wmi:
        try:
            # CPU Temperature
            c = wmi.WMI(namespace="root\\wmi")
            for sensor in c.MSAcpi_ThermalZoneTemperature():
                temp_celsius = (sensor.CurrentTemperature / 10.0 - 273.15)
                data['sensors']['cpu_temp'] = round(temp_celsius, 2)
                data['sensors']['cpu_temp_raw'] = sensor.CurrentTemperature
                data['sensors']['thermal_zone'] = sensor.InstanceName.strip(
                ) if sensor.InstanceName else None
        except Exception as e:
            logger.debug(f"[HARDWARE] Could not get CPU temperature: {e}")
            data['sensors']['cpu_temp'] = f'Unavailable: {e}'

        # Fan speeds (jeśli dostępne)
        try:
            c = wmi.WMI(namespace="root\\wmi")
            fans = []
            for fan in c.MSAcpi_Fan():
                fans.append({'active': fan.Active,
                             'desired_speed': fan.DesiredSpeed if hasattr(fan,
                                                                          'DesiredSpeed') else None})
            if fans:
                data['sensors']['fans'] = fans
        except Exception as e:
            logger.debug(f"[HARDWARE] Could not get fan info: {e}")

    # psutil sensors (jeśli dostępne)
    try:
        if hasattr(psutil, "sensors_temperatures"):
            temps = psutil.sensors_temperatures()
            if temps:
                data['sensors']['psutil_temperatures'] = temps
        if hasattr(psutil, "sensors_fans"):
            fans = psutil.sensors_fans()
            if fans:
                data['sensors']['psutil_fans'] = fans
    except Exception as e:
        logger.debug(f"[HARDWARE] Could not get psutil sensors: {e}")

    # Battery - szczegółowe informacje
    logger.debug("[HARDWARE] Collecting battery information")
    try:
        battery = psutil.sensors_battery()
        if battery:
            data['battery'] = {
                'percent': battery.percent,
                'plugged_in': battery.power_plugged,
                'seconds_left': battery.secsleft if hasattr(
                    battery,
                    'secsleft') else None}

            # Dodatkowe informacje z WMI (Windows)
            if sys.platform == "win32" and wmi:
                try:
                    c = wmi.WMI()
                    for battery_wmi in c.Win32_Battery():
                        data['battery'].update({
                            'name': battery_wmi.Name.strip() if battery_wmi.Name else None,
                            'manufacturer': battery_wmi.Manufacturer.strip() if battery_wmi.Manufacturer else None,
                            'chemistry': battery_wmi.Chemistry.strip() if battery_wmi.Chemistry else None,
                            'design_capacity': battery_wmi.DesignCapacity if battery_wmi.DesignCapacity else None,
                            'full_charge_capacity': battery_wmi.FullChargeCapacity if battery_wmi.FullChargeCapacity else None,
                            'estimated_charge_remaining': battery_wmi.EstimatedChargeRemaining if battery_wmi.EstimatedChargeRemaining else None,
                            'expected_life': battery_wmi.ExpectedLife if battery_wmi.ExpectedLife else None,
                            'expected_battery_life': battery_wmi.ExpectedBatteryLife if battery_wmi.ExpectedBatteryLife else None,
                            'max_recharge_capacity': battery_wmi.MaxRechargeCapacity if battery_wmi.MaxRechargeCapacity else None,
                            'time_on_battery': battery_wmi.TimeOnBattery if battery_wmi.TimeOnBattery else None,
                            'time_to_full_charge': battery_wmi.TimeToFullCharge if battery_wmi.TimeToFullCharge else None,
                            'status': battery_wmi.Status,
                            'availability': battery_wmi.Availability,
                            'battery_status': battery_wmi.BatteryStatus,
                            'battery_recharge_time': battery_wmi.BatteryRechargeTime if battery_wmi.BatteryRechargeTime else None
                        })
                        break
                except Exception as e:
                    logger.debug(
                        f"[HARDWARE] Could not get detailed battery info from WMI: {e}")
        else:
            data['battery'] = {'info': 'No battery detected'}
    except Exception as e:
        logger.warning(f"[HARDWARE] Error collecting battery info: {e}")
        data['battery'] = {'error': f'Battery info unavailable: {e}'}

    # USB Devices
    logger.debug("[HARDWARE] Collecting USB devices information")
    data['usb_devices'] = []
    if sys.platform == "win32" and wmi:
        try:
            c = wmi.WMI()
            for usb in c.Win32_USBControllerDevice():
                try:
                    device = usb.Dependent
                    data['usb_devices'].append({
                        'device_id': device.DeviceID.strip() if device.DeviceID else None,
                        'description': device.Description.strip() if device.Description else None,
                        'name': device.Name.strip() if device.Name else None,
                        'manufacturer': device.Manufacturer.strip() if device.Manufacturer else None,
                        'service': device.Service.strip() if device.Service else None,
                        'status': device.Status,
                        'pnp_class': device.PNPClass.strip() if device.PNPClass else None
                    })
                except BaseException:
                    pass
        except Exception as e:
            logger.debug(f"[HARDWARE] Could not get USB devices info: {e}")

    # PCI Devices
    logger.debug("[HARDWARE] Collecting PCI devices information")
    data['pci_devices'] = []
    if sys.platform == "win32" and wmi:
        try:
            c = wmi.WMI()
            for pci in c.Win32_PnPEntity():
                if 'PCI' in (pci.PNPClass or ''):
                    data['pci_devices'].append({
                        'name': pci.Name.strip() if pci.Name else None,
                        'device_id': pci.DeviceID.strip() if pci.DeviceID else None,
                        'manufacturer': pci.Manufacturer.strip() if pci.Manufacturer else None,
                        'description': pci.Description.strip() if pci.Description else None,
                        'status': pci.Status,
                        'pnp_class': pci.PNPClass.strip() if pci.PNPClass else None,
                        'service': pci.Service.strip() if pci.Service else None
                    })
        except Exception as e:
            logger.debug(f"[HARDWARE] Could not get PCI devices info: {e}")

    # System Chassis
    logger.debug("[HARDWARE] Collecting system chassis information")
    data['chassis'] = []
    if sys.platform == "win32" and wmi:
        try:
            c = wmi.WMI()
            for chassis in c.Win32_SystemEnclosure():
                data['chassis'].append({
                    'manufacturer': chassis.Manufacturer.strip() if chassis.Manufacturer else None,
                    'model': chassis.Model.strip() if chassis.Model else None,
                    'serial_number': chassis.SerialNumber.strip() if chassis.SerialNumber else None,
                    'chassis_types': chassis.ChassisTypes,
                    'tag': chassis.Tag.strip() if chassis.Tag else None,
                    'sku': chassis.SKU.strip() if chassis.SKU else None,
                    'height': chassis.Height if chassis.Height else None,
                    'depth': chassis.Depth if chassis.Depth else None,
                    'width': chassis.Width if chassis.Width else None,
                    'weight': chassis.Weight if chassis.Weight else None,
                    'lock_present': chassis.LockPresent,
                    'security_status': chassis.SecurityStatus,
                    'smbios_asset_tag': chassis.SMBIOSAssetTag.strip() if chassis.SMBIOSAssetTag else None
                })
        except Exception as e:
            logger.debug(f"[HARDWARE] Could not get chassis info: {e}")

    # Memory SPD table
    logger.debug("[HARDWARE] Collecting memory SPD information")
    data['memory_spd'] = []
    if sys.platform == "win32" and wmi:
        try:
            c = wmi.WMI()
            for mem in c.Win32_PhysicalMemory():
                spd_data = {
                    'manufacturer': mem.Manufacturer.strip() if mem.Manufacturer else None,
                    'part_number': mem.PartNumber.strip() if mem.PartNumber else None,
                    'serial_number': mem.SerialNumber.strip() if mem.SerialNumber else None,
                    'speed': mem.Speed if mem.Speed else None,
                    'capacity': int(
                        mem.Capacity) if mem.Capacity else None,
                    'form_factor': mem.FormFactor if mem.FormFactor else None,
                    'memory_type': mem.MemoryType if mem.MemoryType else None,
                    'configured_clock_speed': mem.ConfiguredClockSpeed if mem.ConfiguredClockSpeed else None,
                    'configured_voltage': mem.ConfiguredVoltage if mem.ConfiguredVoltage else None,
                    'max_voltage': mem.MaxVoltage if mem.MaxVoltage else None,
                    'min_voltage': mem.MinVoltage if mem.MinVoltage else None,
                    'bank_label': mem.BankLabel.strip() if mem.BankLabel else None,
                    'device_locator': mem.DeviceLocator.strip() if mem.DeviceLocator else None,
                    'tag': mem.Tag.strip() if mem.Tag else None}
                data['memory_spd'].append(spd_data)
        except Exception as e:
            logger.debug(f"[HARDWARE] Could not get memory SPD info: {e}")

    # PSU readings (jeśli dostępne)
    logger.debug("[HARDWARE] Collecting PSU information")
    data['psu'] = {}
    if sys.platform == "win32" and wmi:
        try:
            c = wmi.WMI(namespace="root\\wmi")
            # MSAcpi_ThermalZoneTemperature może zawierać info o PSU
            for thermal in c.MSAcpi_ThermalZoneTemperature():
                if 'PSU' in str(thermal) or 'Power' in str(thermal):
                    data['psu']['thermal_zone'] = {
                        'current_temperature': thermal.CurrentTemperature if hasattr(
                            thermal,
                            'CurrentTemperature') else None,
                        'critical_trip_point': thermal.CriticalTripPoint if hasattr(
                            thermal,
                            'CriticalTripPoint') else None}
        except Exception as e:
            logger.debug(f"[HARDWARE] Could not get PSU info: {e}")

    logger.info("[HARDWARE] Hardware collection completed")
    return data


def get_smart_data(device_id):
    """Pobiera SMART data dla dysku (CrystalDiskInfo-like)."""
    import json

    from utils.logger import get_logger
    from utils.subprocess_helper import run_powershell_hidden

    logger = get_logger()
    try:
        # Użyj PowerShell do pobrania SMART attributes
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
        logger = get_logger()
        logger.debug(f"[HARDWARE] Error getting SMART data: {e}")
    return None


def get_nvme_health(device_id):
    """Pobiera NVMe health status."""
    import json

    from utils.logger import get_logger
    from utils.subprocess_helper import run_powershell_hidden

    logger = get_logger()
    try:
        # Użyj wmic lub PowerShell do NVMe health
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
        logger = get_logger()
        logger.debug(f"[HARDWARE] Error getting NVMe health: {e}")
    return None


def get_pcie_info(device_id):
    """Pobiera informacje o PCIe link width i speed."""
    import json

    from utils.logger import get_logger
    from utils.subprocess_helper import run_powershell_hidden

    logger = get_logger()
    try:
        # Użyj PowerShell do pobrania PCIe info
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
        logger = get_logger()
        logger.debug(f"[HARDWARE] Error getting PCIe info: {e}")
    return None
