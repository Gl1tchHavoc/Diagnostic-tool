"""
Helper functions for disk detection and validation.
Używa WMI do poprawnego wykrywania dysków fizycznych i filtrowania shadowcopy/virtual disks.
"""
import os
import sys
import psutil
from utils.logger import get_logger
from utils.shadowcopy_helper import is_shadowcopy_path

logger = get_logger()

# Cache dla listy dysków (resetowany przy każdym wywołaniu get_existing_drives z force_refresh=True)
_drives_cache = None

def get_existing_drives(force_refresh=False):
    """
    Zwraca listę istniejących i dostępnych liter dysków w systemie.
    Używa WMI do wykrywania fizycznych dysków i filtruje shadowcopy/virtual disks.
    
    Args:
        force_refresh (bool): Jeśli True, wymusza odświeżenie cache
    
    Returns:
        list: Lista liter dysków (np. ['C:', 'D:', 'E:'])
    """
    global _drives_cache
    
    # Zwróć cache jeśli istnieje i nie wymuszamy odświeżenia
    if not force_refresh and _drives_cache is not None:
        logger.debug(f"[DISK_HELPER] Returning cached drives: {_drives_cache}")
        return _drives_cache
    
    drives = []
    
    if sys.platform == "win32":
        # Użyj WMI do wykrywania dysków fizycznych
        try:
            import wmi
            c = wmi.WMI()
            
            # Pobierz fizyczne dyski
            physical_disks = {}
            for disk in c.Win32_DiskDrive():
                physical_disks[disk.DeviceID] = {
                    'model': disk.Model,
                    'serial': disk.SerialNumber,
                    'size': disk.Size
                }
            
            # Pobierz partycje i powiąż z dyskami fizycznymi
            disk_partitions = {}
            for partition in c.Win32_DiskPartition():
                disk_partitions[partition.DeviceID] = {
                    'disk_id': partition.DiskIndex,
                    'type': partition.Type
                }
            
            # Pobierz wolumeny logiczne
            for logical_disk in c.Win32_LogicalDisk():
                drive_letter = logical_disk.DeviceID  # np. "C:"
                
                # Sprawdź czy wolumen jest online
                if logical_disk.DriveType != 3:  # 3 = Fixed disk
                    logger.debug(f"[DISK_HELPER] Skipping non-fixed drive {drive_letter} (type: {logical_disk.DriveType})")
                    continue
                
                # Sprawdź czy wolumen jest online
                if logical_disk.Status != "OK":
                    logger.debug(f"[DISK_HELPER] Skipping offline drive {drive_letter} (status: {logical_disk.Status})")
                    continue
                
                # Sprawdź czy to nie jest shadowcopy
                if is_shadowcopy_path(logical_disk.VolumeName or ""):
                    logger.debug(f"[DISK_HELPER] Skipping ShadowCopy drive {drive_letter}")
                    continue
                
                # Sprawdź czy to nie jest wirtualny dysk
                if logical_disk.Description and any(keyword in logical_disk.Description.upper() for keyword in ['VIRTUAL', 'RAMDISK', 'SUBST']):
                    logger.debug(f"[DISK_HELPER] Skipping virtual drive {drive_letter} (description: {logical_disk.Description})")
                    continue
                
                # Sprawdź czy dysk jest faktycznie dostępny (można odczytać)
                try:
                    usage = psutil.disk_usage(logical_disk.DeviceID)
                    if drive_letter not in drives:
                        drives.append(drive_letter)
                        logger.debug(f"[DISK_HELPER] Added accessible drive {drive_letter} (total: {usage.total} bytes, model: {logical_disk.VolumeName or 'N/A'})")
                except (PermissionError, OSError) as e:
                    logger.debug(f"[DISK_HELPER] Skipping inaccessible drive {drive_letter}: {type(e).__name__}")
                    continue
                except Exception as e:
                    logger.debug(f"[DISK_HELPER] Error checking drive {drive_letter}: {type(e).__name__}: {e}")
                    continue
            
        except ImportError:
            logger.warning("[DISK_HELPER] WMI not available, falling back to psutil")
            # Fallback do psutil
        except Exception as e:
            logger.warning(f"[DISK_HELPER] Error using WMI: {e}, falling back to psutil")
            # Fallback do psutil
    
    # Fallback: użyj psutil jeśli WMI nie działa
    if not drives:
        try:
            partitions = psutil.disk_partitions()
            logger.debug(f"[DISK_HELPER] Found {len(partitions)} partitions from psutil (fallback)")
            
            for part in partitions:
                if sys.platform == "win32":
                    device = part.device
                    if device and len(device) >= 2 and device[1] == ':':
                        drive_letter = device[:2].upper()
                        
                        # Sprawdź czy to nie jest shadowcopy
                        if is_shadowcopy_path(device):
                            logger.debug(f"[DISK_HELPER] Skipping ShadowCopy drive {drive_letter} (fallback)")
                            continue
                        
                        try:
                            usage = psutil.disk_usage(part.mountpoint)
                            if drive_letter not in drives:
                                drives.append(drive_letter)
                                logger.debug(f"[DISK_HELPER] Added accessible drive {drive_letter} (total: {usage.total} bytes, fallback)")
                        except (PermissionError, OSError) as e:
                            logger.debug(f"[DISK_HELPER] Skipping inaccessible drive {drive_letter}: {type(e).__name__}")
                            continue
                        except Exception as e:
                            logger.debug(f"[DISK_HELPER] Error checking drive {drive_letter}: {type(e).__name__}: {e}")
                            continue
                else:
                    # Dla innych systemów, użyj mountpoint
                    if part.mountpoint:
                        try:
                            psutil.disk_usage(part.mountpoint)
                            drives.append(part.mountpoint)
                        except:
                            continue
        except Exception as e:
            logger.error(f"[DISK_HELPER] Error getting drives: {type(e).__name__}: {e}")
            import traceback
            logger.debug(f"[DISK_HELPER] Traceback: {traceback.format_exc()}")
    
    # Cache wyników
    _drives_cache = drives
    logger.info(f"[DISK_HELPER] Found {len(drives)} accessible drives: {drives}")
    
    return drives

def drive_exists(drive_letter):
    """
    Sprawdza, czy dysk o podanej literze istnieje.
    
    Args:
        drive_letter (str): Litera dysku (np. 'C:', 'D:')
    
    Returns:
        bool: True jeśli dysk istnieje, False w przeciwnym razie
    """
    if not drive_letter:
        return False
    
    # Normalizuj literę dysku
    if len(drive_letter) >= 2 and drive_letter[1] == ':':
        drive_letter = drive_letter[:2].upper()
    elif len(drive_letter) == 1:
        drive_letter = f"{drive_letter.upper()}:"
    else:
        return False
    
    try:
        # Sprawdź czy dysk istnieje
        existing_drives = get_existing_drives()
        return drive_letter in existing_drives
    except Exception as e:
        logger.debug(f"[DISK_HELPER] Error checking drive {drive_letter}: {e}")
        return False

def filter_disk_errors_by_existing_drives(disk_errors, existing_drives=None):
    """
    Filtruje błędy dysków, pozostawiając tylko te dotyczące istniejących dysków.
    
    Args:
        disk_errors (list): Lista błędów dysków
        existing_drives (list, optional): Lista istniejących dysków. Jeśli None, pobierze automatycznie.
    
    Returns:
        list: Przefiltrowana lista błędów
    """
    if existing_drives is None:
        existing_drives = get_existing_drives()
    
    filtered_errors = []
    for error in disk_errors:
        message = error.get("message", "").upper()
        
        # Sprawdź czy błąd dotyczy istniejącego dysku
        should_include = True
        
        # Jeśli wiadomość zawiera literę dysku, sprawdź czy dysk istnieje
        for drive in existing_drives:
            drive_letter = drive.replace(':', '').upper()
            if f" {drive_letter}:\\" in message or f" {drive_letter}:" in message:
                should_include = True
                break
        
        # Jeśli wiadomość nie zawiera żadnej litery dysku, załóż że dotyczy systemu
        if not any(f" {d.replace(':', '').upper()}:\\" in message or f" {d.replace(':', '').upper()}:" in message for d in existing_drives):
            # Sprawdź czy to nie jest błąd dotyczący nieistniejącego dysku
            # Szukaj wzorców typu "E:\", "F:\" itp.
            import re
            drive_pattern = r'([A-Z]):\\'
            matches = re.findall(drive_pattern, message)
            if matches:
                # Jeśli znaleziono literę dysku, która nie istnieje, odfiltruj
                for match in matches:
                    if f"{match}:" not in existing_drives:
                        should_include = False
                        logger.debug(f"[DISK_HELPER] Filtered error for non-existent drive {match}:")
                        break
        
        if should_include:
            filtered_errors.append(error)
    
    logger.debug(f"[DISK_HELPER] Filtered disk errors: {len(disk_errors)} -> {len(filtered_errors)}")
    return filtered_errors

