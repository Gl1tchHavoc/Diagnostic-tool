"""
Helper functions for disk detection and validation.
"""
import os
import sys
import psutil
from utils.logger import get_logger

logger = get_logger()

def get_existing_drives():
    """
    Zwraca listę istniejących liter dysków w systemie.
    
    Returns:
        list: Lista liter dysków (np. ['C:', 'D:', 'E:'])
    """
    drives = []
    try:
        # Użyj psutil do pobrania wszystkich partycji
        partitions = psutil.disk_partitions()
        for part in partitions:
            if sys.platform == "win32":
                # Dla Windows, weź literę dysku (np. C:)
                device = part.device
                if device and len(device) >= 2 and device[1] == ':':
                    drive_letter = device[:2].upper()
                    if drive_letter not in drives:
                        drives.append(drive_letter)
            else:
                # Dla innych systemów, użyj mountpoint
                if part.mountpoint:
                    drives.append(part.mountpoint)
        
        logger.debug(f"[DISK_HELPER] Found {len(drives)} existing drives: {drives}")
    except Exception as e:
        logger.error(f"[DISK_HELPER] Error getting drives: {e}")
    
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

