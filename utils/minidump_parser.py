"""
Minidump parser - parsuje pliki .dmp i wyciąga STOP code oraz offending driver.
"""
import os
import struct
from pathlib import Path
from utils.logger import get_logger
from utils.safe_read import safe_read_text

logger = get_logger()

# STOP codes mapping
STOP_CODES = {
    0x0000007E: "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED",
    0x0000007F: "UNEXPECTED_KERNEL_MODE_TRAP",
    0x0000008E: "KERNEL_MODE_EXCEPTION_NOT_HANDLED",
    0x00000050: "PAGE_FAULT_IN_NONPAGED_AREA",
    0x000000D1: "DRIVER_IRQL_NOT_LESS_OR_EQUAL",
    0x0000000A: "IRQL_NOT_LESS_OR_EQUAL",
    0x0000001E: "KMODE_EXCEPTION_NOT_HANDLED",
    0x0000003B: "SYSTEM_SERVICE_EXCEPTION",
    0x000000EF: "CRITICAL_PROCESS_DIED",
    0x000000C2: "BAD_POOL_CALLER",
    0x000000BE: "ATTEMPTED_WRITE_TO_READONLY_MEMORY",
    0x00000024: "NTFS_FILE_SYSTEM",
    0x00000077: "KERNEL_STACK_INPAGE_ERROR",
    0x0000007A: "KERNEL_DATA_INPAGE_ERROR",
    0x000000F4: "CRITICAL_OBJECT_TERMINATION",
    0x0000009F: "DRIVER_POWER_STATE_FAILURE",
    0x000000A5: "ACPI_BIOS_ERROR",
    0x000000C4: "DRIVER_VERIFIER_DETECTED_VIOLATION",
    0x000000CE: "DRIVER_UNLOADED_WITHOUT_CANCELLING_PENDING_OPERATIONS",
    0x000000ED: "UNMOUNTABLE_BOOT_VOLUME",
    0x000000F2: "HARDWARE_INTERRUPT_STORM"
}

def parse_minidump(dump_file_path):
    """
    Parsuje plik minidump i wyciąga STOP code oraz offending driver.
    
    Args:
        dump_file_path (str): Ścieżka do pliku .dmp
    
    Returns:
        dict: {
            'stop_code': str,
            'stop_code_name': str,
            'offending_driver': str,
            'parameters': dict,
            'success': bool
        }
    """
    result = {
        'stop_code': None,
        'stop_code_name': None,
        'offending_driver': None,
        'parameters': {},
        'success': False
    }
    
    if not os.path.exists(dump_file_path):
        logger.warning(f"[MINIDUMP_PARSER] File does not exist: {dump_file_path}")
        return result
    
    try:
        logger.debug(f"[MINIDUMP_PARSER] Parsing minidump: {dump_file_path}")
        
        with open(dump_file_path, 'rb') as f:
            # Minidump header (pierwsze 32 bajty)
            header = f.read(32)
            
            # Sprawdź signature (PAGEDUMP lub MINIDUMP)
            signature = header[:4]
            if signature != b'PAGE' and signature != b'MDMP':
                logger.warning(f"[MINIDUMP_PARSER] Invalid minidump signature: {signature}")
                # Spróbuj znaleźć STOP code w pliku binarnym
                return parse_minidump_binary_search(dump_file_path)
            
            # Szukaj BugCheckCode w pliku
            # W minidump BugCheckCode jest zwykle w strukturze DUMP_HEADER
            f.seek(0)
            content = f.read(min(8192, os.path.getsize(dump_file_path)))
            
            # Szukaj wzorców w binarnych danych
            # BugCheckCode jest często w formacie 4-byte integer
            for i in range(len(content) - 4):
                # Sprawdź czy to może być STOP code (0x00000000 - 0x00000100)
                potential_code = struct.unpack('<I', content[i:i+4])[0]
                if potential_code in STOP_CODES:
                    result['stop_code'] = f"0x{potential_code:08X}"
                    result['stop_code_name'] = STOP_CODES[potential_code]
                    logger.info(f"[MINIDUMP_PARSER] Found STOP code: {result['stop_code']} ({result['stop_code_name']})")
                    break
            
            # Szukaj nazw sterowników w pliku (szukaj .sys i .dll)
            f.seek(0)
            full_content = f.read()
            driver_patterns = [
                b'ntoskrnl.exe',
                b'hal.dll',
                b'win32k.sys',
                b'atikmdag.sys',
                b'nvlddmkm.sys',
                b'igdkmd64.sys',
                b'amdkmdap.sys'
            ]
            
            for pattern in driver_patterns:
                if pattern in full_content:
                    driver_name = pattern.decode('utf-8', errors='ignore')
                    if driver_name not in ['ntoskrnl.exe', 'hal.dll']:  # Pomiń zbyt ogólne
                        result['offending_driver'] = driver_name
                        logger.info(f"[MINIDUMP_PARSER] Found potential offending driver: {driver_name}")
                        break
            
            result['success'] = True
            
    except Exception as e:
        logger.warning(f"[MINIDUMP_PARSER] Error parsing minidump {dump_file_path}: {e}")
        # Fallback: spróbuj znaleźć informacje w tekście
        return parse_minidump_binary_search(dump_file_path)
    
    return result

def parse_minidump_binary_search(dump_file_path):
    """
    Fallback: szuka STOP code i driverów w pliku binarnym przez wyszukiwanie wzorców.
    """
    result = {
        'stop_code': None,
        'stop_code_name': None,
        'offending_driver': None,
        'parameters': {},
        'success': False
    }
    
    try:
        with open(dump_file_path, 'rb') as f:
            # Przeczytaj cały plik (lub pierwsze 64KB)
            content = f.read(min(65536, os.path.getsize(dump_file_path)))
            
            # Szukaj STOP codes w różnych formatach
            for code, name in STOP_CODES.items():
                # Szukaj jako 4-byte little-endian
                code_bytes = struct.pack('<I', code)
                if code_bytes in content:
                    result['stop_code'] = f"0x{code:08X}"
                    result['stop_code_name'] = name
                    result['success'] = True
                    logger.info(f"[MINIDUMP_PARSER] Found STOP code via binary search: {result['stop_code']}")
                    break
            
            # Szukaj nazw sterowników
            driver_names = ['atikmdag.sys', 'nvlddmkm.sys', 'igdkmd64.sys', 'amdkmdap.sys', 
                          'dxgkrnl.sys', 'nvlddmkm.sys', 'atikmpag.sys']
            for driver in driver_names:
                if driver.encode('utf-8') in content:
                    result['offending_driver'] = driver
                    logger.info(f"[MINIDUMP_PARSER] Found driver via binary search: {driver}")
                    break
                    
    except Exception as e:
        logger.warning(f"[MINIDUMP_PARSER] Error in binary search: {e}")
    
    return result

