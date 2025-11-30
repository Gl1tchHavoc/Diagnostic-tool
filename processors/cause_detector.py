"""
Cause Detector - wykrywa konkretne przyczyny problemów systemowych na podstawie wzorców.
"""
from collections import defaultdict
from datetime import datetime
from utils.logger import get_logger
from utils.shadowcopy_helper import is_shadowcopy_path
from utils.error_analyzer import (
    safe_get_with_analysis, 
    log_error_with_analysis, 
    analyze_data_structure,
    analyze_attribute_error
)

logger = get_logger()

def detect_all_causes(processed_data, collected_data):
    """
    Wykrywa wszystkie możliwe przyczyny problemów na podstawie zebranych danych.
    
    Args:
        processed_data (dict): Przetworzone dane z procesorów
        collected_data (dict): Surowe dane z kolektorów
    
    Returns:
        dict: Wykryte przyczyny z confidence scores
    """
    causes = []
    
    # 1. Dyski i system plików
    causes.extend(detect_disk_filesystem_causes(processed_data, collected_data))
    
    # 2. BSOD / krytyczne błędy systemowe
    causes.extend(detect_bsod_critical_causes(processed_data, collected_data))
    
    # 3. Sterowniki i aplikacje
    causes.extend(detect_driver_app_causes(processed_data, collected_data))
    
    # 4. Pamięć RAM
    causes.extend(detect_memory_causes(processed_data, collected_data))
    
    # 5. Sieć i UPnP
    causes.extend(detect_network_upnp_causes(processed_data, collected_data))
    
    # 6. Procesor i temperatura
    causes.extend(detect_cpu_thermal_causes(processed_data, collected_data))
    
    # 7. Zasilanie
    causes.extend(detect_power_causes(processed_data, collected_data))
    
    # 8. Inne poważne problemy systemowe
    causes.extend(detect_other_critical_causes(processed_data, collected_data))
    
    # 9. WER (Windows Error Reporting) - golden rules
    causes.extend(detect_wer_causes(processed_data, collected_data))
    
    # Sortuj według confidence
    causes.sort(key=lambda x: x.get('confidence', 0), reverse=True)
    
    logger.info(f"[CAUSE_DETECTOR] Detected {len(causes)} potential causes")
    
    return {
        'causes': causes,
        'total_causes': len(causes),
        'high_confidence_causes': [c for c in causes if c.get('confidence', 0) >= 70],
        'medium_confidence_causes': [c for c in causes if 40 <= c.get('confidence', 0) < 70],
        'low_confidence_causes': [c for c in causes if c.get('confidence', 0) < 40]
    }

def detect_disk_filesystem_causes(processed_data, collected_data):
    """Wykrywa przyczyny związane z dyskami i systemem plików."""
    causes = []
    
    # REGISTRY_TXR_FAILURE + ShadowCopy errors → uszkodzony dysk lub wolumin Shadow Copy
    registry_txr = processed_data.get('registry_txr', {})
    if registry_txr:
        critical_issues = registry_txr.get('critical_issues', [])
        shadowcopy_issues = registry_txr.get('shadowcopy_issues', [])
        
        txr_failures = [i for i in critical_issues if i.get('type') == 'REGISTRY_TXR_FAILURE']
        if txr_failures and shadowcopy_issues:
            causes.append({
                'category': 'Disk/FileSystem',
                'cause': 'CORRUPTED_DISK_OR_SHADOWCOPY',
                'confidence': 85.0,
                'description': 'Registry TxR failures combined with ShadowCopy errors indicate corrupted disk or ShadowCopy volume',
                'evidence': {
                    'txr_failures': len(txr_failures),
                    'shadowcopy_errors': len(shadowcopy_issues)
                },
                'recommendation': 'Check disk health with chkdsk, verify ShadowCopy integrity, consider removing old shadow copies'
            })
    
    # Chkdsk wykrywa bad sectors → fizyczna awaria dysku
    storage_health = processed_data.get('storage_health', {})
    if storage_health:
        issues = storage_health.get('issues', [])
        for issue in issues:
            message = issue.get('message', '').lower()
            if 'bad sector' in message or 'bad block' in message or 'chkdsk' in message:
                causes.append({
                    'category': 'Disk/FileSystem',
                    'cause': 'PHYSICAL_DISK_FAILURE',
                    'confidence': 90.0,
                    'description': 'Chkdsk detected bad sectors - indicates physical disk failure',
                    'evidence': {'message': issue.get('message', '')},
                    'recommendation': 'Backup data immediately, replace disk, run chkdsk /f /r'
                })
                break
    
    # System nie może naprawić plików po sfc /scannow → poważna korupcja systemu
    system_logs = processed_data.get('system_logs', {})
    if system_logs:
        issues = system_logs.get('issues', [])
        for issue in issues:
            message = issue.get('message', '').lower()
            if 'sfc' in message and ('cannot repair' in message or 'failed to repair' in message or 'corruption' in message):
                causes.append({
                    'category': 'Disk/FileSystem',
                    'cause': 'SEVERE_SYSTEM_CORRUPTION',
                    'confidence': 95.0,
                    'description': 'SFC cannot repair system files - indicates severe system corruption',
                    'evidence': {'message': issue.get('message', '')},
                    'recommendation': 'Run DISM /Online /Cleanup-Image /RestoreHealth, then sfc /scannow again. Consider system restore or reinstall'
                })
                break
    
    # EventID 55 (NTFS file system error) → korupcja systemu plików
    if system_logs:
        issues = system_logs.get('issues', [])
        for issue in issues:
            event_id = str(issue.get('event_id', ''))
            if event_id == '55' or 'ntfs' in issue.get('message', '').lower():
                causes.append({
                    'category': 'Disk/FileSystem',
                    'cause': 'NTFS_FILESYSTEM_CORRUPTION',
                    'confidence': 80.0,
                    'description': 'EventID 55 or NTFS errors indicate file system corruption',
                    'evidence': {'event_id': event_id, 'message': issue.get('message', '')[:200]},
                    'recommendation': 'Run chkdsk /f on affected volume, check disk for errors'
                })
                break
    
    # KERNEL_DATA_INPAGE_ERROR (0x7A) + IO error → uszkodzony dysk lub kontroler
    bsod_data = collected_data.get('collectors', {}).get('bsod_dumps', {})
    if bsod_data:
        bugchecks = bsod_data.get('bugchecks', [])
        for bugcheck in bugchecks:
            code = bugcheck.get('bugcheck_code', '').upper()
            if '0x7A' in code or '0x0000007A' in code:
                # Sprawdź czy są IO errors
                storage_issues = storage_health.get('issues', []) if storage_health else []
                io_errors = [i for i in storage_issues if 'io' in i.get('type', '').lower() or 'i/o' in i.get('message', '').lower()]
                if io_errors:
                    causes.append({
                        'category': 'Disk/FileSystem',
                        'cause': 'CORRUPTED_DISK_OR_CONTROLLER',
                        'confidence': 90.0,
                        'description': 'KERNEL_DATA_INPAGE_ERROR (0x7A) combined with IO errors indicates corrupted disk or SATA/NVMe controller',
                        'evidence': {'bugcheck_code': code, 'io_errors': len(io_errors)},
                        'recommendation': 'Check disk health, update storage controller drivers, test with different SATA port/cable'
                    })
                    break
    
    # Disk read/write errors w logach → prawdopodobna awaria dysku fizycznego
    if storage_health:
        issues = storage_health.get('issues', [])
        disk_errors = [i for i in issues if 'read error' in i.get('message', '').lower() or 'write error' in i.get('message', '').lower()]
        if disk_errors:
            causes.append({
                'category': 'Disk/FileSystem',
                'cause': 'PHYSICAL_DISK_FAILURE_LIKELY',
                'confidence': 75.0,
                'description': 'Disk read/write errors in logs indicate probable physical disk failure',
                'evidence': {'disk_errors': len(disk_errors)},
                'recommendation': 'Backup data immediately, check SMART status, replace disk if necessary'
            })
    
    return causes

def detect_bsod_critical_causes(processed_data, collected_data):
    """Wykrywa przyczyny związane z BSOD i krytycznymi błędami systemowymi."""
    causes = []
    
    # EventID 41 (Kernel-Power) + brak logów przed BSOD → niespodziewane wyłączenie
    bsod_data = collected_data.get('collectors', {}).get('bsod_dumps', {})
    system_logs = processed_data.get('system_logs', {})
    
    if bsod_data:
        recent_crashes = bsod_data.get('recent_crashes', [])
        for crash in recent_crashes:
            event_id = str(crash.get('event_id', ''))
            if event_id == '41':
                # Sprawdź czy są logi przed BSOD
                logs_before = system_logs.get('data', {})
                has_logs_before = any(len(logs) > 0 for logs in logs_before.values() if isinstance(logs, list))
                
                if not has_logs_before:
                    causes.append({
                        'category': 'BSOD/Critical',
                        'cause': 'UNEXPECTED_SHUTDOWN_NO_LOGS',
                        'confidence': 70.0,
                        'description': 'EventID 41 (Kernel-Power) with no logs before BSOD indicates unexpected shutdown, power loss or critical system error',
                        'evidence': {'event_id': event_id, 'has_logs_before': False},
                        'recommendation': 'Check power supply, verify system stability, check for hardware failures'
                    })
    
    # WHEA-Logger EventID 18, 19, 20 → awaria sprzętowa
    if bsod_data:
        whea_errors = bsod_data.get('whea_errors', [])
        if whea_errors:
            whea_event_ids = [str(e.get('event_id', '')) for e in whea_errors]
            if any(eid in ['18', '19', '20'] for eid in whea_event_ids):
                causes.append({
                    'category': 'BSOD/Critical',
                    'cause': 'HARDWARE_FAILURE_WHEA',
                    'confidence': 95.0,
                    'description': 'WHEA-Logger EventID 18, 19, 20 indicate hardware failure (CPU, RAM or motherboard)',
                    'evidence': {'whea_event_ids': whea_event_ids, 'count': len(whea_errors)},
                    'recommendation': 'Run hardware diagnostics, check CPU/RAM/motherboard, update BIOS, check for overheating'
                })
    
    # BugCheck 0x1E → krytyczny błąd sterownika lub pamięci
    if bsod_data:
        bugchecks = bsod_data.get('bugchecks', [])
        for bugcheck in bugchecks:
            code = bugcheck.get('bugcheck_code', '').upper()
            if '0x1E' in code or '0x0000001E' in code:
                causes.append({
                    'category': 'BSOD/Critical',
                    'cause': 'CRITICAL_DRIVER_OR_MEMORY_ERROR',
                    'confidence': 85.0,
                    'description': 'BugCheck 0x1E (KMODE_EXCEPTION_NOT_HANDLED) indicates critical driver or memory error',
                    'evidence': {'bugcheck_code': code, 'driver': bugcheck.get('crashed_driver', 'Unknown')},
                    'recommendation': 'Update or reinstall problematic driver, test RAM with MemTest86, check for driver conflicts'
                })
                break
    
    # BugCheck 0x50 → uszkodzona pamięć RAM lub niepoprawny sterownik
    if bsod_data:
        bugchecks = bsod_data.get('bugchecks', [])
        for bugcheck in bugchecks:
            code = bugcheck.get('bugcheck_code', '').upper()
            if '0x50' in code or '0x00000050' in code:
                causes.append({
                    'category': 'BSOD/Critical',
                    'cause': 'CORRUPTED_RAM_OR_DRIVER',
                    'confidence': 80.0,
                    'description': 'BugCheck 0x50 (PAGE_FAULT_IN_NONPAGED_AREA) indicates corrupted RAM or incorrect driver',
                    'evidence': {'bugcheck_code': code},
                    'recommendation': 'Test RAM with Windows Memory Diagnostic or MemTest86, update drivers, check for memory leaks'
                })
                break
    
    # BugCheck 0x7F → awaria CPU lub RAM
    if bsod_data:
        bugchecks = bsod_data.get('bugchecks', [])
        for bugcheck in bugchecks:
            code = bugcheck.get('bugcheck_code', '').upper()
            if '0x7F' in code or '0x0000007F' in code:
                causes.append({
                    'category': 'BSOD/Critical',
                    'cause': 'CPU_OR_RAM_FAILURE',
                    'confidence': 85.0,
                    'description': 'BugCheck 0x7F (UNEXPECTED_KERNEL_MODE_TRAP) most commonly indicates CPU or RAM failure',
                    'evidence': {'bugcheck_code': code},
                    'recommendation': 'Test CPU and RAM, check for overheating, update BIOS, run hardware diagnostics'
                })
                break
    
    # BugCheck 0x124 → poważna awaria CPU, RAM lub chipsetu
    if bsod_data:
        bugchecks = bsod_data.get('bugchecks', [])
        for bugcheck in bugchecks:
            code = bugcheck.get('bugcheck_code', '').upper()
            if '0x124' in code or '0x00000124' in code:
                causes.append({
                    'category': 'BSOD/Critical',
                    'cause': 'SEVERE_CPU_RAM_CHIPSET_FAILURE',
                    'confidence': 95.0,
                    'description': 'BugCheck 0x124 (WHEA_UNCORRECTABLE_ERROR) indicates severe CPU, RAM or chipset failure',
                    'evidence': {'bugcheck_code': code},
                    'recommendation': 'Immediate hardware diagnostics required, check CPU/RAM/chipset, update BIOS, check for overheating'
                })
                break
    
    # BSOD przy wysokim obciążeniu CPU/RAM → awaria sprzętowa
    hardware_data = collected_data.get('collectors', {}).get('hardware', {})
    if bsod_data and hardware_data:
        cpu_usage = hardware_data.get('cpu', {}).get('usage_percent', 0)
        ram_usage = hardware_data.get('ram', {}).get('percent', 0)
        if (cpu_usage > 80 or ram_usage > 80) and (bsod_data.get('bugchecks') or bsod_data.get('recent_crashes')):
            causes.append({
                'category': 'BSOD/Critical',
                'cause': 'HARDWARE_FAILURE_UNDER_LOAD',
                'confidence': 70.0,
                'description': 'BSOD occurs under high CPU/RAM load indicates hardware failure',
                'evidence': {'cpu_usage': cpu_usage, 'ram_usage': ram_usage},
                'recommendation': 'Stress test CPU and RAM, check for overheating, verify power supply capacity'
            })
    
    return causes

def detect_driver_app_causes(processed_data, collected_data):
    """Wykrywa przyczyny związane ze sterownikami i aplikacjami."""
    causes = []
    
    # Driver failed to load → sterownik uszkodzony lub niekompatybilny
    drivers_data = processed_data.get('drivers', {})
    if drivers_data:
        issues = drivers_data.get('issues', [])
        for issue in issues:
            message = issue.get('message', '').lower()
            if 'failed to load' in message or 'driver failed' in message:
                causes.append({
                    'category': 'Drivers/Apps',
                    'cause': 'CORRUPTED_OR_INCOMPATIBLE_DRIVER',
                    'confidence': 75.0,
                    'description': 'Driver failed to load indicates corrupted or incompatible driver',
                    'evidence': {'message': issue.get('message', '')[:200]},
                    'recommendation': 'Reinstall or update driver, check for driver conflicts, verify driver compatibility'
                })
                break
    
    # .NET application fails → brak lub nieaktualna wersja .NET Framework
    system_logs = processed_data.get('system_logs', {})
    if system_logs:
        issues = system_logs.get('issues', [])
        for issue in issues:
            message = issue.get('message', '').lower()
            if '.net' in message and ('fail' in message or 'error' in message or 'missing' in message):
                causes.append({
                    'category': 'Drivers/Apps',
                    'cause': 'MISSING_OR_OUTDATED_NET_FRAMEWORK',
                    'confidence': 70.0,
                    'description': '.NET application failure indicates missing or outdated .NET Framework',
                    'evidence': {'message': issue.get('message', '')[:200]},
                    'recommendation': 'Install or update .NET Framework, check application requirements'
                })
                break
    
    # Sterownik powoduje BugCheck → awaria lub konflikt sterownika
    bsod_data = collected_data.get('collectors', {}).get('bsod_dumps', {})
    if bsod_data:
        bugchecks = bsod_data.get('bugchecks', [])
        for bugcheck in bugchecks:
            crashed_driver = bugcheck.get('crashed_driver')
            if crashed_driver and crashed_driver.lower() not in ['ntoskrnl.exe', 'hal.dll', 'unknown']:
                causes.append({
                    'category': 'Drivers/Apps',
                    'cause': 'DRIVER_CAUSING_BUGCHECK',
                    'confidence': 90.0,
                    'description': f'Driver {crashed_driver} caused BugCheck - indicates driver failure or conflict',
                    'evidence': {'driver': crashed_driver, 'bugcheck_code': bugcheck.get('bugcheck_code', '')},
                    'recommendation': f'Update or reinstall {crashed_driver}, check for driver conflicts, rollback to previous version'
                })
                break
    
    # Nieudana instalacja sterownika → konflikt lub brak zgodności
    if system_logs:
        issues = system_logs.get('issues', [])
        for issue in issues:
            message = issue.get('message', '').lower()
            if 'driver' in message and 'install' in message and ('fail' in message or 'error' in message):
                causes.append({
                    'category': 'Drivers/Apps',
                    'cause': 'DRIVER_INSTALLATION_FAILURE',
                    'confidence': 65.0,
                    'description': 'Driver installation failure indicates conflict or incompatibility',
                    'evidence': {'message': issue.get('message', '')[:200]},
                    'recommendation': 'Check driver compatibility, remove conflicting drivers, verify system requirements'
                })
                break
    
    return causes

def detect_memory_causes(processed_data, collected_data):
    """Wykrywa przyczyny związane z pamięcią RAM."""
    causes = []
    
    # Memory parity/ECC errors + WHEA → uszkodzona pamięć RAM
    bsod_data = collected_data.get('collectors', {}).get('bsod_dumps', {})
    system_logs = processed_data.get('system_logs', {})
    
    has_whea = bool(bsod_data.get('whea_errors', []))
    if system_logs:
        issues = system_logs.get('issues', [])
        memory_errors = [i for i in issues if 'memory' in i.get('message', '').lower() and ('parity' in i.get('message', '').lower() or 'ecc' in i.get('message', '').lower())]
        if memory_errors and has_whea:
            causes.append({
                'category': 'Memory',
                'cause': 'CORRUPTED_RAM_WITH_WHEA',
                'confidence': 95.0,
                'description': 'Memory parity/ECC errors combined with WHEA errors indicate corrupted RAM',
                'evidence': {'memory_errors': len(memory_errors), 'whea_errors': True},
                'recommendation': 'Test RAM with MemTest86, replace faulty RAM modules, check RAM slots'
            })
    
    # BSOD z BugCheck 0x1E lub 0x50 przy testach pamięci → uszkodzona pamięć RAM
    if bsod_data:
        bugchecks = bsod_data.get('bugchecks', [])
        for bugcheck in bugchecks:
            code = bugcheck.get('bugcheck_code', '').upper()
            if '0x1E' in code or '0x50' in code or '0x0000001E' in code or '0x00000050' in code:
                causes.append({
                    'category': 'Memory',
                    'cause': 'CORRUPTED_RAM_BUGCHECK',
                    'confidence': 80.0,
                    'description': 'BugCheck 0x1E or 0x50 during memory tests indicates corrupted RAM',
                    'evidence': {'bugcheck_code': code},
                    'recommendation': 'Run Windows Memory Diagnostic or MemTest86, replace faulty RAM modules'
                })
                break
    
    return causes

def detect_network_upnp_causes(processed_data, collected_data):
    """Wykrywa przyczyny związane z siecią i UPnP."""
    causes = []
    
    # Konflikty UPnP + network warnings → problem z usługą Windows Network/UPnP
    system_logs = processed_data.get('system_logs', {})
    if system_logs:
        issues = system_logs.get('issues', [])
        warnings = system_logs.get('warnings', [])
        
        upnp_errors = [i for i in issues + warnings if 'upnp' in i.get('message', '').lower()]
        network_warnings = [i for i in warnings if 'network' in i.get('type', '').lower() or 'network' in i.get('message', '').lower()]
        
        if upnp_errors and network_warnings:
            causes.append({
                'category': 'Network/UPnP',
                'cause': 'UPNP_SERVICE_CONFLICT',
                'confidence': 60.0,
                'description': 'UPnP conflicts combined with network warnings indicate Windows Network/UPnP service problem',
                'evidence': {'upnp_errors': len(upnp_errors), 'network_warnings': len(network_warnings)},
                'recommendation': 'Restart UPnP service, check network adapter settings, update network drivers'
            })
    
    # DNS resolution fails + EventID network errors → problem konfiguracji lub sterownika sieciowego
    if system_logs:
        issues = system_logs.get('issues', [])
        dns_errors = [i for i in issues if 'dns' in i.get('message', '').lower() and ('fail' in i.get('message', '').lower() or 'error' in i.get('message', '').lower())]
        network_event_errors = [i for i in issues if 'network' in i.get('message', '').lower() and i.get('event_id')]
        
        if dns_errors and network_event_errors:
            causes.append({
                'category': 'Network/UPnP',
                'cause': 'DNS_OR_NETWORK_DRIVER_ISSUE',
                'confidence': 65.0,
                'description': 'DNS resolution failures combined with network EventID errors indicate configuration or network driver problem',
                'evidence': {'dns_errors': len(dns_errors), 'network_errors': len(network_event_errors)},
                'recommendation': 'Check DNS settings, update network adapter drivers, verify network configuration'
            })
    
    # NIC driver fails to load → sterownik sieciowy uszkodzony lub niekompatybilny
    drivers_data = processed_data.get('drivers', {})
    if drivers_data:
        issues = drivers_data.get('issues', [])
        for issue in issues:
            message = issue.get('message', '').lower()
            if ('nic' in message or 'network' in message or 'ethernet' in message) and 'fail' in message:
                causes.append({
                    'category': 'Network/UPnP',
                    'cause': 'CORRUPTED_NETWORK_DRIVER',
                    'confidence': 75.0,
                    'description': 'NIC driver failed to load indicates corrupted or incompatible network driver',
                    'evidence': {'message': issue.get('message', '')[:200]},
                    'recommendation': 'Reinstall network adapter driver, check for driver conflicts, verify compatibility'
                })
                break
    
    return causes

def detect_cpu_thermal_causes(processed_data, collected_data):
    """Wykrywa przyczyny związane z procesorem i temperaturą."""
    causes = []
    
    # CPU Thermal Trip / Overheat events → przegrzewanie CPU
    hardware_data = collected_data.get('collectors', {}).get('hardware', {})
    system_logs = processed_data.get('system_logs', {})
    
    if hardware_data:
        sensors = hardware_data.get('sensors', {})
        cpu_temp = sensors.get('cpu_temp', '')
        
        # Sprawdź czy temperatura jest zbyt wysoka (jeśli dostępna jako liczba)
        try:
            if isinstance(cpu_temp, (int, float)) and cpu_temp > 80:
                causes.append({
                    'category': 'CPU/Thermal',
                    'cause': 'CPU_OVERHEATING',
                    'confidence': 85.0,
                    'description': f'CPU temperature {cpu_temp}°C indicates overheating',
                    'evidence': {'cpu_temp': cpu_temp},
                    'recommendation': 'Check CPU cooler, clean dust, reapply thermal paste, verify fan operation'
                })
        except:
            pass
    
    # CPU throttling z powodu temperatury → niedostateczne chłodzenie
    if system_logs:
        issues = system_logs.get('issues', [])
        for issue in issues:
            message = issue.get('message', '').lower()
            if 'throttl' in message and ('thermal' in message or 'temperature' in message or 'cpu' in message):
                causes.append({
                    'category': 'CPU/Thermal',
                    'cause': 'INSUFFICIENT_CPU_COOLING',
                    'confidence': 80.0,
                    'description': 'CPU throttling due to temperature indicates insufficient cooling',
                    'evidence': {'message': issue.get('message', '')[:200]},
                    'recommendation': 'Improve CPU cooling, check thermal paste, verify cooler installation, clean system'
                })
                break
    
    # BSOD przy wysokim obciążeniu CPU → możliwe uszkodzenie CPU
    bsod_data = collected_data.get('collectors', {}).get('bsod_dumps', {})
    if bsod_data and hardware_data:
        cpu_usage = hardware_data.get('cpu', {}).get('usage_percent', 0)
        if cpu_usage > 90 and (bsod_data.get('bugchecks') or bsod_data.get('recent_crashes')):
            causes.append({
                'category': 'CPU/Thermal',
                'cause': 'POSSIBLE_CPU_DAMAGE',
                'confidence': 70.0,
                'description': 'BSOD under high CPU load may indicate CPU damage',
                'evidence': {'cpu_usage': cpu_usage},
                'recommendation': 'Stress test CPU, check for overheating, verify CPU stability, consider CPU replacement'
            })
    
    return causes

def detect_power_causes(processed_data, collected_data):
    """Wykrywa przyczyny związane z zasilaniem."""
    causes = []
    
    # EventID 41 (Kernel-Power) + częste restartowanie → niestabilne zasilanie lub uszkodzony PSU
    bsod_data = collected_data.get('collectors', {}).get('bsod_dumps', {})
    if bsod_data:
        recent_crashes = bsod_data.get('recent_crashes', [])
        kernel_power_41 = [c for c in recent_crashes if str(c.get('event_id', '')) == '41']
        
        if len(kernel_power_41) >= 2:  # Częste restartowanie
            causes.append({
                'category': 'Power',
                'cause': 'UNSTABLE_POWER_OR_PSU_FAILURE',
                'confidence': 80.0,
                'description': 'EventID 41 (Kernel-Power) with frequent restarts indicates unstable power or PSU failure',
                'evidence': {'kernel_power_events': len(kernel_power_41)},
                'recommendation': 'Check power supply, verify power connections, test with different PSU, check for power surges'
            })
    
    # Voltage fluctuations w logach WHEA → problem z PSU lub płytą główną
    if bsod_data:
        whea_errors = bsod_data.get('whea_errors', [])
        for error in whea_errors:
            message = error.get('message', '').lower()
            if 'voltage' in message or 'power' in message:
                causes.append({
                    'category': 'Power',
                    'cause': 'PSU_OR_MOTHERBOARD_POWER_ISSUE',
                    'confidence': 75.0,
                    'description': 'Voltage fluctuations in WHEA logs indicate PSU or motherboard power problem',
                    'evidence': {'message': error.get('message', '')[:200]},
                    'recommendation': 'Check PSU voltage output, verify motherboard power delivery, test with different PSU'
                })
                break
    
    # Nagłe wyłączenia przy wysokim poborze mocy → awaria zasilacza
    hardware_data = collected_data.get('collectors', {}).get('hardware', {})
    if bsod_data and hardware_data:
        cpu_usage = hardware_data.get('cpu', {}).get('usage_percent', 0)
        if cpu_usage > 80 and bsod_data.get('recent_crashes'):
            causes.append({
                'category': 'Power',
                'cause': 'PSU_FAILURE_UNDER_LOAD',
                'confidence': 70.0,
                'description': 'Sudden shutdowns under high power draw indicate PSU failure',
                'evidence': {'cpu_usage': cpu_usage},
                'recommendation': 'Test PSU capacity, check power consumption, replace PSU if necessary'
            })
    
    return causes

def detect_other_critical_causes(processed_data, collected_data):
    """Wykrywa inne poważne problemy systemowe."""
    causes = []
    
    # System files missing / cannot boot → poważna korupcja systemu
    system_logs = processed_data.get('system_logs', {})
    if system_logs:
        issues = system_logs.get('issues', [])
        for issue in issues:
            message = issue.get('message', '').lower()
            if ('system file' in message or 'boot' in message) and ('missing' in message or 'cannot' in message or 'corrupt' in message):
                causes.append({
                    'category': 'System',
                    'cause': 'SEVERE_SYSTEM_CORRUPTION',
                    'confidence': 95.0,
                    'description': 'Missing system files or boot failure indicates severe system corruption',
                    'evidence': {'message': issue.get('message', '')[:200]},
                    'recommendation': 'Run DISM /Online /Cleanup-Image /RestoreHealth, sfc /scannow, consider system restore or reinstall'
                })
                break
    
    # Registry corruption + nieudane naprawy → poważna korupcja rejestru
    registry_txr = processed_data.get('registry_txr', {})
    if registry_txr:
        critical_issues = registry_txr.get('critical_issues', [])
        if len(critical_issues) >= 5:  # Wiele błędów TxR
            causes.append({
                'category': 'System',
                'cause': 'SEVERE_REGISTRY_CORRUPTION',
                'confidence': 90.0,
                'description': 'Multiple Registry TxR failures indicate severe registry corruption',
                'evidence': {'txr_failures': len(critical_issues)},
                'recommendation': 'Run registry repair tools, check disk health, consider system restore'
            })
    
    # VSS service consistently fails → problem z Volume Shadow Copy
    if system_logs:
        issues = system_logs.get('issues', [])
        vss_failures = [i for i in issues if 'vss' in i.get('message', '').lower() and 'fail' in i.get('message', '').lower()]
        if len(vss_failures) >= 3:
            causes.append({
                'category': 'System',
                'cause': 'VSS_SERVICE_FAILURE',
                'confidence': 75.0,
                'description': 'VSS service consistently fails - possible Volume Shadow Copy problem, possible disk corruption',
                'evidence': {'vss_failures': len(vss_failures)},
                'recommendation': 'Check VSS service status, verify disk integrity, check ShadowCopy repository'
            })
    
    # Repeated driver crash → sterownik powoduje awarię systemu
    drivers_data = processed_data.get('drivers', {})
    if drivers_data:
        issues = drivers_data.get('issues', [])
        driver_crashes = [i for i in issues if 'crash' in i.get('message', '').lower() or 'fail' in i.get('message', '').lower()]
        if len(driver_crashes) >= 3:
            causes.append({
                'category': 'System',
                'cause': 'REPEATED_DRIVER_CRASH',
                'confidence': 80.0,
                'description': 'Repeated driver crashes indicate driver causing system failure',
                'evidence': {'driver_crashes': len(driver_crashes)},
                'recommendation': 'Identify problematic driver, update or rollback, check for conflicts'
            })
    
    # EventID 1001 z krytycznymi błędami → poważna awaria aplikacji lub sterownika
    if system_logs:
        issues = system_logs.get('issues', [])
        event_1001 = [i for i in issues if str(i.get('event_id', '')) == '1001']
        critical_1001 = [i for i in event_1001 if i.get('severity', '').upper() in ['CRITICAL', 'ERROR']]
        if critical_1001:
            causes.append({
                'category': 'System',
                'cause': 'SEVERE_APPLICATION_OR_DRIVER_FAILURE',
                'confidence': 85.0,
                'description': 'EventID 1001 (Windows Error Reporting) with critical errors indicates severe application or driver failure',
                'evidence': {'critical_1001_events': len(critical_1001)},
                'recommendation': 'Check Windows Error Reporting logs, update problematic applications/drivers, check for conflicts'
            })
    
    # Power surge detected → awaria sprzętowa lub PSU
    if system_logs:
        issues = system_logs.get('issues', [])
        for issue in issues:
            message = issue.get('message', '').lower()
            if 'power surge' in message or 'surge' in message:
                causes.append({
                    'category': 'System',
                    'cause': 'HARDWARE_OR_PSU_FAILURE',
                    'confidence': 75.0,
                    'description': 'Power surge detected indicates hardware failure or PSU problem',
                    'evidence': {'message': issue.get('message', '')[:200]},
                    'recommendation': 'Check PSU, verify power connections, test hardware components'
                })
                break
    
    # Storage controller errors → problem z kontrolerem SATA/NVMe
    storage_health = processed_data.get('storage_health', {})
    if storage_health:
        issues = storage_health.get('issues', [])
        controller_errors = [i for i in issues if 'controller' in i.get('message', '').lower() or 'sata' in i.get('message', '').lower() or 'nvme' in i.get('message', '').lower()]
        if controller_errors:
            causes.append({
                'category': 'System',
                'cause': 'STORAGE_CONTROLLER_ISSUE',
                'confidence': 80.0,
                'description': 'Storage controller errors indicate SATA/NVMe controller problem',
                'evidence': {'controller_errors': len(controller_errors)},
                'recommendation': 'Update storage controller drivers, check controller settings, test with different port/cable'
            })
    
    # Disk SMART status critical → dysk zbliża się do awarii
    hardware_data = collected_data.get('collectors', {}).get('hardware', {})
    if hardware_data:
        disks = hardware_data.get('disks', [])
        for disk in disks:
            smart = disk.get('smart', {})
            if smart and smart.get('HealthStatus', '').upper() in ['CRITICAL', 'FAIL', 'FAILING']:
                causes.append({
                    'category': 'System',
                    'cause': 'DISK_NEAR_FAILURE',
                    'confidence': 90.0,
                    'description': f'Disk {disk.get("device", "Unknown")} SMART status critical - disk approaching failure',
                    'evidence': {'device': disk.get('device'), 'smart_status': smart.get('HealthStatus')},
                    'recommendation': 'Backup data immediately, replace disk, check SMART attributes'
                })
                break
    
    # File system corruption on multiple volumes → system niebezpiecznie niestabilny
    if storage_health:
        issues = storage_health.get('issues', [])
        corruption_errors = [i for i in issues if 'corrupt' in i.get('message', '').lower() or 'corruption' in i.get('message', '').lower()]
        if len(corruption_errors) >= 2:
            causes.append({
                'category': 'System',
                'cause': 'SYSTEM_DANGEROUSLY_UNSTABLE',
                'confidence': 95.0,
                'description': 'File system corruption detected on multiple volumes - system dangerously unstable',
                'evidence': {'corruption_errors': len(corruption_errors)},
                'recommendation': 'Immediate backup, run chkdsk on all volumes, consider system restore or reinstall'
            })
    
    # Unexpected shutdowns during disk-intensive operations → dysk lub kontroler prawdopodobnie uszkodzony
    bsod_data = collected_data.get('collectors', {}).get('bsod_dumps', {})
    if bsod_data and storage_health:
        recent_crashes = bsod_data.get('recent_crashes', [])
        io_errors = storage_health.get('issues', [])
        io_error_count = len([i for i in io_errors if 'io' in i.get('type', '').lower() or 'i/o' in i.get('message', '').lower()])
        
        if recent_crashes and io_error_count >= 2:
            causes.append({
                'category': 'System',
                'cause': 'DISK_OR_CONTROLLER_LIKELY_DAMAGED',
                'confidence': 85.0,
                'description': 'Unexpected shutdowns during disk-intensive operations indicate disk or controller likely damaged',
                'evidence': {'crashes': len(recent_crashes), 'io_errors': io_error_count},
                'recommendation': 'Test disk health, check controller, backup data, replace if necessary'
            })
    
    # Kernel-Power 41 + EventID 101 → problem z hardware lub sterownikiem
    if bsod_data and system_logs:
        recent_crashes = bsod_data.get('recent_crashes', [])
        has_kernel_power_41 = any(str(c.get('event_id', '')) == '41' for c in recent_crashes)
        
        if system_logs:
            issues = system_logs.get('issues', [])
            event_101 = [i for i in issues if str(i.get('event_id', '')) == '101']
            
            if has_kernel_power_41 and event_101:
                causes.append({
                    'category': 'System',
                    'cause': 'HARDWARE_OR_DRIVER_ISSUE',
                    'confidence': 75.0,
                    'description': 'Kernel-Power 41 combined with EventID 101 indicates hardware or driver problem',
                    'evidence': {'has_kernel_power_41': True, 'event_101_count': len(event_101)},
                    'recommendation': 'Check hardware components, update drivers, verify system stability'
                })
    
    return causes

def detect_wer_causes(processed_data, collected_data):
    """
    Wykrywa przyczyny na podstawie Windows Error Reporting (WER) - golden rules.
    
    Golden Rules:
    1. FaultingModule = ntdll.dll + EventID=1000 → crash systemowy (≥95%)
    2. Crash >=3 w 30 min dla tej samej aplikacji → prawdopodobny błąd aplikacji (≥95%)
    3. Crash w tym samym czasie co BSOD EventID=41 → prawdopodobna awaria sprzętowa (≥95%)
    """
    causes = []
    
    # DEBUG: Sprawdź collected_data
    logger.debug(f"[CAUSE_DETECTOR] DEBUG: collected_data type: {type(collected_data)}")
    logger.debug(f"[CAUSE_DETECTOR] DEBUG: collected_data is dict: {isinstance(collected_data, dict)}")
    if isinstance(collected_data, dict):
        logger.debug(f"[CAUSE_DETECTOR] DEBUG: collected_data keys: {list(collected_data.keys())}")
        if 'collectors' in collected_data:
            logger.debug(f"[CAUSE_DETECTOR] DEBUG: collected_data['collectors'] type: {type(collected_data['collectors'])}")
            if isinstance(collected_data['collectors'], dict):
                logger.debug(f"[CAUSE_DETECTOR] DEBUG: collected_data['collectors'] keys: {list(collected_data['collectors'].keys())}")
                if 'wer' in collected_data['collectors']:
                    logger.debug(f"[CAUSE_DETECTOR] DEBUG: collected_data['collectors']['wer'] type: {type(collected_data['collectors']['wer'])}")
    
    wer_data = collected_data.get('collectors', {}).get('wer', {})
    
    # ZABEZPIECZENIE: Upewnij się, że wer_data jest bezpieczny
    if not isinstance(wer_data, dict):
        logger.warning(f"[CAUSE_DETECTOR] WER data is not a dict: {type(wer_data)}")
        return causes
    
    # DEBUG: Sprawdź wer_data (tylko podstawowe info)
    logger.debug(f"[CAUSE_DETECTOR] DEBUG: wer_data type: {type(wer_data)}")
    logger.debug(f"[CAUSE_DETECTOR] DEBUG: wer_data is dict: {isinstance(wer_data, dict)}")
    logger.debug(f"[CAUSE_DETECTOR] DEBUG: wer_data empty: {not wer_data}")
    
    if not wer_data:
        logger.debug("[CAUSE_DETECTOR] DEBUG: wer_data is empty, returning empty causes")
        return causes
    
    logger.debug(f"[CAUSE_DETECTOR] DEBUG: wer_data keys: {list(wer_data.keys())}")
    
    # Bezpieczne pobranie recent_crashes i grouped_crashes
    recent_crashes = wer_data.get('recent_crashes', [])
    grouped_crashes = wer_data.get('grouped_crashes', [])
    
    # KRYTYCZNE ZABEZPIECZENIE: grouped_crashes MUSI być listą (konsumenci iterują po niej, NIE używają .get())
    # Jeśli jest dict, to błąd - konwertuj na listę
    if isinstance(grouped_crashes, dict):
        logger.error(f"[CAUSE_DETECTOR] CRITICAL: grouped_crashes is dict (keys: {list(grouped_crashes.keys())[:5]}) instead of list! Converting...")
        grouped_crashes = [grouped_crashes] if grouped_crashes else []
    elif not isinstance(grouped_crashes, list):
        logger.warning(f"[CAUSE_DETECTOR] grouped_crashes is not a list: {type(grouped_crashes)}, converting...")
        grouped_crashes = [grouped_crashes] if grouped_crashes is not None else []
    
    # ZABEZPIECZENIE: Upewnij się, że recent_crashes jest listą
    if not isinstance(recent_crashes, list):
        logger.warning(f"[CAUSE_DETECTOR] recent_crashes is not a list: {type(recent_crashes)}, converting...")
        recent_crashes = [recent_crashes] if recent_crashes is not None else []
    
    # DEBUG: Sprawdź typy po konwersji
    logger.debug(f"[CAUSE_DETECTOR] DEBUG: recent_crashes type: {type(recent_crashes)}, is_list: {isinstance(recent_crashes, list)}")
    logger.debug(f"[CAUSE_DETECTOR] DEBUG: grouped_crashes type: {type(grouped_crashes)}, is_list: {isinstance(grouped_crashes, list)}, length: {len(grouped_crashes) if isinstance(grouped_crashes, list) else 'N/A'}")
    
    # DEBUG: Sprawdź typy po konwersji
    logger.debug(f"[CAUSE_DETECTOR] DEBUG: After conversion - recent_crashes type: {type(recent_crashes)}, length: {len(recent_crashes) if isinstance(recent_crashes, list) else 'N/A'}")
    logger.debug(f"[CAUSE_DETECTOR] DEBUG: After conversion - grouped_crashes type: {type(grouped_crashes)}, length: {len(grouped_crashes) if isinstance(grouped_crashes, list) else 'N/A'}")
    
    bsod_data = collected_data.get('collectors', {}).get('bsod_dumps', {})
    
    # Golden Rule 1: FaultingModule = ntdll.dll + EventID=1000 → crash systemowy (≥95%)
    try:
        # ZABEZPIECZENIE: Upewnij się, że recent_crashes jest iterowalne
        if not isinstance(recent_crashes, (list, tuple)):
            logger.error(f"[CAUSE_DETECTOR] CRITICAL: recent_crashes is not iterable! Type: {type(recent_crashes)}")
            log_error_with_analysis(
                TypeError(f"recent_crashes is not iterable: {type(recent_crashes)}"),
                recent_crashes,
                {
                    'variable_name': 'recent_crashes',
                    'location': 'cause_detector.py:834',
                    'function': 'detect_wer_causes'
                },
                continue_execution=True
            )
        else:
            for idx, crash in enumerate(recent_crashes):
                # ZABEZPIECZENIE: Upewnij się, że crash jest dict
                if not isinstance(crash, dict):
                    logger.warning(f"[CAUSE_DETECTOR] Crash[{idx}] is not a dict: {type(crash)}")
                    log_error_with_analysis(
                        TypeError(f"Crash[{idx}] is not a dict: {type(crash)}"),
                        crash,
                        {
                            'variable_name': f'recent_crashes[{idx}]',
                            'location': 'cause_detector.py:837',
                            'function': 'detect_wer_causes'
                        },
                        continue_execution=True
                    )
                    continue
                
                try:
                    event_id = str(safe_get_with_analysis(crash, 'event_id', '', {
                        'variable_name': f'crash[{idx}].event_id',
                        'location': 'cause_detector.py:841'
                    }))
                    module_name = (str(safe_get_with_analysis(crash, 'module_name', '', {
                        'variable_name': f'crash[{idx}].module_name',
                        'location': 'cause_detector.py:842'
                    })) or '').lower()
                    app_name = (str(safe_get_with_analysis(crash, 'application', '', {
                        'variable_name': f'crash[{idx}].application',
                        'location': 'cause_detector.py:843'
                    })) or '').lower()
                    
                    if event_id == '1000' and 'ntdll.dll' in module_name:
                        causes.append({
                            'category': 'System',
                            'cause': 'SYSTEM_CRASH_NTDLL',
                            'confidence': 95.0,
                            'description': f'System crash detected: FaultingModule=ntdll.dll with EventID=1000. Application: {app_name}',
                            'evidence': {
                                'event_id': event_id,
                                'module_name': safe_get_with_analysis(crash, 'module_name', '', {
                                    'variable_name': f'crash[{idx}].module_name',
                                    'location': 'cause_detector.py:853'
                                }),
                                'application': safe_get_with_analysis(crash, 'application', '', {
                                    'variable_name': f'crash[{idx}].application',
                                    'location': 'cause_detector.py:854'
                                }),
                                'exception_code': safe_get_with_analysis(crash, 'exception_code', '', {
                                    'variable_name': f'crash[{idx}].exception_code',
                                    'location': 'cause_detector.py:855'
                                }),
                                'timestamp': safe_get_with_analysis(crash, 'timestamp', '', {
                                    'variable_name': f'crash[{idx}].timestamp',
                                    'location': 'cause_detector.py:856'
                                })
                            },
                            'recommendation': 'System crash indicates serious system instability. Check for hardware failures, update drivers, run system file checker (sfc /scannow), check for malware'
                        })
                        break  # Tylko jeden raz
                except Exception as e:
                    # Kompleksowa analiza błędu z kontynuacją wykonania
                    log_error_with_analysis(
                        e,
                        crash,
                        {
                            'variable_name': f'recent_crashes[{idx}]',
                            'location': 'cause_detector.py:861',
                            'function': 'detect_wer_causes'
                        },
                        continue_execution=True
                    )
                    continue
    except Exception as e:
        # Kompleksowa analiza błędu na poziomie iteracji
        log_error_with_analysis(
            e,
            recent_crashes,
            {
                'variable_name': 'recent_crashes',
                'location': 'cause_detector.py:834',
                'function': 'detect_wer_causes'
            },
            continue_execution=True
        )
    
    # Golden Rule 2: Crash >=3 w 30 min dla tej samej aplikacji → prawdopodobny błąd aplikacji (≥95%)
    for group in grouped_crashes:
        # ZABEZPIECZENIE: Upewnij się, że group jest dict
        if not isinstance(group, dict):
            logger.debug(f"[CAUSE_DETECTOR] Skipping non-dict group: {type(group)}")
            continue
        
        try:
            is_repeating = group.get('is_repeating', False)
            occurrences_30min = group.get('occurrences_30min', 0)
            
            # Upewnij się, że wartości są poprawnego typu
            if not isinstance(is_repeating, bool):
                is_repeating = False
            if not isinstance(occurrences_30min, (int, float)):
                occurrences_30min = 0
            
            if is_repeating and occurrences_30min >= 3:
                app = str(group.get('application', 'Unknown'))[:200]  # Ogranicz długość
                module = str(group.get('module_name', ''))[:200]  # Ogranicz długość
                exception = str(group.get('exception_code', ''))[:100]  # Ogranicz długość
                
                causes.append({
                    'category': 'Application',
                    'cause': 'REPEATING_APPLICATION_CRASH',
                    'confidence': 95.0,
                    'description': f'Repeating application crash: {app} crashed {occurrences_30min} times in last 30 minutes. Faulting module: {module}, Exception: {exception}',
                    'evidence': {
                        'application': app,
                        'module_name': module,
                        'exception_code': exception,
                        'occurrences_30min': occurrences_30min,
                        'occurrences_24h': group.get('occurrences_24h', 0),
                        'first_occurrence': str(group.get('first_occurrence', ''))[:100],
                        'last_occurrence': str(group.get('last_occurrence', ''))[:100]
                    },
                    'recommendation': f'Application {app} is repeatedly crashing. Update the application, check for compatibility issues, reinstall if necessary, check for corrupted files or dependencies'
                })
        except Exception as e:
            logger.warning(f"[CAUSE_DETECTOR] Error processing group in Golden Rule 2: {e}")
            continue
    
    # Golden Rule 3: Crash w tym samym czasie co BSOD EventID=41 → prawdopodobna awaria sprzętowa (≥95%)
    try:
        if bsod_data:
            recent_crashes_bsod = safe_get_with_analysis(
                bsod_data, 'recent_crashes', [],
                context={
                    'variable_name': 'bsod_data.recent_crashes',
                    'location': 'cause_detector.py:903',
                    'function': 'detect_wer_causes'
                }
            )
            
            # Upewnij się, że recent_crashes_bsod jest listą
            if not isinstance(recent_crashes_bsod, list):
                logger.warning(f"[CAUSE_DETECTOR] recent_crashes_bsod is not a list: {type(recent_crashes_bsod)}")
                recent_crashes_bsod = []
            
            # Znajdź BSOD EventID 41
            bsod_41_times = []
            for idx, bsod in enumerate(recent_crashes_bsod):
                try:
                    if not isinstance(bsod, dict):
                        logger.debug(f"[CAUSE_DETECTOR] BSOD[{idx}] is not a dict: {type(bsod)}")
                        continue
                    
                    event_id = str(safe_get_with_analysis(bsod, 'event_id', '', {
                        'variable_name': f'bsod[{idx}].event_id',
                        'location': 'cause_detector.py:909'
                    }))
                    if event_id == '41':
                        timestamp = safe_get_with_analysis(bsod, 'timestamp', '', {
                            'variable_name': f'bsod[{idx}].timestamp',
                            'location': 'cause_detector.py:910'
                        })
                        bsod_time = parse_bsod_timestamp(timestamp)
                        if bsod_time:
                            bsod_41_times.append(bsod_time)
                except Exception as e:
                    log_error_with_analysis(
                        e,
                        bsod,
                        {
                            'variable_name': f'recent_crashes_bsod[{idx}]',
                            'location': 'cause_detector.py:908',
                            'function': 'detect_wer_causes'
                        },
                        continue_execution=True
                    )
                    continue
            
            # Sprawdź czy crashy systemowe wystąpiły w tym samym czasie (±5 minut)
            if bsod_41_times:
                for idx, crash in enumerate(recent_crashes):
                    try:
                        if not isinstance(crash, dict):
                            logger.debug(f"[CAUSE_DETECTOR] Crash[{idx}] is not a dict: {type(crash)}")
                            continue
                        
                        crash_type = str(safe_get_with_analysis(crash, 'type', '', {
                            'variable_name': f'crash[{idx}].type',
                            'location': 'cause_detector.py:916'
                        }))
                        timestamp = safe_get_with_analysis(crash, 'timestamp', '', {
                            'variable_name': f'crash[{idx}].timestamp',
                            'location': 'cause_detector.py:917'
                        })
                        crash_time = parse_wer_timestamp(timestamp)
                        
                        if crash_type == 'SYSTEM_CRASH' and crash_time:
                            # Sprawdź czy crash jest w oknie ±5 minut od BSOD
                            for bsod_time in bsod_41_times:
                                time_diff = abs((crash_time - bsod_time).total_seconds())
                                if time_diff <= 300:  # 5 minut
                                    app = str(safe_get_with_analysis(crash, 'application', 'Unknown', {
                                        'variable_name': f'crash[{idx}].application',
                                        'location': 'cause_detector.py:980'
                                    }))
                                    module = str(safe_get_with_analysis(crash, 'module_name', '', {
                                        'variable_name': f'crash[{idx}].module_name',
                                        'location': 'cause_detector.py:981'
                                    }))
                                    
                                    causes.append({
                                        'category': 'Hardware',
                                        'cause': 'HARDWARE_FAILURE_WER_BSOD_CORRELATION',
                                        'confidence': 95.0,
                                        'description': f'System crash ({app}) occurred at the same time as BSOD EventID 41, indicating probable hardware failure',
                                        'evidence': {
                                            'system_crash': {
                                                'application': app,
                                                'module_name': module,
                                                'exception_code': safe_get_with_analysis(crash, 'exception_code', '', {
                                                    'variable_name': f'crash[{idx}].exception_code',
                                                    'location': 'cause_detector.py:992'
                                                }),
                                                'timestamp': safe_get_with_analysis(crash, 'timestamp', '', {
                                                    'variable_name': f'crash[{idx}].timestamp',
                                                    'location': 'cause_detector.py:993'
                                                })
                                            },
                                            'bsod_timestamp': bsod_time.isoformat() if hasattr(bsod_time, 'isoformat') else str(bsod_time),
                                            'time_difference_seconds': time_diff
                                        },
                                        'recommendation': 'System crash correlated with BSOD indicates hardware failure. Check CPU, RAM, motherboard, power supply. Run hardware diagnostics, check temperatures, verify all connections'
                                    })
                                    break  # Tylko jeden raz
                    except Exception as e:
                        log_error_with_analysis(
                            e,
                            crash,
                            {
                                'variable_name': f'recent_crashes[{idx}]',
                                'location': 'cause_detector.py:1028',
                                'function': 'detect_wer_causes'
                            },
                            continue_execution=True
                        )
                        continue
    except Exception as e:
        # Kompleksowa analiza błędu na poziomie Golden Rule 3
        log_error_with_analysis(
            e,
            bsod_data if 'bsod_data' in locals() else None,
            {
                'variable_name': 'bsod_data',
                'location': 'cause_detector.py:976',
                'function': 'detect_wer_causes'
            },
            continue_execution=True
        )
    
    # Dodatkowa reguła: Systemowe procesy (winlogon.exe, csrss.exe) crashują + WHEA → hardware failure
    try:
        if bsod_data and isinstance(bsod_data, dict):
            whea_errors = safe_get_with_analysis(
                bsod_data, 'whea_errors', [],
                context={
                    'variable_name': 'bsod_data.whea_errors',
                    'location': 'cause_detector.py:1108',
                    'function': 'detect_wer_causes'
                }
            )
            
            # Upewnij się, że whea_errors jest listą
            if not isinstance(whea_errors, list):
                logger.warning(f"[CAUSE_DETECTOR] whea_errors is not a list: {type(whea_errors)}")
                whea_errors = []
            
            if whea_errors:
                system_processes = ['winlogon.exe', 'csrss.exe', 'lsass.exe']
                for idx, crash in enumerate(recent_crashes):
                    try:
                        if not isinstance(crash, dict):
                            logger.debug(f"[CAUSE_DETECTOR] Crash[{idx}] is not a dict: {type(crash)}")
                            continue
                        
                        app = (str(safe_get_with_analysis(crash, 'application', '', {
                            'variable_name': f'crash[{idx}].application',
                            'location': 'cause_detector.py:1112'
                        })) or '').lower()
                        
                        if any(proc in app for proc in system_processes):
                            timestamp = safe_get_with_analysis(crash, 'timestamp', '', {
                                'variable_name': f'crash[{idx}].timestamp',
                                'location': 'cause_detector.py:1114'
                            })
                            crash_time = parse_wer_timestamp(timestamp)
                            if crash_time:
                                # Sprawdź czy WHEA error jest w oknie ±10 minut
                                for whea_idx, whea in enumerate(whea_errors):
                                    try:
                                        if not isinstance(whea, dict):
                                            logger.debug(f"[CAUSE_DETECTOR] WHEA[{whea_idx}] is not a dict: {type(whea)}")
                                            continue
                                        
                                        whea_timestamp = safe_get_with_analysis(whea, 'timestamp', '', {
                                            'variable_name': f'whea[{whea_idx}].timestamp',
                                            'location': 'cause_detector.py:1118'
                                        })
                                        whea_time = parse_bsod_timestamp(whea_timestamp)
                                        if whea_time:
                                            time_diff = abs((crash_time - whea_time).total_seconds())
                                            if time_diff <= 600:  # 10 minut
                                                whea_message = str(safe_get_with_analysis(whea, 'message', '', {
                                                    'variable_name': f'whea[{whea_idx}].message',
                                                    'location': 'cause_detector.py:1129'
                                                }))[:200]
                                                
                                                causes.append({
                                                    'category': 'Hardware',
                                                    'cause': 'HARDWARE_FAILURE_SYSTEM_CRASH_WHEA',
                                                    'confidence': 95.0,
                                                    'description': f'System process ({app}) crash correlated with WHEA hardware error, indicating hardware failure',
                                                    'evidence': {
                                                        'system_process': app,
                                                        'whea_error': whea_message,
                                                        'time_difference_seconds': time_diff
                                                    },
                                                    'recommendation': 'System process crash with WHEA error indicates severe hardware failure. Check CPU, RAM, motherboard, run hardware diagnostics immediately'
                                                })
                                                break  # Tylko jeden raz
                                    except Exception as e:
                                        log_error_with_analysis(
                                            e,
                                            whea,
                                            {
                                                'variable_name': f'whea_errors[{whea_idx}]',
                                                'location': 'cause_detector.py:1145',
                                                'function': 'detect_wer_causes'
                                            },
                                            continue_execution=True
                                        )
                                        continue
                    except Exception as e:
                        log_error_with_analysis(
                            e,
                            crash,
                            {
                                'variable_name': f'recent_crashes[{idx}]',
                                'location': 'cause_detector.py:1126',
                                'function': 'detect_wer_causes'
                            },
                            continue_execution=True
                        )
                        continue
    except Exception as e:
        # Kompleksowa analiza błędu na poziomie dodatkowej reguły
        log_error_with_analysis(
            e,
            bsod_data if 'bsod_data' in locals() else None,
            {
                'variable_name': 'bsod_data',
                'location': 'cause_detector.py:1107',
                'function': 'detect_wer_causes'
            },
            continue_execution=True
        )
    
    logger.info(f"[CAUSE_DETECTOR] WER golden rules detected {len(causes)} causes")
    return causes


def parse_wer_timestamp(timestamp_str):
    """Parsuje timestamp z WER do datetime."""
    if not timestamp_str:
        return None
    
    formats = [
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%m/%d/%Y %I:%M:%S %p",
        "%m/%d/%Y %H:%M:%S"
    ]
    
    for fmt in formats:
        try:
            return datetime.strptime(timestamp_str[:19], fmt)
        except (ValueError, IndexError):
            continue
    
    try:
        return datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
    except:
        pass
    
    return None


def parse_bsod_timestamp(timestamp_str):
    """Parsuje timestamp z BSOD do datetime."""
    return parse_wer_timestamp(timestamp_str)  # Użyj tej samej funkcji

