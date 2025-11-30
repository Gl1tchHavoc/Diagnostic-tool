"""
Procesor zdrowia dysków - analizuje stan dysków i wykrywa problemy.
Zaimplementowano filtrowanie ShadowCopy errors i de-duplikację zdarzeń.
"""
from utils.disk_helper import (
    filter_disk_errors_by_existing_drives,
    get_existing_drives,
)
from utils.event_deduplicator import deduplicate_events
from utils.logger import get_logger
from utils.shadowcopy_helper import filter_shadowcopy_errors
from utils.warning_classifier import classify_warning, is_false_disk_warning

logger = get_logger()

def process(storage_data):
    """
    Przetwarza dane o zdrowiu dysków i wykrywa problemy.
    
    Args:
        storage_data (dict): Dane z collectors.storage_health
    
    Returns:
        dict: Przetworzone dane z wykrytymi problemami
    """
    issues = []
    warnings = []

    if isinstance(storage_data, dict) and "error" in storage_data:
        issues.append({
            "type": "STORAGE_COLLECTION_ERROR",
            "severity": "ERROR",
            "message": f"Failed to collect storage data: {storage_data.get('error')}",
            "component": "Storage"
        })
        return {
            "data": storage_data,
            "issues": issues,
            "warnings": warnings,
            "summary": {"total_issues": len(issues), "total_warnings": len(warnings)}
        }

    # Sprawdź statusy dysków
    disks = storage_data.get("disks", [])
    for disk in disks:
        status = disk.get("status", "").lower()
        if "error" in status or "fail" in status or "degraded" in status:
            issues.append({
                "type": "DISK_STATUS_ERROR",
                "severity": "ERROR",
                "message": f"Disk {disk.get('model')} has status: {status}",
                "component": "Storage",
                "disk_model": disk.get("model"),
                "serial": disk.get("serial")
            })

    # Sprawdź błędy SMART (z de-duplikacją)
    smart_errors = storage_data.get("smart_errors", [])
    if smart_errors:
        smart_errors = deduplicate_events(smart_errors)
        for error in smart_errors:
            issues.append({
                "type": "SMART_ERROR",
                "severity": "CRITICAL",
                "message": error.get("message", ""),
                "event_id": error.get("event_id", ""),
                "timestamp": error.get("timestamp", ""),
                "component": "Storage",
                "description": "SMART error indicates physical disk problems"
            })

    # Sprawdź błędy I/O (z de-duplikacją)
    io_errors = storage_data.get("io_errors", [])
    if io_errors:
        io_errors = deduplicate_events(io_errors)
        for error in io_errors:
            issues.append({
                "type": "IO_ERROR",
                "severity": "ERROR",
                "message": error.get("message", ""),
                "event_id": error.get("event_id", ""),
                "timestamp": error.get("timestamp", ""),
                "component": "Storage"
            })

    # Sprawdź ogólne błędy dysków - filtruj ShadowCopy i nieistniejące dyski (z de-duplikacją)
    disk_errors = storage_data.get("disk_errors", [])
    if disk_errors:
        disk_errors = deduplicate_events(disk_errors)
        # Pobierz listę istniejących dysków
        existing_drives = get_existing_drives()
        logger.debug(f"[STORAGE_HEALTH] Filtering {len(disk_errors)} disk errors against {len(existing_drives)} existing drives")

        # Najpierw filtruj ShadowCopy errors
        real_disk_errors, shadowcopy_errors = filter_shadowcopy_errors(disk_errors)
        logger.info(f"[STORAGE_HEALTH] Filtered ShadowCopy: {len(real_disk_errors)} real, {len(shadowcopy_errors)} ShadowCopy")

        # Następnie filtruj błędy dotyczące nieistniejących dysków
        filtered_disk_errors = filter_disk_errors_by_existing_drives(real_disk_errors, existing_drives)

        # Dodaj rzeczywiste błędy dysków (z filtrowaniem fałszywych DISK_WARNING)
        for error in filtered_disk_errors:
            message = error.get("message", "")

            # Sprawdź czy to nie jest fałszywy DISK_WARNING
            if is_false_disk_warning(message):
                warning_type = classify_warning(message, error.get("event_id"))
                if warning_type == "IGNORE":
                    logger.debug(f"[STORAGE_HEALTH] Ignoring false DISK_WARNING: {message[:100]}")
                    continue
                elif warning_type == "NETWORK_WARNING":
                    logger.debug(f"[STORAGE_HEALTH] Reclassifying as NETWORK_WARNING: {message[:100]}")
                    warnings.append({
                        "type": "NETWORK_WARNING",
                        "severity": "WARNING",
                        "message": message,
                        "event_id": error.get("event_id", ""),
                        "timestamp": error.get("timestamp", ""),
                        "component": "Network",
                        "category": "NETWORK_WARNING"
                    })
                    continue

            # Rzeczywisty błąd dysku
            warnings.append({
                "type": "DISK_WARNING",
                "severity": "WARNING",
                "message": message,
                "event_id": error.get("event_id", ""),
                "timestamp": error.get("timestamp", ""),
                "component": "Storage",
                "category": "REAL_DISK_ERROR"
            })

        # Dodaj błędy ShadowCopy jako osobna kategoria (nie wpływają na zdrowie dysku)
        for error in shadowcopy_errors:
            warnings.append({
                "type": "SHADOWCOPY_ERROR",
                "severity": "INFO",
                "message": error.get("message", ""),
                "event_id": error.get("event_id", ""),
                "timestamp": error.get("timestamp", ""),
                "component": "ShadowCopy",
                "category": "SHADOWCOPY_ERROR",
                "description": "ShadowCopy error - does not affect disk health"
            })

        if len(filtered_disk_errors) < len(real_disk_errors):
            logger.info(f"[STORAGE_HEALTH] Filtered out {len(real_disk_errors) - len(filtered_disk_errors)} errors for non-existent drives")

    return {
        "data": storage_data,
        "issues": issues,
        "warnings": warnings,
        "summary": {
            "total_issues": len(issues),
            "total_warnings": len(warnings),
            "smart_errors_count": len(smart_errors),
            "io_errors_count": len(io_errors)
        }
    }

