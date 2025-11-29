"""
Procesor zdrowia dysków - analizuje stan dysków i wykrywa problemy.
"""
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
    
    # Sprawdź błędy SMART
    smart_errors = storage_data.get("smart_errors", [])
    if smart_errors:
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
    
    # Sprawdź błędy I/O
    io_errors = storage_data.get("io_errors", [])
    if io_errors:
        for error in io_errors:
            issues.append({
                "type": "IO_ERROR",
                "severity": "ERROR",
                "message": error.get("message", ""),
                "event_id": error.get("event_id", ""),
                "timestamp": error.get("timestamp", ""),
                "component": "Storage"
            })
    
    # Sprawdź ogólne błędy dysków
    disk_errors = storage_data.get("disk_errors", [])
    if disk_errors:
        for error in disk_errors:
            warnings.append({
                "type": "DISK_WARNING",
                "severity": "WARNING",
                "message": error.get("message", ""),
                "event_id": error.get("event_id", ""),
                "timestamp": error.get("timestamp", ""),
                "component": "Storage"
            })
    
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

