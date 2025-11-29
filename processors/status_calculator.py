"""
Status Calculator - oblicza Health Status systemu na podstawie wykrytych problemów.
"""
from collections import defaultdict

def calculate_status(processed_data):
    """
    Oblicza status zdrowia systemu na podstawie wykrytych problemów.
    
    Zasady:
    - 0 Critical → 🟢 HEALTHY
    - 1 Critical → 🟠 DEGRADED
    - 2+ Critical lub dotyczą dysku/rejestru/kernel driverów → 🔴 UNHEALTHY
    
    Args:
        processed_data (dict): Przetworzone dane z wszystkich procesorów
    
    Returns:
        dict: Status systemu z szczegółami
    """
    all_critical = []
    all_errors = []
    all_warnings = []
    
    # Zbierz wszystkie problemy z wszystkich procesorów
    for processor_name, processor_data in processed_data.items():
        if isinstance(processor_data, dict):
            # Critical issues
            critical = processor_data.get("critical_issues", [])
            if critical:
                all_critical.extend(critical)
            
            # Critical events
            critical_events = processor_data.get("critical_events", [])
            if critical_events:
                all_critical.extend(critical_events)
            
            # Errors (issues z severity ERROR)
            issues = processor_data.get("issues", [])
            for issue in issues:
                severity = issue.get("severity", "").upper()
                if severity == "ERROR":
                    all_errors.append(issue)
                elif severity == "CRITICAL":
                    all_critical.append(issue)
            
            # Warnings
            warnings = processor_data.get("warnings", [])
            if warnings:
                all_warnings.extend(warnings)
    
    # Sprawdź czy są krytyczne problemy związane z dyskiem/rejestrem/kernel driverami
    critical_disk_registry_kernel = []
    for critical in all_critical:
        issue_type = critical.get("type", "").upper()
        component = critical.get("component", "").upper()
        message = critical.get("message", "").upper()
        
        # Sprawdź czy dotyczy dysku/rejestru/kernel
        is_critical_category = (
            "TXR" in issue_type or
            "REGISTRY" in issue_type or
            "DISK" in issue_type or
            "SMART" in issue_type or
            "STORAGE" in component or
            "REGISTRY" in component or
            "KERNEL" in issue_type or
            "DRIVER" in issue_type and "KERNEL" in message
        )
        
        if is_critical_category:
            critical_disk_registry_kernel.append(critical)
    
    # Oblicz status
    critical_count = len(all_critical)
    
    if critical_count == 0:
        status = "HEALTHY"
        status_icon = "🟢"
        status_color = "green"
    elif critical_count == 1:
        status = "DEGRADED"
        status_icon = "🟠"
        status_color = "orange"
    elif critical_count >= 2 or len(critical_disk_registry_kernel) > 0:
        status = "UNHEALTHY"
        status_icon = "🔴"
        status_color = "red"
    else:
        # Fallback
        status = "DEGRADED"
        status_icon = "🟠"
        status_color = "orange"
    
    return {
        "status": status,
        "status_icon": status_icon,
        "status_color": status_color,
        "critical_count": critical_count,
        "error_count": len(all_errors),
        "warning_count": len(all_warnings),
        "critical_disk_registry_kernel_count": len(critical_disk_registry_kernel),
        "breakdown": {
            "critical": critical_count,
            "errors": len(all_errors),
            "warnings": len(all_warnings)
        }
    }

