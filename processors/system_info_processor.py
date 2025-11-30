"""
Procesor informacji systemowych - analizuje konfigurację systemu.
"""


def process(system_info_data):
    """
    Przetwarza informacje o systemie.
    
    Args:
        system_info_data (dict): Dane z collectors.system_info
    
    Returns:
        dict: Przetworzone dane
    """
    issues = []
    warnings = []

    if isinstance(system_info_data, dict) and "error" in system_info_data:
        issues.append({
            "type": "SYSTEM_INFO_COLLECTION_ERROR",
            "severity": "ERROR",
            "message": f"Failed to collect system info: {system_info_data.get('error')}",
            "component": "System Info"
        })
        return {
            "data": system_info_data,
            "issues": issues,
            "warnings": warnings,
            "summary": {"total_issues": len(issues), "total_warnings": len(warnings)}
        }

    # Sprawdź uptime - bardzo krótki uptime może wskazywać na problemy
    uptime = system_info_data.get("uptime", "")
    if uptime:
        # Parsuj uptime (format: "Xh Ym")
        try:
            parts = uptime.split()
            hours = 0
            for part in parts:
                if "h" in part:
                    hours = int(part.replace("h", ""))
                    break
            if hours < 1:
                warnings.append({
                    "type": "LOW_UPTIME",
                    "severity": "INFO",
                    "message": f"System uptime is very low: {uptime} - may indicate recent crashes",
                    "component": "System"
                })
        except Exception:
            pass

    return {
        "data": system_info_data,
        "issues": issues,
        "warnings": warnings,
        "summary": {
            "total_issues": len(issues),
            "total_warnings": len(warnings)
        }
    }
