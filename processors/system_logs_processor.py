"""
Procesor logów systemowych - analizuje logi i wykrywa wzorce problemów.
Z filtrowaniem fałszywych DISK_WARNING.
"""
from datetime import datetime

from utils.logger import get_logger
from utils.warning_classifier import classify_warning, is_false_disk_warning

logger = get_logger()

def process(logs_data):
    """
    Przetwarza logi systemowe i wykrywa problemy.
    
    Args:
        logs_data (dict): Dane z collectors.system_logs
    
    Returns:
        dict: Przetworzone dane z wykrytymi problemami
    """
    issues = []
    warnings = []
    critical_events = []

    if isinstance(logs_data, dict) and "error" in logs_data:
        issues.append({
            "type": "LOGS_COLLECTION_ERROR",
            "severity": "ERROR",
            "message": f"Failed to collect logs: {logs_data.get('error')}",
            "component": "System Logs"
        })
        return {
            "data": logs_data,
            "issues": issues,
            "warnings": warnings,
            "critical_events": critical_events,
            "summary": {"total_issues": len(issues), "total_warnings": len(warnings)}
        }

    # Przetwarzaj logi z każdej kategorii
    for category, logs in logs_data.items():
        if not isinstance(logs, list):
            continue

        for log_entry in logs:
            if isinstance(log_entry, dict):
                level = log_entry.get("level", "").upper()
                message = log_entry.get("message", "").lower()
                event_id = log_entry.get("event_id", "")

                # Krytyczne błędy
                if level in ["CRITICAL", "ERROR"]:
                    if any(keyword in message for keyword in ["bsod", "bugcheck", "crash", "0xc00000a2"]):
                        critical_events.append({
                            "type": "SYSTEM_CRASH",
                            "severity": "CRITICAL",
                            "message": log_entry.get("raw", ""),
                            "event_id": event_id,
                            "category": category,
                            "timestamp": log_entry.get("timestamp", "")
                        })
                    elif "driver" in message and "fail" in message:
                        issues.append({
                            "type": "DRIVER_LOAD_FAILURE",
                            "severity": "ERROR",
                            "message": log_entry.get("raw", ""),
                            "event_id": event_id,
                            "category": category
                        })
                    elif any(keyword in message for keyword in ["disk", "ntfs", "bad block"]):
                        # Sprawdź czy to nie jest fałszywy DISK_ERROR
                        if not is_false_disk_warning(log_entry.get("message", "")):
                            issues.append({
                                "type": "DISK_ERROR",
                                "severity": "ERROR",
                                "message": log_entry.get("raw", ""),
                                "event_id": event_id,
                                "category": category
                            })
                        else:
                            warning_type = classify_warning(log_entry.get("message", ""), event_id)
                            if warning_type == "NETWORK_WARNING":
                                warnings.append({
                                    "type": "NETWORK_WARNING",
                                    "severity": "WARNING",
                                    "message": log_entry.get("raw", ""),
                                    "event_id": event_id,
                                    "category": category
                                })
                            # Jeśli IGNORE, pomiń
                    elif "service" in message and "fail" in message:
                        warnings.append({
                            "type": "SERVICE_FAILURE",
                            "severity": "WARNING",
                            "message": log_entry.get("raw", ""),
                            "event_id": event_id,
                            "category": category
                        })
                elif level == "WARNING":
                    # Klasyfikuj warning
                    warning_type = classify_warning(log_entry.get("message", ""), event_id)
                    if warning_type == "IGNORE":
                        logger.debug(f"[SYSTEM_LOGS_PROCESSOR] Ignoring warning: {log_entry.get('message', '')[:100]}")
                        continue

                    warnings.append({
                        "type": warning_type,
                        "severity": "WARNING",
                        "message": log_entry.get("raw", ""),
                        "event_id": event_id,
                        "category": category
                    })

    return {
        "data": logs_data,
        "issues": issues,
        "warnings": warnings,
        "critical_events": critical_events,
        "summary": {
            "total_issues": len(issues),
            "total_warnings": len(warnings),
            "total_critical": len(critical_events)
        }
    }

