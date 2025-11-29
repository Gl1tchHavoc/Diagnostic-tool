"""
Procesor błędów Registry TxR - analizuje błędy transakcji rejestru.
"""
def process(txr_data):
    """
    Przetwarza błędy Registry TxR - bardzo poważne błędy systemowe.
    
    Args:
        txr_data (list): Dane z collectors.registry_txr
    
    Returns:
        dict: Przetworzone dane z wykrytymi problemami
    """
    issues = []
    critical_issues = []
    
    if isinstance(txr_data, list):
        for error in txr_data:
            if "error" in error:
                # To jest błąd kolekcji, nie błąd TxR
                issues.append({
                    "type": "TXR_COLLECTION_ERROR",
                    "severity": "ERROR",
                    "message": error.get("error", ""),
                    "component": "Registry TxR"
                })
            else:
                # Prawdziwy błąd TxR - bardzo poważny
                critical_issues.append({
                    "type": "REGISTRY_TXR_FAILURE",
                    "severity": "CRITICAL",
                    "message": error.get("message", ""),
                    "event_id": error.get("event_id", ""),
                    "timestamp": error.get("timestamp", ""),
                    "component": "Registry/Storage",
                    "description": "Registry Transaction failure indicates possible disk corruption or ShadowCopy issues"
                })
    
    return {
        "data": txr_data,
        "issues": issues,
        "critical_issues": critical_issues,
        "summary": {
            "total_issues": len(issues),
            "total_critical": len(critical_issues),
            "has_txr_errors": len(critical_issues) > 0
        }
    }

