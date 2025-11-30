"""
Procesor błędów Registry TxR - analizuje błędy transakcji rejestru.
Zaimplementowano filtrowanie ShadowCopy errors i de-duplikację zdarzeń.
"""
from utils.event_deduplicator import deduplicate_events
from utils.logger import get_logger
from utils.shadowcopy_helper import categorize_txr_errors

logger = get_logger()


def process(txr_data):
    """
    Przetwarza błędy Registry TxR - bardzo poważne błędy systemowe.
    Filtruje błędy ShadowCopy jako false positives.
    
    Args:
        txr_data (list): Dane z collectors.registry_txr
    
    Returns:
        dict: Przetworzone dane z wykrytymi problemami
    """
    issues = []
    critical_issues = []
    shadowcopy_issues = []

    if isinstance(txr_data, list):
        # De-duplikuj zdarzenia
        deduplicated_data = deduplicate_events(txr_data)
        logger.info(f"[TXR_PROCESSOR] Deduplicated {len(txr_data)} events to {len(deduplicated_data)} unique events")

        # Kategoryzuj błędy na rzeczywiste i ShadowCopy
        categorized = categorize_txr_errors(deduplicated_data)
        real_errors = categorized['real_errors']
        shadowcopy_errors = categorized['shadowcopy_errors']
        all_shadowcopy = categorized['all_shadowcopy']

        logger.info(
            f"[TXR_PROCESSOR] Categorized {len(deduplicated_data)} errors: "
            f"{len(real_errors)} real, {len(shadowcopy_errors)} ShadowCopy"
        )

        # Błędy kolekcji
        for error in txr_data:
            if "error" in error:
                issues.append({
                    "type": "TXR_COLLECTION_ERROR",
                    "severity": "ERROR",
                    "message": error.get("error", ""),
                    "component": "Registry TxR"
                })

        # Rzeczywiste błędy TxR - bardzo poważne
        for error in real_errors:
            critical_issues.append({
                "type": "REGISTRY_TXR_FAILURE",
                "severity": "CRITICAL",
                "message": error.get("message", ""),
                "event_id": error.get("event_id", ""),
                "timestamp": error.get("timestamp", ""),
                "component": "Registry/Storage",
                "description": "Registry Transaction failure indicates possible disk corruption",
                "category": "REAL_DISK_ERROR"
            })

        # Błędy ShadowCopy - nie wpływają na zdrowie dysku
        for error in shadowcopy_errors:
            shadowcopy_issues.append({
                "type": "SHADOWCOPY_ERROR",
                "severity": "INFO",
                "message": error.get("message", ""),
                "event_id": error.get("event_id", ""),
                "timestamp": error.get("timestamp", ""),
                "component": "ShadowCopy",
                "description": "ShadowCopy error - does not affect disk health",
                "category": "SHADOWCOPY_ERROR"
            })

        # Jeśli wszystkie błędy dotyczą ShadowCopy, dysk jest zdrowy
        if all_shadowcopy and len(shadowcopy_errors) > 0:
            logger.info("[TXR_PROCESSOR] All TxR errors are ShadowCopy-related - disk is healthy")

    return {
        "data": txr_data,
        "issues": issues,
        "critical_issues": critical_issues,
        "shadowcopy_issues": shadowcopy_issues,
        "summary": {
            "total_issues": len(issues),
            "total_critical": len(critical_issues),
            "total_shadowcopy": len(shadowcopy_issues),
            "has_txr_errors": len(critical_issues) > 0,
            "all_shadowcopy": len(shadowcopy_issues) > 0 and len(critical_issues) == 0
        }
    }