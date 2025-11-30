"""
Confidence Engine - generuje confidence dla przyczyn problemów (max 100%).
"""
from collections import defaultdict

# Mapowanie typów problemów na prawdopodobne przyczyny
PROBLEM_TO_CAUSES = {
    "REGISTRY_TXR_FAILURE": [
        "Disk corruption or bad sectors",
        "ShadowCopy corruption",
        "Registry corruption",
        "Hardware failure (disk/controller)"
    ],
    "SMART_ERROR": [
        "Physical disk failure",
        "Bad sectors",
        "Disk controller issues"
    ],
    "DISK_ERROR": [
        "Disk I/O failure",
        "NTFS corruption",
        "Bad sectors",
        "Disk controller issues"
    ],
    "IO_ERROR": [
        "Disk I/O failure",
        "Cable issues",
        "Disk controller problems"
    ],
    "DRIVER_LOAD_FAILURE": [
        "Corrupted driver",
        "Driver version incompatibility",
        "System file corruption"
    ],
    "SYSTEM_CRASH": [
        "Hardware failure",
        "Driver issues",
        "Memory problems",
        "Overheating"
    ],
    "CPU_HIGH_TEMP": [
        "Cooling system failure",
        "Thermal paste degradation",
        "Dust accumulation"
    ],
    "RAM_HIGH_USAGE": [
        "Memory leak",
        "Insufficient RAM",
        "Resource-intensive applications"
    ],
    "GPU_HIGH_TEMP": [
        "GPU cooling failure",
        "Dust accumulation",
        "Thermal paste degradation"
    ],
    "NETWORK_ERROR": [
        "DNS issues",
        "Network adapter problems",
        "Driver issues",
        "Firewall blocking"
    ]
}


def calculate_confidence(processed_data):
    """
    Oblicza confidence dla każdej przyczyny problemów.

    Formuła:
    Confidence = (liczba powiązanych eventów / liczba wszystkich krytycznych eventów) × 100%
    Max: 100%

    Args:
        processed_data (dict): Przetworzone dane z wszystkich procesorów

    Returns:
        dict: Analiza przyczyn z confidence
    """
    # Zbierz wszystkie krytyczne eventy
    all_critical = []

    for processor_name, processor_data in processed_data.items():
        if isinstance(processor_data, dict):
            critical = processor_data.get("critical_issues", [])
            if critical:
                all_critical.extend(critical)

            critical_events = processor_data.get("critical_events", [])
            if critical_events:
                all_critical.extend(critical_events)

            # Issues z severity CRITICAL
            issues = processor_data.get("issues", [])
            for issue in issues:
                if issue.get("severity", "").upper() == "CRITICAL":
                    all_critical.append(issue)

    total_critical_events = len(all_critical)

    if total_critical_events == 0:
        return {
            "top_causes": [],
            "all_causes": {},
            "total_critical_events": 0
        }

    # Mapuj problemy na przyczyny
    cause_to_events = defaultdict(list)

    for critical_event in all_critical:
        issue_type = critical_event.get("type", "")

        # Znajdź przyczyny dla tego typu problemu
        if issue_type in PROBLEM_TO_CAUSES:
            causes = PROBLEM_TO_CAUSES[issue_type]
            for cause in causes:
                cause_to_events[cause].append(critical_event)

    # Oblicz confidence dla każdej przyczyny
    cause_confidence = {}
    for cause, related_events in cause_to_events.items():
        # Confidence = (liczba powiązanych eventów / liczba wszystkich
        # krytycznych eventów) × 100%
        confidence = (len(related_events) / total_critical_events) * 100
        # Limit do 100%
        confidence = min(100.0, confidence)

        cause_confidence[cause] = {
            "confidence": round(confidence, 2),
            "related_events_count": len(related_events),
            "related_events": related_events[:5]  # Max 5 przykładów
        }

    # Sortuj według confidence
    sorted_causes = sorted(
        cause_confidence.items(),
        key=lambda x: x[1]["confidence"],
        reverse=True
    )

    # Top przyczyny
    top_causes = [
        {
            "cause": cause,
            "confidence": data["confidence"],
            "related_events_count": data["related_events_count"]
        }
        for cause, data in sorted_causes[:10]  # Top 10
    ]

    return {
        "top_causes": top_causes,
        "all_causes": {
            cause: data["confidence"] for cause,
            data in cause_confidence.items()},
        "total_critical_events": total_critical_events}
