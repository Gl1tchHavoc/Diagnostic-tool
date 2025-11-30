"""
System oceny problemów - przypisuje wyniki (scores) do wykrytych problemów
i określa prawdopodobieństwo przyczyny błędu.
"""
from collections import defaultdict

# Wagi dla różnych typów problemów
SEVERITY_WEIGHTS = {
    "CRITICAL": 100,
    "ERROR": 50,
    "WARNING": 20,
    "INFO": 5
}

# Wagi dla różnych komponentów
COMPONENT_WEIGHTS = {
    "Storage": 80,  # Problemy z dyskiem są bardzo poważne
    "Registry/Storage": 100,  # TxR błędy są krytyczne
    "System": 30,
    "CPU": 25,
    "RAM": 25,
    "GPU": 15,
    "Drivers": 40,
    "System Logs": 30
}

# Wzorce problemów i ich prawdopodobne przyczyny
PROBLEM_PATTERNS = {
    "REGISTRY_TXR_FAILURE": {
        "likely_causes": [
            "Disk corruption or bad sectors",
            "Registry corruption",
            "Hardware failure (disk/controller)"
        ],
        "confidence": 0.95
    },
    "SHADOWCOPY_ERROR": {
        "likely_causes": [
            "ShadowCopy corruption (does not affect disk health)",
            "VSS service issues",
            "Old snapshot cleanup needed"
        ],
        "confidence": 0.0  # Nie wpływa na zdrowie dysku
    },
    "SMART_ERROR": {
        "likely_causes": [
            "Physical disk failure",
            "Bad sectors",
            "Disk controller issues"
        ],
        "confidence": 0.90
    },
    "DISK_ERROR": {
        "likely_causes": [
            "Disk I/O failure",
            "NTFS corruption",
            "Bad sectors",
            "Disk controller issues"
        ],
        "confidence": 0.85
    },
    "IO_ERROR": {
        "likely_causes": [
            "Disk I/O failure",
            "Cable issues",
            "Disk controller problems"
        ],
        "confidence": 0.80
    },
    "DRIVER_LOAD_FAILURE": {
        "likely_causes": [
            "Corrupted driver",
            "Driver version incompatibility",
            "System file corruption"
        ],
        "confidence": 0.75
    },
    "SYSTEM_CRASH": {
        "likely_causes": [
            "Hardware failure",
            "Driver issues",
            "Memory problems",
            "Overheating"
        ],
        "confidence": 0.70
    },
    "CPU_HIGH_TEMP": {
        "likely_causes": [
            "Cooling system failure",
            "Thermal paste degradation",
            "Dust accumulation"
        ],
        "confidence": 0.65
    },
    "RAM_HIGH_USAGE": {
        "likely_causes": [
            "Memory leak",
            "Insufficient RAM",
            "Resource-intensive applications"
        ],
        "confidence": 0.50
    }
}


def score_issues(processed_data):
    """
    Ocenia wszystkie wykryte problemy i przypisuje im wyniki.
    
    Args:
        processed_data (dict): Słownik z przetworzonymi danymi z wszystkich procesorów
    
    Returns:
        dict: Wyniki oceny z rankingiem problemów
    """
    all_issues = []
    all_warnings = []
    all_critical = []

    # Zbierz wszystkie problemy z wszystkich procesorów
    for _processor_name, processor_data in processed_data.items():
        if isinstance(processor_data, dict):
            # Issues
            issues = processor_data.get("issues", [])
            all_issues.extend(issues)

            # Warnings
            warnings = processor_data.get("warnings", [])
            all_warnings.extend(warnings)

            # Critical
            critical = processor_data.get("critical_issues", [])
            if critical:
                all_critical.extend(critical)

            # Critical events
            critical_events = processor_data.get("critical_events", [])
            if critical_events:
                all_critical.extend(critical_events)

    # Oblicz wyniki dla każdego problemu
    scored_issues = []
    for issue in all_issues + all_critical:
        score = calculate_score(issue)
        issue["score"] = score
        scored_issues.append(issue)

    # Sortuj według wyniku (najwyższe pierwsze)
    scored_issues.sort(key=lambda x: x.get("score", 0), reverse=True)

    # Grupuj problemy według prawdopodobnych przyczyn
    cause_analysis = analyze_causes(scored_issues)

    # Oblicz ogólny wynik systemu (0-100, gdzie 100 = bardzo zły stan)
    system_score = calculate_system_score(scored_issues, all_warnings)

    return {
        "system_score": system_score,
        "scored_issues": scored_issues,
        "top_issues": scored_issues[:10],  # Top 10 problemów
        "cause_analysis": cause_analysis,
        "summary": {
            "total_issues": len(scored_issues),
            "total_warnings": len(all_warnings),
            "total_critical": len(all_critical),
            "severity_breakdown": count_by_severity(scored_issues)
        }
    }


def calculate_score(issue):
    """Oblicza wynik dla pojedynczego problemu."""
    score = 0

    # ShadowCopy errors → 0 punktów (nie wpływają na zdrowie dysku)
    issue_type = issue.get("type", "")
    category = issue.get("category", "")

    if issue_type == "SHADOWCOPY_ERROR" or category == "SHADOWCOPY_ERROR":
        return 0

    # Błędy z nieistniejących wolumenów → 0 punktów
    if "non-existent" in issue.get("message", "").lower() or "not accessible" in issue.get("message", "").lower():
        if category and "REAL_DISK_ERROR" not in category:
            return 0

    # Podstawowy wynik na podstawie severity
    severity = issue.get("severity", "INFO")
    score += SEVERITY_WEIGHTS.get(severity, 5)

    # Bonus za komponent
    component = issue.get("component", "")
    score += COMPONENT_WEIGHTS.get(component, 10)

    # Bonus za znany wzorzec problemu
    if issue_type in PROBLEM_PATTERNS:
        pattern = PROBLEM_PATTERNS[issue_type]
        score += pattern["confidence"] * 50

    return score


def analyze_causes(issues):
    """Analizuje prawdopodobne przyczyny na podstawie wykrytych problemów."""
    cause_scores = defaultdict(float)
    cause_issues = defaultdict(list)

    for issue in issues:
        issue_type = issue.get("type", "")
        if issue_type in PROBLEM_PATTERNS:
            pattern = PROBLEM_PATTERNS[issue_type]
            confidence = pattern["confidence"]
            score = issue.get("score", 0)

            for cause in pattern["likely_causes"]:
                cause_scores[cause] += score * confidence
                cause_issues[cause].append(issue)

    # Sortuj przyczyny według wyniku
    sorted_causes = sorted(cause_scores.items(), key=lambda x: x[1], reverse=True)

    return {
        "top_causes": [
            {
                "cause": cause,
                "score": score,
                "confidence": score / 100.0,  # Normalizuj do 0-1
                "related_issues": len(cause_issues[cause])
            }
            for cause, score in sorted_causes[:5]  # Top 5 przyczyn
        ],
        "all_causes": dict(cause_scores)
    }


def calculate_system_score(issues, warnings):
    """Oblicza ogólny wynik systemu (0-100)."""
    if not issues and not warnings:
        return 0  # System w dobrym stanie

    # Suma wszystkich wyników problemów
    total_score = sum(issue.get("score", 0) for issue in issues)
    total_score += len(warnings) * 5  # Mały bonus za ostrzeżenia

    # Normalizuj do 0-100 (maksymalny możliwy wynik to ~5000)
    normalized = min(100, (total_score / 50.0))

    return round(normalized, 2)


def count_by_severity(issues):
    """Liczy problemy według severity."""
    counts = defaultdict(int)
    for issue in issues:
        severity = issue.get("severity", "INFO")
        counts[severity] += 1
    return dict(counts)