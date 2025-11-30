"""
Score Calculator - ujednolicony scoring engine.
Skala 0-100 z kategoriami: Healthy, Slight Issues, Warning, Unhealthy, Critical.
"""
from utils.logger import get_logger

logger = get_logger()


def calculate_score(processed_data):
    """
    Oblicza System Score na podstawie wykrytych problemów.

    Ujednolicony model:
    RAW events → Normalized Score (0-100) → Category → Final Status
    
    Skala 0-100:
    - 0-20 → Healthy
    - 21-50 → Slight Issues
    - 51-75 → Warning
    - 76-90 → Unhealthy
    - 91-100 → Critical

    Args:
        processed_data (dict): Przetworzone dane z wszystkich procesorów

    Returns:
        dict: Wyniki scoringu z normalized score i category
    """
    # Punkty za severity (używane do obliczenia RAW score)
    POINTS = {
        "CRITICAL": 15,
        "ERROR": 8,
        "WARNING": 3,
        "INFO": 0
    }

    raw_score = 0
    critical_count = 0
    error_count = 0
    warning_count = 0
    info_count = 0

    logger.debug("[SCORE_CALCULATOR] Starting score calculation")

    # Zbierz wszystkie problemy z wszystkich procesorów
    for _processor_name, processor_data in processed_data.items():
        if isinstance(processor_data, dict):
            # Critical issues
            critical = processor_data.get("critical_issues", [])
            for issue in critical:
                severity = issue.get("severity", "CRITICAL").upper()
                category = issue.get("category", "")
                issue_type = issue.get("type", "")

                # ShadowCopy errors nie wpływają na score
                if category == "SHADOWCOPY_ERROR" or issue_type == "SHADOWCOPY_ERROR":
                    continue

                points = POINTS.get(severity, 0)
                raw_score += points
                if severity == "CRITICAL":
                    critical_count += 1

            # Critical events
            critical_events = processor_data.get("critical_events", [])
            for event in critical_events:
                severity = event.get("severity", "CRITICAL").upper()
                category = event.get("category", "")

                if category == "SHADOWCOPY_ERROR":
                    continue

                points = POINTS.get(severity, 0)
                raw_score += points
                if severity == "CRITICAL":
                    critical_count += 1

            # Issues
            issues = processor_data.get("issues", [])
            for issue in issues:
                severity = issue.get("severity", "ERROR").upper()
                category = issue.get("category", "")
                issue_type = issue.get("type", "")

                if category == "SHADOWCOPY_ERROR" or issue_type == "SHADOWCOPY_ERROR":
                    continue

                points = POINTS.get(severity, 0)
                raw_score += points

                if severity == "CRITICAL":
                    critical_count += 1
                elif severity == "ERROR":
                    error_count += 1
                elif severity == "WARNING":
                    warning_count += 1
                elif severity == "INFO":
                    info_count += 1

            # Warnings
            warnings = processor_data.get("warnings", [])
            for warning in warnings:
                severity = warning.get("severity", "WARNING").upper()
                category = warning.get("category", "")
                warning_type = warning.get("type", "")

                # Ignoruj IGNORE warnings i ShadowCopy
                if category == "SHADOWCOPY_ERROR" or warning_type == "SHADOWCOPY_ERROR" or warning_type == "IGNORE":
                    continue

                points = POINTS.get(severity, 0)
                raw_score += points
                warning_count += 1

    logger.debug(f"[SCORE_CALCULATOR] Raw score: {raw_score}, Critical: {critical_count}, Errors: {error_count}, Warnings: {warning_count}")

    # Normalizuj do zakresu 0-100
    # Maksymalny możliwy score: ~1000 (zakładając 50 critical issues)
    # Normalizacja: min(100, (raw_score / 10))
    normalized_score = min(100, max(0, raw_score / 10.0))
    normalized_score = round(normalized_score, 2)

    # Kategoria na podstawie normalized score
    if normalized_score <= 20:
        category = "Healthy"
    elif normalized_score <= 50:
        category = "Slight Issues"
    elif normalized_score <= 75:
        category = "Warning"
    elif normalized_score <= 90:
        category = "Unhealthy"
    else:
        category = "Critical"

    logger.info(f"[SCORE_CALCULATOR] Normalized score: {normalized_score}/100, Category: {category}")

    return {
        "raw_score": raw_score,
        "normalized_score": normalized_score,
        "category": category,
        "breakdown": {
            "critical": critical_count,
            "errors": error_count,
            "warnings": warning_count,
            "info": info_count
        },
        "points_breakdown": {
            "critical_points": critical_count * POINTS["CRITICAL"],
            "error_points": error_count * POINTS["ERROR"],
            "warning_points": warning_count * POINTS["WARNING"]
        }
    }