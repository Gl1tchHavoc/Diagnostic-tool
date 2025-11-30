"""
Status Calculator - oblicza Health Status systemu na podstawie normalized score.
Status musi pochodzić bezpośrednio z Category (score_calculator).
"""

from utils.logger import get_logger

from .score_calculator import calculate_score

logger = get_logger()


def calculate_status(processed_data):
    """
    Oblicza status zdrowia systemu na podstawie normalized score.
    Status pochodzi bezpośrednio z Category z score_calculator.
    
    Args:
        processed_data (dict): Przetworzone dane z wszystkich procesorów
    
    Returns:
        dict: Status systemu z szczegółami
    """
    # Oblicz score (który zwraca category)
    score_info = calculate_score(processed_data)
    category = score_info.get("category", "Unknown")

    logger.debug(f"[STATUS_CALCULATOR] Category from score: {category}")

    # Mapuj category na status (bezpośrednio z category)
    status_map = {
        "Healthy": ("HEALTHY", "🟢", "green"),
        "Slight Issues": ("DEGRADED", "🟠", "orange"),
        "Warning": ("WARNING", "🟡", "yellow"),
        "Unhealthy": ("UNHEALTHY", "🔴", "red"),
        "Critical": ("CRITICAL", "🔴", "red")
    }

    status, status_icon, status_color = status_map.get(category, ("UNKNOWN", "⚪", "gray"))

    logger.info(f"[STATUS_CALCULATOR] Status: {status} (from category: {category})")
    # Zbierz statystyki dla breakdown
    all_critical = []
    all_errors = []
    all_warnings = []

    for _processor_name, processor_data in processed_data.items():
        if isinstance(processor_data, dict):
            critical = processor_data.get("critical_issues", [])
            if critical:
                all_critical.extend(critical)

            critical_events = processor_data.get("critical_events", [])
            if critical_events:
                all_critical.extend(critical_events)

            issues = processor_data.get("issues", [])
            for issue in issues:
                severity = issue.get("severity", "").upper()
                if severity == "ERROR":
                    all_errors.append(issue)
                elif severity == "CRITICAL":
                    all_critical.append(issue)

            warnings = processor_data.get("warnings", [])
            if warnings:
                all_warnings.extend(warnings)

    return {
        "status": status,
        "status_icon": status_icon,
        "status_color": status_color,
        "category": category,
        "normalized_score": score_info.get("normalized_score", 0),
        "critical_count": len(all_critical),
        "error_count": len(all_errors),
        "warning_count": len(all_warnings),
        "breakdown": {
            "critical": len(all_critical),
            "errors": len(all_errors),
            "warnings": len(all_warnings)
        }
    }