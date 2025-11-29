"""
Score Calculator - oblicza punkty i normalizację systemu.
"""
def calculate_score(processed_data):
    """
    Oblicza System Score na podstawie wykrytych problemów.
    
    Model punktowy:
    - Critical: 40 pkt za każdy
    - Error: 20 pkt
    - Warning: 10 pkt
    - Info: 0 pkt
    
    Normalizacja:
    Score = total_points
    Normalized Score = min(100, total_points / 2)
    
    Kategorie:
    - 0-20 = Healthy
    - 21-50 = Degraded
    - 51-100 = Unhealthy
    
    Args:
        processed_data (dict): Przetworzone dane z wszystkich procesorów
    
    Returns:
        dict: Wyniki scoringu
    """
    # Punkty za severity
    POINTS = {
        "CRITICAL": 40,
        "ERROR": 20,
        "WARNING": 10,
        "INFO": 0
    }
    
    total_points = 0
    critical_count = 0
    error_count = 0
    warning_count = 0
    info_count = 0
    
    # Zbierz wszystkie problemy z wszystkich procesorów
    for processor_name, processor_data in processed_data.items():
        if isinstance(processor_data, dict):
            # Critical issues
            critical = processor_data.get("critical_issues", [])
            for issue in critical:
                severity = issue.get("severity", "CRITICAL").upper()
                points = POINTS.get(severity, 0)
                total_points += points
                if severity == "CRITICAL":
                    critical_count += 1
            
            # Critical events
            critical_events = processor_data.get("critical_events", [])
            for event in critical_events:
                severity = event.get("severity", "CRITICAL").upper()
                points = POINTS.get(severity, 0)
                total_points += points
                if severity == "CRITICAL":
                    critical_count += 1
            
            # Issues
            issues = processor_data.get("issues", [])
            for issue in issues:
                severity = issue.get("severity", "ERROR").upper()
                points = POINTS.get(severity, 0)
                total_points += points
                
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
                points = POINTS.get(severity, 0)
                total_points += points
                warning_count += 1
    
    # Normalizacja
    normalized_score = min(100, total_points / 2)
    
    # Kategoria na podstawie normalized score
    if normalized_score <= 20:
        category = "Healthy"
    elif normalized_score <= 50:
        category = "Degraded"
    else:
        category = "Unhealthy"
    
    return {
        "total_points": total_points,
        "normalized_score": round(normalized_score, 2),
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

