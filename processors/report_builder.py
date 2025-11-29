"""
Report Builder - składa wszystko w końcowy raport.
"""
from .status_calculator import calculate_status
from .score_calculator import calculate_score
from .confidence_engine import calculate_confidence
from .recommendation_engine import generate_recommendations

def build_report(processed_data):
    """
    Buduje kompleksowy raport diagnostyczny.
    
    Args:
        processed_data (dict): Przetworzone dane z wszystkich procesorów
    
    Returns:
        dict: Kompleksowy raport
    """
    # 1. Oblicz status systemu
    status_info = calculate_status(processed_data)
    
    # 2. Oblicz score
    score_info = calculate_score(processed_data)
    
    # 3. Oblicz confidence
    confidence_info = calculate_confidence(processed_data)
    
    # 4. Generuj rekomendacje
    recommendations = generate_recommendations(processed_data)
    
    # 5. Zbierz wszystkie problemy dla szczegółów
    all_issues = []
    all_warnings = []
    all_critical = []
    
    for processor_name, processor_data in processed_data.items():
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
                if severity == "CRITICAL":
                    all_critical.append(issue)
                elif severity == "ERROR":
                    all_issues.append(issue)
            
            warnings = processor_data.get("warnings", [])
            if warnings:
                all_warnings.extend(warnings)
    
    # Sortuj problemy według severity
    all_critical.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    all_issues.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    all_warnings.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    
    # Buduj raport
    report = {
        "status": {
            "value": status_info["status"],
            "icon": status_info["status_icon"],
            "color": status_info["status_color"],
            "breakdown": status_info["breakdown"]
        },
        "score": {
            "normalized": score_info["normalized_score"],
            "total_points": score_info["total_points"],
            "category": score_info["category"],
            "breakdown": score_info["breakdown"],
            "points_breakdown": score_info["points_breakdown"]
        },
        "confidence": {
            "top_causes": confidence_info["top_causes"],
            "total_critical_events": confidence_info["total_critical_events"]
        },
        "issues": {
            "critical": all_critical[:20],  # Top 20 critical
            "errors": all_issues[:20],  # Top 20 errors
            "warnings": all_warnings[:30]  # Top 30 warnings
        },
        "recommendations": recommendations,
        "summary": {
            "total_critical": len(all_critical),
            "total_errors": len(all_issues),
            "total_warnings": len(all_warnings),
            "total_issues": len(all_critical) + len(all_issues) + len(all_warnings)
        }
    }
    
    # Dodaj analizę BSOD jeśli dostępna (będzie dodana w analyzer.py)
    # BSOD analysis jest już w final_report, więc nie trzeba jej tutaj dodawać
    
    return report

