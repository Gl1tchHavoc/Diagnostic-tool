"""
Report Builder - składa wszystko w końcowy raport.
Zawiera sekcję ShadowCopy Diagnostic.
"""
from .status_calculator import calculate_status
from .score_calculator import calculate_score
from .confidence_engine import calculate_confidence
from .recommendation_engine import generate_recommendations
from utils.shadowcopy_helper import get_shadowcopy_info
from utils.logger import get_logger

logger = get_logger()

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
    
    # 5. Zbierz wszystkie problemy dla szczegółów (z kategoryzacją)
    all_issues = []
    all_warnings = []
    all_critical = []
    real_disk_errors = []
    shadowcopy_errors = []
    registry_txr_real = []
    registry_txr_shadowcopy = []
    
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
                category = issue.get("category", "")
                issue_type = issue.get("type", "")
                
                # Kategoryzuj błędy
                if category == "SHADOWCOPY_ERROR" or issue_type == "SHADOWCOPY_ERROR":
                    shadowcopy_errors.append(issue)
                elif category == "REAL_DISK_ERROR":
                    real_disk_errors.append(issue)
                elif issue_type == "REGISTRY_TXR_FAILURE":
                    if category == "SHADOWCOPY_ERROR":
                        registry_txr_shadowcopy.append(issue)
                    else:
                        registry_txr_real.append(issue)
                
                if severity == "CRITICAL":
                    all_critical.append(issue)
                elif severity == "ERROR":
                    all_issues.append(issue)
            
            warnings = processor_data.get("warnings", [])
            if warnings:
                for warning in warnings:
                    category = warning.get("category", "")
                    issue_type = warning.get("type", "")
                    
                    if category == "SHADOWCOPY_ERROR" or issue_type == "SHADOWCOPY_ERROR":
                        shadowcopy_errors.append(warning)
                    elif category == "REAL_DISK_ERROR":
                        real_disk_errors.append(warning)
                
                all_warnings.extend(warnings)
            
            # ShadowCopy issues z registry_txr_processor
            shadowcopy_issues = processor_data.get("shadowcopy_issues", [])
            if shadowcopy_issues:
                shadowcopy_errors.extend(shadowcopy_issues)
    
    # Sortuj problemy według severity
    all_critical.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    all_issues.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    all_warnings.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    
    # 6. Pobierz informacje o ShadowCopy
    shadowcopy_info = get_shadowcopy_info()
    
    # 7. Buduj raport z kategoryzacją błędów
    report = {
        "status": {
            "value": status_info["status"],
            "icon": status_info["status_icon"],
            "color": status_info["status_color"],
            "breakdown": status_info["breakdown"]
        },
        "score": {
            "normalized": score_info["normalized_score"],
            "raw_score": score_info.get("raw_score", 0),  # Użyj raw_score zamiast total_points
            "total_points": score_info.get("raw_score", 0),  # Zachowaj kompatybilność wsteczną
            "category": score_info["category"],
            "breakdown": score_info["breakdown"],
            "points_breakdown": score_info.get("points_breakdown", {})
        },
        "confidence": {
            "top_causes": confidence_info["top_causes"],
            "total_critical_events": confidence_info["total_critical_events"]
        },
        "issues": {
            "critical": all_critical[:20],  # Top 20 critical
            "errors": all_issues[:20],  # Top 20 errors
            "warnings": all_warnings[:30],  # Top 30 warnings
            # Kategoryzacja błędów
            "real_disk_errors": real_disk_errors[:20],
            "shadowcopy_errors": shadowcopy_errors[:20],
            "registry_txr_real": registry_txr_real[:10],
            "registry_txr_shadowcopy": registry_txr_shadowcopy[:10]
        },
        "shadowcopy_diagnostic": {
            "info": shadowcopy_info,
            "errors": shadowcopy_errors[:20],
            "recommendations": [
                {
                    "priority": "MEDIUM",
                    "action": "Usuń stare shadowcopies",
                    "description": "Stare snapshoty mogą powodować błędy TxR",
                    "command": "vssadmin delete shadows /oldest"
                },
                {
                    "priority": "MEDIUM",
                    "action": "Zweryfikuj integralność VSS",
                    "description": "Sprawdź czy VSS service działa poprawnie",
                    "command": "Get-Service VSS"
                },
                {
                    "priority": "LOW",
                    "action": "Zresetuj repozytorium copy-on-write",
                    "description": "Może rozwiązać problemy z ShadowCopy",
                    "command": "vssadmin resize shadowstorage"
                }
            ] if shadowcopy_errors else []
        },
        "recommendations": recommendations,
        "summary": {
            "total_critical": len(all_critical),
            "total_errors": len(all_issues),
            "total_warnings": len(all_warnings),
            "total_issues": len(all_critical) + len(all_issues) + len(all_warnings),
            "real_disk_errors_count": len(real_disk_errors),
            "shadowcopy_errors_count": len(shadowcopy_errors),
            "registry_txr_real_count": len(registry_txr_real),
            "registry_txr_shadowcopy_count": len(registry_txr_shadowcopy)
        }
    }
    
    # Dodaj analizę BSOD jeśli dostępna (będzie dodana w analyzer.py)
    # BSOD analysis jest już w final_report, więc nie trzeba jej tutaj dodawać
    
    return report

