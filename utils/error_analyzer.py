"""
Narzędzie do kompleksowej analizy błędów związanych z typami danych.
Pomaga diagnozować problemy z AttributeError, KeyError, TypeError itp.
"""
import sys
import traceback
from typing import Any, Optional
from utils.logger import get_logger

logger = get_logger()

def analyze_data_structure(obj: Any, name: str = "object", max_depth: int = 3, current_depth: int = 0) -> str:
    """
    Kompleksowa analiza struktury danych - zwraca szczegółowy opis obiektu.
    
    Args:
        obj: Obiekt do analizy
        name: Nazwa obiektu (dla logowania)
        max_depth: Maksymalna głębokość rekurencji
        current_depth: Aktualna głębokość rekurencji
        
    Returns:
        str: Szczegółowy opis struktury danych
    """
    if current_depth >= max_depth:
        return f"{'  ' * current_depth}... (max depth reached)"
    
    indent = "  " * current_depth
    analysis = []
    
    # Podstawowe informacje o typie
    obj_type = type(obj)
    analysis.append(f"{indent}Type: {obj_type.__name__} ({obj_type.__module__}.{obj_type.__qualname__})")
    analysis.append(f"{indent}Is None: {obj is None}")
    
    if obj is None:
        return "\n".join(analysis)
    
    # Analiza w zależności od typu
    if isinstance(obj, dict):
        analysis.append(f"{indent}Is dict: True")
        analysis.append(f"{indent}Keys ({len(obj)}): {list(obj.keys())[:10]}{'...' if len(obj) > 10 else ''}")
        analysis.append(f"{indent}Has 'get' method: {hasattr(obj, 'get')}")
        
        # Przykładowe wartości (tylko pierwsze 3 klucze)
        for i, (key, value) in enumerate(list(obj.items())[:3]):
            value_type = type(value).__name__
            value_preview = str(value)[:50] if not isinstance(value, (dict, list)) else f"<{value_type}>"
            analysis.append(f"{indent}  [{key}]: {value_type} = {value_preview}")
            if isinstance(value, (dict, list)) and current_depth < max_depth - 1:
                nested = analyze_data_structure(value, f"{name}.{key}", max_depth, current_depth + 1)
                analysis.append(nested)
    
    elif isinstance(obj, list):
        analysis.append(f"{indent}Is list: True")
        analysis.append(f"{indent}Length: {len(obj)}")
        analysis.append(f"{indent}Has 'get' method: {hasattr(obj, 'get')} (FALSE - lists don't have .get()!)")
        
        if len(obj) > 0:
            first_type = type(obj[0]).__name__
            analysis.append(f"{indent}First element type: {first_type}")
            if len(obj) > 1:
                analysis.append(f"{indent}Second element type: {type(obj[1]).__name__}")
            
            # Analiza pierwszego elementu
            if current_depth < max_depth - 1:
                nested = analyze_data_structure(obj[0], f"{name}[0]", max_depth, current_depth + 1)
                analysis.append(nested)
    
    elif isinstance(obj, (str, int, float, bool)):
        analysis.append(f"{indent}Value: {str(obj)[:100]}")
    
    else:
        analysis.append(f"{indent}Has 'get' method: {hasattr(obj, 'get')}")
        analysis.append(f"{indent}Has '__dict__': {hasattr(obj, '__dict__')}")
        if hasattr(obj, '__dict__'):
            attrs = list(obj.__dict__.keys())[:5]
            analysis.append(f"{indent}Attributes: {attrs}")
    
    return "\n".join(analysis)

def analyze_attribute_error(error: AttributeError, obj: Any, attribute: str, context: dict = None) -> dict:
    """
    Kompleksowa analiza AttributeError - szczegółowa diagnoza problemu.
    
    Args:
        error: Wyjątek AttributeError
        obj: Obiekt, na którym wystąpił błąd
        attribute: Nazwa atrybutu/metody, która nie istnieje
        context: Dodatkowy kontekst (np. nazwa zmiennej, lokalizacja)
        
    Returns:
        dict: Szczegółowa analiza błędu
    """
    analysis = {
        "error_type": "AttributeError",
        "error_message": str(error),
        "missing_attribute": attribute,
        "object_type": type(obj).__name__,
        "object_module": type(obj).__module__,
        "is_none": obj is None,
        "has_get_method": hasattr(obj, 'get'),
        "available_methods": [],
        "data_structure": "",
        "recommendation": "",
        "context": context or {}
    }
    
    # Sprawdź dostępne metody/atrybuty
    if obj is not None:
        available = [attr for attr in dir(obj) if not attr.startswith('_')]
        analysis["available_methods"] = available[:20]  # Tylko pierwsze 20
    
    # Analiza struktury danych
    obj_name = context.get('variable_name', 'object') if context else 'object'
    analysis["data_structure"] = analyze_data_structure(obj, obj_name, max_depth=2)
    
    # Rekomendacje
    if isinstance(obj, list) and attribute == 'get':
        analysis["recommendation"] = (
            "PROBLEM: Attempting to use .get() on a list object.\n"
            "SOLUTION: Lists don't have .get() method. Use:\n"
            "  - For iteration: for item in list:\n"
            "  - For indexing: list[index] if index < len(list) else default\n"
            "  - For checking: if item in list:\n"
            "If you expected a dict, check why the data is a list."
        )
    elif isinstance(obj, dict) and attribute == 'get':
        analysis["recommendation"] = (
            "Strange: dict should have .get() method.\n"
            "This might be a custom dict-like object. Try:\n"
            "  - dict(obj) to convert\n"
            "  - obj[key] for direct access\n"
        )
    elif obj is None:
        analysis["recommendation"] = (
            "PROBLEM: Object is None.\n"
            "SOLUTION: Check why the object is None before accessing attributes."
        )
    else:
        analysis["recommendation"] = (
            f"Object type '{type(obj).__name__}' doesn't have attribute '{attribute}'.\n"
            f"Available methods: {', '.join(analysis['available_methods'][:10])}"
        )
    
    return analysis

def safe_get_with_analysis(obj: Any, key: Any, default: Any = None, context: dict = None) -> Any:
    """
    Bezpieczne pobranie wartości z obiektu z kompleksową analizą w przypadku błędu.
    
    Args:
        obj: Obiekt (dict, list, lub inny)
        key: Klucz/indeks do pobrania
        default: Wartość domyślna
        context: Kontekst dla logowania (np. {'variable_name': 'grouped_crashes', 'location': 'cause_detector.py:801'})
        
    Returns:
        Wartość z obiektu lub default
    """
    try:
        if isinstance(obj, dict):
            return obj.get(key, default)
        elif isinstance(obj, list):
            # Dla listy, key powinien być indeksem
            if isinstance(key, int) and 0 <= key < len(obj):
                return obj[key]
            else:
                logger.warning(f"[SAFE_GET] Attempting to use key '{key}' on list (length: {len(obj)}). Use index instead.")
                return default
        else:
            # Próbuj użyć getattr
            return getattr(obj, str(key), default)
    except (AttributeError, TypeError, KeyError, IndexError) as e:
        # Kompleksowa analiza błędu
        variable_name = context.get('variable_name', 'object') if context else 'object'
        location = context.get('location', 'unknown') if context else 'unknown'
        
        logger.error(f"[SAFE_GET] Error accessing '{key}' on {variable_name} at {location}")
        logger.error(f"[SAFE_GET] Error type: {type(e).__name__}, Message: {str(e)}")
        
        # Analiza błędu
        if isinstance(e, AttributeError):
            analysis = analyze_attribute_error(e, obj, str(key), context)
            logger.error(f"[SAFE_GET] COMPREHENSIVE ANALYSIS:\n{format_analysis_report(analysis)}")
        
        # Analiza struktury danych
        logger.error(f"[SAFE_GET] DATA STRUCTURE ANALYSIS:\n{analyze_data_structure(obj, variable_name, max_depth=2)}")
        
        return default

def format_analysis_report(analysis: dict) -> str:
    """Formatuje raport analizy do czytelnego formatu."""
    lines = [
        "=" * 70,
        "ERROR ANALYSIS REPORT",
        "=" * 70,
        f"Error Type: {analysis['error_type']}",
        f"Error Message: {analysis['error_message']}",
        f"Missing Attribute: {analysis['missing_attribute']}",
        f"Object Type: {analysis['object_type']}",
        f"Object Module: {analysis['object_module']}",
        f"Is None: {analysis['is_none']}",
        f"Has .get() method: {analysis['has_get_method']}",
        "",
        "Data Structure:",
        analysis['data_structure'],
        "",
        "Recommendation:",
        analysis['recommendation'],
        "",
        "=" * 70
    ]
    return "\n".join(lines)

def log_error_with_analysis(error: Exception, obj: Any, context: dict = None, continue_execution: bool = True):
    """
    Loguje błąd z kompleksową analizą i kontynuuje wykonanie.
    
    Args:
        error: Wyjątek
        obj: Obiekt, na którym wystąpił błąd
        context: Kontekst (np. {'variable_name': 'grouped_crashes', 'location': 'cause_detector.py:801', 'function': 'detect_wer_causes'})
        continue_execution: Czy kontynuować wykonanie (domyślnie True)
    """
    variable_name = context.get('variable_name', 'object') if context else 'object'
    location = context.get('location', 'unknown') if context else 'unknown'
    function = context.get('function', 'unknown') if context else 'unknown'
    
    logger.error(f"[ERROR_ANALYZER] Error in {function} at {location}")
    logger.error(f"[ERROR_ANALYZER] Variable: {variable_name}")
    logger.error(f"[ERROR_ANALYZER] Error type: {type(error).__name__}")
    logger.error(f"[ERROR_ANALYZER] Error message: {str(error)}")
    
    # Kompleksowa analiza
    if isinstance(error, AttributeError):
        missing_attr = str(error).split("'")[1] if "'" in str(error) else "unknown"
        analysis = analyze_attribute_error(error, obj, missing_attr, context)
        logger.error(f"[ERROR_ANALYZER] COMPREHENSIVE ANALYSIS:\n{format_analysis_report(analysis)}")
    
    # Analiza struktury danych
    logger.error(f"[ERROR_ANALYZER] DATA STRUCTURE ANALYSIS:\n{analyze_data_structure(obj, variable_name, max_depth=2)}")
    
    # Stack trace (tylko ostatnie 5 linii)
    tb_lines = traceback.format_exc().split('\n')
    logger.error(f"[ERROR_ANALYZER] Stack trace (last 5 lines):")
    for line in tb_lines[-5:]:
        if line.strip():
            logger.error(f"[ERROR_ANALYZER]   {line}")
    
    if continue_execution:
        logger.warning(f"[ERROR_ANALYZER] Continuing execution despite error (resilient mode)")
    else:
        logger.error(f"[ERROR_ANALYZER] Execution will be stopped")

