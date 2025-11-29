"""
Progress Calculator - agreguje postęp wszystkich kolektorów i subtasków.
"""
from utils.logger import get_logger

logger = get_logger()

class ProgressCalculator:
    """
    Kalkulator postępu globalnego na podstawie postępu kolektorów.
    
    Oblicza średnią ważoną z lokalnych % postępu wszystkich kolektorów.
    """
    
    def __init__(self, collectors, weights=None):
        """
        Inicjalizuje kalkulator postępu.
        
        Args:
            collectors (list): Lista kolektorów (BaseCollector)
            weights (dict, optional): Słownik wag dla każdego kolektora {name: weight}
                                     Jeśli None, wszystkie kolektory mają wagę 1.0
        """
        self.collectors = collectors
        self.weights = weights or {}
        self._logger = get_logger()
    
    def get_progress(self):
        """
        Oblicza globalny postęp jako średnią ważoną z postępu kolektorów.
        
        Returns:
            dict: {
                'global_progress': float,  # 0-100%
                'collectors_progress': dict,  # {name: progress}
                'total_weight': float,
                'weighted_sum': float
            }
        """
        if not self.collectors:
            return {
                'global_progress': 0.0,
                'collectors_progress': {},
                'total_weight': 0.0,
                'weighted_sum': 0.0
            }
        
        weighted_sum = 0.0
        total_weight = 0.0
        collectors_progress = {}
        
        for collector in self.collectors:
            collector_name = collector.name if hasattr(collector, 'name') else str(collector)
            collector_progress = collector.progress if hasattr(collector, 'progress') else 0.0
            
            # Pobierz wagę dla tego kolektora (domyślnie 1.0)
            weight = self.weights.get(collector_name, 1.0)
            
            weighted_sum += collector_progress * weight
            total_weight += weight
            
            collectors_progress[collector_name] = {
                'progress': collector_progress,
                'weight': weight,
                'status': collector.status if hasattr(collector, 'status') else 'UNKNOWN'
            }
        
        # Oblicz globalny postęp
        if total_weight > 0:
            global_progress = weighted_sum / total_weight
        else:
            global_progress = 0.0
        
        return {
            'global_progress': round(global_progress, 2),
            'collectors_progress': collectors_progress,
            'total_weight': total_weight,
            'weighted_sum': weighted_sum
        }
    
    def get_detailed_progress(self):
        """
        Zwraca szczegółowy postęp z informacjami o subtaskach.
        
        Returns:
            dict: Szczegółowy postęp z subtaskami
        """
        progress_info = self.get_progress()
        
        # Dodaj informacje o subtaskach
        subtasks_info = {}
        for collector in self.collectors:
            collector_name = collector.name if hasattr(collector, 'name') else str(collector)
            if hasattr(collector, 'subtasks') and collector.subtasks:
                subtasks_info[collector_name] = collector.subtasks
        
        progress_info['subtasks'] = subtasks_info
        
        return progress_info
    
    def is_complete(self):
        """
        Sprawdza czy wszystkie kolektory są zakończone.
        
        Returns:
            bool: True jeśli wszystkie kolektory mają status "DONE" lub "ERROR"
        """
        for collector in self.collectors:
            if hasattr(collector, 'status'):
                if collector.status not in ["DONE", "ERROR"]:
                    return False
            else:
                return False
        return True
    
    def get_status_summary(self):
        """
        Zwraca podsumowanie statusów kolektorów.
        
        Returns:
            dict: {
                'pending': int,
                'running': int,
                'done': int,
                'error': int,
                'total': int
            }
        """
        summary = {
            'pending': 0,
            'running': 0,
            'done': 0,
            'error': 0,
            'total': len(self.collectors)
        }
        
        for collector in self.collectors:
            if hasattr(collector, 'status'):
                status = collector.status.lower()
                if status in summary:
                    summary[status] += 1
        
        return summary

