"""
Monitor wydajności - Faza 2.
Zbiera i analizuje metryki wydajności dla collectorów i procesorów.
"""
from datetime import datetime
from typing import Dict, List, Optional
from collections import defaultdict
from utils.logger import get_logger

logger = get_logger()


class PerformanceMonitor:
    """Monitor wydajności dla collectorów i procesorów."""
    
    def __init__(self):
        """Inicjalizuje monitor wydajności."""
        self.collector_metrics: Dict[str, List[Dict]] = defaultdict(list)
        self.processor_metrics: Dict[str, List[Dict]] = defaultdict(list)
        self.session_start = datetime.now()
        logger.info("[PERFORMANCE] Performance monitor initialized")
    
    def record_collector(self, collector_name: str, execution_time_ms: int, 
                        status: str, data_count: int = 0, error: Optional[str] = None):
        """
        Rejestruje metryki collectora.
        
        Args:
            collector_name: Nazwa collectora
            execution_time_ms: Czas wykonania w milisekundach
            status: Status (Collected/Error)
            data_count: Liczba zebranych elementów
            error: Komunikat błędu (jeśli status=Error)
        """
        metric = {
            "timestamp": datetime.now().isoformat(),
            "execution_time_ms": execution_time_ms,
            "status": status,
            "data_count": data_count,
            "error": error
        }
        self.collector_metrics[collector_name].append(metric)
        logger.debug(f"[PERFORMANCE] Collector {collector_name}: {execution_time_ms}ms, status={status}")
    
    def record_processor(self, processor_name: str, execution_time_ms: int,
                        status: str, errors: int = 0, warnings: int = 0):
        """
        Rejestruje metryki procesora.
        
        Args:
            processor_name: Nazwa procesora
            execution_time_ms: Czas wykonania w milisekundach
            status: Status (Collected/Error)
            errors: Liczba błędów
            warnings: Liczba ostrzeżeń
        """
        metric = {
            "timestamp": datetime.now().isoformat(),
            "execution_time_ms": execution_time_ms,
            "status": status,
            "errors": errors,
            "warnings": warnings
        }
        self.processor_metrics[processor_name].append(metric)
        logger.debug(f"[PERFORMANCE] Processor {processor_name}: {execution_time_ms}ms, status={status}")
    
    def get_collector_stats(self, collector_name: str) -> Dict:
        """
        Zwraca statystyki dla collectora.
        
        Args:
            collector_name: Nazwa collectora
        
        Returns:
            dict: Statystyki (avg_time, min_time, max_time, success_rate, total_runs)
        """
        metrics = self.collector_metrics.get(collector_name, [])
        if not metrics:
            return {
                "avg_time_ms": 0,
                "min_time_ms": 0,
                "max_time_ms": 0,
                "success_rate": 0.0,
                "total_runs": 0
            }
        
        times = [m["execution_time_ms"] for m in metrics]
        successes = sum(1 for m in metrics if m["status"] == "Collected")
        
        return {
            "avg_time_ms": sum(times) / len(times),
            "min_time_ms": min(times),
            "max_time_ms": max(times),
            "success_rate": successes / len(metrics) if metrics else 0.0,
            "total_runs": len(metrics)
        }
    
    def get_all_stats(self) -> Dict:
        """
        Zwraca statystyki dla wszystkich collectorów i procesorów.
        
        Returns:
            dict: Wszystkie statystyki
        """
        collector_stats = {}
        for name in self.collector_metrics.keys():
            collector_stats[name] = self.get_collector_stats(name)
        
        processor_stats = {}
        for name, metrics in self.processor_metrics.items():
            if metrics:
                times = [m["execution_time_ms"] for m in metrics]
                processor_stats[name] = {
                    "avg_time_ms": sum(times) / len(times),
                    "min_time_ms": min(times),
                    "max_time_ms": max(times),
                    "total_runs": len(metrics)
                }
        
        session_duration = (datetime.now() - self.session_start).total_seconds()
        
        return {
            "session_start": self.session_start.isoformat(),
            "session_duration_seconds": session_duration,
            "collectors": collector_stats,
            "processors": processor_stats,
            "summary": {
                "total_collector_runs": sum(len(m) for m in self.collector_metrics.values()),
                "total_processor_runs": sum(len(m) for m in self.processor_metrics.values())
            }
        }
    
    def log_summary(self):
        """Loguje podsumowanie wydajności."""
        stats = self.get_all_stats()
        logger.info("=" * 60)
        logger.info("[PERFORMANCE] Performance Summary")
        logger.info("=" * 60)
        logger.info(f"Session duration: {stats['session_duration_seconds']:.2f}s")
        logger.info(f"Total collector runs: {stats['summary']['total_collector_runs']}")
        logger.info(f"Total processor runs: {stats['summary']['total_processor_runs']}")
        
        # Top 5 najwolniejszych collectorów
        collector_avgs = [
            (name, s["avg_time_ms"])
            for name, s in stats["collectors"].items()
            if s["total_runs"] > 0
        ]
        collector_avgs.sort(key=lambda x: x[1], reverse=True)
        
        if collector_avgs:
            logger.info("\nTop 5 slowest collectors:")
            for name, avg_time in collector_avgs[:5]:
                logger.info(f"  {name}: {avg_time:.0f}ms avg")
        
        logger.info("=" * 60)


# Globalna instancja monitora
_performance_monitor: Optional[PerformanceMonitor] = None

def get_performance_monitor() -> PerformanceMonitor:
    """Zwraca globalną instancję monitora wydajności."""
    global _performance_monitor
    if _performance_monitor is None:
        _performance_monitor = PerformanceMonitor()
    return _performance_monitor

