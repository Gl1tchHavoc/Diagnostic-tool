"""
Collector informacji o procesach - zbiera dane o problematycznych procesach.
"""
import psutil
import sys
from datetime import datetime

def collect():
    """
    Zbiera informacje o procesach, szczególnie tych problematycznych.
    """
    processes_data = {
        "all_processes": [],
        "high_cpu": [],
        "high_memory": [],
        "suspicious": [],
        "summary": {}
    }
    
    try:
        all_procs = []
        high_cpu_procs = []
        high_memory_procs = []
        
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'memory_info', 'status', 'create_time']):
            try:
                proc_info = proc.info
                
                # Pobierz więcej szczegółów
                try:
                    proc_info['exe'] = proc.exe() if proc.exe() else "N/A"
                    proc_info['cmdline'] = ' '.join(proc.cmdline()) if proc.cmdline() else "N/A"
                    proc_info['username'] = proc.username() if proc.username() else "N/A"
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    proc_info['exe'] = "Access Denied"
                    proc_info['cmdline'] = "Access Denied"
                    proc_info['username'] = "Access Denied"
                
                # Oblicz czas działania
                if proc_info.get('create_time'):
                    try:
                        create_time = datetime.fromtimestamp(proc_info['create_time'])
                        uptime = datetime.now() - create_time
                        proc_info['uptime_seconds'] = uptime.total_seconds()
                    except:
                        proc_info['uptime_seconds'] = 0
                
                all_procs.append(proc_info)
                
                # Identyfikuj problematyczne procesy
                cpu_percent = proc_info.get('cpu_percent', 0) or 0
                memory_percent = proc_info.get('memory_percent', 0) or 0
                
                if cpu_percent > 50:  # Wysokie użycie CPU
                    high_cpu_procs.append({
                        "pid": proc_info.get('pid'),
                        "name": proc_info.get('name'),
                        "cpu_percent": cpu_percent,
                        "memory_percent": memory_percent,
                        "exe": proc_info.get('exe', 'N/A')
                    })
                
                if memory_percent > 10:  # Wysokie użycie pamięci (>10%)
                    high_memory_procs.append({
                        "pid": proc_info.get('pid'),
                        "name": proc_info.get('name'),
                        "cpu_percent": cpu_percent,
                        "memory_percent": memory_percent,
                        "memory_mb": proc_info.get('memory_info', {}).get('rss', 0) / (1024 * 1024) if proc_info.get('memory_info') else 0,
                        "exe": proc_info.get('exe', 'N/A')
                    })
                
                # Wykryj podejrzane procesy
                name = proc_info.get('name', '').lower()
                exe = proc_info.get('exe', '').lower()
                if any(suspicious in name or suspicious in exe for suspicious in ['temp', 'tmp', 'random', 'unknown']):
                    processes_data["suspicious"].append({
                        "pid": proc_info.get('pid'),
                        "name": proc_info.get('name'),
                        "exe": proc_info.get('exe', 'N/A'),
                        "reason": "Suspicious name or path"
                    })
                
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        
        processes_data["all_processes"] = all_procs[:100]  # Ogranicz do 100 najważniejszych
        processes_data["high_cpu"] = sorted(high_cpu_procs, key=lambda x: x.get('cpu_percent', 0), reverse=True)[:20]
        processes_data["high_memory"] = sorted(high_memory_procs, key=lambda x: x.get('memory_percent', 0), reverse=True)[:20]
        
        # Podsumowanie
        processes_data["summary"] = {
            "total_processes": len(all_procs),
            "high_cpu_count": len(high_cpu_procs),
            "high_memory_count": len(high_memory_procs),
            "suspicious_count": len(processes_data["suspicious"])
        }
        
    except Exception as e:
        processes_data["error"] = f"Failed to collect processes: {type(e).__name__}: {e}"
    
    return processes_data

