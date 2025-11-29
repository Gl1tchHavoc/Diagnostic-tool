"""
BSOD Analyzer - analizuje ostatni BSOD i identyfikuje najbardziej prawdopodobne przyczyny.
"""
from datetime import datetime, timedelta
from collections import defaultdict
import re

# Konfiguracja
DEFAULT_TIME_WINDOW_MINUTES = 15
MAX_TIME_WINDOW_MINUTES = 60

# Wagi kategorii eventów
CATEGORY_WEIGHTS = {
    "GPU_DRIVER": 50,
    "DISK_ERROR": 50,
    "MEMORY_ERROR": 40,
    "DRIVER_ERROR": 40,
    "SYSTEM_CRITICAL": 30,
    "TXR_FAILURE": 50,
    "SERVICE_FAILURE": 25,
    "OTHER": 10
}

# Słowa kluczowe dla różnych kategorii
KEYWORDS = {
    "GPU_DRIVER": [
        "dxgkrnl", "nvlddmkm", "atikmpag", "igdkmd64", "amdkmdap",
        "gpu", "graphics", "display", "video", "directx"
    ],
    "DISK_ERROR": [
        "disk", "volume", "volsnap", "ntfs", "file system",
        "i/o error", "read error", "write error", "bad block",
        "event id 51", "event id 55", "event id 57", "event id 7"
    ],
    "MEMORY_ERROR": [
        "memory management", "page fault", "memory", "ram",
        "event id 1001", "bugcheck", "stop error"
    ],
    "DRIVER_ERROR": [
        "driver", "failed to load", "driver error", "driver crash"
    ],
    "TXR_FAILURE": [
        "txr", "transaction", "registry", "0xc00000a2", "event id 8193"
    ],
    "SERVICE_FAILURE": [
        "service", "failed to start", "service error", "event id 7000",
        "event id 7001", "event id 7023", "event id 7024"
    ],
    "SYSTEM_CRITICAL": [
        "critical", "stop error", "system crash", "fatal error"
    ]
}

# Eventy do wykluczenia (informacyjne, rutynowe)
EXCLUDE_KEYWORDS = [
    "heartbeat", "scheduled task", "login", "logoff", "user logged",
    "windows update", "defender", "antivirus scan", "backup",
    "maintenance", "idle", "timeout", "connection established"
]


def analyze_bsod(system_logs_data, hardware_data, drivers_data, bsod_data=None, 
                 time_window_minutes=DEFAULT_TIME_WINDOW_MINUTES):
    """
    Analizuje ostatni BSOD i identyfikuje najbardziej prawdopodobne przyczyny.
    
    Args:
        system_logs_data (dict): Przetworzone logi systemowe
        hardware_data (dict): Dane sprzętowe (CPU, RAM, GPU, disks)
        drivers_data (list): Lista driverów z informacjami
        bsod_data (dict, optional): Dane z bsod_dumps collector
        time_window_minutes (int): Okno czasowe do analizy przed BSOD (domyślnie 15 min)
    
    Returns:
        dict: Strukturyzowana analiza BSOD z confidence scores i rekomendacjami
    """
    result = {
        "bsod_found": False,
        "last_bsod_timestamp": None,
        "related_events": [],
        "top_causes": [],
        "recommendations": [],
        "hardware_correlations": [],
        "driver_correlations": []
    }
    
    # 1. Znajdź ostatni BSOD
    last_bsod = find_last_bsod(system_logs_data, bsod_data)
    
    if not last_bsod:
        result["message"] = "No BSOD events found in logs"
        return result
    
    result["bsod_found"] = True
    result["last_bsod_timestamp"] = last_bsod["timestamp"]
    result["bsod_details"] = {
        "event_id": last_bsod.get("event_id", "N/A"),
        "message": last_bsod.get("message", "")[:500],  # Skróć długie wiadomości
        "level": last_bsod.get("level", "Critical")
    }
    
    # 2. Parsuj timestamp BSOD
    bsod_time = parse_timestamp(last_bsod["timestamp"])
    if not bsod_time:
        result["message"] = "Could not parse BSOD timestamp"
        return result
    
    # 3. Znajdź candidate events w oknie czasowym
    time_window = timedelta(minutes=min(time_window_minutes, MAX_TIME_WINDOW_MINUTES))
    window_start = bsod_time - time_window
    
    # Zbierz wszystkie eventy z logów
    all_events = collect_all_events(system_logs_data)
    
    # Filtruj eventy w oknie czasowym
    candidate_events = filter_events_by_time(all_events, window_start, bsod_time)
    
    # 4. Kategoryzuj i oblicz confidence scores
    categorized_events = categorize_events(candidate_events)
    scored_events = calculate_confidence_scores(
        categorized_events, bsod_time, time_window_minutes
    )
    
    # 5. Koreluj z hardware i driver info
    hardware_correlations = correlate_with_hardware(scored_events, hardware_data)
    driver_correlations = correlate_with_drivers(scored_events, drivers_data)
    
    # 6. Oblicz top causes (kumulatywny confidence)
    top_causes = calculate_top_causes(scored_events, hardware_correlations, driver_correlations)
    
    # 7. Generuj rekomendacje
    recommendations = generate_bsod_recommendations(
        top_causes, hardware_correlations, driver_correlations, scored_events
    )
    
    # Sortuj eventy według confidence (najwyższe pierwsze)
    scored_events.sort(key=lambda x: x.get("confidence_score", 0), reverse=True)
    
    result["related_events"] = scored_events[:20]  # Top 20 eventów
    result["top_causes"] = top_causes[:5]  # Top 5 przyczyn
    result["recommendations"] = recommendations
    result["hardware_correlations"] = hardware_correlations
    result["driver_correlations"] = driver_correlations
    result["analysis_window"] = {
        "start": window_start.isoformat(),
        "end": bsod_time.isoformat(),
        "minutes": time_window_minutes
    }
    
    return result


def find_last_bsod(system_logs_data, bsod_data=None):
    """
    Znajduje ostatni BSOD w logach.
    
    Returns:
        dict: Ostatni BSOD event lub None
    """
    bsod_keywords = ["bugcheck", "stop error", "bsod", "blue screen", 
                     "system crash", "unexpected shutdown"]
    
    all_bsod_events = []
    
    # Sprawdź system_logs_data
    if isinstance(system_logs_data, dict):
        for category, logs in system_logs_data.items():
            if isinstance(logs, list):
                for log in logs:
                    if isinstance(log, dict):
                        message = log.get("message", "").lower()
                        level = log.get("level", "").lower()
                        event_id = str(log.get("event_id", "")).lower()
                        
                        # Sprawdź czy to BSOD
                        is_bsod = (
                            any(keyword in message for keyword in bsod_keywords) or
                            level in ["critical", "error"] and (
                                "1001" in event_id or "41" in event_id or
                                "6008" in event_id
                            )
                        )
                        
                        if is_bsod:
                            all_bsod_events.append(log)
    
    # Sprawdź bsod_data jeśli dostępne
    if bsod_data and isinstance(bsod_data, dict):
        recent_crashes = bsod_data.get("recent_crashes", [])
        if recent_crashes:
            for crash in recent_crashes:
                if isinstance(crash, dict):
                    all_bsod_events.append({
                        "timestamp": crash.get("timestamp", ""),
                        "message": crash.get("message", "BSOD detected"),
                        "event_id": crash.get("event_id", "N/A"),
                        "level": "Critical"
                    })
    
    if not all_bsod_events:
        return None
    
    # Sortuj według timestamp (najnowsze pierwsze)
    all_bsod_events.sort(
        key=lambda x: parse_timestamp(x.get("timestamp", "")) or datetime.min,
        reverse=True
    )
    
    return all_bsod_events[0] if all_bsod_events else None


def collect_all_events(system_logs_data):
    """
    Zbiera wszystkie eventy z logów systemowych.
    
    Returns:
        list: Lista wszystkich eventów
    """
    all_events = []
    
    if isinstance(system_logs_data, dict):
        for category, logs in system_logs_data.items():
            if isinstance(logs, list):
                for log in logs:
                    if isinstance(log, dict):
                        # Pomiń błędy parsowania
                        if "error" in log:
                            continue
                        all_events.append(log)
    
    return all_events


def filter_events_by_time(events, window_start, window_end):
    """
    Filtruje eventy w oknie czasowym i wyklucza nieistotne.
    
    Args:
        events (list): Lista eventów
        window_start (datetime): Początek okna czasowego
        window_end (datetime): Koniec okna czasowego (BSOD time)
    
    Returns:
        list: Przefiltrowane eventy
    """
    filtered = []
    
    for event in events:
        # Pomiń jeśli brak timestamp
        event_time = parse_timestamp(event.get("timestamp", ""))
        if not event_time:
            continue
        
        # Sprawdź czy w oknie czasowym
        if window_start <= event_time <= window_end:
            # Wyklucz rutynowe/informacyjne eventy
            message = event.get("message", "").lower()
            if not should_exclude_event(message):
                filtered.append(event)
    
    return filtered


def should_exclude_event(message):
    """
    Sprawdza czy event powinien być wykluczony (rutynowy/informacyjny).
    
    Returns:
        bool: True jeśli wykluczyć, False jeśli uwzględnić
    """
    message_lower = message.lower()
    
    # Sprawdź czy zawiera słowa kluczowe do wykluczenia
    for exclude_keyword in EXCLUDE_KEYWORDS:
        if exclude_keyword in message_lower:
            return True
    
    return False


def categorize_events(events):
    """
    Kategoryzuje eventy według typu problemu.
    
    Returns:
        list: Eventy z dodaną kategorią
    """
    categorized = []
    
    for event in events:
        message = event.get("message", "").lower()
        event_id = str(event.get("event_id", "")).lower()
        level = event.get("level", "").lower()
        
        category = "OTHER"
        
        # Sprawdź każdą kategorię
        for cat_name, keywords in KEYWORDS.items():
            if any(keyword in message or keyword in event_id for keyword in keywords):
                category = cat_name
                break
        
        event["detected_category"] = category
        categorized.append(event)
    
    return categorized


def calculate_confidence_scores(events, bsod_time, time_window_minutes):
    """
    Oblicza confidence scores dla każdego eventu.
    
    Args:
        events (list): Kategoryzowane eventy
        bsod_time (datetime): Czas BSOD
        time_window_minutes (int): Okno czasowe w minutach
    
    Returns:
        list: Eventy z confidence scores
    """
    scored_events = []
    
    # Policz powtórzenia kategorii
    category_counts = defaultdict(int)
    for event in events:
        category = event.get("detected_category", "OTHER")
        category_counts[category] += 1
    
    for event in events:
        category = event.get("detected_category", "OTHER")
        base_score = CATEGORY_WEIGHTS.get(category, 10)
        
        # Zwiększ score jeśli kategoria się powtarza
        if category_counts[category] > 1:
            base_score *= 1.2  # +20% za powtórzenia
        
        # Oblicz czas od BSOD
        event_time = parse_timestamp(event.get("timestamp", ""))
        if event_time:
            time_diff = (bsod_time - event_time).total_seconds() / 60  # minuty
            
            # Zmniejsz score jeśli event jest daleko od BSOD
            if time_diff > 30:
                base_score *= 0.7  # -30% jeśli >30 min
            elif time_diff > 15:
                base_score *= 0.85  # -15% jeśli >15 min
        
        # Normalizuj do 0-100%
        confidence = min(100.0, base_score)
        
        event["confidence_score"] = round(confidence, 2)
        event["time_from_bsod_minutes"] = round(time_diff, 2) if event_time else None
        scored_events.append(event)
    
    return scored_events


def correlate_with_hardware(scored_events, hardware_data):
    """
    Koreluje eventy z danymi sprzętowymi.
    
    Returns:
        list: Korelacje hardware
    """
    correlations = []
    
    if not isinstance(hardware_data, dict):
        return correlations
    
    # Sprawdź GPU
    gpu_issues = []
    gpu_data = hardware_data.get("gpu", [])
    if gpu_data:
        for gpu in gpu_data:
            if isinstance(gpu, dict):
                temp = gpu.get("temperature", 0)
                if temp > 85:  # Wysoka temperatura GPU
                    gpu_issues.append(f"GPU temperature high: {temp}°C")
    
    # Sprawdź CPU
    cpu_issues = []
    cpu_data = hardware_data.get("cpu", {})
    if isinstance(cpu_data, dict):
        usage = cpu_data.get("usage_percent", 0)
        if usage > 95:
            cpu_issues.append(f"CPU usage very high: {usage}%")
    
    # Sprawdź RAM
    ram_issues = []
    ram_data = hardware_data.get("ram", {})
    if isinstance(ram_data, dict):
        percent = ram_data.get("percent", 0)
        if percent > 95:
            ram_issues.append(f"RAM usage very high: {percent}%")
    
    # Sprawdź dyski
    disk_issues = []
    disks_data = hardware_data.get("disks", [])
    if disks_data:
        for disk in disks_data:
            if isinstance(disk, dict):
                status = disk.get("status", "").lower()
                if "fail" in status or "error" in status:
                    disk_issues.append(f"Disk {disk.get('device', 'unknown')} status: {status}")
    
    # Znajdź eventy związane z hardware
    for event in scored_events:
        category = event.get("detected_category", "")
        message = event.get("message", "").lower()
        
        if category == "GPU_DRIVER" and gpu_issues:
            correlations.append({
                "event": event.get("event_id", "N/A"),
                "hardware_issue": gpu_issues[0],
                "correlation_type": "GPU"
            })
        
        if category == "DISK_ERROR" and disk_issues:
            correlations.append({
                "event": event.get("event_id", "N/A"),
                "hardware_issue": disk_issues[0],
                "correlation_type": "DISK"
            })
    
    return correlations


def correlate_with_drivers(scored_events, drivers_data):
    """
    Koreluje eventy z informacjami o driverach.
    
    Returns:
        list: Korelacje driverów
    """
    correlations = []
    
    if not isinstance(drivers_data, list):
        return correlations
    
    # Stwórz słownik driverów po nazwie
    drivers_dict = {}
    for driver in drivers_data:
        if isinstance(driver, dict):
            name = driver.get("name", "").lower()
            drivers_dict[name] = driver
    
    # Sprawdź eventy związane z driverami
    for event in scored_events:
        category = event.get("detected_category", "")
        message = event.get("message", "").lower()
        
        if category in ["GPU_DRIVER", "DRIVER_ERROR"]:
            # Znajdź driver w wiadomości
            for driver_name, driver_info in drivers_dict.items():
                if driver_name in message:
                    driver_status = driver_info.get("status", "").lower()
                    driver_version = driver_info.get("version", "unknown")
                    
                    correlations.append({
                        "event": event.get("event_id", "N/A"),
                        "driver_name": driver_name,
                        "driver_status": driver_status,
                        "driver_version": driver_version,
                        "correlation_type": "DRIVER",
                        "is_problematic": "fail" in driver_status or "error" in driver_status
                    })
                    break
    
    return correlations


def calculate_top_causes(scored_events, hardware_correlations, driver_correlations):
    """
    Oblicza top causes na podstawie kumulatywnego confidence.
    
    Returns:
        list: Top causes z kumulatywnym confidence
    """
    cause_scores = defaultdict(float)
    cause_details = defaultdict(list)
    
    # Zbierz scores według kategorii
    for event in scored_events:
        category = event.get("detected_category", "OTHER")
        confidence = event.get("confidence_score", 0)
        cause_scores[category] += confidence
        cause_details[category].append(event)
    
    # Zwiększ score jeśli są korelacje hardware/driver
    for corr in hardware_correlations:
        corr_type = corr.get("correlation_type", "")
        if corr_type == "GPU":
            cause_scores["GPU_DRIVER"] += 15
        elif corr_type == "DISK":
            cause_scores["DISK_ERROR"] += 15
    
    for corr in driver_correlations:
        if corr.get("is_problematic", False):
            cause_scores["DRIVER_ERROR"] += 10
    
    # Normalizuj i sortuj
    top_causes = []
    for cause, total_score in cause_scores.items():
        # Normalizuj do 0-100%
        normalized_score = min(100.0, total_score)
        
        top_causes.append({
            "cause": cause,
            "confidence": round(normalized_score, 2),
            "related_events_count": len(cause_details.get(cause, [])),
            "description": get_cause_description(cause)
        })
    
    top_causes.sort(key=lambda x: x["confidence"], reverse=True)
    
    return top_causes


def get_cause_description(cause):
    """Zwraca opis przyczyny."""
    descriptions = {
        "GPU_DRIVER": "Graphics driver issue or GPU hardware problem",
        "DISK_ERROR": "Disk I/O error, bad sectors, or storage controller issue",
        "MEMORY_ERROR": "RAM problem or memory management issue",
        "DRIVER_ERROR": "Driver failure or incompatibility",
        "TXR_FAILURE": "Registry transaction failure, possible disk corruption",
        "SERVICE_FAILURE": "Critical system service failure",
        "SYSTEM_CRITICAL": "Critical system error",
        "OTHER": "Other system issue"
    }
    return descriptions.get(cause, "Unknown issue")


def generate_bsod_recommendations(top_causes, hardware_correlations, driver_correlations, scored_events):
    """
    Generuje rekomendacje na podstawie analizy.
    
    Returns:
        list: Lista rekomendacji z priorytetami
    """
    recommendations = []
    seen_actions = set()
    
    # Rekomendacje na podstawie top causes
    for cause in top_causes[:3]:  # Top 3 causes
        cause_type = cause.get("cause", "")
        confidence = cause.get("confidence", 0)
        
        if cause_type == "GPU_DRIVER":
            if "Update GPU drivers" not in seen_actions:
                recommendations.append({
                    "priority": "CRITICAL" if confidence > 70 else "HIGH",
                    "action": "Update GPU drivers to latest version",
                    "description": "GPU driver issues are a common cause of BSODs",
                    "confidence": confidence
                })
                seen_actions.add("Update GPU drivers")
            
            if "Check GPU temperature" not in seen_actions:
                recommendations.append({
                    "priority": "HIGH",
                    "action": "Check GPU temperature and cooling",
                    "description": "Overheating can cause GPU driver crashes",
                    "confidence": confidence
                })
                seen_actions.add("Check GPU temperature")
        
        elif cause_type == "DISK_ERROR":
            if "Run chkdsk" not in seen_actions:
                recommendations.append({
                    "priority": "CRITICAL" if confidence > 70 else "HIGH",
                    "action": "Run chkdsk /f /r on affected drive",
                    "description": "Disk errors can cause system crashes",
                    "confidence": confidence
                })
                seen_actions.add("Run chkdsk")
            
            if "Check SMART status" not in seen_actions:
                recommendations.append({
                    "priority": "HIGH",
                    "action": "Check disk SMART status",
                    "description": "SMART errors indicate physical disk failure",
                    "confidence": confidence
                })
                seen_actions.add("Check SMART status")
        
        elif cause_type == "MEMORY_ERROR":
            if "Run memory diagnostic" not in seen_actions:
                recommendations.append({
                    "priority": "CRITICAL" if confidence > 70 else "HIGH",
                    "action": "Run Windows Memory Diagnostic",
                    "description": "Memory errors can cause BSODs",
                    "confidence": confidence
                })
                seen_actions.add("Run memory diagnostic")
        
        elif cause_type == "TXR_FAILURE":
            if "Run DISM" not in seen_actions:
                recommendations.append({
                    "priority": "CRITICAL",
                    "action": "Run DISM /Online /Cleanup-Image /RestoreHealth",
                    "description": "TxR failures indicate system file corruption",
                    "confidence": confidence
                })
                seen_actions.add("Run DISM")
            
            if "Run sfc" not in seen_actions:
                recommendations.append({
                    "priority": "HIGH",
                    "action": "Run sfc /scannow",
                    "description": "Scan and repair system files",
                    "confidence": confidence
                })
                seen_actions.add("Run sfc")
    
    # Dodaj ogólne rekomendacje
    if "Check minidump files" not in seen_actions:
        recommendations.append({
            "priority": "MEDIUM",
            "action": "Check minidump files in C:\\Windows\\Minidump",
            "description": "Analyze crash dumps for specific error codes",
            "confidence": 50
        })
        seen_actions.add("Check minidump files")
    
    # Sortuj według priorytetu
    priority_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    recommendations.sort(key=lambda x: priority_order.get(x.get("priority", "MEDIUM"), 99))
    
    return recommendations


def parse_timestamp(timestamp_str):
    """
    Parsuje timestamp z różnych formatów do datetime.
    
    Returns:
        datetime: Parsed timestamp lub None
    """
    if not timestamp_str:
        return None
    
    # Różne formaty timestampów
    formats = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y/%m/%d %H:%M:%S",
    ]
    
    # Wyczyść timestamp
    timestamp_clean = timestamp_str.strip()
    
    # Usuń milisekundy jeśli są
    if '.' in timestamp_clean:
        timestamp_clean = timestamp_clean.split('.')[0]
    
    # Usuń 'Z' jeśli jest
    timestamp_clean = timestamp_clean.replace('Z', '')
    
    for fmt in formats:
        try:
            return datetime.strptime(timestamp_clean, fmt)
        except (ValueError, TypeError):
            continue
    
    # Ostateczny fallback - próbuj podstawowe parsowanie
    try:
        # Usuń wszystko po spacji jeśli jest
        parts = timestamp_str.split()
        if parts:
            date_part = parts[0]
            time_part = parts[1] if len(parts) > 1 else "00:00:00"
            combined = f"{date_part} {time_part}"
            return datetime.strptime(combined, "%Y-%m-%d %H:%M:%S")
    except:
        pass
    
    return None

