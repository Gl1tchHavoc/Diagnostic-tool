"""
Event de-duplication utility.
Groups identical events occurring at the same time and counts occurrences.
"""
from collections import defaultdict
from datetime import datetime, timedelta
from utils.logger import get_logger

logger = get_logger()

# Okno czasowe dla de-duplikacji (zdarzenia w tej samej sekundzie są traktowane jako duplikaty)
DEDUP_TIME_WINDOW_SECONDS = 1

def deduplicate_events(events, time_window_seconds=DEDUP_TIME_WINDOW_SECONDS):
    """
    De-duplikuje zdarzenia, grupując identyczne zdarzenia w tym samym oknie czasowym.
    
    Args:
        events (list): Lista zdarzeń (dict z kluczami: message, timestamp, event_id, etc.)
        time_window_seconds (int): Okno czasowe w sekundach dla de-duplikacji
    
    Returns:
        list: Lista zdarzeń z atrybutem 'occurrences' dla duplikatów
    """
    if not events:
        return []
    
    # Grupuj zdarzenia według klucza (message + event_id)
    event_groups = defaultdict(list)
    
    for event in events:
        # Utwórz klucz dla grupowania
        message = str(event.get('message', '')).strip()
        event_id = str(event.get('event_id', '')).strip()
        key = f"{event_id}:{message[:100]}"  # Użyj pierwszych 100 znaków wiadomości
        
        event_groups[key].append(event)
    
    deduplicated = []
    
    for key, group in event_groups.items():
        if len(group) == 1:
            # Pojedyncze zdarzenie - dodaj bez zmian
            event = group[0].copy()
            event['occurrences'] = 1
            deduplicated.append(event)
        else:
            # Wiele zdarzeń - sprawdź czy są w tym samym oknie czasowym
            grouped_by_time = group_by_time_window(group, time_window_seconds)
            
            for time_group in grouped_by_time:
                if len(time_group) == 1:
                    event = time_group[0].copy()
                    event['occurrences'] = 1
                    deduplicated.append(event)
                else:
                    # Zdarzenia w tym samym oknie czasowym - połącz
                    main_event = time_group[0].copy()
                    main_event['occurrences'] = len(time_group)
                    
                    # Dodaj informacje o czasach wystąpień
                    timestamps = [e.get('timestamp', '') for e in time_group]
                    main_event['occurrence_timestamps'] = timestamps
                    main_event['first_occurrence'] = min(timestamps) if timestamps else main_event.get('timestamp', '')
                    main_event['last_occurrence'] = max(timestamps) if timestamps else main_event.get('timestamp', '')
                    
                    deduplicated.append(main_event)
                    
                    logger.debug(f"[DEDUP] Deduplicated {len(time_group)} events: {key[:50]}... (occurrences: {len(time_group)})")
    
    logger.info(f"[DEDUP] Deduplicated {len(events)} events to {len(deduplicated)} unique events")
    
    return deduplicated

def group_by_time_window(events, window_seconds):
    """
    Grupuje zdarzenia według okna czasowego.
    
    Args:
        events (list): Lista zdarzeń
        window_seconds (int): Okno czasowe w sekundach
    
    Returns:
        list: Lista grup zdarzeń
    """
    if not events:
        return []
    
    # Parsuj timestamps
    events_with_time = []
    for event in events:
        timestamp_str = event.get('timestamp', '')
        parsed_time = parse_timestamp(timestamp_str)
        if parsed_time:
            events_with_time.append((parsed_time, event))
        else:
            # Jeśli nie można sparsować, traktuj jako osobne zdarzenie
            events_with_time.append((None, event))
    
    # Sortuj według czasu
    events_with_time.sort(key=lambda x: x[0] if x[0] else datetime.min)
    
    # Grupuj według okna czasowego
    groups = []
    current_group = []
    current_group_time = None
    
    for event_time, event in events_with_time:
        if event_time is None:
            # Zdarzenie bez czasu - osobna grupa
            if current_group:
                groups.append([e for _, e in current_group])
                current_group = []
            groups.append([event])
            continue
        
        if current_group_time is None:
            # Pierwsze zdarzenie w grupie
            current_group_time = event_time
            current_group = [(event_time, event)]
        else:
            # Sprawdź czy zdarzenie jest w oknie czasowym
            time_diff = abs((event_time - current_group_time).total_seconds())
            if time_diff <= window_seconds:
                # W tym samym oknie - dodaj do grupy
                current_group.append((event_time, event))
            else:
                # Nowe okno - zapisz poprzednią grupę i zacznij nową
                if current_group:
                    groups.append([e for _, e in current_group])
                current_group_time = event_time
                current_group = [(event_time, event)]
    
    # Dodaj ostatnią grupę
    if current_group:
        groups.append([e for _, e in current_group])
    
    return groups

def parse_timestamp(timestamp_str):
    """
    Parsuje timestamp string do datetime object.
    
    Args:
        timestamp_str (str): String z timestampem
    
    Returns:
        datetime or None: Sparsowany czas lub None
    """
    if not timestamp_str:
        return None
    
    # Różne formaty timestampów
    formats = [
        '%Y-%m-%d %H:%M:%S',
        '%Y-%m-%dT%H:%M:%S',
        '%Y-%m-%dT%H:%M:%S.%f',
        '%m/%d/%Y %H:%M:%S %p',
        '%m/%d/%Y %I:%M:%S %p',
        '%Y-%m-%d %H:%M:%S.%f'
    ]
    
    for fmt in formats:
        try:
            return datetime.strptime(timestamp_str, fmt)
        except (ValueError, TypeError):
            continue
    
    # Spróbuj ISO format
    try:
        return datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
    except:
        pass
    
    return None

