"""
Event Correlation Engine - tworzy timeline i mapuje zależności między eventami.
Używa priorytetów: WHEA > BugCheck > Kernel-Power > Disk > Driver
Generuje finalne logiczne "Root Cause".
"""
from collections import defaultdict
from datetime import datetime, timedelta

from utils.event_deduplicator import deduplicate_events
from utils.logger import get_logger

logger = get_logger()

# Priorytety eventów (wyższy = ważniejszy)
EVENT_PRIORITIES = {
    "WHEA": 100,
    "HARDWARE_FAILURE": 100,
    "BUGCHECK": 90,
    "KERNEL_POWER": 80,
    "DISK_ERROR": 70,
    "SMART_ERROR": 70,
    "TXR_FAILURE": 65,
    "DRIVER_ERROR": 60,
    "GPU_DRIVER": 55,
    "MEMORY_ERROR": 50,
    "SERVICE_FAILURE": 40,
    "NETWORK_WARNING": 20,
    "SYSTEM_WARNING": 10,
    "OTHER": 5
}


def correlate_events(processed_data, time_window_minutes=10):
    """
    Koreluje eventy z różnych źródeł i tworzy timeline.

    Args:
        processed_data (dict): Przetworzone dane z wszystkich procesorów
        time_window_minutes (int): Okno czasowe do korelacji (domyślnie 10 min)

    Returns:
        dict: {
            'timeline': [...],
            'root_causes': [...],
            'correlations': [...]
        }
    """
    logger.info("[EVENT_CORRELATION] Starting event correlation")

    # Zbierz wszystkie eventy z różnych źródeł
    all_events = []

    for processor_name, processor_data in processed_data.items():
        if not isinstance(processor_data, dict):
            continue

        # Critical issues
        critical = processor_data.get("critical_issues", [])
        for event in critical:
            event['source'] = processor_name
            event['priority'] = get_event_priority(event)
            all_events.append(event)

        # Critical events
        critical_events = processor_data.get("critical_events", [])
        for event in critical_events:
            event['source'] = processor_name
            event['priority'] = get_event_priority(event)
            all_events.append(event)

        # Issues
        issues = processor_data.get("issues", [])
        for event in issues:
            event['source'] = processor_name
            event['priority'] = get_event_priority(event)
            all_events.append(event)

        # Warnings
        warnings = processor_data.get("warnings", [])
        for event in warnings:
            event['source'] = processor_name
            event['priority'] = get_event_priority(event)
            all_events.append(event)

    # Deduplikuj eventy
    logger.debug(f"[EVENT_CORRELATION] Deduplicating {len(all_events)} events")
    all_events = deduplicate_events(all_events)
    logger.info(
        f"[EVENT_CORRELATION] After deduplication: {len(all_events)} unique events")

    # Parsuj timestampy i sortuj
    for event in all_events:
        event['parsed_timestamp'] = parse_event_timestamp(
            event.get('timestamp', ''))

    # Usuń eventy bez timestampa
    all_events = [e for e in all_events if e.get('parsed_timestamp')]

    # Sortuj według czasu (najstarsze pierwsze)
    all_events.sort(key=lambda x: x.get('parsed_timestamp', datetime.min))

    # Twórz timeline
    timeline = create_timeline(all_events, time_window_minutes)

    # Mapuj zależności
    correlations = map_dependencies(all_events, time_window_minutes)

    # Generuj root causes
    root_causes = generate_root_causes(all_events, correlations, timeline)

    logger.info(
        f"[EVENT_CORRELATION] Generated timeline with {len(timeline)} time windows, {len(correlations)} correlations, {len(root_causes)} root causes")

    return {
        'timeline': timeline,
        'root_causes': root_causes,
        'correlations': correlations,
        'total_events': len(all_events)
    }


def get_event_priority(event):
    """Zwraca priorytet eventu na podstawie typu."""
    event_type = event.get('type', '').upper()
    component = event.get('component', '').upper()
    message = event.get('message', '').upper()

    # Sprawdź priorytety
    for priority_name, priority_value in EVENT_PRIORITIES.items():
        if priority_name in event_type or priority_name in component or priority_name in message:
            return priority_value

    # Sprawdź szczególne przypadki
    if 'WHEA' in message or 'HARDWARE' in message:
        return EVENT_PRIORITIES['WHEA']
    if 'BUGCHECK' in message or 'STOP' in message:
        return EVENT_PRIORITIES['BUGCHECK']
    if 'KERNEL-POWER' in message or 'UNEXPECTED SHUTDOWN' in message:
        return EVENT_PRIORITIES['KERNEL_POWER']
    if 'DISK' in event_type or 'SMART' in event_type:
        return EVENT_PRIORITIES['DISK_ERROR']
    if 'DRIVER' in event_type or 'DRIVER' in component:
        return EVENT_PRIORITIES['DRIVER_ERROR']

    return EVENT_PRIORITIES['OTHER']


def parse_event_timestamp(timestamp_str):
    """Parsuje timestamp string do datetime."""
    if not timestamp_str:
        return None

    try:
        # Różne formaty timestampów
        formats = [
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S.%f"
        ]

        for fmt in formats:
            try:
                return datetime.strptime(timestamp_str[:19], fmt)
            except BaseException:
                continue

        # Fallback: ISO format
        return datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
    except BaseException:
        return None


def create_timeline(events, time_window_minutes):
    """Tworzy timeline z oknami czasowymi."""
    if not events:
        return []

    timeline = []
    current_window_start = None
    current_window_events = []

    for event in events:
        event_time = event.get('parsed_timestamp')
        if not event_time:
            continue

        # Jeśli to pierwszy event lub event jest poza oknem, stwórz nowe okno
        if current_window_start is None or (
                event_time - current_window_start).total_seconds() > time_window_minutes * 60:
            # Zapisz poprzednie okno
            if current_window_events:
                timeline.append(
                    {
                        'window_start': current_window_start.isoformat() if current_window_start else None,
                        'window_end': (
                            current_window_start
                            + timedelta(
                                minutes=time_window_minutes)
                        ).isoformat() if current_window_start else None,
                        'events': current_window_events,
                        'event_count': len(current_window_events),
                        'max_priority': max(
                            [
                                e.get('priority', 0)
                                for e in current_window_events
                            ]
                        ) if current_window_events else 0})

            # Nowe okno
            current_window_start = event_time
            current_window_events = [event]
        else:
            # Dodaj do obecnego okna
            current_window_events.append(event)

    # Zapisz ostatnie okno
    if current_window_events:
        timeline.append(
            {
                'window_start': current_window_start.isoformat() if current_window_start else None,
                'window_end': (
                    current_window_start
                    + timedelta(
                        minutes=time_window_minutes)
                ).isoformat() if current_window_start else None,
                'events': current_window_events,
                'event_count': len(current_window_events),
                'max_priority': max(
                    [
                        e.get(
                            'priority',
                            0) for e in current_window_events]) if current_window_events else 0})

    return timeline


def map_dependencies(events, time_window_minutes):
    """Mapuje zależności między eventami."""
    correlations = []

    # Grupuj eventy według komponentów
    component_events = defaultdict(list)
    for event in events:
        component = event.get('component', 'OTHER')
        component_events[component].append(event)

    # Znajdź korelacje w oknie czasowym
    for component, comp_events in component_events.items():
        if len(comp_events) < 2:
            continue

        # Sortuj według czasu
        comp_events.sort(key=lambda x: x.get('parsed_timestamp', datetime.min))

        # Sprawdź czy eventy są w tym samym oknie czasowym
        for i in range(len(comp_events) - 1):
            event1 = comp_events[i]
            event2 = comp_events[i + 1]

            time_diff = (event2.get('parsed_timestamp')
                         - event1.get('parsed_timestamp')).total_seconds() / 60

            if time_diff <= time_window_minutes:
                correlations.append({
                    'event1': event1.get('type', ''),
                    'event2': event2.get('type', ''),
                    'component': component,
                    'time_diff_minutes': round(time_diff, 2),
                    'correlation_type': 'SAME_COMPONENT',
                    'priority': max(event1.get('priority', 0), event2.get('priority', 0))
                })

    # Sortuj według priorytetu
    correlations.sort(key=lambda x: x.get('priority', 0), reverse=True)

    return correlations


def generate_root_causes(events, correlations, timeline):
    """Generuje finalne logiczne Root Causes."""
    root_causes = []

    # Znajdź eventy z najwyższym priorytetem
    if not events:
        return root_causes

    # Sortuj według priorytetu
    sorted_events = sorted(
        events, key=lambda x: x.get(
            'priority', 0), reverse=True)

    # Top 5 eventów z najwyższym priorytetem
    top_events = sorted_events[:5]

    for event in top_events:
        event_type = event.get('type', '')
        component = event.get('component', '')
        priority = event.get('priority', 0)

        # Generuj root cause description
        description = generate_root_cause_description(event, correlations)

        root_causes.append({
            'event_type': event_type,
            'component': component,
            'priority': priority,
            'timestamp': event.get('timestamp', ''),
            'description': description,
            'confidence': min(100, priority),  # Priorytet jako confidence
            'related_events': find_related_events(event, events, correlations)
        })

    return root_causes


def generate_root_cause_description(event, correlations):
    """Generuje opis root cause."""
    event_type = event.get('type', '')
    component = event.get('component', '')
    message = event.get('message', '')

    # Sprawdź korelacje
    related_correlations = [c for c in correlations if c.get(
        'event1') == event_type or c.get('event2') == event_type]

    if related_correlations:
        return f"{event_type} in {component} correlated with {len(related_correlations)} other events"

    return f"{event_type} in {component}: {message[:100]}"


def find_related_events(event, all_events, correlations):
    """Znajduje powiązane eventy."""
    related = []
    event_type = event.get('type', '')
    event_time = event.get('parsed_timestamp')

    if not event_time:
        return related

    # Znajdź korelacje
    for corr in correlations:
        if corr.get('event1') == event_type or corr.get(
                'event2') == event_type:
            # Znajdź powiązany event
            related_type = corr.get('event2') if corr.get(
                'event1') == event_type else corr.get('event1')
            for e in all_events:
                if e.get('type') == related_type:
                    related.append({
                        'type': related_type,
                        'timestamp': e.get('timestamp', ''),
                        'component': e.get('component', '')
                    })
                    break

    return related
