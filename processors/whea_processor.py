"""
WHEA Processor - analizuje błędy WHEA i stosuje Golden Rules do wykrywania przyczyn awarii sprzętowych.
Implementuje wszystkie Golden Rules z 95-100% pewnością.
"""
from collections import defaultdict
from datetime import datetime, timedelta

from utils.logger import get_logger

logger = get_logger()


def process(whea_data, bsod_data=None, hardware_data=None):
    """
    Przetwarza dane WHEA i stosuje Golden Rules do wykrywania przyczyn.
    
    Args:
        whea_data (dict): Dane z collectors.whea_analyzer
        bsod_data (dict, optional): Dane z collectors.bsod_dumps dla korelacji
        hardware_data (dict, optional): Dane z collectors.hardware dla kontekstu
        
    Returns:
        dict: Przetworzone dane z wykrytymi przyczynami i confidence scores
    """
    if not whea_data or not whea_data.get("whea_events"):
        return {
            "root_causes": [],
            "top_root_cause": None,
            "affected_components": [],
            "summary": "No WHEA events found",
            "confidence_score": 0.0
        }

    whea_events = whea_data.get("whea_events", [])

    logger.info(f"[WHEA_PROCESSOR] Processing {len(whea_events)} WHEA events")

    # Zastosuj wszystkie Golden Rules
    root_causes = []

    # Golden Rule 1-5: Podstawowe reguły dla każdego eventu
    for event in whea_events:
        # Upewnij się, że event jest słownikiem
        if not isinstance(event, dict):
            logger.debug(f"[WHEA_PROCESSOR] Skipping non-dict event: {type(event)}")
            continue
        causes = apply_golden_rules_1_5(event)
        root_causes.extend(causes)

    # Golden Rule 6: Correctable Errors burst
    causes_6 = apply_golden_rule_6(whea_events)
    root_causes.extend(causes_6)

    # Golden Rule 7: WHEA + Kernel-Power 41
    if bsod_data:
        causes_7 = apply_golden_rule_7(whea_events, bsod_data)
        root_causes.extend(causes_7)

    # Dodatkowe reguły (VRM, Voltage, RAM/XMP)
    additional_causes = apply_additional_rules(whea_events, hardware_data)
    root_causes.extend(additional_causes)

    # Agreguj i wybierz TOP root cause
    aggregated = aggregate_root_causes(root_causes)
    top_cause = get_top_root_cause(aggregated)
    affected_components = get_affected_components(whea_events, root_causes)
    confidence_score = calculate_aggregated_confidence(aggregated)

    # Generuj human-readable summary
    summary = generate_summary(top_cause, affected_components, confidence_score, whea_events)

    logger.info(
        f"[WHEA_PROCESSOR] Detected {len(aggregated)} unique root causes, "
        f"top: {top_cause.get('root_cause', 'None') if top_cause else 'None'}"
    )

    return {
        "root_causes": aggregated,
        "top_root_cause": top_cause,
        "affected_components": affected_components,
        "summary": summary,
        "confidence_score": confidence_score,
        "total_events": len(whea_events),
        "events_by_type": count_events_by_type(whea_events)
    }


def apply_golden_rules_1_5(event):
    """
    Stosuje Golden Rules 1-5 dla pojedynczego eventu WHEA.
    
    Golden Rule 1: CPU Core Failure (100%)
    Golden Rule 2: Cache Hierarchy Failure (98%)
    Golden Rule 3: Internal Fabric Failure (97%)
    Golden Rule 4: Memory Controller Failure (96%)
    Golden Rule 5: PCIe Hardware Error (95%)
    """
    causes = []

    error_source = (event.get("error_source", "") or "").upper()
    mca_cod = (event.get("mca_cod", "") or "").upper()
    bank = (event.get("bank", "") or "").upper()
    apic_id = event.get("processor_apic_id")

    # Golden Rule 1: CPU Core Failure (100%)
    if "MACHINE CHECK EXCEPTION" in error_source:
        if mca_cod and (mca_cod.startswith("0x00") or mca_cod.startswith("0x01") or "0x00" in mca_cod or "0x01" in mca_cod):
            causes.append({
                "root_cause": "CPU CORE FAILURE",
                "confidence": 100.0,
                "rule": "Golden Rule 1",
                "evidence": {
                    "error_source": error_source,
                    "mca_cod": mca_cod,
                    "apic_id": apic_id,
                    "event_id": event.get("event_id", "")
                },
                "affected_component": f"CPU Core {apic_id}" if apic_id is not None else "CPU Core (Unknown)",
                "explanation": f"Machine Check Exception with MCACOD {mca_cod} indicates CPU core failure"
            })

    # Golden Rule 2: Cache Hierarchy Failure (98%)
    if mca_cod and ("0xC0" in mca_cod or "0xC1" in mca_cod or "CACHE" in mca_cod.upper()):
        causes.append({
            "root_cause": "CPU CACHE L0/L1/L2/L3 FAILURE",
            "confidence": 98.0,
            "rule": "Golden Rule 2",
            "evidence": {
                "mca_cod": mca_cod,
                "bank": bank,
                "apic_id": apic_id
            },
            "affected_component": f"CPU Cache {bank}" if bank else "CPU Cache (Unknown Level)",
            "explanation": f"MCACOD {mca_cod} indicates CPU cache hierarchy failure"
        })

    # Golden Rule 3: Internal Fabric Failure (97%)
    if "BUS/INTERCONNECT" in error_source or "FABRIC" in error_source.upper() or "INTERCONNECT" in error_source.upper():
        causes.append({
            "root_cause": "INTERCONNECT / FABRIC FAILURE (IF)",
            "confidence": 97.0,
            "rule": "Golden Rule 3",
            "evidence": {
                "error_source": error_source,
                "mca_cod": mca_cod
            },
            "affected_component": "CPU Interconnect/Fabric",
            "explanation": f"Error source {error_source} indicates interconnect/fabric failure"
        })

    # Golden Rule 4: Memory Controller Failure (96%)
    if bank == "MC" or "MEMORY CONTROLLER" in error_source.upper() or (mca_cod and "MEMORY CONTROLLER" in mca_cod.upper()):
        causes.append({
            "root_cause": "MEMORY CONTROLLER FAILURE",
            "confidence": 96.0,
            "rule": "Golden Rule 4",
            "evidence": {
                "bank": bank,
                "error_source": error_source,
                "mca_cod": mca_cod
            },
            "affected_component": "Memory Controller",
            "explanation": f"Bank {bank} or error source {error_source} indicates memory controller failure"
        })

    # Golden Rule 5: PCIe Hardware Error (95%)
    if "PCI EXPRESS ERROR" in error_source or "PCIE" in error_source.upper():
        causes.append({
            "root_cause": "PCIE HARDWARE FAILURE",
            "confidence": 95.0,
            "rule": "Golden Rule 5",
            "evidence": {
                "error_source": error_source,
                "mca_cod": mca_cod
            },
            "affected_component": "PCIe Bus/Device",
            "explanation": f"Error source {error_source} indicates PCIe hardware failure"
        })

    return causes


def apply_golden_rule_6(whea_events):
    """
    Golden Rule 6: Correctable Errors burst (95%).
    Jeśli Event 19 powtarza się > 3 razy w 10 minutach → CPU Instability / VCORE Drop.
    """
    causes = []

    # Filtruj Event 19 (Correctable Hardware Error)
    event_19_events = [e for e in whea_events if isinstance(e, dict) and str(e.get("event_id", "")) == "19"]

    if len(event_19_events) < 3:
        return causes

    # Grupuj po czasie (okno 10 minut)
    now = datetime.now()
    time_windows = defaultdict(list)

    for event in event_19_events:
        if not isinstance(event, dict):
            continue
        timestamp = parse_timestamp(event.get("timestamp", ""))
        if timestamp:
            # Zaokrąglij do 10-minutowych okien
            window_key = timestamp.replace(minute=(timestamp.minute // 10) * 10, second=0, microsecond=0)
            time_windows[window_key].append(event)

    # Sprawdź czy któreś okno ma > 3 eventy
    for window_time, events_in_window in time_windows.items():
        if len(events_in_window) > 3:
            causes.append({
                "root_cause": "CPU INSTABILITY / VCORE DROP",
                "confidence": 95.0,
                "rule": "Golden Rule 6",
                "evidence": {
                    "event_count": len(events_in_window),
                    "time_window": window_time.isoformat(),
                    "event_ids": [str(e.get("event_id", "")) for e in events_in_window]
                },
                "affected_component": "CPU Power Delivery / VRM",
                "explanation": (
                    f"Event 19 (Correctable Error) occurred "
                    f"{len(events_in_window)} times in 10 minutes, "
                    f"indicating CPU instability or voltage drop"
                )
            })
            break  # Tylko jeden raz

    return causes


def apply_golden_rule_7(whea_events, bsod_data):
    """
    Golden Rule 7: WHEA + Kernel-Power 41 (99%).
    Jeśli EventID 41 występuje w ±1 minucie od WHEA 18/19 → Hardware Electrical Failure.
    """
    causes = []

    if not bsod_data:
        return causes

    # Znajdź BSOD EventID 41
    recent_crashes = bsod_data.get("recent_crashes", []) if isinstance(bsod_data, dict) else []
    bsod_41_times = []

    for crash in recent_crashes:
        if not isinstance(crash, dict):
            continue
        if str(crash.get("event_id", "")) == "41":
            bsod_time = parse_timestamp(crash.get("timestamp", ""))
            if bsod_time:
                bsod_41_times.append(bsod_time)

    if not bsod_41_times:
        return causes

    # Sprawdź WHEA 18/19 w oknie ±1 minuta
    for event in whea_events:
        if not isinstance(event, dict):
            continue
        event_id = str(event.get("event_id", ""))
        if event_id in ["18", "19"]:
            whea_time = parse_timestamp(event.get("timestamp", ""))
            if whea_time:
                for bsod_time in bsod_41_times:
                    time_diff = abs((whea_time - bsod_time).total_seconds())
                    if time_diff <= 60:  # 1 minuta
                        causes.append({
                            "root_cause": "HARDWARE ELECTRICAL FAILURE",
                            "confidence": 99.0,
                            "rule": "Golden Rule 7",
                            "evidence": {
                                "whea_event_id": event_id,
                                "whea_timestamp": whea_time.isoformat(),
                                "bsod_timestamp": bsod_time.isoformat(),
                                "time_difference_seconds": time_diff
                            },
                            "affected_component": "Power Delivery / Electrical System",
                            "explanation": (
                                f"WHEA Event {event_id} occurred within ±1 "
                                f"minute of BSOD EventID 41, indicating "
                                f"hardware electrical failure"
                            )
                        })
                        break

    return causes


def apply_additional_rules(whea_events, hardware_data):
    """
    Dodatkowe reguły dla płyty głównej / VRM / zasilania.
    
    4.1 VRM Drop (95%)
    4.2 CPU Voltage Too Low (97%)
    4.3 RAM / XMP Instability (96%)
    """
    causes = []

    if not whea_events:
        return causes

    # 4.1 VRM Drop - błędy przy niskim obciążeniu (idle)
    # Sprawdź czy większość błędów to Machine Check (18/19)
    mce_events = [e for e in whea_events if "MACHINE CHECK" in (e.get("error_source", "") or "").upper()]
    if len(mce_events) >= len(whea_events) * 0.8:  # 80% to MCE
        causes.append({
            "root_cause": "VRM / POWER DELIVERY INSTABILITY",
            "confidence": 95.0,
            "rule": "Additional Rule 4.1",
            "evidence": {
                "mce_events": len(mce_events),
                "total_events": len(whea_events)
            },
            "affected_component": "VRM / Power Delivery",
            "explanation": "High percentage of Machine Check Exceptions indicates VRM or power delivery instability"
        })

    # 4.2 CPU Voltage Too Low - >80% błędów z tego samego APIC ID
    apic_counts = defaultdict(int)
    for event in whea_events:
        if not isinstance(event, dict):
            continue
        apic_id = event.get("processor_apic_id")
        if apic_id is not None:
            apic_counts[apic_id] += 1

    if apic_counts:
        total_apic_events = sum(apic_counts.values())
        for apic_id, count in apic_counts.items():
            if count >= total_apic_events * 0.8:  # 80% błędów z jednego rdzenia
                causes.append({
                    "root_cause": "CPU CORE UNDERVOLTAGE / OC INSTABILITY",
                    "confidence": 97.0,
                    "rule": "Additional Rule 4.2",
                    "evidence": {
                        "apic_id": apic_id,
                        "errors_from_core": count,
                        "total_apic_errors": total_apic_events,
                        "percentage": (count / total_apic_events * 100) if total_apic_events > 0 else 0
                    },
                    "affected_component": f"CPU Core {apic_id}",
                    "explanation": (
                        f"Over 80% of WHEA errors come from CPU core "
                        f"{apic_id}, indicating undervoltage or "
                        f"overclocking instability"
                    )
                })
                break

    # 4.3 RAM / XMP Instability - EventID 19 + Memory w message lub Bank >= 4
    for event in whea_events:
        if not isinstance(event, dict):
            continue
        event_id = str(event.get("event_id", ""))
        message = (event.get("message", "") or "").upper()
        bank = event.get("bank", "")

        if event_id == "19" and ("MEMORY" in message or (bank and (bank.isdigit() and int(bank) >= 4))):
            causes.append({
                "root_cause": "MEMORY INSTABILITY",
                "confidence": 96.0,
                "rule": "Additional Rule 4.3",
                "evidence": {
                    "event_id": event_id,
                    "bank": bank,
                    "message_contains_memory": "MEMORY" in message
                },
                "affected_component": "RAM / Memory Subsystem",
                "explanation": f"EventID 19 with memory-related indicators (Bank {bank}) suggests RAM or XMP instability"
            })
            break

    return causes


def aggregate_root_causes(root_causes):
    """
    Agreguje powtarzające się root causes i oblicza średnią ważoną confidence.
    """
    aggregated = defaultdict(lambda: {"count": 0, "confidences": [], "rules": [], "evidence_list": []})

    for cause in root_causes:
        # Upewnij się, że cause jest słownikiem
        if not isinstance(cause, dict):
            logger.debug(f"[WHEA_PROCESSOR] Skipping non-dict cause: {type(cause)}")
            continue
        root_cause = cause.get("root_cause", "UNKNOWN")
        confidence = cause.get("confidence", 0.0)
        rule = cause.get("rule", "")
        evidence = cause.get("evidence", {})
        component = cause.get("affected_component", "")

        aggregated[root_cause]["count"] += 1
        aggregated[root_cause]["confidences"].append(confidence)
        aggregated[root_cause]["rules"].append(rule)
        aggregated[root_cause]["evidence_list"].append(evidence)
        if "components" not in aggregated[root_cause]:
            aggregated[root_cause]["components"] = set()
        aggregated[root_cause]["components"].add(component)

    # Konwertuj na listę z obliczoną średnią ważoną confidence
    result = []
    for root_cause, data in aggregated.items():
        # Średnia ważona confidence (większa waga dla wyższych wartości)
        confidences = data["confidences"]
        if confidences:
            # Użyj średniej ważonej (wyższe confidence mają większą wagę)
            weighted_sum = sum(c * c for c in confidences)  # Kwadrat confidence jako waga
            weight_sum = sum(c for c in confidences)
            avg_confidence = weighted_sum / weight_sum if weight_sum > 0 else sum(confidences) / len(confidences)
        else:
            avg_confidence = 0.0

        result.append({
            "root_cause": root_cause,
            "confidence": round(avg_confidence, 2),
            "occurrences": data["count"],
            "rules": list(set(data["rules"])),
            "evidence": data["evidence_list"],
            "affected_components": list(data["components"])
        })

    # Sortuj po confidence (malejąco)
    result.sort(key=lambda x: x["confidence"], reverse=True)

    return result


def get_top_root_cause(aggregated_causes):
    """Zwraca top root cause z najwyższą confidence."""
    if not aggregated_causes:
        return None

    return aggregated_causes[0]


def get_affected_components(whea_events, root_causes):
    """Wyciąga listę unikalnych komponentów dotkniętych błędami."""
    components = set()

    for cause in root_causes:
        component = cause.get("affected_component", "")
        if component:
            components.add(component)

    # Dodaj komponenty z eventów
    for event in whea_events:
        apic_id = event.get("processor_apic_id")
        if apic_id is not None:
            components.add(f"CPU Core {apic_id}")
        bank = event.get("bank")
        if bank:
            components.add(f"Bank {bank}")

    return sorted(list(components))


def calculate_aggregated_confidence(aggregated_causes):
    """Oblicza agregowany confidence score ze wszystkich przyczyn."""
    if not aggregated_causes:
        return 0.0

    # Użyj średniej ważonej (wyższe confidence mają większą wagę)
    total_weight = 0.0
    weighted_sum = 0.0

    for cause in aggregated_causes:
        confidence = cause.get("confidence", 0.0)
        occurrences = cause.get("occurrences", 1)
        weight = confidence * occurrences  # Waga = confidence * liczba wystąpień
        weighted_sum += confidence * weight
        total_weight += weight

    if total_weight > 0:
        return round(weighted_sum / total_weight, 2)
    else:
        return round(sum(c.get("confidence", 0.0) for c in aggregated_causes) / len(aggregated_causes), 2)


def generate_summary(top_cause, affected_components, confidence_score, whea_events):
    """
    Generuje human-readable summary z wnioskami.
    """
    if not top_cause:
        return "No WHEA errors detected. System appears stable."

    root_cause = top_cause.get("root_cause", "UNKNOWN")
    confidence = top_cause.get("confidence", 0.0)
    occurrences = top_cause.get("occurrences", 0)

    # Znajdź przykładowy event dla szczegółów
    example_event = None
    for event in whea_events:
        if event.get("event_id") in ["18", "19"]:
            example_event = event
            break

    summary_parts = [
        f"Wykryto krytyczne błędy WHEA ({len(whea_events)} eventów)."
    ]

    if example_event:
        event_id = example_event.get("event_id", "")
        apic_id = example_event.get("processor_apic_id")
        mca_cod = example_event.get("mca_cod", "")

        if apic_id is not None:
            summary_parts.append(f"EventID {event_id} na rdzeniu CPU (APIC ID {apic_id}).")
        else:
            summary_parts.append(f"EventID {event_id} wykryty.")

        if mca_cod:
            summary_parts.append(f"MCACOD {mca_cod} wskazuje na {root_cause}.")

    summary_parts.append(f"Jest to silnie powiązane z awarią sprzętową.")
    summary_parts.append(f"Confidence: {confidence}%")

    if affected_components:
        summary_parts.append(f"Dotknięte komponenty: {', '.join(affected_components[:3])}")
        if len(affected_components) > 3:
            summary_parts.append(f"i {len(affected_components) - 3} więcej")

    return " ".join(summary_parts)


def count_events_by_type(whea_events):
    """Liczy eventy według typu."""
    counts = defaultdict(int)
    for event in whea_events:
        if not isinstance(event, dict):
            continue
        event_id = str(event.get("event_id", ""))
        error_type = event.get("error_type", "Unknown")
        counts[error_type] += 1
        counts[f"EventID_{event_id}"] += 1
    return dict(counts)


def parse_timestamp(timestamp_str):
    """Parsuje timestamp string do datetime object."""
    if not timestamp_str:
        return None

    formats = [
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%m/%d/%Y %I:%M:%S %p",
        "%m/%d/%Y %H:%M:%S"
    ]

    for fmt in formats:
        try:
            return datetime.strptime(timestamp_str[:19], fmt)
        except (ValueError, IndexError):
            continue

    try:
        return datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
    except:
        pass

    return None

