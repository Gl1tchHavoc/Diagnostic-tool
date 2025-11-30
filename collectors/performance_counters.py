"""
Collector Performance Counters - zbiera metryki wydajności systemu.
"""
import time
from datetime import datetime

import psutil


def collect(sample_duration=2):
    """
    Zbiera metryki wydajności systemu przez określony czas.

    Args:
        sample_duration (int): Czas próbkowania w sekundach (domyślnie 2)

    Returns:
        dict: Metryki wydajności
    """
    perf_data = {
        "timestamp": datetime.now().isoformat(),
        "cpu": {},
        "memory": {},
        "disk": {},
        "network": {},
        "samples": []
    }

    # Pobierz próbki przez określony czas
    samples = []
    for i in range(sample_duration):
        sample = {
            "time": datetime.now().isoformat(),
            "cpu_percent": psutil.cpu_percent(interval=1, percpu=True),
            "cpu_total": psutil.cpu_percent(interval=1),
            "memory": dict(psutil.virtual_memory()._asdict()),
            "disk_io": dict(psutil.disk_io_counters()._asdict()) if psutil.disk_io_counters() else {},
            "network_io": dict(psutil.net_io_counters()._asdict()) if psutil.net_io_counters() else {}
        }
        samples.append(sample)
        time.sleep(0.5)

    perf_data["samples"] = samples

    # Oblicz średnie i maksima
    if samples:
        cpu_totals = [s["cpu_total"] for s in samples]
        perf_data["cpu"] = {
            "average": sum(cpu_totals) / len(cpu_totals),
            "max": max(cpu_totals),
            "min": min(cpu_totals),
            "current": cpu_totals[-1] if cpu_totals else 0
        }

        memory_values = [s["memory"].get("percent", 0) for s in samples]
        perf_data["memory"] = {
            "average_percent": sum(memory_values) / len(memory_values) if memory_values else 0,
            "max_percent": max(memory_values) if memory_values else 0,
            "current": samples[-1]["memory"] if samples else {}
        }

        # Disk I/O
        disk_reads = [s["disk_io"].get("read_bytes", 0)
                      for s in samples if "disk_io" in s]
        disk_writes = [
            s["disk_io"].get(
                "write_bytes",
                0) for s in samples if "disk_io" in s]
        if disk_reads:
            perf_data["disk"] = {
                "read_bytes_total": disk_reads[-1] - disk_reads[0] if len(disk_reads) > 1 else 0,
                "write_bytes_total": disk_writes[-1] - disk_writes[0] if len(disk_writes) > 1 else 0,
                "read_count": samples[-1]["disk_io"].get("read_count", 0) if samples else 0,
                "write_count": samples[-1]["disk_io"].get("write_count", 0) if samples else 0
            }

        # Network I/O
        net_sent = [
            s["network_io"].get(
                "bytes_sent",
                0) for s in samples if "network_io" in s]
        net_recv = [
            s["network_io"].get(
                "bytes_recv",
                0) for s in samples if "network_io" in s]
        if net_sent:
            perf_data["network"] = {
                "bytes_sent_total": net_sent[-1] - net_sent[0] if len(net_sent) > 1 else 0,
                "bytes_recv_total": net_recv[-1] - net_recv[0] if len(net_recv) > 1 else 0,
                "packets_sent": samples[-1]["network_io"].get("packets_sent", 0) if samples else 0,
                "packets_recv": samples[-1]["network_io"].get("packets_recv", 0) if samples else 0
            }

    # Sprawdź problemy wydajności
    perf_data["issues"] = []
    if perf_data["cpu"].get("average", 0) > 90:
        perf_data["issues"].append({
            "type": "HIGH_CPU_USAGE",
            "severity": "WARNING",
            "message": f"CPU usage is very high: {perf_data['cpu']['average']:.1f}%"
        })

    if perf_data["memory"].get("average_percent", 0) > 90:
        perf_data["issues"].append({
            "type": "HIGH_MEMORY_USAGE",
            "severity": "WARNING",
            "message": f"Memory usage is very high: {perf_data['memory']['average_percent']:.1f}%"
        })

    return perf_data
