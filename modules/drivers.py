# modules/drivers.py
from datetime import datetime

def scan():
    """
    Scan drivers using WMI. Returns a list of dicts.
    Raises RuntimeError on failure so callers can handle/display errors cleanly.
    """
    try:
        import wmi  # local import to avoid import-time failure on non-Windows
    except Exception as e:
        raise RuntimeError(f"WMI import failed: {e}")

    results = []
    try:
        c = wmi.WMI()
        for drv in c.Win32_PnPSignedDriver():
            name = getattr(drv, "DeviceName", None) or getattr(drv, "FriendlyName", None) or "Unknown"
            provider = getattr(drv, "DriverProviderName", None) or "Unknown"
            version = getattr(drv, "DriverVersion", None) or "Unknown"
            date = getattr(drv, "DriverDate", None) or "Unknown"
            status = getattr(drv, "Status", None) or "Unknown"
            results.append({
                'name': str(name).strip(),
                'provider': str(provider).strip(),
                'version': str(version).strip(),
                'date': str(date),
                'status': str(status)
            })
    except Exception as e:
        # let caller handle by raising a clear exception
        raise RuntimeError(f"WMI scan failed: {e}")
    return results

def filter_duplicates(drivers_list):
    seen = set()
    filtered = []
    for d in drivers_list:
        key = (d.get('name', '').lower().strip(), d.get('provider', '').lower().strip(), d.get('version', '').lower().strip())
        if key not in seen:
            seen.add(key)
            filtered.append(d)
    return filtered

IGNORE_PROVIDERS = [
    "microsoft", "standard system", "standard usb", "standard keyboard", "standard disk", "standard display"
]

def filter_system_drivers(drivers_list):
    """
    Exclude drivers whose provider matches common system providers (case-insensitive, substring match).
    """
    filtered = []
    for d in drivers_list:
        prov = d.get('provider', '') or ""
        prov_l = prov.lower()
        if any(ignore in prov_l for ignore in IGNORE_PROVIDERS):
            continue
        filtered.append(d)
    return filtered

def format_date(raw_date):
    """Convert WMI CIM_DATETIME to YYYY-MM-DD, handle None/Unknown gracefully."""
    if not raw_date or raw_date == "Unknown":
        return "Unknown"
    try:
        # raw_date often like "YYYYMMDDHHMMSS.mmmmmms+/-TZ"
        core = str(raw_date).split('.', 1)[0]
        dt = datetime.strptime(core, "%Y%m%d%H%M%S")
        return dt.strftime("%Y-%m-%d")
    except Exception:
        # If parsing fails, return the original string (trimmed)
        return str(raw_date)

def group_drivers(drivers_list):
    """Grupuje sterowniki według typu w prosty sposób"""
    groups = {
        "GPU": [],
        "Audio": [],
        "Network": [],
        "USB": [],
        "Chipset": [],
        "Other": []
    }
    for d in drivers_list:
        name_lower = d['name'].lower()
        prov_lower = d['provider'].lower()
        if "nvidia" in name_lower or "amd" in name_lower or "gpu" in name_lower:
            groups["GPU"].append(d)
        elif "audio" in name_lower or "sound" in name_lower or "realtek" in name_lower:
            groups["Audio"].append(d)
        elif "network" in name_lower or "ethernet" in name_lower or "wireless" in name_lower:
            groups["Network"].append(d)
        elif "usb" in name_lower:
            groups["USB"].append(d)
        elif "chipset" in name_lower or "intel" in prov_lower:
            groups["Chipset"].append(d)
        else:
            groups["Other"].append(d)
    return groups

def format_results(drivers_list):
    """
    Zwraca czytelny tekst do GUI.
    Filtruje powtarzające się i standardowe sterowniki, grupuje po typach.
    """
    drivers = filter_duplicates(drivers_list)
    drivers = filter_system_drivers(drivers)
    grouped = group_drivers(drivers)

    lines = []
    for group, items in grouped.items():
        if items:
            lines.append(f"=== {group} Drivers ===")
            for d in items:
                date_fmt = format_date(d['date'])
                lines.append(f"{d['name']} | {d['provider']} | Version: {d['version']} | Date: {date_fmt} | Status: {d['status']}")
            lines.append("")
    return "\n".join(lines)
