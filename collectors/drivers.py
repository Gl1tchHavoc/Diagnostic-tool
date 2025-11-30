# collectors/drivers.py
import sys


def collect():
    """
    Zbiera informacje o sterownikach systemowych.
    Zwraca listę słowników z danymi driverów.
    """
    try:
        import wmi
    except ImportError as e:
        raise RuntimeError(f"WMI import failed: {e}")

    results = []
    try:
        c = wmi.WMI()
        for drv in c.Win32_PnPSignedDriver():
            name = getattr(
                drv, "DeviceName", None) or getattr(
                drv, "FriendlyName", None) or "Unknown"
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
        raise RuntimeError(f"WMI scan failed: {e}")
    return results
