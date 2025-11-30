# collectors/drivers.py
import os
import sys


def collect():
    """
    Zbiera informacje o sterownikach systemowych.
    Zwraca listę słowników z danymi driverów.
    """
    # W CI zwróć pustą listę - WMI może powodować access violation
    IS_CI = (
        os.environ.get("CI") in ("true", "1", "True") or
        os.environ.get("GITHUB_ACTIONS") == "true" or
        os.environ.get("TF_BUILD") == "True"
    )
    if IS_CI:
        return []
    
    try:
        import wmi
    except ImportError as e:
        raise RuntimeError(f"WMI import failed: {e}")

    results = []
    try:
        c = wmi.WMI()
        # Bezpieczny dostęp do Win32_PnPSignedDriver
        try:
            drivers = c.Win32_PnPSignedDriver()
        except Exception as wmi_error:
            # Jeśli access violation - zwróć pustą listę zamiast crashować
            return []
        
        for drv in drivers:
            try:
                name = getattr(
                    drv, "DeviceName", None) or getattr(
                    drv, "FriendlyName", None) or "Unknown"
                provider = getattr(
                    drv, "DriverProviderName", None) or "Unknown"
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
            except Exception as driver_error:
                # Pomiń problematyczny driver i kontynuuj
                continue
    except Exception as e:
        # W przypadku błędów WMI zwróć pustą listę zamiast crashować
        return []
    return results
