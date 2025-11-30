# collectors/drivers.py
import os


def _is_ci_environment():
    """
    Sprawdza czy środowisko to CI.

    Returns:
        bool: True jeśli jest to środowisko CI
    """
    return (
        os.environ.get("CI") in ("true", "1", "True") or
        os.environ.get("GITHUB_ACTIONS") == "true" or
        os.environ.get("TF_BUILD") == "True"
    )


def _get_driver_attributes(drv):
    """
    Wyciąga atrybuty z obiektu driver.

    Args:
        drv: Obiekt WMI driver

    Returns:
        dict: Atrybuty driver lub None w przypadku błędu
    """
    try:
        name = (
            getattr(drv, "DeviceName", None) or
            getattr(drv, "FriendlyName", None) or
            "Unknown"
        )
        provider = getattr(drv, "DriverProviderName", None) or "Unknown"
        version = getattr(drv, "DriverVersion", None) or "Unknown"
        date = getattr(drv, "DriverDate", None) or "Unknown"
        status = getattr(drv, "Status", None) or "Unknown"

        return {
            'name': str(name).strip(),
            'provider': str(provider).strip(),
            'version': str(version).strip(),
            'date': str(date),
            'status': str(status)
        }
    except Exception:
        return None


def _collect_drivers_from_wmi():
    """
    Zbiera informacje o driverach z WMI.

    Returns:
        list: Lista driverów
    """
    try:
        import wmi
    except ImportError as e:
        raise RuntimeError(f"WMI import failed: {e}")

    results = []
    try:
        c = wmi.WMI()
        try:
            drivers = c.Win32_PnPSignedDriver()
        except Exception:
            return []

        for drv in drivers:
            driver_info = _get_driver_attributes(drv)
            if driver_info:
                results.append(driver_info)

    except Exception:
        return []

    return results


def collect():
    """
    Zbiera informacje o sterownikach systemowych.
    Zwraca listę słowników z danymi driverów.
    """
    if _is_ci_environment():
        return []

    return _collect_drivers_from_wmi()
