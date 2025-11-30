"""
Procesor danych driverów - analizuje i wykrywa problemy ze sterownikami.
"""


def process(drivers_data):
    """
    Przetwarza dane driverów i wykrywa potencjalne problemy.

    Args:
        drivers_data (list): Dane z collectors.drivers

    Returns:
        dict: Przetworzone dane z wykrytymi problemami
    """
    issues = []
    warnings = []

    if isinstance(drivers_data, dict) and "error" in drivers_data:
        issues.append({
            "type": "DRIVER_COLLECTION_ERROR",
            "severity": "ERROR",
            "message": f"Failed to collect drivers: {drivers_data['error']}",
            "component": "Drivers"
        })
        return {
            "data": drivers_data,
            "issues": issues,
            "warnings": warnings,
            "summary": {
                "total_issues": len(issues),
                "total_warnings": len(warnings)}}

    if not isinstance(drivers_data, list):
        return {
            "data": drivers_data,
            "issues": [],
            "warnings": [],
            "summary": {"total_issues": 0, "total_warnings": 0}
        }

    # Sprawdź statusy driverów
    failed_drivers = []
    for driver in drivers_data:
        status = driver.get("status", "").lower()
        if "error" in status or "fail" in status or "stop" in status:
            failed_drivers.append(driver)

    if failed_drivers:
        for driver in failed_drivers:
            issues.append({
                "type": "DRIVER_FAILED",
                "severity": "ERROR",
                "message": f"Driver {driver.get('name')} has status: {driver.get('status')}",
                "component": "Drivers",
                "driver_name": driver.get('name'),
                "provider": driver.get('provider')
            })

    # Sprawdź stare wersje driverów (można rozszerzyć o sprawdzanie dat)
    for driver in drivers_data:
        date_str = driver.get("date", "")
        if date_str and date_str != "Unknown":
            # Można dodać logikę sprawdzania daty
            pass

    return {
        "data": drivers_data,
        "issues": issues,
        "warnings": warnings,
        "summary": {
            "total_issues": len(issues),
            "total_warnings": len(warnings),
            "total_drivers": len(drivers_data),
            "failed_drivers": len(failed_drivers)
        }
    }
