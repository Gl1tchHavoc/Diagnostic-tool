"""
Collector statusu usług Windows - zbiera informacje o wszystkich usługach i ich statusie.
"""
import os
import subprocess
import sys
import xml.etree.ElementTree as ET

if sys.platform == "win32":
    try:
        import wmi
    except ImportError:
        wmi = None

from utils.subprocess_helper import run_powershell_hidden


def _initialize_services_data():
    """
    Inicjalizuje strukturę danych services.

    Returns:
        dict: Pusta struktura danych services
    """
    return {
        "services": [],
        "failed_services": [],
        "stopped_services": [],
        "errors": []
    }


def _check_platform_and_wmi():
    """
    Sprawdza czy platforma to Windows i czy WMI jest dostępne.

    Returns:
        bool: True jeśli platforma i WMI są OK
    """
    if sys.platform != "win32" or not wmi:
        return False
    return True


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


def _create_service_info(service):
    """
    Tworzy słownik z informacjami o usłudze.

    Args:
        service: Obiekt WMI Win32_Service

    Returns:
        dict: Informacje o usłudze
    """
    return {
        "name": service.Name,
        "display_name": service.DisplayName,
        "state": service.State,
        "start_mode": service.StartMode,
        "status": service.Status,
        "process_id": service.ProcessId if service.ProcessId else None,
        "path_name": service.PathName if service.PathName else None,
        "description": service.Description if service.Description else ""
    }


def _is_problematic_stopped_service(service):
    """
    Sprawdza czy usługa jest zatrzymana mimo że powinna być uruchomiona.

    Args:
        service: Obiekt WMI Win32_Service

    Returns:
        bool: True jeśli usługa jest problematyczna
    """
    return (
        service.State == "Stopped" and
        service.StartMode in ["Auto", "Automatic"]
    )


def _is_failed_service(service):
    """
    Sprawdza czy usługa ma status błędu.

    Args:
        service: Obiekt WMI Win32_Service

    Returns:
        bool: True jeśli usługa ma błąd
    """
    if not service.Status:
        return False
    return "error" in service.Status.lower()


def _add_stopped_service_info(service, services_data):
    """
    Dodaje informacje o zatrzymanej usłudze do services_data.

    Args:
        service: Obiekt WMI Win32_Service
        services_data: Słownik z danymi services do uzupełnienia
    """
    services_data["stopped_services"].append({
        "name": service.Name,
        "display_name": service.DisplayName,
        "start_mode": service.StartMode,
        "issue": "Service should be running but is stopped"
    })


def _add_failed_service_info(service, services_data):
    """
    Dodaje informacje o usłudze z błędem do services_data.

    Args:
        service: Obiekt WMI Win32_Service
        services_data: Słownik z danymi services do uzupełnienia
    """
    services_data["failed_services"].append({
        "name": service.Name,
        "display_name": service.DisplayName,
        "status": service.Status,
        "issue": "Service has error status"
    })


def _process_service(service, services_data):
    """
    Przetwarza pojedynczą usługę i dodaje informacje do services_data.

    Args:
        service: Obiekt WMI Win32_Service
        services_data: Słownik z danymi services do uzupełnienia
    """
    service_info = _create_service_info(service)
    services_data["services"].append(service_info)

    if _is_problematic_stopped_service(service):
        _add_stopped_service_info(service, services_data)

    if _is_failed_service(service):
        _add_failed_service_info(service, services_data)


def _collect_services_from_wmi(services_data):
    """
    Zbiera informacje o usługach przez WMI.

    Args:
        services_data: Słownik z danymi services do uzupełnienia
    """
    try:
        c = wmi.WMI()
        services = c.Win32_Service()
    except (AttributeError, TypeError, ValueError, ImportError) as e:
        # WMI może zwracać różne błędy lub może nie być dostępny
        return

    for service in services:
        _process_service(service, services_data)


def _parse_xml_record(obj):
    """
    Parsuje pojedynczy rekord XML z Event Log.

    Args:
        obj: Element XML reprezentujący rekord

    Returns:
        dict: Słownik z danymi rekordu
    """
    record = {}
    for prop in obj.findall("Property"):
        name = prop.attrib.get("Name")
        if name:
            record[name] = prop.text if prop.text else ""
    return record


def _is_service_error_event(event_id):
    """
    Sprawdza czy event ID wskazuje na błąd usługi.

    Args:
        event_id: Event ID jako string lub int

    Returns:
        bool: True jeśli to błąd usługi
    """
    service_error_ids = [
        "7000", "7001", "7009", "7011", "7022", "7023",
        "7024", "7031", "7032", "7034"
    ]
    return str(event_id) in service_error_ids


def _collect_service_errors_from_event_log(services_data):
    """
    Zbiera błędy usług z Event Log.

    Args:
        services_data: Słownik z danymi services do uzupełnienia
    """
    cmd = (
        "Get-WinEvent -LogName System -MaxEvents 500 | "
        "Where-Object {$_.Id -in @(7000,7001,7009,7011,7022,7023,7024,"
        "7031,7032,7034) -or $_.Message -like '*service*' -and "
        "($_.Message -like '*fail*' -or $_.Message -like '*error*' "
        "-or $_.Message -like '*timeout*')} | "
        "ConvertTo-Xml -As String -Depth 3"
    )

    try:
        output = run_powershell_hidden(cmd)

        try:
            root = ET.fromstring(output)
            for obj in root.findall(".//Object"):
                record = _parse_xml_record(obj)

                event_id = record.get("Id") or record.get("EventID", "N/A")
                message = record.get("Message", "")
                timestamp = record.get("TimeCreated") or record.get("Time", "")

                if _is_service_error_event(event_id):
                    services_data["errors"].append({
                        "event_id": str(event_id),
                        "timestamp": timestamp,
                        "message": message,
                        "type": "SERVICE_ERROR"
                    })
        except ET.ParseError:
            pass
    except (subprocess.CalledProcessError, Exception) as e:
        if isinstance(e, Exception) and not isinstance(e, subprocess.CalledProcessError):
            services_data["collection_errors"] = (
                f"Failed to collect service errors from Event Log: {e}"
            )


def collect():
    """
    Zbiera informacje o wszystkich usługach Windows.
    Zwraca listę usług z ich statusem, typem startu i błędami.
    """
    services_data = _initialize_services_data()

    if not _check_platform_and_wmi():
        services_data["error"] = "WMI not available - Windows only"
        return services_data

    if _is_ci_environment():
        return services_data

    try:
        _collect_services_from_wmi(services_data)
        _collect_service_errors_from_event_log(services_data)
    except Exception as e:
        services_data["error"] = (
            f"Failed to collect services: {type(e).__name__}: {e}"
        )

    return services_data
