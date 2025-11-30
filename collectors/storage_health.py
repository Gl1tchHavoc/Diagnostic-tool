import os
import subprocess
import sys
import xml.etree.ElementTree as ET

# WMI dla Windows
if sys.platform == "win32":
    try:
        import wmi
    except ImportError:
        wmi = None

from utils.subprocess_helper import run_powershell_hidden


def _initialize_storage_data():
    """
    Inicjalizuje strukturę danych storage.

    Returns:
        dict: Pusta struktura danych storage
    """
    return {
        "disks": [],
        "smart_errors": [],
        "io_errors": [],
        "disk_errors": []
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


def _create_disk_info(disk):
    """
    Tworzy słownik z informacjami o dysku.

    Args:
        disk: Obiekt WMI Win32_DiskDrive

    Returns:
        dict: Informacje o dysku
    """
    return {
        "model": disk.Model.strip() if disk.Model else "Unknown",
        "serial": disk.SerialNumber.strip() if disk.SerialNumber else "Unknown",
        "status": disk.Status if disk.Status else "Unknown",
        "size": int(disk.Size) if disk.Size else 0,
        "interface": disk.InterfaceType if disk.InterfaceType else "Unknown",
        "media_type": disk.MediaType if disk.MediaType else "Unknown"
    }


def _collect_disk_info_from_wmi(storage_data):
    """
    Zbiera informacje o dyskach przez WMI.

    Args:
        storage_data: Słownik z danymi storage do uzupełnienia
    """
    try:
        c = wmi.WMI()
        disks = c.Win32_DiskDrive()
    except (AttributeError, TypeError, ValueError, ImportError) as e:
        # WMI może zwracać różne błędy lub może nie być dostępny
        return

    for disk in disks:
        disk_info = _create_disk_info(disk)
        storage_data["disks"].append(disk_info)


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


def _classify_storage_error(record, storage_data):
    """
    Klasyfikuje błąd storage i dodaje do odpowiedniej kategorii.

    Args:
        record: Słownik z danymi rekordu Event Log
        storage_data: Słownik z danymi storage do uzupełnienia
    """
    event_id = record.get("Id") or record.get("EventID", "N/A")
    message = record.get("Message", "")
    timestamp = record.get("TimeCreated") or record.get("Time", "")

    error_entry = {
        "event_id": str(event_id),
        "timestamp": timestamp,
        "message": message
    }

    message_lower = message.lower()

    # SMART errors
    if any(keyword in message_lower for keyword in [
        "bad block", "bad sector", "reallocated"
    ]):
        error_entry["type"] = "SMART_ERROR"
        storage_data["smart_errors"].append(error_entry)
        return

    # IO errors
    if any(keyword in message_lower for keyword in [
        "io error", "i/o error", "read error", "write error"
    ]):
        error_entry["type"] = "IO_ERROR"
        storage_data["io_errors"].append(error_entry)
        return

    # Disk errors
    if any(keyword in message_lower for keyword in [
        "disk", "ntfs", "volsnap"
    ]):
        error_entry["type"] = "DISK_ERROR"
        storage_data["disk_errors"].append(error_entry)


def _collect_disk_errors_from_event_log(storage_data):
    """
    Zbiera błędy dysków z Event Log.

    Args:
        storage_data: Słownik z danymi storage do uzupełnienia
    """
    cmd = (
        "Get-WinEvent -LogName System -MaxEvents 200 | "
        "Where-Object {$_.Id -in @(7,51,52,55,57,129) -or "
        "$_.Message -like '*disk*' -or $_.Message -like '*ntfs*' "
        "-or $_.Message -like '*bad block*'} | "
        "ConvertTo-Xml -As String -Depth 3"
    )

    try:
        output = run_powershell_hidden(cmd)
        root = ET.fromstring(output)

        for obj in root.findall(".//Object"):
            record = _parse_xml_record(obj)
            _classify_storage_error(record, storage_data)
    except (ET.ParseError, subprocess.CalledProcessError):
        pass


def _try_collect_smart_data(storage_data):
    """
    Próbuje pobrać SMART data (obecnie tylko ustawia flagę).

    Args:
        storage_data: Słownik z danymi storage do uzupełnienia
    """
    try:
        c = wmi.WMI()
        for _ in c.Win32_DiskDrive():
            storage_data["smart_available"] = False
            break
    except (AttributeError, TypeError, ValueError, ImportError) as e:
        # WMI może zwracać różne błędy
        pass


def collect():
    """
    Zbiera informacje o zdrowiu dysków (SMART, błędy I/O, wydajność).
    Zwraca szczegółowe dane o stanie dysków.
    """
    storage_data = _initialize_storage_data()

    if not _check_platform_and_wmi():
        storage_data["error"] = "WMI not available - Windows only"
        return storage_data

    if _is_ci_environment():
        return storage_data

    try:
        _collect_disk_info_from_wmi(storage_data)
        _collect_disk_errors_from_event_log(storage_data)
        _try_collect_smart_data(storage_data)
    except Exception as e:
        storage_data["error"] = (
            f"Failed to collect storage health: "
            f"{type(e).__name__}: {e}"
        )

    return storage_data
