"""
ShadowCopy detection and filtering utility.
Eliminates false positives from ShadowCopy-related errors.
"""
import re
from utils.logger import get_logger

logger = get_logger()

# Wzorce ShadowCopy
SHADOWCOPY_PATTERNS = [
    r'\\\?\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy\d+',
    r'\\Device\\HarddiskVolumeShadowCopy\d+',
    r'VolumeShadowCopy\d+',
    r'ShadowCopy\d+',
    r'\\\?\?\\GLOBALROOT.*ShadowCopy',
    r'volsnap.*shadow',
    r'vss.*shadow'
]


def is_shadowcopy_path(path_or_message):
    """
    Sprawdza czy ścieżka lub wiadomość zawiera referencję do ShadowCopy.

    Args:
        path_or_message (str): Ścieżka lub wiadomość do sprawdzenia

    Returns:
        bool: True jeśli dotyczy ShadowCopy, False w przeciwnym razie
    """
    if not path_or_message:
        return False

    path_upper = str(path_or_message).upper()

    for pattern in SHADOWCOPY_PATTERNS:
        if re.search(pattern, path_upper, re.IGNORECASE):
            logger.debug(
                f"[SHADOWCOPY] Detected ShadowCopy pattern in: {path_or_message[:100]}")
            return True

    return False


def filter_shadowcopy_errors(errors):
    """
    Filtruje błędy, oddzielając te dotyczące ShadowCopy od rzeczywistych błędów dysku.

    Args:
        errors (list): Lista błędów (dict z kluczem 'message' lub 'path')

    Returns:
        tuple: (real_errors, shadowcopy_errors)
    """
    real_errors = []
    shadowcopy_errors = []

    for error in errors:
        message = error.get('message', '')
        path = error.get('path', '')
        device = error.get('device', '')

        # Sprawdź wszystkie możliwe pola
        text_to_check = f"{message} {path} {device}".strip()

        if is_shadowcopy_path(text_to_check):
            shadowcopy_errors.append(error)
            logger.debug(
                f"[SHADOWCOPY] Classified as ShadowCopy error: {text_to_check[:100]}")
        else:
            real_errors.append(error)

    logger.info(
        f"[SHADOWCOPY] Filtered {len(errors)} errors: {len(real_errors)} real, {len(shadowcopy_errors)} ShadowCopy")

    return real_errors, shadowcopy_errors


def categorize_txr_errors(txr_errors):
    """
    Kategoryzuje błędy Registry TxR na rzeczywiste i ShadowCopy.

    Args:
        txr_errors (list): Lista błędów TxR

    Returns:
        dict: {
            'real_errors': [...],
            'shadowcopy_errors': [...],
            'all_shadowcopy': bool  # True jeśli WSZYSTKIE błędy dotyczą ShadowCopy
        }
    """
    real_errors = []
    shadowcopy_errors = []

    for error in txr_errors:
        message = error.get('message', '')
        if is_shadowcopy_path(message):
            shadowcopy_errors.append(error)
        else:
            real_errors.append(error)

    all_shadowcopy = len(shadowcopy_errors) > 0 and len(real_errors) == 0

    return {
        'real_errors': real_errors,
        'shadowcopy_errors': shadowcopy_errors,
        'all_shadowcopy': all_shadowcopy
    }


def get_shadowcopy_info():
    """
    Pobiera informacje o ShadowCopy z systemu (VSS).

    Returns:
        dict: Informacje o ShadowCopy
    """
    import sys
    if sys.platform != "win32":
        return {"error": "Windows only"}

    shadowcopy_info = {
        "snapshots": [],
        "status": "unknown",
        "errors": []
    }

    try:
        from utils.subprocess_helper import run_powershell_hidden

        # Sprawdź status VSS
        cmd = "Get-Service -Name VSS | Select-Object Status, StartType | ConvertTo-Json"
        output = run_powershell_hidden(cmd)

        if output:
            import json
            try:
                vss_info = json.loads(output)
                shadowcopy_info["vss_service_status"] = vss_info.get(
                    "Status", "Unknown")
                shadowcopy_info["vss_service_starttype"] = vss_info.get(
                    "StartType", "Unknown")
            except BaseException:
                pass

        # Sprawdź snapshoty
        cmd = "Get-ComputerRestorePoint | Select-Object SequenceNumber, CreationTime, Description | ConvertTo-Json"
        output = run_powershell_hidden(cmd)

        if output:
            import json
            try:
                restore_points = json.loads(output)
                if isinstance(restore_points, list):
                    shadowcopy_info["snapshots"] = restore_points
                elif isinstance(restore_points, dict):
                    shadowcopy_info["snapshots"] = [restore_points]
            except BaseException:
                pass

        # Sprawdź błędy VSS w Event Log
        cmd = (
            "Get-WinEvent -LogName System -MaxEvents 50 | "
            "Where-Object {$_.Message -like '*VSS*' -or "
            "$_.Message -like '*ShadowCopy*' -or "
            "$_.Message -like '*volsnap*'} | "
            "Select-Object -First 10 | ConvertTo-Json"
        )
        output = run_powershell_hidden(cmd)

        if output:
            import json
            try:
                vss_events = json.loads(output)
                if isinstance(vss_events, list):
                    shadowcopy_info["recent_events"] = vss_events
                elif isinstance(vss_events, dict):
                    shadowcopy_info["recent_events"] = [vss_events]
            except BaseException:
                pass

        shadowcopy_info["status"] = "ok" if shadowcopy_info.get(
            "vss_service_status") == "Running" else "warning"

    except Exception as e:
        logger.warning(f"[SHADOWCOPY] Error getting ShadowCopy info: {e}")
        shadowcopy_info["error"] = str(e)

    return shadowcopy_info
