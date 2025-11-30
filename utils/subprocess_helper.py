"""
Helper do uruchamiania subprocess z ukrytymi oknami PowerShell.
"""
import subprocess
import sys
import signal
from utils.logger import get_logger

logger = get_logger()


def get_hidden_startupinfo():
    """
    Zwraca STARTUPINFO z ukrytym oknem dla Windows.

    Returns:
        subprocess.STARTUPINFO lub None (dla nie-Windows)
    """
    if sys.platform != "win32":
        return None

    try:
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = subprocess.SW_HIDE
        return startupinfo
    except Exception as e:
        logger.debug(f"[SUBPROCESS] Error creating STARTUPINFO: {e}")
        return None


def run_powershell_safe(cmd_list, startupinfo=None, timeout=30):
    """
    Uruchamia PowerShell z bezpieczną obsługą kodowania i timeoutem.
    Próbuje różne kodowania w przypadku błędów UnicodeDecodeError.

    Args:
        cmd_list (list): Lista argumentów dla subprocess (np. ["powershell", "-Command", "..."])
        startupinfo: STARTUPINFO dla ukrycia okna (opcjonalne)
        timeout (int): Timeout w sekundach (domyślnie 30)

    Returns:
        str: Output z PowerShell

    Raises:
        RuntimeError: Jeśli komenda się nie powiedzie lub timeout
    """
    # Lista kodowań do wypróbowania (w kolejności priorytetu)
    encodings = [
        'utf-8',
        'utf-8-sig',  # UTF-8 z BOM
        'cp1250',     # Windows-1250 (Central European)
        'cp1252',     # Windows-1252 (Western European)
        'cp850',      # DOS Latin-1
        'latin1',     # ISO-8859-1
        'cp437',      # DOS US
    ]

    # Najpierw spróbuj bez text=True, żeby dostać raw bytes
    try:
        result_bytes = subprocess.check_output(
            cmd_list,
            stderr=subprocess.DEVNULL,
            startupinfo=startupinfo,
            timeout=timeout,
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
        )
    except subprocess.TimeoutExpired:
        logger.warning(
            f"[SUBPROCESS] PowerShell command timeout after {timeout}s")
        raise RuntimeError(f"PowerShell command timeout after {timeout}s")
    except subprocess.CalledProcessError as e:
        logger.warning(
            f"[SUBPROCESS] PowerShell command failed with code {e.returncode}")
        raise RuntimeError(f"PowerShell command failed: {e}")
    except OSError as e:
        # Błąd 0x800401f0 i podobne błędy COM/Windows API
        logger.warning(f"[SUBPROCESS] OS error during subprocess: {e}")
        # Zwróć pusty string zamiast crashować
        return ""
    except Exception as e:
        logger.warning(f"[SUBPROCESS] Unexpected error during subprocess: {e}")
        # Zwróć pusty string zamiast crashować
        return ""

    # Próbuj różne kodowania
    for encoding in encodings:
        try:
            result = result_bytes.decode(encoding)
            if encoding != 'utf-8':
                logger.debug(f"[SUBPROCESS] Used encoding: {encoding}")
            return result
        except UnicodeDecodeError:
            continue

    # Jeśli wszystkie kodowania zawiodły, użyj errors='replace' z UTF-8
    # To zastąpi nieprawidłowe znaki znakiem zastępczym
    logger.warning(
        "[SUBPROCESS] All encodings failed, using UTF-8 with error replacement")
    try:
        result = result_bytes.decode('utf-8', errors='replace')
        return result
    except Exception as e:
        # Ostateczny fallback - użyj errors='ignore'
        logger.error(
            f"[SUBPROCESS] UTF-8 decode failed: {e}, using ignore mode")
        result = result_bytes.decode('utf-8', errors='ignore')
        return result


def run_powershell_hidden(command, timeout=30):
    """
    Uruchamia PowerShell z ukrytym oknem i bezpieczną obsługą kodowania.

    Args:
        command (str): Komenda PowerShell
        timeout (int): Timeout w sekundach (domyślnie 30)

    Returns:
        str: Output z PowerShell (pusty string w przypadku błędu)
    """
    startupinfo = get_hidden_startupinfo()
    cmd_list = ["powershell", "-Command", command]

    try:
        return run_powershell_safe(cmd_list, startupinfo, timeout=timeout)
    except RuntimeError:
        # RuntimeError już jest zalogowany w run_powershell_safe
        return ""
    except Exception as e:
        logger.warning(
            f"[SUBPROCESS] Unexpected error in run_powershell_hidden: {e}")
        return ""
