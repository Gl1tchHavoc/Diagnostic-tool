"""
Helper do uruchamiania subprocess z ukrytymi oknami PowerShell.
"""
import subprocess
import sys

def get_hidden_startupinfo():
    """
    Zwraca STARTUPINFO z ukrytym oknem dla Windows.
    
    Returns:
        subprocess.STARTUPINFO lub None (dla nie-Windows)
    """
    if sys.platform != "win32":
        return None
    
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startupinfo.wShowWindow = subprocess.SW_HIDE
    return startupinfo

def run_powershell_safe(cmd_list, startupinfo=None):
    """
    Uruchamia PowerShell z bezpieczną obsługą kodowania.
    Próbuje różne kodowania w przypadku błędów UnicodeDecodeError.
    
    Args:
        cmd_list (list): Lista argumentów dla subprocess (np. ["powershell", "-Command", "..."])
        startupinfo: STARTUPINFO dla ukrycia okna (opcjonalne)
    
    Returns:
        str: Output z PowerShell
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
            startupinfo=startupinfo
        )
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"PowerShell command failed: {e}")
    
    # Próbuj różne kodowania
    for encoding in encodings:
        try:
            result = result_bytes.decode(encoding)
            return result
        except UnicodeDecodeError:
            continue
    
    # Jeśli wszystkie kodowania zawiodły, użyj errors='replace' z UTF-8
    # To zastąpi nieprawidłowe znaki znakiem zastępczym
    try:
        result = result_bytes.decode('utf-8', errors='replace')
        return result
    except Exception as e:
        # Ostateczny fallback - użyj errors='ignore'
        result = result_bytes.decode('utf-8', errors='ignore')
        return result

def run_powershell_hidden(command):
    """
    Uruchamia PowerShell z ukrytym oknem i bezpieczną obsługą kodowania.
    
    Args:
        command (str): Komenda PowerShell
    
    Returns:
        str: Output z PowerShell
    """
    startupinfo = get_hidden_startupinfo()
    cmd_list = ["powershell", "-Command", command]
    
    try:
        return run_powershell_safe(cmd_list, startupinfo)
    except Exception as e:
        raise RuntimeError(f"PowerShell command failed: {e}")

