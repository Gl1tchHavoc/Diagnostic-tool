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

def run_powershell_hidden(command):
    """
    Uruchamia PowerShell z ukrytym oknem.
    
    Args:
        command (str): Komenda PowerShell
    
    Returns:
        str: Output z PowerShell
    """
    startupinfo = get_hidden_startupinfo()
    
    try:
        result = subprocess.check_output(
            ["powershell", "-Command", command],
            text=True,
            encoding="utf-8",
            stderr=subprocess.DEVNULL,
            startupinfo=startupinfo
        )
        return result
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"PowerShell command failed: {e}")

