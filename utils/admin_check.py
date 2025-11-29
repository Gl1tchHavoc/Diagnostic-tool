"""
Sprawdzanie uprawnień administratora i automatyczne podnoszenie uprawnień.
"""
import sys
import ctypes
import os

def is_admin():
    """
    Sprawdza czy program działa z uprawnieniami administratora.
    
    Returns:
        bool: True jeśli ma uprawnienia administratora, False w przeciwnym razie
    """
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def restart_as_admin(hide_console=False):
    """
    Próbuje uruchomić program ponownie z uprawnieniami administratora.
    Wyświetla UAC prompt użytkownikowi.
    Tylko dla Windows.
    
    Args:
        hide_console (bool): Czy ukryć konsolę (dla GUI)
    
    Returns:
        bool: True jeśli udało się uruchomić ponownie, False w przeciwnym razie
    """
    if sys.platform != "win32":
        return False
    
    if is_admin():
        return True
    
    try:
        # Pobierz ścieżkę do skryptu
        script = sys.argv[0]
        if not os.path.isabs(script):
            script = os.path.abspath(script)
        
        # Przygotuj argumenty (wszystkie oprócz nazwy skryptu)
        params = " ".join([f'"{arg}"' if " " in arg else arg for arg in sys.argv[1:]])
        if params:
            cmd_line = f'"{script}" {params}'
        else:
            cmd_line = f'"{script}"'
        
        # Dla GUI używamy pythonw.exe zamiast python.exe (ukrywa konsolę)
        if hide_console:
            # Znajdź pythonw.exe w tym samym katalogu co python.exe
            python_exe = sys.executable
            pythonw_exe = python_exe.replace("python.exe", "pythonw.exe")
            if not os.path.exists(pythonw_exe):
                pythonw_exe = python_exe  # Fallback do python.exe
            executable = pythonw_exe
            show_cmd = 0  # SW_HIDE
        else:
            executable = sys.executable
            show_cmd = 1  # SW_SHOWNORMAL
        
        # Próbuj uruchomić ponownie jako admin (to wyświetli UAC prompt)
        # ShellExecute z "runas" wyświetla UAC dialog
        result = ctypes.windll.shell32.ShellExecuteW(
            None,  # hwnd
            "runas",  # lpOperation - "runas" powoduje wyświetlenie UAC prompt
            executable,  # lpFile - Python interpreter
            cmd_line,  # lpParameters - argumenty (ścieżka do skryptu + parametry)
            None,  # lpDirectory
            show_cmd  # nShowCmd
        )
        
        # Jeśli result > 32, to sukces (wartości < 32 to błędy)
        if result > 32:
            return True
        return False
    except Exception as e:
        if not hide_console:
            print(f"Błąd podczas próby uruchomienia jako administrator: {e}")
        return False

def require_admin(auto_restart=True):
    """
    Sprawdza uprawnienia i automatycznie próbuje uruchomić jako admin jeśli potrzeba.
    
    Args:
        auto_restart (bool): Czy automatycznie próbować uruchomić jako admin
    
    Returns:
        bool: True jeśli ma uprawnienia, False w przeciwnym razie
    """
    if is_admin():
        return True
    
    if auto_restart and sys.platform == "win32":
        print("Wykryto brak uprawnień administratora.")
        print("Próba automatycznego uruchomienia jako administrator...")
        print("(Zostaniesz poproszony o potwierdzenie w oknie UAC)")
        print()
        
        if restart_as_admin():
            # Program zostanie uruchomiony ponownie jako admin, więc kończymy obecną instancję
            sys.exit(0)
        else:
            print("Nie udało się uruchomić jako administrator.")
            print()
    
    print("=" * 60)
    print("WYMAGANE UPRAWNIENIA ADMINISTRATORA")
    print("=" * 60)
    print()
    print("Ten program wymaga uprawnień administratora do:")
    print("- Czytania logów systemowych Windows")
    print("- Dostępu do Registry TxR errors")
    print("- Sprawdzania statusu usług systemowych")
    print("- Analizy BSOD i memory dumps")
    print()
    print("Uruchom program jako administrator:")
    print("1. Kliknij prawym przyciskiem na plik")
    print("2. Wybierz 'Uruchom jako administrator'")
    print()
    print("=" * 60)
    return False

