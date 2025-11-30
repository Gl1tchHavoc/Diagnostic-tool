"""
Skrypt do automatycznego formatowania całego kodu zgodnie z PEP8 i flake8.
Instaluje wymagane narzędzia i formatuje wszystkie pliki.
"""
import subprocess
import sys
from pathlib import Path

# Katalogi i pliki do formatowania
CODE_PATHS = [
    "collectors",
    "processors",
    "core",
    "utils",
    "correlation",
    "scans",
    "tests",
    "main.py",
    "gui_mvp.py",
    "gui.py",
    "cli.py",
]


def install_package(package_name):
    """Instaluje pakiet jeśli nie jest zainstalowany."""
    try:
        __import__(package_name)
        return True
    except ImportError:
        print(f"Installing {package_name}...")
        try:
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", package_name],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            return True
        except subprocess.CalledProcessError:
            print(f"Failed to install {package_name}")
            return False


def format_with_autopep8(path):
    """Formatuje plik/katalog używając autopep8."""
    if not Path(path).exists():
        return False
    
    is_dir = Path(path).is_dir()
    cmd = [
        sys.executable, "-m", "autopep8",
        "--in-place",
        "--aggressive",
        "--aggressive",
        "--max-line-length=79",
    ]
    
    if is_dir:
        cmd.append("--recursive")
    
    cmd.append(path)
    
    try:
        subprocess.run(
            cmd,
            check=False,
            capture_output=True,
            text=True
        )
        return True
    except Exception as e:
        print(f"Error formatting {path}: {e}")
        return False


def sort_imports_with_isort(path):
    """Sortuje importy używając isort."""
    if not Path(path).exists():
        return False
    
    is_dir = Path(path).is_dir()
    cmd = [
        sys.executable, "-m", "isort",
        "--profile=black",
        "--line-length=79",
    ]
    
    if is_dir:
        cmd.append("--recursive")
    
    cmd.append(path)
    
    try:
        subprocess.run(
            cmd,
            check=False,
            capture_output=True,
            text=True
        )
        return True
    except Exception as e:
        print(f"Error sorting imports in {path}: {e}")
        return False


def main():
    """Główna funkcja formatująca kod."""
    print("="*70)
    print("Code Formatting Script")
    print("="*70)
    
    # Sprawdź i zainstaluj wymagane narzędzia
    print("\n1. Checking required tools...")
    if not install_package("autopep8"):
        print("❌ Failed to install autopep8")
        return
    
    if not install_package("isort"):
        print("❌ Failed to install isort")
        return
    
    print("✅ All tools installed")
    
    # Formatuj kod
    print("\n2. Formatting code with autopep8...")
    formatted = 0
    for path in CODE_PATHS:
        if format_with_autopep8(path):
            formatted += 1
            print(f"  ✓ Formatted: {path}")
    
    print(f"\n✅ Formatted {formatted} paths")
    
    # Sortuj importy
    print("\n3. Sorting imports with isort...")
    sorted_count = 0
    for path in CODE_PATHS:
        if sort_imports_with_isort(path):
            sorted_count += 1
            print(f"  ✓ Sorted imports: {path}")
    
    print(f"\n✅ Sorted imports in {sorted_count} paths")
    
    print("\n" + "="*70)
    print("✅ Formatting complete!")
    print("="*70)
    print("\nNext steps:")
    print("1. Review changes: git diff")
    print("2. Run flake8: flake8 collectors/ processors/ core/ utils/")
    print("3. Commit if satisfied")


if __name__ == "__main__":
    main()

