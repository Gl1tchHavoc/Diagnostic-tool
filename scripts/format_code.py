"""
Skrypt do automatycznego formatowania kodu zgodnie z PEP8 i flake8.
Używa autopep8 i isort do naprawienia większości błędów stylistycznych.
"""
import subprocess
import sys
from pathlib import Path

# Katalogi do formatowania
CODE_DIRS = [
    "collectors",
    "processors",
    "core",
    "utils",
    "correlation",
    "scans",
    "tests",
]

# Pliki do formatowania
CODE_FILES = [
    "main.py",
    "gui_mvp.py",
    "gui.py",
    "cli.py",
]

def run_command(cmd, description):
    """Uruchamia komendę i wyświetla wynik."""
    print(f"\n{'='*70}")
    print(f"{description}")
    print(f"{'='*70}")
    print(f"Running: {' '.join(cmd)}")
    
    try:
        result = subprocess.run(
            cmd,
            check=False,
            capture_output=True,
            text=True
        )
        
        if result.stdout:
            print(result.stdout)
        if result.stderr:
            print(result.stderr, file=sys.stderr)
        
        return result.returncode == 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return False

def format_with_autopep8():
    """Formatuje kod używając autopep8."""
    all_paths = CODE_DIRS + CODE_FILES
    
    # Najpierw sprawdź co będzie zmienione (--diff)
    print("\n📋 Checking what will be changed...")
    for path in all_paths:
        if Path(path).exists():
            cmd = [
                "autopep8",
                "--in-place",
                "--aggressive",
                "--aggressive",
                "--max-line-length=79",
                "--recursive" if Path(path).is_dir() else "",
                path
            ]
            cmd = [c for c in cmd if c]  # Usuń puste stringi
            
            run_command(cmd, f"Formatting {path}")

def sort_imports():
    """Sortuje importy używając isort."""
    all_paths = CODE_DIRS + CODE_FILES
    
    for path in all_paths:
        if Path(path).exists():
            cmd = [
                "isort",
                "--profile=black",
                "--line-length=79",
                "--recursive" if Path(path).is_dir() else "",
                path
            ]
            cmd = [c for c in cmd if c]  # Usuń puste stringi
            
            run_command(cmd, f"Sorting imports in {path}")

def main():
    """Główna funkcja formatująca kod."""
    print("="*70)
    print("Code Formatting Script")
    print("="*70)
    print("\nThis script will:")
    print("1. Format code using autopep8 (PEP8 compliance)")
    print("2. Sort imports using isort")
    print("3. Fix indentation, whitespace, and style issues")
    print("\n⚠️  This will modify files in place!")
    
    response = input("\nContinue? (yes/no): ")
    if response.lower() not in ['yes', 'y']:
        print("Aborted.")
        return
    
    # Formatuj kod
    format_with_autopep8()
    
    # Sortuj importy
    sort_imports()
    
    print("\n" + "="*70)
    print("✅ Formatting complete!")
    print("="*70)
    print("\nNext steps:")
    print("1. Run: flake8 collectors/ processors/ core/ utils/")
    print("2. Review changes with: git diff")
    print("3. Commit if satisfied")

if __name__ == "__main__":
    main()

