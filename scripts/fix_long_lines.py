"""
Skrypt do automatycznego dzielenia długich linii (>79 znaków).
Używa autopep8 do naprawienia większości problemów.
"""
import subprocess
import sys
from pathlib import Path

# Wszystkie katalogi i pliki do formatowania
PATHS = [
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


def fix_long_lines(path):
    """Naprawia długie linie w pliku/katalogu."""
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
        result = subprocess.run(
            cmd,
            check=False,
            capture_output=True,
            text=True
        )
        return result.returncode == 0
    except Exception:
        return False


def main():
    """Naprawia długie linie we wszystkich plikach."""
    print("Fixing long lines (>79 characters)...")
    
    fixed = 0
    for path in PATHS:
        if fix_long_lines(path):
            fixed += 1
            print(f"  ✓ Fixed: {path}")
    
    print(f"\n✅ Fixed {fixed} paths")


if __name__ == "__main__":
    main()

