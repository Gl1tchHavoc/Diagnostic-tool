"""
Narzędzie do czyszczenia starych plików raw_data.
Można uruchomić ręcznie: python -m utils.cleanup_raw_data
"""
from utils.logger import get_logger
from collectors.collector_master import cleanup_old_raw_files
import sys
from pathlib import Path

# Dodaj główny katalog do ścieżki
sys.path.insert(0, str(Path(__file__).parent.parent))


def main():
    """Główna funkcja - czyści stare pliki raw_data."""
    logger = get_logger()

    print("=" * 60)
    print("RAW DATA CLEANUP")
    print("=" * 60)
    print()

    # Sprawdź ile plików jest przed czyszczeniem
    output_dir = Path("output/raw")
    if output_dir.exists():
        raw_files = sorted(
            output_dir.glob("raw_data_*.json"),
            key=lambda p: p.stat().st_mtime,
            reverse=True
        )

        total_size = sum(f.stat().st_size for f in raw_files)
        total_mb = total_size / (1024 * 1024)

        print(f"Current files: {len(raw_files)}")
        print(f"Total size: {total_mb:.2f} MB")
        print()

        if len(raw_files) > 5:
            print(f"Cleaning up... (keeping last 5 files)")
            cleanup_old_raw_files("output/raw", keep_last=5)

            # Sprawdź po czyszczeniu
            raw_files_after = sorted(
                output_dir.glob("raw_data_*.json"),
                key=lambda p: p.stat().st_mtime,
                reverse=True
            )

            total_size_after = sum(f.stat().st_size for f in raw_files_after)
            total_mb_after = total_size_after / (1024 * 1024)

            print()
            print(f"After cleanup:")
            print(f"  Files: {len(raw_files_after)}")
            print(f"  Size: {total_mb_after:.2f} MB")
            print(f"  Freed: {total_mb - total_mb_after:.2f} MB")
        else:
            print("No cleanup needed - less than 5 files")
    else:
        print("No output/raw directory found")

    print()
    print("=" * 60)


if __name__ == "__main__":
    main()
