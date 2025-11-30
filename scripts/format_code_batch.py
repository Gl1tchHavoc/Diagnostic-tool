"""
Formatuje kod w partiach aby uniknąć timeoutów.
"""
import subprocess
import sys
from pathlib import Path

# Podziel na mniejsze partie
BATCHES = [
    ["collectors/base_collector.py", "collectors/__init__.py"],
    ["collectors/hardware.py"],
    ["collectors/system_info.py", "collectors/system_logs.py"],
    ["collectors/drivers.py", "collectors/services.py"],
    ["collectors/storage_health.py", "collectors/registry_txr.py"],
    ["collectors/bsod_dumps.py", "collectors/whea_analyzer.py"],
    ["collectors/performance_counters.py", "collectors/processes.py"],
    ["collectors/wer.py"],
    ["collectors/collector_master.py"],
    ["collectors/collector_master_async.py"],
    ["collectors/collector_master_with_timeouts.py"],
    ["core/collector_registry.py", "core/processor_registry.py"],
    ["core/config_loader.py", "core/orchestrator.py"],
    ["processors/analyzer.py", "processors/base_processor.py"],
    ["utils/logger.py", "utils/subprocess_helper.py"],
    ["utils/requirements_check.py", "utils/export_utils.py"],
    ["utils/performance_monitor.py"],
    ["main.py", "gui_mvp.py"],
]

def format_batch(batch):
    """Formatuje partię plików."""
    formatted = []
    for path in batch:
        if not Path(path).exists():
            continue
        
        try:
            # autopep8
            subprocess.run(
                [sys.executable, "-m", "autopep8", "--in-place",
                 "--aggressive", "--max-line-length=79", path],
                check=False,
                capture_output=True
            )
            # isort
            subprocess.run(
                [sys.executable, "-m", "isort", "--profile=black",
                 "--line-length=79", path],
                check=False,
                capture_output=True
            )
            formatted.append(path)
        except Exception as e:
            print(f"Error formatting {path}: {e}")
    
    return formatted

def main():
    """Formatuje kod w partiach."""
    print("Formatting code in batches...")
    total = 0
    
    for i, batch in enumerate(BATCHES, 1):
        print(f"\nBatch {i}/{len(BATCHES)}: {len(batch)} files")
        formatted = format_batch(batch)
        total += len(formatted)
        print(f"  ✓ Formatted {len(formatted)} files")
    
    print(f"\n✅ Total: {total} files formatted")

if __name__ == "__main__":
    main()

