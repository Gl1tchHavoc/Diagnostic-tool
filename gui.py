import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk
from threading import Thread
import json
import sys
import time
from datetime import timedelta

# Sprawdź uprawnienia administratora
from utils.admin_check import is_admin, require_admin, restart_as_admin

# Logger
from utils.logger import get_logger, log_performance, log_exception
from utils.requirements_check import check_all_requirements, print_requirements_status

# Nowa struktura - wszystkie collectory
from collectors import (
    hardware, drivers, system_logs, registry_txr, storage_health, system_info,
    services, bsod_dumps, performance_counters, wer, processes
)
from collectors.collector_master import collect_all
from processors.analyzer import analyze_all
# Nowy system skanów
from scans.scan_manager import QuickScan, FullScan
# bsod_analyzer importowany lokalnie w funkcji, żeby nie blokować uruchomienia

class DiagnosticsGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Super Diagnostics Tool")
        self.root.geometry("1800x1200")
        self.root.configure(bg="#2e2e2e")
        
        # Sprawdź uprawnienia administratora
        if not is_admin():
            self.show_admin_warning()
        
        self.setup_widgets()
    
    def show_admin_warning(self):
        """Wyświetla ostrzeżenie o braku uprawnień administratora."""
        warning_text = (
            "⚠️ WYMAGANE UPRAWNIENIA ADMINISTRATORA\n\n"
            "Ten program wymaga uprawnień administratora do:\n"
            "• Czytania logów systemowych Windows\n"
            "• Dostępu do Registry TxR errors\n"
            "• Sprawdzania statusu usług systemowych\n"
            "• Analizy BSOD i memory dumps\n\n"
            "Niektóre funkcje mogą nie działać poprawnie.\n\n"
            "Uruchom program jako administrator:\n"
            "1. Zamknij to okno\n"
            "2. Kliknij prawym przyciskiem na plik\n"
            "3. Wybierz 'Uruchom jako administrator'"
        )
        messagebox.showwarning("Uprawnienia administratora", warning_text)

    def setup_widgets(self):
        # Frame dla przycisków skanów
        scan_frame = tk.Frame(self.root, bg="#2e2e2e")
        scan_frame.pack(pady=10)
        
        # Przycisk - Quick Scan
        self.quick_scan_btn = tk.Button(
            scan_frame, text="⚡ QUICK SCAN", command=self.start_quick_scan,
            bg="#00cc66", fg="white", activebackground="#00aa55", activeforeground="white",
            font=("Arial", 12, "bold"), pady=8, width=25
        )
        self.quick_scan_btn.pack(side=tk.LEFT, padx=5)
        
        # Główny przycisk - Full System Scan
        self.full_scan_btn = tk.Button(
            scan_frame, text="🔍 FULL SYSTEM SCAN", command=self.start_full_scan,
            bg="#0066cc", fg="white", activebackground="#0055aa", activeforeground="white",
            font=("Arial", 14, "bold"), pady=10, width=25
        )
        self.full_scan_btn.pack(side=tk.LEFT, padx=5)
        
        # Przycisk - BSOD Analysis
        self.bsod_analysis_btn = tk.Button(
            self.root, text="💥 BSOD ANALYSIS", command=self.start_bsod_analysis,
            bg="#cc6600", fg="white", activebackground="#aa5500", activeforeground="white",
            font=("Arial", 12, "bold"), pady=8, width=30
        )
        self.bsod_analysis_btn.pack(pady=5)

        # Separator
        separator1 = tk.Frame(self.root, height=2, bg="#555555")
        separator1.pack(fill=tk.X, padx=20, pady=10)

        # Frame dla przycisków collectorów
        collectors_frame = tk.Frame(self.root, bg="#2e2e2e")
        collectors_frame.pack(pady=10)

        # Label
        label = tk.Label(
            collectors_frame, text="Individual Collectors:", 
            bg="#2e2e2e", fg="white", font=("Arial", 10, "bold")
        )
        label.pack(pady=5)

        # Przyciski dla każdego collectora - w dwóch kolumnach
        buttons_frame = tk.Frame(collectors_frame, bg="#2e2e2e")
        buttons_frame.pack()

        # Kolumna 1
        col1 = tk.Frame(buttons_frame, bg="#2e2e2e")
        col1.pack(side=tk.LEFT, padx=10)

        # Kolumna 2
        col2 = tk.Frame(buttons_frame, bg="#2e2e2e")
        col2.pack(side=tk.LEFT, padx=10)

        # Definicje collectorów
        collectors = [
            ("Hardware", hardware.collect, col1),
            ("Drivers", drivers.collect, col1),
            ("System Logs", lambda: system_logs.collect(max_events=200, filter_levels=['Error', 'Warning', 'Critical']), col1),
            ("Registry TxR", lambda: registry_txr.collect(max_events=200), col1),
            ("Storage Health", storage_health.collect, col1),
            ("System Info", system_info.collect, col1),
            ("Services", services.collect, col2),
            ("BSOD/Dumps", bsod_dumps.collect, col2),
            ("Performance", performance_counters.collect, col2),
            ("WER", wer.collect, col2),
            ("Processes", processes.collect, col2),
        ]

        # Tworzenie przycisków
        self.collector_buttons = {}
        for name, collector_func, parent in collectors:
            btn = tk.Button(
                parent, text=name, command=lambda c=collector_func, n=name: self.start_collector_scan(c, n),
                bg="#444444", fg="white", activebackground="#555555", activeforeground="white",
                width=20, pady=3
            )
            btn.pack(pady=2)
            self.collector_buttons[name] = btn

        # Separator
        separator2 = tk.Frame(self.root, height=2, bg="#555555")
        separator2.pack(fill=tk.X, padx=20, pady=10)

        # Output Text
        self.output_text = scrolledtext.ScrolledText(
            self.root, width=200, height=40, bg="#1e1e1e", fg="white", insertbackground="white",
            font=("Consolas", 9)
        )
        self.output_text.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        # Progress bar
        progress_frame = tk.Frame(self.root, bg="#2e2e2e")
        progress_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=10, pady=5)
        
        self.progress_label = tk.Label(
            progress_frame, text="Ready", bg="#2e2e2e", fg="white", 
            font=("Arial", 9), anchor=tk.W
        )
        self.progress_label.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        self.progress_percent = tk.Label(
            progress_frame, text="0%", bg="#2e2e2e", fg="#00ff00", 
            font=("Arial", 9, "bold"), width=5
        )
        self.progress_percent.pack(side=tk.RIGHT)
        
        self.progress_bar = tk.ttk.Progressbar(
            self.root, mode='determinate', length=400, maximum=100
        )
        self.progress_bar.pack(side=tk.BOTTOM, fill=tk.X, padx=10, pady=(0, 5))
        
        # Status bar
        self.status = tk.Label(
            self.root, text="Ready", bd=1, relief=tk.SUNKEN, anchor=tk.W,
            bg="#444444", fg="white", font=("Arial", 9)
        )
        self.status.pack(side=tk.BOTTOM, fill=tk.X)

#-----------------------------------------
# Full System Scan
    def start_quick_scan(self):
        """Uruchamia Quick Scan w osobnym wątku."""
        thread = Thread(target=self.run_quick_scan, daemon=True)
        thread.start()
    
    def start_full_scan(self):
        thread = Thread(target=self.run_full_scan, daemon=True)
        thread.start()

    def update_progress(self, step, total, message):
        """Aktualizuje pasek postępu i status."""
        percent = int((step / total) * 100)
        self.progress_bar['value'] = percent
        self.progress_percent.config(text=f"{percent}%")
        self.progress_label.config(text=message)
        self.status.config(text=f"{message} ({step}/{total})")
        self.root.update()
    
    def run_quick_scan(self):
        """Uruchamia Quick Scan używając nowego systemu ScanManager."""
        logger = get_logger()
        logger.info("[GUI] Starting quick scan")
        scan_start_time = time.time()
        
        self.status.config(text="Starting Quick Scan...")
        self.progress_bar['value'] = 0
        self.progress_percent.config(text="0%")
        self.progress_label.config(text="Initializing...")
        self.quick_scan_btn.config(state=tk.DISABLED)
        self.full_scan_btn.config(state=tk.DISABLED)
        for btn in self.collector_buttons.values():
            btn.config(state=tk.DISABLED)
        
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert(tk.END, "=" * 70 + "\n")
        self.output_text.insert(tk.END, "QUICK SYSTEM SCAN\n")
        self.output_text.insert(tk.END, "=" * 70 + "\n\n")
        self.root.update()
        
        try:
            # Callback do aktualizacji postępu
            def progress_callback(progress, message):
                self.progress_bar['value'] = progress
                self.progress_percent.config(text=f"{progress:.1f}%")
                self.progress_label.config(text=message)
                self.status.config(text=message)
                self.output_text.insert(tk.END, f"  [{progress:.1f}%] {message}\n")
                self.output_text.see(tk.END)
                self.root.update()
            
            # Uruchom Quick Scan
            quick_scan = QuickScan(progress_callback=progress_callback)
            scan_results = quick_scan.run()
            
            # Konwertuj wyniki do formatu oczekiwanego przez analyzer
            # Upewnij się, że scan_results jest słownikiem
            if not isinstance(scan_results, dict):
                raise ValueError(f"scan_results is not a dict: {type(scan_results)}")
            
            results = scan_results.get('results', {})
            if not isinstance(results, dict):
                results = {}
            
            collectors = results.get('collectors', {})
            if not isinstance(collectors, dict):
                collectors = {}
            
            collected_data = {
                "timestamp": scan_results.get('timestamp', ''),
                "collectors": collectors
            }
            
            # Bezpieczne pobranie progress_info
            progress_info = scan_results.get('progress_info', {})
            if not isinstance(progress_info, dict):
                progress_info = {}
            global_progress = progress_info.get('global_progress', 100.0)
            self.output_text.insert(tk.END, f"✓ Quick scan completed ({global_progress:.1f}%)\n\n")
            self.root.update()
            
            # Analizuj wyniki
            analysis_report = analyze_all(collected_data)
            self.display_analysis_results(analysis_report)
            
            scan_duration = time.time() - scan_start_time
            logger.info(f"[GUI] Quick scan completed in {scan_duration:.2f}s")
            self.status.config(text="Quick Scan Completed")
            self.progress_label.config(text="Quick scan completed successfully")
            
        except Exception as e:
            error_msg = f"Quick scan failed: {type(e).__name__}: {str(e)}"
            logger.exception("[GUI] Quick scan failed")
            messagebox.showerror("Error", error_msg)
            self.output_text.insert(tk.END, f"\n❌ ERROR: {error_msg}\n")
        finally:
            self.quick_scan_btn.config(state=tk.NORMAL)
            self.full_scan_btn.config(state=tk.NORMAL)
            for btn in self.collector_buttons.values():
                btn.config(state=tk.NORMAL)
    
    def run_full_scan(self):
        logger = get_logger()
        logger.info("[GUI] Starting full system scan")
        scan_start_time = time.time()
        
        self.status.config(text="Starting Full System Scan...")
        self.progress_bar['value'] = 0
        self.progress_percent.config(text="0%")
        self.progress_label.config(text="Initializing...")
        self.quick_scan_btn.config(state=tk.DISABLED)
        self.full_scan_btn.config(state=tk.DISABLED)
        for btn in self.collector_buttons.values():
            btn.config(state=tk.DISABLED)
        
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert(tk.END, "=" * 70 + "\n")
        self.output_text.insert(tk.END, "FULL SYSTEM DIAGNOSTIC SCAN\n")
        self.output_text.insert(tk.END, "=" * 70 + "\n\n")
        self.root.update()
        
        try:
            # Callback do aktualizacji postępu
            def progress_callback(progress, message):
                try:
                    logger.debug(f"[GUI] DEBUG: progress_callback called: progress={progress}, message={message}")
                    # Progress jest już 0-100% z ProgressCalculator
                    self.progress_bar['value'] = progress
                    self.progress_percent.config(text=f"{progress:.1f}%")
                    self.progress_label.config(text=message)
                    self.status.config(text=message)
                    self.output_text.insert(tk.END, f"  [{progress:.1f}%] {message}\n")
                    self.output_text.see(tk.END)
                    logger.debug(f"[GUI] DEBUG: About to call root.update()")
                    self.root.update()
                    logger.debug(f"[GUI] DEBUG: root.update() completed")
                except Exception as e:
                    logger.exception(f"[GUI] DEBUG: Exception in progress_callback: {e}")
                    # Nie przerywaj - tylko loguj błąd
            
            # Uruchom Full Scan używając nowego systemu
            logger.debug("[GUI] DEBUG: About to create FullScan")
            full_scan = FullScan(progress_callback=progress_callback)
            logger.debug("[GUI] DEBUG: About to run FullScan")
            scan_results = full_scan.run()
            
            # DEBUG: Sprawdź wyniki skanowania
            logger.debug(f"[GUI] DEBUG: scan_results type: {type(scan_results)}")
            logger.debug(f"[GUI] DEBUG: scan_results is dict: {isinstance(scan_results, dict)}")
            if isinstance(scan_results, dict):
                logger.debug(f"[GUI] DEBUG: scan_results keys: {list(scan_results.keys())}")
                if 'results' in scan_results:
                    logger.debug(f"[GUI] DEBUG: scan_results['results'] type: {type(scan_results['results'])}")
                    if isinstance(scan_results['results'], dict) and 'collectors' in scan_results['results']:
                        logger.debug(f"[GUI] DEBUG: scan_results['results']['collectors'] type: {type(scan_results['results']['collectors'])}")
                        if isinstance(scan_results['results']['collectors'], dict) and 'wer' in scan_results['results']['collectors']:
                            wer_data = scan_results['results']['collectors']['wer']
                            logger.debug(f"[GUI] DEBUG: WER data type: {type(wer_data)}")
                            if isinstance(wer_data, dict) and 'grouped_crashes' in wer_data:
                                logger.debug(f"[GUI] DEBUG: WER grouped_crashes type: {type(wer_data['grouped_crashes'])}")
                                logger.debug(f"[GUI] DEBUG: WER grouped_crashes is list: {isinstance(wer_data['grouped_crashes'], list)}")
            
            # Konwertuj wyniki do formatu oczekiwanego przez analyzer
            # Upewnij się, że scan_results jest słownikiem
            if not isinstance(scan_results, dict):
                raise ValueError(f"scan_results is not a dict: {type(scan_results)}")
            
            results = scan_results.get('results', {})
            if not isinstance(results, dict):
                results = {}
            
            collectors = results.get('collectors', {})
            if not isinstance(collectors, dict):
                collectors = {}
            
            # DEBUG: Sprawdź collectors przed utworzeniem collected_data
            logger.debug(f"[GUI] DEBUG: collectors type: {type(collectors)}")
            logger.debug(f"[GUI] DEBUG: collectors keys: {list(collectors.keys()) if isinstance(collectors, dict) else 'N/A'}")
            if isinstance(collectors, dict) and 'wer' in collectors:
                logger.debug(f"[GUI] DEBUG: collectors['wer'] type: {type(collectors['wer'])}")
            
            collected_data = {
                "timestamp": scan_results.get('timestamp', ''),
                "collectors": collectors
            }
            
            # DEBUG: Sprawdź collected_data przed przekazaniem do analyzer
            logger.debug(f"[GUI] DEBUG: collected_data type: {type(collected_data)}")
            logger.debug(f"[GUI] DEBUG: collected_data['collectors'] type: {type(collected_data.get('collectors'))}")
            if isinstance(collected_data.get('collectors'), dict) and 'wer' in collected_data['collectors']:
                logger.debug(f"[GUI] DEBUG: collected_data['collectors']['wer'] type: {type(collected_data['collectors']['wer'])}")
            
            # Bezpieczne pobranie progress_info
            progress_info = scan_results.get('progress_info', {})
            if not isinstance(progress_info, dict):
                progress_info = {}
            global_progress = progress_info.get('global_progress', 100.0)
            self.output_text.insert(tk.END, f"✓ Data collection completed ({global_progress:.1f}%)\n\n")
            self.root.update()
            
            # Krok 2: Analizuj
            self.output_text.insert(tk.END, "Step 2: Processing and analyzing data...\n")
            self.output_text.insert(tk.END, "-" * 70 + "\n")
            self.root.update()
            
            # Callback do aktualizacji postępu analizy (50-100%)
            def analysis_callback(step, total, message):
                # Oblicz procent dla kroku analizy (50-100%)
                analysis_percent = 50 + int((step / total) * 50)
                self.progress_bar['value'] = analysis_percent
                self.progress_percent.config(text=f"{analysis_percent}%")
                self.progress_label.config(text=message)
                self.status.config(text=f"{message} ({step}/{total})")
                self.output_text.insert(tk.END, f"  [{step}/{total}] {message}\n")
                self.output_text.see(tk.END)
                self.root.update()
            
            analysis_report = analyze_all(collected_data, progress_callback=analysis_callback)
            
            self.output_text.insert(tk.END, "✓ Data collection completed\n\n")
            self.root.update()
            
            # Krok 2: Analizuj
            self.output_text.insert(tk.END, "Step 2: Processing and analyzing data...\n")
            self.output_text.insert(tk.END, "-" * 70 + "\n")
            self.root.update()
            
            # Callback do aktualizacji postępu analizy (50-100%)
            def analysis_callback(step, total, message):
                # Oblicz procent dla kroku analizy (50-100%)
                analysis_percent = 50 + int((step / total) * 50)
                self.progress_bar['value'] = analysis_percent
                self.progress_percent.config(text=f"{analysis_percent}%")
                self.progress_label.config(text=message)
                self.status.config(text=f"{message} ({step}/{total})")
                self.output_text.insert(tk.END, f"  [{step}/{total}] {message}\n")
                self.output_text.see(tk.END)
                self.root.update()
            
            analysis_report = analyze_all(collected_data, progress_callback=analysis_callback)
            
            self.output_text.insert(tk.END, "✓ Analysis completed\n\n")
            self.progress_bar['value'] = 100
            self.progress_percent.config(text="100%")
            self.root.update()
            
            # Wyświetl wyniki
            self.display_analysis_results(analysis_report)
            
            # Wyświetl analizę BSOD jeśli dostępna
            if not isinstance(analysis_report, dict):
                analysis_report = {}
            bsod_analysis = analysis_report.get("bsod_analysis")
            if bsod_analysis and isinstance(bsod_analysis, dict) and bsod_analysis.get("bsod_found", False):
                self.output_text.insert(tk.END, "\n" + "=" * 70 + "\n")
                self.output_text.insert(tk.END, "BSOD ANALYSIS (from full scan)\n")
                self.output_text.insert(tk.END, "=" * 70 + "\n\n")
                self.display_bsod_analysis(bsod_analysis)
            
            scan_duration = time.time() - scan_start_time
            logger.info(f"[GUI] Full system scan completed in {scan_duration:.2f}s")
            log_performance("Full System Scan (GUI)", scan_duration)
            
            self.status.config(text="Full System Scan Completed")
            self.progress_label.config(text="Scan completed successfully")
        except Exception as e:
            error_msg = f"Scan failed: {type(e).__name__}: {str(e)}"
            logger.exception("[GUI] Full system scan failed")
            log_exception(logger, f"[GUI] Scan error: {error_msg}")
            messagebox.showerror("Error", error_msg)
            self.output_text.insert(tk.END, f"\n❌ ERROR: {error_msg}\n")
            self.status.config(text="Scan Failed")
            self.progress_label.config(text="Scan failed")
        finally:
            self.full_scan_btn.config(state=tk.NORMAL)
            for btn in self.collector_buttons.values():
                btn.config(state=tk.NORMAL)

#-----------------------------------------
# Individual Collector Scans
    def start_collector_scan(self, collector_func, collector_name):
        thread = Thread(target=self.run_collector_scan, args=(collector_func, collector_name), daemon=True)
        thread.start()

    def run_collector_scan(self, collector_func, collector_name):
        btn = self.collector_buttons.get(collector_name)
        if btn:
            btn.config(state=tk.DISABLED)
        
        self.status.config(text=f"Collecting {collector_name}...")
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert(tk.END, "=" * 70 + "\n")
        self.output_text.insert(tk.END, f"COLLECTING: {collector_name.upper()}\n")
        self.output_text.insert(tk.END, "=" * 70 + "\n\n")
        self.root.update()
        
        try:
            result = collector_func()
            
            # Formatuj wynik
            formatted = self.format_collector_result(collector_name, result)
            self.output_text.insert(tk.END, formatted)
            self.output_text.see(tk.END)
            
            self.status.config(text=f"{collector_name} Collection Completed")
        except Exception as e:
            error_msg = f"Collection failed: {type(e).__name__}: {str(e)}"
            messagebox.showerror("Error", error_msg)
            self.output_text.insert(tk.END, f"\n❌ ERROR: {error_msg}\n")
            self.status.config(text="Collection Failed")
        finally:
            if btn:
                btn.config(state=tk.NORMAL)

    def format_collector_result(self, collector_name, result):
        """Formatuje wynik collectora do wyświetlenia."""
        output = ""
        
        if isinstance(result, dict):
            if "error" in result:
                output += f"❌ Error: {result['error']}\n\n"
                return output
            
            # Formatuj w zależności od typu collectora
            if collector_name == "Hardware":
                output += self.format_hardware(result)
            elif collector_name == "Drivers":
                output += self.format_drivers(result)
            elif collector_name == "System Logs":
                output += self.format_system_logs(result)
            elif collector_name == "Services":
                output += self.format_services(result)
            elif collector_name == "BSOD/Dumps":
                output += self.format_bsod(result)
            elif collector_name == "Performance":
                output += self.format_performance(result)
            elif collector_name == "WER":
                output += self.format_wer(result)
            elif collector_name == "Processes":
                output += self.format_processes(result)
            else:
                # Domyślne formatowanie JSON
                output += json.dumps(result, indent=2, ensure_ascii=False, default=str)
        else:
            # Jeśli to lista lub inny typ
            output += json.dumps(result, indent=2, ensure_ascii=False, default=str)
        
        return output

    def format_hardware(self, data):
        """Formatuje dane hardware z pełnymi szczegółami."""
        output = "=== HARDWARE INFORMATION ===\n\n"
        
        # CPU - szczegółowe informacje
        if "cpu" in data:
            cpu = data["cpu"]
            output += "CPU:\n"
            # Użyj name z WMI jeśli dostępne, w przeciwnym razie model
            cpu_name = cpu.get('name') or cpu.get('model', 'N/A')
            output += f"  Model: {cpu_name}\n"
            if cpu.get('manufacturer'):
                output += f"  Manufacturer: {cpu.get('manufacturer')}\n"
            output += f"  Physical Cores: {cpu.get('physical_cores', cpu.get('number_of_cores', 'N/A'))}\n"
            output += f"  Logical Cores: {cpu.get('logical_cores', cpu.get('number_of_logical_processors', 'N/A'))}\n"
            output += f"  Usage: {cpu.get('usage_percent', cpu.get('load_percentage', 0)):.1f}%\n"
            
            # Frequency
            if cpu.get('frequency', {}).get('current'):
                freq = cpu['frequency']
                output += f"  Frequency: {freq.get('current', 0)/1000:.2f} GHz"
                if freq.get('max'):
                    output += f" (Max: {freq.get('max', 0)/1000:.2f} GHz)"
                output += "\n"
            elif cpu.get('current_clock_speed'):
                output += f"  Current Clock: {cpu.get('current_clock_speed', 0)} MHz\n"
            if cpu.get('max_clock_speed'):
                output += f"  Max Clock: {cpu.get('max_clock_speed', 0)} MHz\n"
            
            # Cache
            if cpu.get('l2_cache_size'):
                output += f"  L2 Cache: {cpu.get('l2_cache_size')} KB\n"
            if cpu.get('l3_cache_size'):
                output += f"  L3 Cache: {cpu.get('l3_cache_size')} KB\n"
            
            # Architecture
            if cpu.get('architecture'):
                arch_map = {0: "x86", 1: "MIPS", 2: "Alpha", 3: "PowerPC", 5: "ARM", 6: "ia64", 9: "x64"}
                arch = arch_map.get(cpu.get('architecture'), f"Unknown ({cpu.get('architecture')})")
                output += f"  Architecture: {arch}\n"
            
            output += "\n"
        
        # RAM - szczegółowe informacje
        if "ram" in data:
            ram = data["ram"]
            output += "RAM:\n"
            total_gb = ram.get('total', 0) // (1024**3)
            used_gb = ram.get('used', 0) // (1024**3)
            available_gb = ram.get('available', 0) // (1024**3)
            output += f"  Total: {total_gb} GB\n"
            output += f"  Used: {used_gb} GB ({ram.get('percent', 0):.1f}%)\n"
            output += f"  Available: {available_gb} GB\n"
            if ram.get('free'):
                free_gb = ram.get('free', 0) // (1024**3)
                output += f"  Free: {free_gb} GB\n"
            
            # Swap
            if ram.get('swap', {}).get('total'):
                swap = ram['swap']
                swap_total_gb = swap.get('total', 0) // (1024**3)
                swap_used_gb = swap.get('used', 0) // (1024**3)
                output += f"  Swap: {swap_total_gb} GB total, {swap_used_gb} GB used ({swap.get('percent', 0):.1f}%)\n"
            
            # RAM slots
            if "ram_slots" in data and data["ram_slots"]:
                output += f"  RAM Slots: {len(data['ram_slots'])} module(s)\n"
                for i, slot in enumerate(data["ram_slots"][:4], 1):  # Max 4 sloty
                    capacity = slot.get('capacity', 0)
                    if capacity:
                        capacity_gb = capacity // (1024**3)
                        output += f"    Slot {i}: {capacity_gb} GB"
                        if slot.get('speed'):
                            output += f" @ {slot.get('speed')} MHz"
                        if slot.get('manufacturer'):
                            output += f" ({slot.get('manufacturer')})"
                        output += "\n"
            
            output += "\n"
        
        # DISKS - szczegółowe informacje
        if "disks" in data:
            output += "DISKS:\n"
            for disk in data["disks"][:10]:  # Max 10 dysków
                device = disk.get('device', 'N/A')
                total_gb = disk.get('total', 0) // (1024**3)
                used_gb = disk.get('used', 0) // (1024**3) if disk.get('used') else None
                free_gb = disk.get('free', 0) // (1024**3) if disk.get('free') else None
                percent = disk.get('percent', 0)
                
                output += f"  {device}: {total_gb} GB"
                if used_gb is not None:
                    output += f" (Used: {used_gb} GB, Free: {free_gb} GB, {percent:.1f}%)"
                output += "\n"
                
                # Volume name
                if disk.get('volume_name'):
                    output += f"    Volume: {disk.get('volume_name')}\n"
                
                # File system
                if disk.get('fstype'):
                    output += f"    File System: {disk.get('fstype')}\n"
                
                # Physical disk info
                if disk.get('physical_disk_info'):
                    phys = disk['physical_disk_info']
                    if phys.get('model'):
                        output += f"    Model: {phys.get('model')}\n"
                    if phys.get('serial'):
                        output += f"    Serial: {phys.get('serial')}\n"
                    if phys.get('interface_type'):
                        output += f"    Interface: {phys.get('interface_type')}\n"
                    if phys.get('firmware_revision'):
                        output += f"    Firmware: {phys.get('firmware_revision')}\n"
                
                # SMART data
                if disk.get('smart'):
                    smart = disk['smart']
                    output += f"    SMART Status: {smart.get('HealthStatus', 'N/A')}\n"
                    if smart.get('Temperature'):
                        output += f"    Temperature: {smart.get('Temperature')}°C\n"
                    if smart.get('Wear'):
                        output += f"    Wear: {smart.get('Wear')}%\n"
                
                # NVMe health
                if disk.get('nvme_health'):
                    nvme = disk['nvme_health']
                    output += f"    NVMe Health: {nvme.get('HealthStatus', 'N/A')}\n"
                    if nvme.get('Temperature'):
                        output += f"    NVMe Temp: {nvme.get('Temperature')}°C\n"
                
                # Status
                if disk.get('status') and disk.get('status') != 'None':
                    output += f"    Status: {disk.get('status')}\n"
                if disk.get('accessible') is False:
                    output += f"    Accessible: No"
                    if disk.get('error'):
                        output += f" ({disk.get('error')})"
                    output += "\n"
                
                output += "\n"
        
        # GPU
        if "gpu" in data and data["gpu"]:
            output += "GPU:\n"
            for gpu in data["gpu"][:3]:  # Max 3 GPU
                if gpu.get('name'):
                    output += f"  {gpu.get('name')}\n"
                if gpu.get('driver_version'):
                    output += f"    Driver: {gpu.get('driver_version')}\n"
                if gpu.get('memory_total'):
                    mem_gb = gpu.get('memory_total', 0) // (1024**3)
                    output += f"    Memory: {mem_gb} GB\n"
                if gpu.get('temperature'):
                    output += f"    Temperature: {gpu.get('temperature')}°C\n"
                output += "\n"
        
        # Motherboard
        if "motherboard" in data and data["motherboard"]:
            mb = data["motherboard"][0] if isinstance(data["motherboard"], list) else data["motherboard"]
            output += "MOTHERBOARD:\n"
            if mb.get('manufacturer'):
                output += f"  Manufacturer: {mb.get('manufacturer')}\n"
            if mb.get('product'):
                output += f"  Product: {mb.get('product')}\n"
            if mb.get('version'):
                output += f"  Version: {mb.get('version')}\n"
            if mb.get('bios_version'):
                output += f"  BIOS: {mb.get('bios_version')}\n"
            output += "\n"
        
        # Sensors (temperatury)
        if "sensors" in data and data["sensors"]:
            sensors = data["sensors"]
            output += "SENSORS:\n"
            if sensors.get('cpu_temp'):
                output += f"  CPU Temperature: {sensors.get('cpu_temp')}\n"
            if sensors.get('fans'):
                output += f"  Fans: {len(sensors.get('fans', []))} detected\n"
            output += "\n"
        
        # Battery
        if "battery" in data and data["battery"]:
            battery = data["battery"]
            if battery.get('percent') is not None:
                output += "BATTERY:\n"
                output += f"  Charge: {battery.get('percent', 0):.1f}%\n"
                output += f"  Plugged In: {battery.get('plugged_in', False)}\n"
                if battery.get('name'):
                    output += f"  Name: {battery.get('name')}\n"
                output += "\n"
        
        # USB Devices count
        if "usb_devices" in data and data["usb_devices"]:
            output += f"USB DEVICES: {len(data['usb_devices'])} detected\n\n"
        
        # PCI Devices count
        if "pci_devices" in data and data["pci_devices"]:
            output += f"PCI DEVICES: {len(data['pci_devices'])} detected\n\n"
        
        # Memory SPD
        if "memory_spd" in data and data["memory_spd"]:
            output += f"MEMORY SPD: {len(data['memory_spd'])} module(s) detected\n\n"
        
        return output

    def format_drivers(self, data):
        """Formatuje dane driverów."""
        output = f"=== DRIVERS ({len(data)} total) ===\n\n"
        for driver in data[:20]:  # Max 20 driverów
            output += f"{driver.get('name', 'N/A')}\n"
            output += f"  Provider: {driver.get('provider', 'N/A')}\n"
            output += f"  Version: {driver.get('version', 'N/A')}\n"
            output += f"  Status: {driver.get('status', 'N/A')}\n\n"
        return output

    def format_system_logs(self, data):
        """Formatuje logi systemowe."""
        output = "=== SYSTEM LOGS ===\n\n"
        for category, logs in data.items():
            output += f"{category} Logs ({len(logs)} entries):\n"
            for log in logs[:10]:  # Max 10 logów na kategorię
                if isinstance(log, dict):
                    output += f"  {log.get('raw', 'N/A')}\n"
                else:
                    output += f"  {log}\n"
            output += "\n"
        return output

    def format_services(self, data):
        """Formatuje dane usług."""
        output = "=== SERVICES ===\n\n"
        output += f"Total Services: {len(data.get('services', []))}\n"
        output += f"Failed Services: {len(data.get('failed_services', []))}\n"
        output += f"Stopped Services: {len(data.get('stopped_services', []))}\n\n"
        
        if data.get("failed_services"):
            output += "FAILED SERVICES:\n"
            for svc in data["failed_services"][:10]:
                output += f"  {svc.get('name', 'N/A')}: {svc.get('issue', 'N/A')}\n"
            output += "\n"
        
        return output

    def format_bsod(self, data):
        """Formatuje dane BSOD."""
        output = "=== BSOD / MEMORY DUMPS ===\n\n"
        output += f"Bugchecks: {len(data.get('bugchecks', []))}\n"
        output += f"Recent Crashes: {len(data.get('recent_crashes', []))}\n"
        output += f"Minidumps: {len(data.get('minidumps', []))}\n\n"
        
        if data.get("bugchecks"):
            output += "BUGCHECKS:\n"
            for bugcheck in data["bugchecks"][:5]:
                output += f"  Code: {bugcheck.get('bugcheck_code', 'N/A')}\n"
                output += f"  Time: {bugcheck.get('timestamp', 'N/A')}\n\n"
        
        return output

    def format_performance(self, data):
        """Formatuje dane wydajności."""
        output = "=== PERFORMANCE COUNTERS ===\n\n"
        if "cpu" in data:
            cpu = data["cpu"]
            output += f"CPU: {cpu.get('average', 0):.1f}% avg, {cpu.get('max', 0):.1f}% max\n"
        if "memory" in data:
            mem = data["memory"]
            output += f"Memory: {mem.get('average_percent', 0):.1f}% avg\n"
        if "issues" in data:
            output += f"\nIssues: {len(data['issues'])}\n"
            for issue in data["issues"]:
                output += f"  {issue.get('message', 'N/A')}\n"
        return output

    def format_wer(self, data):
        """Formatuje dane WER."""
        logger = get_logger()
        output = "=== WINDOWS ERROR REPORTING ===\n\n"
        
        # ZABEZPIECZENIE: Sprawdź typ data przed użyciem
        if not isinstance(data, dict):
            logger.error(f"[GUI] format_wer: data is not a dict: {type(data)}")
            from utils.error_analyzer import log_error_with_analysis
            log_error_with_analysis(
                TypeError(f"data is {type(data).__name__} instead of dict"),
                data,
                {
                    'variable_name': 'data',
                    'location': 'gui.py:801',
                    'function': 'format_wer'
                },
                continue_execution=True
            )
            return f"❌ Error: WER data is {type(data).__name__} instead of dict\n"
        
        # ✅ Informacje o LocalDumps - wyświetl na początku
        local_dumps = data.get('local_dumps', {})
        if isinstance(local_dumps, dict):
            output += "📋 LOCALDUMPS STATUS:\n"
            if local_dumps.get('enabled', False):
                output += "  ✅ LocalDumps: ENABLED\n"
                if local_dumps.get('dump_folder'):
                    output += f"  📁 Dump Folder: {local_dumps['dump_folder']}\n"
                if local_dumps.get('dump_type') is not None:
                    dump_type_names = {0: "None", 1: "Mini", 2: "Full", 3: "Kernel"}
                    dump_type = dump_type_names.get(local_dumps['dump_type'], f"Unknown ({local_dumps['dump_type']})")
                    output += f"  🔧 Dump Type: {dump_type}\n"
                if local_dumps.get('dump_count') is not None:
                    output += f"  📊 Dump Count: {local_dumps['dump_count']}\n"
                if local_dumps.get('warnings'):
                    output += f"  ⚠️ Warnings: {', '.join(local_dumps['warnings'])}\n"
            else:
                output += "  ❌ LocalDumps: DISABLED\n"
                if local_dumps.get('warnings'):
                    output += f"  ⚠️ Issues: {', '.join(local_dumps['warnings'])}\n"
                output += "  💡 Recommendation: Enable LocalDumps for complete crash diagnostics.\n"
                output += "     Run the program as administrator to enable automatically.\n"
            output += "\n"
        
        # Sprawdź czy jest za mało danych
        recent_crashes = data.get('recent_crashes', [])
        if not isinstance(recent_crashes, list):
            logger.warning(f"[GUI] format_wer: recent_crashes is not a list: {type(recent_crashes)}")
            recent_crashes = []
        
        reports = data.get("reports", [])
        report_count = len(reports) if isinstance(reports, list) else (reports.get('report_count', 0) if isinstance(reports, dict) else 0)
        total_crashes = data.get('statistics', {}).get('total_crashes', len(recent_crashes))
        
        # Ostrzeżenie jeśli za mało danych
        if report_count == 0 and total_crashes == 0:
            output += "⚠️ WARNING: No WER reports found.\n"
            if isinstance(local_dumps, dict) and not local_dumps.get('enabled', True):
                output += "  LocalDumps was disabled previously.\n"
            output += "  If LocalDumps was just enabled, crashes need time to accumulate.\n"
            output += "  Re-run the tool after the next crash to see full diagnostics.\n\n"
        
        output += f"Recent Crashes: {len(recent_crashes)}\n"
        
        # Reports - KRYTYCZNE: reports może być listą lub dict!
        # (report_count już został obliczony wyżej)
        output += f"Report Count: {report_count}\n\n"
        
        # Grouped Crashes
        grouped_crashes = data.get('grouped_crashes', [])
        if isinstance(grouped_crashes, list):
            output += f"Grouped Crashes: {len(grouped_crashes)} groups\n\n"
        else:
            logger.warning(f"[GUI] format_wer: grouped_crashes is not a list: {type(grouped_crashes)}")
            output += f"Grouped Crashes: N/A\n\n"
        
        # 📌 7.1. Summary
        statistics = data.get('statistics', {})
        if not isinstance(statistics, dict):
            statistics = {}
        
        # Zlicz High Severity crashes
        high_severity_count = sum(1 for group in grouped_crashes 
                                 if isinstance(group, dict) and group.get('severity') == 'High')
        
        # Znajdź najczęstszy proces
        most_frequent_process = "N/A"
        if grouped_crashes:
            try:
                top_group = max(grouped_crashes, 
                              key=lambda x: x.get('total_occurrences', 0) if isinstance(x, dict) else 0)
                if isinstance(top_group, dict):
                    app_name = top_group.get('application', 'N/A')
                    occurrences = top_group.get('total_occurrences', 0)
                    most_frequent_process = f"{app_name} ({occurrences} crashes)"
            except Exception:
                pass
        
        output += "📌 SUMMARY\n"
        output += f"  Total Crashes: {statistics.get('total_crashes', len(recent_crashes))}\n"
        output += f"  Unique Crash Groups: {len(grouped_crashes)}\n"
        output += f"  High Severity Crashes: {high_severity_count}\n"
        output += f"  Most Frequent Process: {most_frequent_process}\n"
        output += f"  Crashes (30min): {statistics.get('crashes_last_30min', 0)}\n"
        output += f"  Crashes (24h): {statistics.get('crashes_last_24h', 0)}\n"
        output += f"  Repeating Crashes: {statistics.get('repeating_crashes', 0)}\n\n"
        
        # 📌 7.2. Top 5 crash groups (z nowymi informacjami)
        if grouped_crashes:
            output += "📌 TOP 5 CRASH GROUPS\n"
            sorted_groups = sorted(
                [g for g in grouped_crashes if isinstance(g, dict)],
                key=lambda x: x.get('total_occurrences', 0),
                reverse=True
            )[:5]
            
            for idx, group in enumerate(sorted_groups, 1):
                app = group.get('application', 'N/A')
                module = group.get('module_name', 'N/A')
                exception = group.get('exception_code', 'N/A')
                occurrences = group.get('total_occurrences', 0)
                severity = group.get('severity', 'Unknown')
                criticality = group.get('criticality', 'Unknown')
                offset = group.get('fault_offset_normalized', 'N/A')
                
                # 2️⃣ Analiza powtarzalności - wyświetl szczegóły
                is_repeating = group.get('is_repeating', False)
                is_repeating_30min = group.get('is_repeating_30min', False)
                is_repeating_1h = group.get('is_repeating_1h', False)
                is_repeating_24h = group.get('is_repeating_24h', False)
                
                # 4️⃣ Średni interwał między crashami
                avg_interval_hours = group.get('avg_interval_hours')
                
                output += f"  [{idx}] {app} | {module} | {exception}"
                if offset != 'N/A' and offset != 0:
                    output += f" | offset 0x{offset:03X}"
                output += f" | {occurrences} occurrences"
                if severity != 'Unknown':
                    output += f" | Severity: {severity}"
                if criticality != 'Unknown':
                    output += f" | Criticality: {criticality}"
                if is_repeating:
                    repeating_info = []
                    if is_repeating_30min:
                        repeating_info.append(f"{group.get('occurrences_30min', 0)}x in 30min")
                    if is_repeating_1h:
                        repeating_info.append(f"{group.get('occurrences_1h', 0)}x in 1h")
                    if is_repeating_24h:
                        repeating_info.append(f"{group.get('occurrences_24h', 0)}x in 24h")
                    if repeating_info:
                        output += f" | Repeating: {', '.join(repeating_info)}"
                if avg_interval_hours is not None:
                    if avg_interval_hours < 1:
                        output += f" | Avg interval: {avg_interval_hours * 60:.1f} min"
                    else:
                        output += f" | Avg interval: {avg_interval_hours:.1f} h"
                output += "\n"
            output += "\n"
        
        # 📌 7.3. Most recent crashes (z łączeniem duplikatów)
        if recent_crashes:
            output += "📌 MOST RECENT CRASHES\n"
            sorted_recent = sorted(
                [c for c in recent_crashes if isinstance(c, dict)],
                key=lambda x: x.get('timestamp', ''),
                reverse=True
            )
            
            # 5️⃣ Łączenie duplikatów - identyczne crashy w krótkim czasie
            deduplicated_recent = []
            seen_crashes = {}  # {(app, module, exception): (count, last_timestamp)}
            dedup_window = timedelta(minutes=1)  # 1 minuta okno dla duplikatów
            
            for crash in sorted_recent[:20]:  # Sprawdź więcej, żeby znaleźć duplikaty
                app = (crash.get('application') or crash.get('faulting_application_name', 'N/A')).lower()
                module = (crash.get('module_name') or crash.get('faulting_module_name', 'N/A')).lower()
                exception = (crash.get('exception_code', 'N/A')).upper()
                timestamp_str = crash.get('timestamp', '')
                
                key = (app, module, exception)
                crash_time = None
                try:
                    if timestamp_str and timestamp_str != 'N/A':
                        from datetime import datetime
                        if isinstance(timestamp_str, str):
                            crash_time = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                except Exception:
                    pass
                
                if crash_time:
                    last_seen = seen_crashes.get(key)
                    if last_seen and (crash_time - last_seen[1]) < dedup_window:
                        # Duplikat - zwiększ licznik
                        seen_crashes[key] = (last_seen[0] + 1, last_seen[1])
                    else:
                        # Nowy crash - dodaj do listy
                        seen_crashes[key] = (1, crash_time)
                        deduplicated_recent.append((crash, crash_time))
            
            # Wyświetl z licznikami duplikatów
            for idx, (crash, crash_time) in enumerate(deduplicated_recent[:10], 1):
                app = crash.get('application') or crash.get('faulting_application_name', 'N/A')
                exception = crash.get('exception_code', 'N/A')
                module = crash.get('module_name') or crash.get('faulting_module_name', 'N/A')
                offset = crash.get('fault_offset', 'N/A')
                criticality = crash.get('criticality', 'Unknown')
                
                # Sprawdź czy to duplikat
                key = (app.lower(), module.lower(), exception.upper())
                count, _ = seen_crashes.get(key, (1, None))
                
                # Formatuj timestamp
                if crash_time:
                    timestamp = crash_time.strftime("%I:%M:%S %p")
                else:
                    timestamp = crash.get('timestamp', 'N/A')
                
                output += f"  {idx}. {app} | {timestamp} | {exception} | {module}"
                if count > 1:
                    output += f" ({count}x)"
                if offset and offset != 'N/A':
                    output += f" | offset {offset}"
                if criticality != 'Unknown':
                    output += f" | {criticality}"
                output += "\n"
            output += "\n"
        
        # 📌 7.4. Full WER details for each group (tylko top 3)
        if grouped_crashes:
            output += "📌 FULL WER DETAILS (Top 3 Groups)\n"
            sorted_groups = sorted(
                [g for g in grouped_crashes if isinstance(g, dict)],
                key=lambda x: x.get('total_occurrences', 0),
                reverse=True
            )[:3]
            
            for idx, group in enumerate(sorted_groups, 1):
                output += f"\n  Group {idx}:\n"
                output += f"    Application: {group.get('application', 'N/A')}\n"
                output += f"    Module: {group.get('module_name', 'N/A')}\n"
                output += f"    Exception Code: {group.get('exception_code', 'N/A')}\n"
                offset_norm = group.get('fault_offset_normalized', 0)
                if offset_norm != 'N/A' and offset_norm != 0:
                    output += f"    Fault Offset (normalized): 0x{offset_norm:03X}\n"
                output += f"    Total Occurrences: {group.get('total_occurrences', 0)}\n"
                output += f"    Occurrences (30min): {group.get('occurrences_30min', 0)}\n"
                output += f"    Occurrences (24h): {group.get('occurrences_24h', 0)}\n"
                output += f"    Is Repeating: {group.get('is_repeating', False)}\n"
                output += f"    Severity: {group.get('severity', 'Unknown')}\n"
                output += f"    First Occurrence: {group.get('first_occurrence', 'N/A')}\n"
                output += f"    Last Occurrence: {group.get('last_occurrence', 'N/A')}\n"
                
                latest_crash = group.get('latest_crash', {})
                if isinstance(latest_crash, dict) and latest_crash:
                    output += f"    Latest Crash Details:\n"
                    output += f"      Timestamp: {latest_crash.get('timestamp', 'N/A')}\n"
                    output += f"      Source: {latest_crash.get('source', 'N/A')}\n"
                    if latest_crash.get('wer_file_path'):
                        output += f"      WER File: {latest_crash.get('wer_file_path', 'N/A')}\n"
        
        return output

    def format_processes(self, data):
        """Formatuje dane procesów."""
        output = "=== PROCESSES ===\n\n"
        summary = data.get("summary", {})
        output += f"Total: {summary.get('total_processes', 0)}\n"
        output += f"High CPU: {summary.get('high_cpu_count', 0)}\n"
        output += f"High Memory: {summary.get('high_memory_count', 0)}\n\n"
        
        if data.get("high_cpu"):
            output += "HIGH CPU PROCESSES:\n"
            for proc in data["high_cpu"][:10]:
                output += f"  {proc.get('name', 'N/A')}: {proc.get('cpu_percent', 0):.1f}%\n"
            output += "\n"
        
        return output

    def display_analysis_results(self, report):
        """Wyświetla wyniki pełnej analizy."""
        # Nowy format raportu
        report_data = report.get("report", {})
        
        self.output_text.insert(tk.END, "=" * 70 + "\n")
        self.output_text.insert(tk.END, "ANALYSIS RESULTS\n")
        self.output_text.insert(tk.END, "=" * 70 + "\n\n")
        
        # Status systemu
        status_info = report_data.get("status", {})
        status = status_info.get("value", "UNKNOWN")
        status_icon = status_info.get("icon", "⚪")
        score_info = report_data.get("score", {})
        normalized_score = score_info.get("normalized", 0)
        
        self.output_text.insert(tk.END, f"System Status: {status_icon} {status}\n")
        self.output_text.insert(tk.END, f"System Score: {normalized_score}/100\n")
        self.output_text.insert(tk.END, f"Category: {score_info.get('category', 'Unknown')}\n\n")
        
        # Podsumowanie
        summary = report_data.get("summary", {})
        self.output_text.insert(tk.END, f"Total Critical: {summary.get('total_critical', 0)}\n")
        self.output_text.insert(tk.END, f"Total Errors: {summary.get('total_errors', 0)}\n")
        self.output_text.insert(tk.END, f"Total Warnings: {summary.get('total_warnings', 0)}\n")
        self.output_text.insert(tk.END, f"Total Issues: {summary.get('total_issues', 0)}\n\n")
        
        # Wykryte przyczyny (z cause_detector)
        detected_causes = report_data.get("detected_causes", {})
        if detected_causes and detected_causes.get('causes'):
            causes_list = detected_causes.get('causes', [])
            if causes_list:
                self.output_text.insert(tk.END, "=" * 70 + "\n")
                self.output_text.insert(tk.END, "DETECTED ROOT CAUSES\n")
                self.output_text.insert(tk.END, "=" * 70 + "\n\n")
                
                # Sortuj według confidence
                high_confidence = [c for c in causes_list if c.get('confidence', 0) >= 70]
                medium_confidence = [c for c in causes_list if 40 <= c.get('confidence', 0) < 70]
                
                if high_confidence:
                    self.output_text.insert(tk.END, "HIGH CONFIDENCE CAUSES:\n")
                    self.output_text.insert(tk.END, "-" * 70 + "\n")
                    for i, cause in enumerate(high_confidence[:10], 1):
                        category = cause.get('category', 'Unknown')
                        cause_name = cause.get('cause', 'Unknown')
                        confidence = cause.get('confidence', 0)
                        description = cause.get('description', '')
                        recommendation = cause.get('recommendation', '')
                        evidence = cause.get('evidence', {})
                        
                        self.output_text.insert(tk.END, f"{i}. [{category}] {cause_name}\n")
                        self.output_text.insert(tk.END, f"   Confidence: {confidence:.1f}%\n")
                        self.output_text.insert(tk.END, f"   Description: {description}\n")
                        if evidence:
                            evidence_str = ', '.join([f"{k}: {v}" for k, v in evidence.items()])
                            self.output_text.insert(tk.END, f"   Evidence: {evidence_str}\n")
                        if recommendation:
                            self.output_text.insert(tk.END, f"   Recommendation: {recommendation}\n")
                        self.output_text.insert(tk.END, "\n")
                
                if medium_confidence:
                    self.output_text.insert(tk.END, "\nMEDIUM CONFIDENCE CAUSES:\n")
                    self.output_text.insert(tk.END, "-" * 70 + "\n")
                    for i, cause in enumerate(medium_confidence[:5], 1):
                        category = cause.get('category', 'Unknown')
                        cause_name = cause.get('cause', 'Unknown')
                        confidence = cause.get('confidence', 0)
                        description = cause.get('description', '')
                        
                        self.output_text.insert(tk.END, f"{i}. [{category}] {cause_name} ({confidence:.1f}%)\n")
                        self.output_text.insert(tk.END, f"   {description}\n\n")
        
        # Top przyczyny z poprawionym confidence (z confidence_engine)
        confidence_info = report_data.get("confidence", {})
        top_causes = confidence_info.get("top_causes", [])
        if top_causes:
            self.output_text.insert(tk.END, "=" * 70 + "\n")
            self.output_text.insert(tk.END, "TOP LIKELY CAUSES (from correlation)\n")
            self.output_text.insert(tk.END, "=" * 70 + "\n")
            for i, cause in enumerate(top_causes[:5], 1):
                cause_name = cause.get("cause", "Unknown")
                confidence = cause.get("confidence", 0)  # Już w procentach (0-100)
                issues_count = cause.get("related_events_count", 0)
                self.output_text.insert(tk.END, f"{i}. {cause_name}\n")
                self.output_text.insert(tk.END, f"   Confidence: {confidence:.1f}% ({issues_count} related events)\n\n")
        
        # Top problemy - szczegółowe wyświetlanie
        issues_data = report_data.get("issues", {})
        
        # Critical Issues
        critical_issues = issues_data.get("critical", [])
        if critical_issues:
            self.output_text.insert(tk.END, "Critical Issues:\n")
            self.output_text.insert(tk.END, "-" * 70 + "\n")
            for i, issue in enumerate(critical_issues[:10], 1):
                issue_type = issue.get("type", "Unknown")
                severity = issue.get("severity", "CRITICAL")
                message = issue.get("message", "")
                event_id = issue.get("event_id", "N/A")
                timestamp = issue.get("timestamp", "N/A")
                component = issue.get("component", "Unknown")
                
                self.output_text.insert(tk.END, f"{i}. [{severity}] {issue_type}\n")
                self.output_text.insert(tk.END, f"   Component: {component}\n")
                if event_id != "N/A":
                    self.output_text.insert(tk.END, f"   Event ID: {event_id}\n")
                if timestamp != "N/A":
                    self.output_text.insert(tk.END, f"   Time: {timestamp}\n")
                if message:
                    # Wyświetl pełną wiadomość (może być długa)
                    msg_lines = message.split('\n')[:5]  # Max 5 linii
                    for line in msg_lines:
                        self.output_text.insert(tk.END, f"   {line}\n")
                self.output_text.insert(tk.END, "\n")
        
        # Error Issues
        error_issues = issues_data.get("errors", [])
        if error_issues:
            self.output_text.insert(tk.END, "Error Issues:\n")
            self.output_text.insert(tk.END, "-" * 70 + "\n")
            for i, issue in enumerate(error_issues[:10], 1):
                issue_type = issue.get("type", "Unknown")
                severity = issue.get("severity", "ERROR")
                message = issue.get("message", "")
                event_id = issue.get("event_id", "N/A")
                timestamp = issue.get("timestamp", "N/A")
                component = issue.get("component", "Unknown")
                
                self.output_text.insert(tk.END, f"{i}. [{severity}] {issue_type}\n")
                self.output_text.insert(tk.END, f"   Component: {component}\n")
                if event_id != "N/A":
                    self.output_text.insert(tk.END, f"   Event ID: {event_id}\n")
                if timestamp != "N/A":
                    self.output_text.insert(tk.END, f"   Time: {timestamp}\n")
                if message:
                    msg_lines = message.split('\n')[:5]  # Max 5 linii
                    for line in msg_lines:
                        self.output_text.insert(tk.END, f"   {line}\n")
                self.output_text.insert(tk.END, "\n")
        
        # Warnings (jeśli są)
        warning_issues = issues_data.get("warnings", [])
        if warning_issues and len(warning_issues) > 0:
            self.output_text.insert(tk.END, f"Warnings ({len(warning_issues)} total):\n")
            self.output_text.insert(tk.END, "-" * 70 + "\n")
            for i, warning in enumerate(warning_issues[:5], 1):  # Max 5 warnings
                issue_type = warning.get("type", "Unknown")
                message = warning.get("message", "")[:100]
                self.output_text.insert(tk.END, f"{i}. {issue_type}: {message}\n")
            self.output_text.insert(tk.END, "\n")
        
        # Rekomendacje
        recommendations = report_data.get("recommendations", [])
        if recommendations:
            self.output_text.insert(tk.END, "Recommended Actions:\n")
            self.output_text.insert(tk.END, "-" * 70 + "\n")
            for i, action in enumerate(recommendations[:15], 1):
                priority = action.get("priority", "MEDIUM")
                action_text = action.get("action", "")
                description = action.get("description", "")
                self.output_text.insert(tk.END, f"{i}. [{priority}] {action_text}\n")
                if description:
                    self.output_text.insert(tk.END, f"   {description}\n")
                self.output_text.insert(tk.END, "\n")
        else:
            # Jeśli brak rekomendacji, pokaż ogólne porady
            if summary.get('total_errors', 0) > 0 or summary.get('total_critical', 0) > 0:
                self.output_text.insert(tk.END, "Recommended Actions:\n")
                self.output_text.insert(tk.END, "-" * 70 + "\n")
                self.output_text.insert(tk.END, "1. [MEDIUM] Review error details above\n")
                self.output_text.insert(tk.END, "   Check specific error messages for guidance\n\n")
                self.output_text.insert(tk.END, "2. [MEDIUM] Run sfc /scannow\n")
                self.output_text.insert(tk.END, "   Scan and repair system file corruption\n\n")
                self.output_text.insert(tk.END, "3. [LOW] Check Windows Event Viewer\n")
                self.output_text.insert(tk.END, "   Review detailed event logs for more information\n\n")
        
        self.output_text.see(tk.END)

#-----------------------------------------
# BSOD Analysis Functions
    def start_bsod_analysis(self):
        """Uruchamia analizę BSOD w osobnym wątku."""
        thread = Thread(target=self.run_bsod_analysis, daemon=True)
        thread.start()

    def run_bsod_analysis(self):
        """Wykonuje analizę BSOD."""
        self.status.config(text="Starting BSOD Analysis...")
        self.bsod_analysis_btn.config(state=tk.DISABLED)
        self.full_scan_btn.config(state=tk.DISABLED)
        for btn in self.collector_buttons.values():
            btn.config(state=tk.DISABLED)
        
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert(tk.END, "=" * 70 + "\n")
        self.output_text.insert(tk.END, "BSOD ANALYSIS\n")
        self.output_text.insert(tk.END, "=" * 70 + "\n\n")
        self.progress_bar['value'] = 0
        self.progress_percent.config(text="0%")
        self.progress_label.config(text="Collecting data for BSOD analysis...")
        self.root.update()
        
        try:
            # Zbierz potrzebne dane
            self.output_text.insert(tk.END, "Collecting required data...\n")
            self.output_text.insert(tk.END, "-" * 70 + "\n")
            
            collected_data = {}
            
            # System logs
            self.output_text.insert(tk.END, "  [1/4] Collecting system logs...\n")
            self.root.update()
            collected_data["system_logs"] = system_logs.collect(max_events=1000, filter_levels=None)  # None = wszystkie poziomy
            
            # Hardware
            self.output_text.insert(tk.END, "  [2/4] Collecting hardware data...\n")
            self.root.update()
            collected_data["hardware"] = hardware.collect()
            
            # Drivers
            self.output_text.insert(tk.END, "  [3/4] Collecting drivers data...\n")
            self.root.update()
            collected_data["drivers"] = drivers.collect()
            
            # BSOD dumps
            self.output_text.insert(tk.END, "  [4/4] Collecting BSOD data...\n")
            self.root.update()
            collected_data["bsod_dumps"] = bsod_dumps.collect()
            
            self.output_text.insert(tk.END, "✓ Data collection completed\n\n")
            self.progress_bar['value'] = 50
            self.progress_percent.config(text="50%")
            self.root.update()
            
            # Przetwórz dane
            self.output_text.insert(tk.END, "Processing data...\n")
            self.output_text.insert(tk.END, "-" * 70 + "\n")
            self.root.update()
            
            from processors import system_logs_processor, hardware_processor, driver_processor
            
            system_logs_processed = system_logs_processor.process(collected_data["system_logs"])
            hardware_processed = hardware_processor.process(collected_data["hardware"])
            drivers_processed = driver_processor.process(collected_data["drivers"])
            
            self.progress_bar['value'] = 75
            self.progress_percent.config(text="75%")
            self.root.update()
            
            # Uruchom analizę BSOD
            self.output_text.insert(tk.END, "Analyzing BSOD...\n")
            self.output_text.insert(tk.END, "-" * 70 + "\n")
            self.root.update()
            
            # Import lokalnie, żeby nie blokować uruchomienia GUI
            from processors.bsod_analyzer import analyze_bsod_with_timeline
            bsod_analysis = analyze_bsod_with_timeline(
                system_logs_processed.get("data", {}),
                hardware_processed.get("data", {}),
                drivers_processed.get("data", []),
                collected_data.get("bsod_dumps", {}),
                time_window_minutes=15,
                max_timeline_events=30
            )
            
            self.progress_bar['value'] = 100
            self.progress_percent.config(text="100%")
            self.root.update()
            
            # Wyświetl wyniki
            self.display_bsod_analysis(bsod_analysis)
            
            self.status.config(text="BSOD Analysis Completed")
            self.progress_label.config(text="BSOD analysis completed")
        except Exception as e:
            error_msg = f"BSOD analysis failed: {type(e).__name__}: {str(e)}"
            messagebox.showerror("Error", error_msg)
            self.output_text.insert(tk.END, f"\n❌ ERROR: {error_msg}\n")
            self.status.config(text="BSOD Analysis Failed")
            self.progress_label.config(text="BSOD analysis failed")
        finally:
            self.bsod_analysis_btn.config(state=tk.NORMAL)
            self.full_scan_btn.config(state=tk.NORMAL)
            for btn in self.collector_buttons.values():
                btn.config(state=tk.NORMAL)

    def display_bsod_analysis(self, bsod_analysis):
        """Wyświetla wyniki analizy BSOD."""
        if not bsod_analysis:
            self.output_text.insert(tk.END, "No BSOD analysis data available.\n")
            return
        
        if not isinstance(bsod_analysis, dict):
            self.output_text.insert(tk.END, f"Invalid BSOD analysis data format: {type(bsod_analysis)}\n")
            return
        
        if not bsod_analysis.get("bsod_found", False):
            self.output_text.insert(tk.END, "=" * 70 + "\n")
            self.output_text.insert(tk.END, "BSOD ANALYSIS RESULTS\n")
            self.output_text.insert(tk.END, "=" * 70 + "\n\n")
            self.output_text.insert(tk.END, "❌ No BSOD events found in system logs.\n")
            self.output_text.insert(tk.END, f"Message: {bsod_analysis.get('message', 'N/A')}\n\n")
            return
        
        self.output_text.insert(tk.END, "=" * 70 + "\n")
        self.output_text.insert(tk.END, "BSOD ANALYSIS RESULTS\n")
        self.output_text.insert(tk.END, "=" * 70 + "\n\n")
        
        # Ostatni BSOD
        bsod_timestamp = bsod_analysis.get("last_bsod_timestamp", "N/A")
        bsod_details = bsod_analysis.get("bsod_details", {})
        
        self.output_text.insert(tk.END, "🔴 LAST BSOD DETECTED\n")
        self.output_text.insert(tk.END, "-" * 70 + "\n")
        self.output_text.insert(tk.END, f"Timestamp: {bsod_timestamp}\n")
        self.output_text.insert(tk.END, f"Event ID: {bsod_details.get('event_id', 'N/A')}\n")
        self.output_text.insert(tk.END, f"Level: {bsod_details.get('level', 'N/A')}\n")
        message = bsod_details.get("message", "")[:200]
        if message:
            self.output_text.insert(tk.END, f"Message: {message}\n")
        self.output_text.insert(tk.END, "\n")
        
        # Top causes
        top_causes = bsod_analysis.get("top_causes", [])
        if top_causes:
            self.output_text.insert(tk.END, "TOP LIKELY CAUSES\n")
            self.output_text.insert(tk.END, "-" * 70 + "\n")
            for i, cause in enumerate(top_causes[:5], 1):
                cause_name = cause.get("cause", "Unknown")
                confidence = cause.get("confidence", 0)
                description = cause.get("description", "")
                events_count = cause.get("related_events_count", 0)
                
                self.output_text.insert(tk.END, f"{i}. {cause_name}\n")
                self.output_text.insert(tk.END, f"   Confidence: {confidence:.1f}%\n")
                self.output_text.insert(tk.END, f"   Description: {description}\n")
                self.output_text.insert(tk.END, f"   Related Events: {events_count}\n\n")
        else:
            # Jeśli brak top_causes, pokaż informację
            self.output_text.insert(tk.END, "TOP LIKELY CAUSES\n")
            self.output_text.insert(tk.END, "-" * 70 + "\n")
            self.output_text.insert(tk.END, "No specific causes identified from event logs.\n")
            self.output_text.insert(tk.END, "This may indicate:\n")
            self.output_text.insert(tk.END, "- Power loss or hardware failure\n")
            self.output_text.insert(tk.END, "- Event logs were cleared or rotated\n")
            self.output_text.insert(tk.END, "- BSOD occurred too long ago (>15 min window)\n\n")
        
        # Related events
        related_events = bsod_analysis.get("related_events", [])
        if related_events:
            self.output_text.insert(tk.END, "RELATED EVENTS (Top 10)\n")
            self.output_text.insert(tk.END, "-" * 70 + "\n")
            for i, event in enumerate(related_events[:10], 1):
                timestamp = event.get("timestamp", "N/A")
                category = event.get("detected_category", "OTHER")
                confidence = event.get("confidence_score", 0)
                event_id = event.get("event_id", "N/A")
                message = event.get("message", "")[:100]
                time_from_bsod = event.get("time_from_bsod_minutes")
                
                self.output_text.insert(tk.END, f"{i}. [{category}] Event ID: {event_id}\n")
                self.output_text.insert(tk.END, f"   Confidence: {confidence:.1f}%\n")
                if time_from_bsod is not None:
                    self.output_text.insert(tk.END, f"   Time from BSOD: {time_from_bsod:.1f} minutes\n")
                self.output_text.insert(tk.END, f"   Timestamp: {timestamp}\n")
                if message:
                    self.output_text.insert(tk.END, f"   Message: {message}\n")
                self.output_text.insert(tk.END, "\n")
        else:
            # Jeśli brak related events, pokaż informację
            self.output_text.insert(tk.END, "RELATED EVENTS\n")
            self.output_text.insert(tk.END, "-" * 70 + "\n")
            self.output_text.insert(tk.END, "No related events found in the 15-minute window before BSOD.\n")
            self.output_text.insert(tk.END, "This suggests:\n")
            self.output_text.insert(tk.END, "- Sudden power loss or hardware failure\n")
            self.output_text.insert(tk.END, "- BSOD occurred too quickly to log events\n")
            self.output_text.insert(tk.END, "- Event logs may have been cleared\n\n")
        
        # Hardware correlations
        hardware_correlations = bsod_analysis.get("hardware_correlations", [])
        if hardware_correlations:
            self.output_text.insert(tk.END, "HARDWARE CORRELATIONS\n")
            self.output_text.insert(tk.END, "-" * 70 + "\n")
            for corr in hardware_correlations:
                corr_type = corr.get("correlation_type", "N/A")
                issue = corr.get("hardware_issue", "N/A")
                event_id = corr.get("event", "N/A")
                self.output_text.insert(tk.END, f"  [{corr_type}] Event {event_id}: {issue}\n")
            self.output_text.insert(tk.END, "\n")
        
        # Driver correlations
        driver_correlations = bsod_analysis.get("driver_correlations", [])
        if driver_correlations:
            self.output_text.insert(tk.END, "DRIVER CORRELATIONS\n")
            self.output_text.insert(tk.END, "-" * 70 + "\n")
            for corr in driver_correlations:
                driver_name = corr.get("driver_name", "N/A")
                driver_status = corr.get("driver_status", "N/A")
                driver_version = corr.get("driver_version", "N/A")
                is_problematic = corr.get("is_problematic", False)
                event_id = corr.get("event", "N/A")
                
                status_icon = "⚠️" if is_problematic else "✓"
                self.output_text.insert(tk.END, f"  {status_icon} Driver: {driver_name}\n")
                self.output_text.insert(tk.END, f"     Version: {driver_version}\n")
                self.output_text.insert(tk.END, f"     Status: {driver_status}\n")
                self.output_text.insert(tk.END, f"     Related Event: {event_id}\n\n")
        
        # Recommendations (zawsze pokazuj, nawet jeśli puste - fallback jest w bsod_analyzer)
        recommendations = bsod_analysis.get("recommendations", [])
        if recommendations:
            self.output_text.insert(tk.END, "RECOMMENDATIONS\n")
            self.output_text.insert(tk.END, "-" * 70 + "\n")
            for i, rec in enumerate(recommendations[:10], 1):
                priority = rec.get("priority", "MEDIUM")
                action = rec.get("action", "")
                description = rec.get("description", "")
                confidence = rec.get("confidence", 0)
                
                self.output_text.insert(tk.END, f"{i}. [{priority}] {action}\n")
                self.output_text.insert(tk.END, f"   {description}\n")
                if confidence > 0:
                    self.output_text.insert(tk.END, f"   Confidence: {confidence:.1f}%\n")
                self.output_text.insert(tk.END, "\n")
        else:
            # Fallback recommendations jeśli brak
            self.output_text.insert(tk.END, "RECOMMENDATIONS\n")
            self.output_text.insert(tk.END, "-" * 70 + "\n")
            self.output_text.insert(tk.END, "1. [CRITICAL] Check minidump files in C:\\Windows\\Minidump\n")
            self.output_text.insert(tk.END, "   Analyze crash dumps for specific error codes\n\n")
            self.output_text.insert(tk.END, "2. [HIGH] Run Windows Memory Diagnostic\n")
            self.output_text.insert(tk.END, "   Check for RAM issues\n\n")
            self.output_text.insert(tk.END, "3. [HIGH] Check Event Viewer for errors before shutdown\n")
            self.output_text.insert(tk.END, "   Review system logs for clues\n\n")
            self.output_text.insert(tk.END, "4. [MEDIUM] Check power supply and connections\n")
            self.output_text.insert(tk.END, "   Unexpected shutdowns can indicate power issues\n\n")
        
        # Event Timeline (chronologiczna oś czasu)
        event_timeline = bsod_analysis.get("event_timeline", [])
        if event_timeline:
            self.output_text.insert(tk.END, "CHRONOLOGICAL EVENT TIMELINE\n")
            self.output_text.insert(tk.END, "-" * 70 + "\n")
            self.output_text.insert(tk.END, "Events leading to BSOD (filtered by relevance):\n\n")
            
            for i, event in enumerate(event_timeline, 1):
                timestamp = event.get("timestamp", "N/A")
                category = event.get("category", "OTHER")
                description = event.get("description", "")
                confidence = event.get("confidence", 0)
                event_id = event.get("event_id", "N/A")
                message = event.get("message", "")
                time_from_bsod = event.get("time_from_bsod_minutes")
                
                # Oznacz wysokie confidence
                confidence_icon = "🔴" if confidence >= 50 else "🟠" if confidence >= 30 else "🟡"
                
                self.output_text.insert(tk.END, f"{i}. {confidence_icon} [{category}] {description}\n")
                self.output_text.insert(tk.END, f"   Timestamp: {timestamp}\n")
                if time_from_bsod is not None:
                    self.output_text.insert(tk.END, f"   Time from BSOD: {time_from_bsod:.1f} minutes before\n")
                self.output_text.insert(tk.END, f"   Confidence: {confidence:.1f}%\n")
                self.output_text.insert(tk.END, f"   Event ID: {event_id}\n")
                if message:
                    self.output_text.insert(tk.END, f"   Message: {message}\n")
                self.output_text.insert(tk.END, "\n")
        
        # Analysis window
        analysis_window = bsod_analysis.get("analysis_window", {})
        if analysis_window:
            self.output_text.insert(tk.END, "ANALYSIS WINDOW\n")
            self.output_text.insert(tk.END, "-" * 70 + "\n")
            self.output_text.insert(tk.END, f"Window: {analysis_window.get('minutes', 15)} minutes before BSOD\n")
            self.output_text.insert(tk.END, f"Start: {analysis_window.get('start', 'N/A')}\n")
            self.output_text.insert(tk.END, f"End: {analysis_window.get('end', 'N/A')}\n")
        
        self.output_text.see(tk.END)

#-----------------------------------------
if __name__ == "__main__":
    # Inicjalizuj logger na starcie
    logger = get_logger()
    logger.info("=" * 70)
    logger.info("Diagnostic Tool - Application Started")
    logger.info("=" * 70)
    
    # Sprawdź i automatycznie zainstaluj brakujące pakiety
    logger.info("Checking and installing requirements...")
    from utils.requirements_check import install_missing_packages
    requirements_status = install_missing_packages(auto_install=True)
    if not requirements_status['all_installed']:
        logger.warning("Some required packages are still missing after auto-installation")
        # Wyświetl ostrzeżenie w konsoli (przed uruchomieniem GUI)
        print_requirements_status(requirements_status)
        print("\n⚠️  Some required packages are still missing. The application may not work correctly.")
        print("Continuing anyway...\n")
    else:
        logger.info("All requirements are satisfied")
    
    # Sprawdź uprawnienia - jeśli brak, od razu próbuj uruchomić jako admin
    if not is_admin():
        logger.warning("Application started without administrator privileges")
        # Próbuj automatycznie uruchomić jako admin (Windows zapyta przez UAC)
        if restart_as_admin(hide_console=False):
            logger.info("Attempting to restart as administrator")
            # Daj chwilę na uruchomienie nowej instancji
            time.sleep(1)
            logger.info("Exiting current instance, new instance will start as admin")
            sys.exit(0)  # Zakończ obecną instancję, nowa zostanie uruchomiona jako admin
        else:
            logger.error("Failed to restart as administrator")
            # Jeśli nie udało się, pokaż ostrzeżenie i kontynuuj
            import tkinter.messagebox as msgbox
            root_warn = tk.Tk()
            root_warn.withdraw()
            msgbox.showwarning(
                "Ostrzeżenie",
                "Nie udało się uruchomić jako administrator.\n"
                "Program będzie działał z ograniczonymi funkcjami.\n\n"
                "Uruchom program ręcznie jako administrator dla pełnej funkcjonalności."
            )
            root_warn.destroy()
    else:
        logger.info("Application running with administrator privileges")
    
    logger.info("Initializing GUI")
    root = tk.Tk()
    app = DiagnosticsGUI(root)
    logger.info("Starting GUI main loop")
    root.mainloop()
    logger.info("Application closed")
