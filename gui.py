import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk
from threading import Thread
import json
import sys

# Sprawdź uprawnienia administratora
from utils.admin_check import is_admin, require_admin, restart_as_admin

# Nowa struktura - wszystkie collectory
from collectors import (
    hardware, drivers, system_logs, registry_txr, storage_health, system_info,
    services, bsod_dumps, performance_counters, wer, processes
)
from collectors.collector_master import collect_all
from processors.analyzer import analyze_all

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
        # Główny przycisk - Full System Scan
        self.full_scan_btn = tk.Button(
            self.root, text="🔍 FULL SYSTEM SCAN", command=self.start_full_scan,
            bg="#0066cc", fg="white", activebackground="#0055aa", activeforeground="white",
            font=("Arial", 14, "bold"), pady=10, width=30
        )
        self.full_scan_btn.pack(pady=15)

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
    
    def run_full_scan(self):
        self.status.config(text="Starting Full System Scan...")
        self.progress_bar['value'] = 0
        self.progress_percent.config(text="0%")
        self.progress_label.config(text="Initializing...")
        self.full_scan_btn.config(state=tk.DISABLED)
        for btn in self.collector_buttons.values():
            btn.config(state=tk.DISABLED)
        
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert(tk.END, "=" * 70 + "\n")
        self.output_text.insert(tk.END, "FULL SYSTEM DIAGNOSTIC SCAN\n")
        self.output_text.insert(tk.END, "=" * 70 + "\n\n")
        self.root.update()
        
        try:
            # Krok 1: Zbierz dane
            self.output_text.insert(tk.END, "Step 1: Collecting system data...\n")
            self.output_text.insert(tk.END, "-" * 70 + "\n")
            self.root.update()
            
            # Callback do aktualizacji postępu
            def progress_callback(step, total, message):
                # Oblicz procent dla kroku zbierania (0-50%)
                collection_percent = int((step / total) * 50)
                self.progress_bar['value'] = collection_percent
                self.progress_percent.config(text=f"{collection_percent}%")
                self.progress_label.config(text=message)
                self.status.config(text=f"{message} ({step}/{total})")
                self.output_text.insert(tk.END, f"  [{step}/{total}] {message}\n")
                self.output_text.see(tk.END)
                self.root.update()
            
            collected_data = collect_all(
                save_raw=True, 
                output_dir="output/raw",
                progress_callback=progress_callback
            )
            
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
            
            self.status.config(text="Full System Scan Completed")
            self.progress_label.config(text="Scan completed successfully")
        except Exception as e:
            error_msg = f"Scan failed: {type(e).__name__}: {str(e)}"
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
        """Formatuje dane hardware."""
        output = "=== HARDWARE INFORMATION ===\n\n"
        
        if "cpu" in data:
            cpu = data["cpu"]
            output += f"CPU: {cpu.get('model', 'N/A')}\n"
            output += f"  Physical Cores: {cpu.get('physical_cores', 'N/A')}\n"
            output += f"  Logical Cores: {cpu.get('logical_cores', 'N/A')}\n"
            output += f"  Usage: {cpu.get('usage_percent', 0):.1f}%\n\n"
        
        if "ram" in data:
            ram = data["ram"]
            output += f"RAM: {ram.get('total', 0)//(1024**3)} GB total\n"
            output += f"  Used: {ram.get('used', 0)//(1024**3)} GB ({ram.get('percent', 0):.1f}%)\n\n"
        
        if "disks" in data:
            output += "DISKS:\n"
            for disk in data["disks"][:5]:  # Max 5 dysków
                output += f"  {disk.get('device', 'N/A')}: {disk.get('total', 0)//(1024**3)} GB\n"
                if "status" in disk:
                    output += f"    Status: {disk.get('status')}\n"
            output += "\n"
        
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
        output = "=== WINDOWS ERROR REPORTING ===\n\n"
        output += f"Recent Crashes: {len(data.get('recent_crashes', []))}\n"
        if data.get("reports"):
            output += f"Report Count: {data['reports'].get('report_count', 0)}\n\n"
        
        if data.get("recent_crashes"):
            output += "RECENT CRASHES:\n"
            for crash in data["recent_crashes"][:10]:
                output += f"  {crash.get('application', 'N/A')}: {crash.get('timestamp', 'N/A')}\n"
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
        
        # Top przyczyny z poprawionym confidence
        confidence_info = report_data.get("confidence", {})
        top_causes = confidence_info.get("top_causes", [])
        if top_causes:
            self.output_text.insert(tk.END, "Top Likely Causes:\n")
            self.output_text.insert(tk.END, "-" * 70 + "\n")
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
if __name__ == "__main__":
    # Sprawdź uprawnienia przed uruchomieniem GUI
    if not is_admin():
        import tkinter.messagebox as msgbox
        root_check = tk.Tk()
        root_check.withdraw()  # Ukryj główne okno
        
        response = msgbox.askyesno(
            "Uprawnienia administratora",
            "Ten program wymaga uprawnień administratora.\n\n"
            "Czy chcesz uruchomić program jako administrator?\n\n"
            "(Zostaniesz poproszony o potwierdzenie w oknie UAC)"
        )
        
        root_check.destroy()
        
        if response:
            # Próbuj uruchomić jako admin (ukryj konsolę dla GUI)
            if restart_as_admin(hide_console=True):
                sys.exit(0)  # Zakończ obecną instancję, nowa zostanie uruchomiona jako admin
            else:
                msgbox.showerror(
                    "Błąd",
                    "Nie udało się uruchomić jako administrator.\n"
                    "Uruchom program ręcznie jako administrator."
                )
                sys.exit(1)
        else:
            msgbox.showwarning(
                "Ostrzeżenie",
                "Program będzie działał z ograniczonymi funkcjami.\n"
                "Niektóre funkcje mogą nie działać poprawnie."
            )
    
    root = tk.Tk()
    app = DiagnosticsGUI(root)
    root.mainloop()
