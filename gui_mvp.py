"""
GUI MVP - Prosty interfejs graficzny zgodny z flow aplikacji.
Wyświetla listę collectorów + status, podgląd surowych danych, eksport raportu.
"""
import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk, filedialog
from threading import Thread
import json
import sys
from datetime import datetime
from pathlib import Path

# Sprawdź uprawnienia administratora
from utils.admin_check import is_admin, require_admin
from utils.logger import get_logger, setup_logger
import logging

# Nowa struktura MVP
from core.config_loader import get_config
from core.collector_registry import get_registry as get_collector_registry, register_all_collectors
from core.processor_registry import get_registry as get_processor_registry, register_all_processors
from collectors.collector_master import collect_all
from processors.analyzer import analyze_all

logger = get_logger()


class DiagnosticsGUIMVP:
    """Prosty GUI MVP zgodny z flow aplikacji."""

    def __init__(self, root):
        self.root = root
        self.config = get_config()

        # Inicjalizacja konfiguracji i rejestrów
        self._initialize_app()

        # Dane z ostatniego skanu
        self.last_collected_data = None
        self.last_processed_data = None

        # Dane pojedynczych collectorów (cache)
        self.collector_data_cache = {}

        # Aktualnie wybrany collector
        self.selected_collector = None

        # Setup GUI
        self.setup_widgets()

        # Sprawdź uprawnienia administratora
        if not is_admin():
            self.show_admin_warning()

    def _initialize_app(self):
        """1. Inicjalizacja i konfiguracja - zgodnie z flow."""
        logger.info("=" * 60)
        logger.info("Diagnostic Tool MVP - Initialization")
        logger.info("=" * 60)

        # Wczytaj konfigurację
        logger.info(f"[INIT] Configuration loaded: {self.config.config_path}")

        # Zarejestruj wszystkie collectory i procesory
        register_all_collectors()
        register_all_processors()

        logger.info("[INIT] Collectors and processors registered")
        logger.info("[INIT] Application ready")

    def show_admin_warning(self):
        """Wyświetla ostrzeżenie o braku uprawnień administratora."""
        warning_text = (
            "⚠️ WYMAGANE UPRAWNIENIA ADMINISTRATORA\n\n"
            "Ten program wymaga uprawnień administratora.\n"
            "Niektóre funkcje mogą nie działać poprawnie."
        )
        messagebox.showwarning("Uprawnienia administratora", warning_text)

    def setup_widgets(self):
        """Konfiguruje widżety GUI."""
        # Tytuł
        title = tk.Label(
            self.root, text="Diagnostic Tool MVP",
            bg="#2e2e2e", fg="white", font=("Arial", 16, "bold")
        )
        title.pack(pady=10)

        # Frame dla przycisków akcji
        action_frame = tk.Frame(self.root, bg="#2e2e2e")
        action_frame.pack(pady=10)

        # Przycisk - Full Scan
        self.scan_btn = tk.Button(
            action_frame, text="🔍 FULL SCAN", command=self.start_full_scan,
            bg="#0066cc", fg="white", activebackground="#0055aa",
            font=("Arial", 12, "bold"), pady=8, width=20
        )
        self.scan_btn.pack(side=tk.LEFT, padx=5)

        # Przycisk - Run Selected Collector
        self.run_selected_btn = tk.Button(
            action_frame, text="▶️ Run Selected", command=self.run_selected_collector,
            bg="#cc6600", fg="white", activebackground="#aa5500",
            font=("Arial", 10), pady=5, width=15,
            state=tk.DISABLED
        )
        self.run_selected_btn.pack(side=tk.LEFT, padx=5)

        # Przycisk - View Selected Data
        self.view_selected_btn = tk.Button(
            action_frame, text="👁️ View Data", command=self.view_collector_data,
            bg="#00aa66", fg="white", activebackground="#008855",
            font=("Arial", 10), pady=5, width=15,
            state=tk.DISABLED
        )
        self.view_selected_btn.pack(side=tk.LEFT, padx=5)

        # Przycisk - Export JSON
        self.export_json_btn = tk.Button(
            action_frame, text="💾 Export JSON", command=self.export_json,
            bg="#00cc66", fg="white", activebackground="#00aa55",
            font=("Arial", 10), pady=5, width=15,
            state=tk.DISABLED
        )
        self.export_json_btn.pack(side=tk.LEFT, padx=5)

        # Przycisk - Export HTML
        self.export_html_btn = tk.Button(
            action_frame, text="📄 Export HTML", command=self.export_html,
            bg="#cc6600", fg="white", activebackground="#aa5500",
            font=("Arial", 10), pady=5, width=15,
            state=tk.DISABLED
        )
        self.export_html_btn.pack(side=tk.LEFT, padx=5)

        # Separator
        separator = tk.Frame(self.root, height=2, bg="#555555")
        separator.pack(fill=tk.X, padx=20, pady=10)

        # Frame główny - podzielony na dwie części
        main_frame = tk.Frame(self.root, bg="#2e2e2e")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Lewa strona - Lista collectorów z statusami
        left_frame = tk.Frame(main_frame, bg="#2e2e2e", width=300)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, padx=(0, 5))
        left_frame.pack_propagate(False)

        # Label dla listy collectorów
        collectors_label = tk.Label(
            left_frame, text="Collectors Status",
            bg="#2e2e2e", fg="white", font=("Arial", 11, "bold")
        )
        collectors_label.pack(pady=5)

        # TreeView dla collectorów
        self.collectors_tree = ttk.Treeview(
            left_frame, columns=("status",), show="tree headings",
            height=20
        )
        self.collectors_tree.heading("#0", text="Collector")
        self.collectors_tree.heading("status", text="Status")
        self.collectors_tree.column("#0", width=200)
        self.collectors_tree.column("status", width=100)
        self.collectors_tree.pack(fill=tk.BOTH, expand=True)

        # Bind events dla TreeView
        self.collectors_tree.bind(
            "<Double-1>",
            self.on_collector_double_click)  # Podwójne kliknięcie
        self.collectors_tree.bind(
            "<Button-3>",
            self.on_collector_right_click)  # Prawy przycisk
        self.collectors_tree.bind(
            "<Button-1>",
            self.on_collector_click)  # Pojedyncze kliknięcie

        # Scrollbar dla TreeView
        scrollbar_left = ttk.Scrollbar(
            left_frame,
            orient=tk.VERTICAL,
            command=self.collectors_tree.yview)
        scrollbar_left.pack(side=tk.RIGHT, fill=tk.Y)
        self.collectors_tree.configure(yscrollcommand=scrollbar_left.set)

        # Menu kontekstowe dla collectorów
        self.collector_context_menu = tk.Menu(self.root, tearoff=0)
        self.collector_context_menu.add_command(
            label="🔍 Run Collector", command=self.run_selected_collector)
        self.collector_context_menu.add_command(
            label="👁️ View Data", command=self.view_collector_data)
        self.collector_context_menu.add_separator()
        self.collector_context_menu.add_command(
            label="🔄 Refresh Status",
            command=self.refresh_collector_status)

        # Prawa strona - Podgląd surowych danych
        right_frame = tk.Frame(main_frame, bg="#2e2e2e")
        right_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(5, 0))

        # Label dla surowych danych
        data_label = tk.Label(
            right_frame, text="Raw Data Preview",
            bg="#2e2e2e", fg="white", font=("Arial", 11, "bold")
        )
        data_label.pack(pady=5)

        # Text widget dla surowych danych
        self.raw_data_text = scrolledtext.ScrolledText(
            right_frame, width=80, height=30,
            bg="#1e1e1e", fg="white", insertbackground="white",
            font=("Consolas", 9), wrap=tk.NONE
        )
        self.raw_data_text.pack(fill=tk.BOTH, expand=True)

        # Status bar na dole
        self.status_bar = tk.Label(
            self.root, text="Ready", bd=1, relief=tk.SUNKEN, anchor=tk.W,
            bg="#444444", fg="white", font=("Arial", 9)
        )
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        # Progress bar
        self.progress_bar = ttk.Progressbar(
            self.root, mode='determinate', length=400, maximum=100
        )
        self.progress_bar.pack(side=tk.BOTTOM, fill=tk.X, padx=10, pady=(0, 5))

        # Inicjalizuj listę collectorów
        self.update_collectors_list()

    def update_collectors_list(self):
        """Aktualizuje listę collectorów w TreeView."""
        self.collectors_tree.delete(*self.collectors_tree.get_children())

        registry = get_collector_registry()
        collectors = registry.get_all(enabled_only=True)

        for name, info in sorted(collectors.items()):
            self.collectors_tree.insert(
                "", tk.END, text=name, values=(
                    "Pending",))

    def update_collector_status(
            self, collector_name: str, status: str, error: str = None, data: dict = None):
        """Aktualizuje status collectora w TreeView."""
        for item in self.collectors_tree.get_children():
            if self.collectors_tree.item(item, "text") == collector_name:
                # Zapisz dane w cache jeśli dostępne
                if data is not None:
                    self.collector_data_cache[collector_name] = data

                status_text = status
                if error:
                    status_text = f"{status} ({error[:30]}...)" if len(
                        error) > 30 else f"{status} ({error})"
                self.collectors_tree.item(item, values=(status_text,))
                # Kolorowanie w zależności od statusu
                if status == "Collected":
                    self.collectors_tree.set(item, "status", "✅ Collected")
                elif status == "Error":
                    self.collectors_tree.set(item, "status", "❌ Error")
                else:
                    self.collectors_tree.set(item, "status", status)
                break

    def update_progress(self, step: int, total: int, message: str):
        """Aktualizuje pasek postępu i status."""
        percent = int((step / total) * 100) if total > 0 else 0
        self.progress_bar['value'] = percent
        self.status_bar.config(text=f"{message} ({step}/{total})")
        self.root.update()

    def start_full_scan(self):
        """Uruchamia pełny skan w osobnym wątku."""
        self.scan_btn.config(state=tk.DISABLED)
        self.export_json_btn.config(state=tk.DISABLED)
        self.export_html_btn.config(state=tk.DISABLED)

        # Wyczyść poprzednie dane
        self.raw_data_text.delete(1.0, tk.END)
        self.update_collectors_list()

        thread = Thread(target=self.run_full_scan, daemon=True)
        thread.start()

    def run_full_scan(self):
        """2. Uruchamianie collectorów - zgodnie z flow."""
        logger.info("[SCAN] Starting full scan")
        self.update_status("Starting collection...")

        try:
            # 2. Uruchamianie collectorów (równolegle jeśli włączone w config)
            collected_data = collect_all(
                save_raw=self.config.get("output.save_raw", True),
                output_dir=self.config.get(
                    "output.raw_output_dir", "output/raw"),
                progress_callback=self.update_progress
            )

            self.last_collected_data = collected_data

            # Aktualizuj statusy collectorów i zapisz dane w cache
            collectors = collected_data.get("collectors", {})
            for name, result in collectors.items():
                if isinstance(result, dict) and "status" in result:
                    status = result.get("status", "Unknown")
                    error = result.get("error")
                    data = result.get("data")
                    # Zapisz dane w cache dla późniejszego wyświetlenia
                    if data is not None:
                        self.collector_data_cache[name] = data
                    self.update_collector_status(name, status, error, result)

            # 3. Walidacja i parsowanie danych
            self.update_status("Processing data...")
            processed_data = analyze_all(
                collected_data, progress_callback=self.update_progress)
            self.last_processed_data = processed_data

            # 4. Prezentacja wyników - wyświetl surowe dane
            self.display_raw_data(collected_data)

            # Włącz przyciski eksportu
            self.export_json_btn.config(state=tk.NORMAL)
            self.export_html_btn.config(state=tk.NORMAL)

            self.update_status("Scan completed successfully")
            logger.info("[SCAN] Full scan completed")

        except Exception as e:
            error_msg = f"Scan failed: {str(e)}"
            logger.exception("[SCAN] Scan failed")
            self.update_status(error_msg)
            messagebox.showerror("Error", error_msg)
        finally:
            self.scan_btn.config(state=tk.NORMAL)
            self.progress_bar['value'] = 0

    def display_raw_data(self, data: dict):
        """Wyświetla surowe dane w text widget w czytelnej formie."""
        try:
            # Włącz edycję przed modyfikacją
            self.raw_data_text.config(state=tk.NORMAL)

            # Formatuj JSON w czytelny sposób
            formatted_json = json.dumps(
                data, indent=2, ensure_ascii=False, default=str)
            self.raw_data_text.delete(1.0, tk.END)

            # Dodaj nagłówek z informacją o skanie
            header = "=== FULL SCAN DATA ===\n"
            header += f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            header += "=" * 60 + "\n\n"

            self.raw_data_text.insert(1.0, header + formatted_json)

            # Ustaw kolor tekstu dla lepszej czytelności
            self.raw_data_text.config(
                fg="#ffffff",
                bg="#1e1e1e",
                insertbackground="#ffffff")

            # Wyłącz edycję po wyświetleniu (tylko do odczytu)
            # Pozostaw włączone dla kopiowania
            self.raw_data_text.config(state=tk.NORMAL)
        except Exception as e:
            logger.error(f"[GUI] Failed to display raw data: {e}")
            self.raw_data_text.config(state=tk.NORMAL)
            self.raw_data_text.delete(1.0, tk.END)
            self.raw_data_text.insert(1.0, f"Error displaying data: {e}")

    def export_json(self):
        """Eksportuje raport do JSON używając wspólnego modułu eksportu."""
        if not self.last_collected_data:
            messagebox.showwarning(
                "No Data", "No data to export. Please run a scan first.")
            return

        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            initialfile=f"diagnostic_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )

        if filename:
            try:
                from utils.export_utils import export_json
                # Przygotuj dane do eksportu
                export_data = {
                    "collected_data": self.last_collected_data,
                    "processed_data": self.last_processed_data
                }
                # Eksportuj do wybranego pliku
                filepath = Path(filename)
                export_json(
                    export_data,
                    filename=filepath.name,
                    output_dir=str(
                        filepath.parent))
                messagebox.showinfo(
                    "Success", f"Report exported to:\n{filename}")
            except Exception as e:
                error_msg = f"Failed to export JSON: {e}"
                logger.error(f"[EXPORT] {error_msg}")
                messagebox.showerror("Error", error_msg)

    def export_html(self):
        """Eksportuje raport do HTML używając wspólnego modułu eksportu."""
        if not self.last_collected_data:
            messagebox.showwarning(
                "No Data", "No data to export. Please run a scan first.")
            return

        filename = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("HTML files", "*.html"), ("All files", "*.*")],
            initialfile=f"diagnostic_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        )

        if filename:
            try:
                from utils.export_utils import export_html
                # Eksportuj do wybranego pliku
                filepath = Path(filename)
                export_html(
                    self.last_collected_data,
                    self.last_processed_data,
                    filename=filepath.name,
                    output_dir=str(filepath.parent)
                )
                messagebox.showinfo(
                    "Success", f"Report exported to:\n{filename}")
            except Exception as e:
                error_msg = f"Failed to export HTML: {e}"
                logger.error(f"[EXPORT] {error_msg}")
                messagebox.showerror("Error", error_msg)

    def update_status(self, message: str):
        """Aktualizuje status bar."""
        self.status_bar.config(text=message)
        self.root.update()

    def on_collector_click(self, event):
        """Obsługuje pojedyncze kliknięcie w collector."""
        item = self.collectors_tree.selection(
        )[0] if self.collectors_tree.selection() else None
        if item:
            collector_name = self.collectors_tree.item(item, "text")
            self.selected_collector = collector_name
            # Włącz przyciski jeśli collector jest wybrany
            self.run_selected_btn.config(state=tk.NORMAL)
            self.view_selected_btn.config(state=tk.NORMAL)
        else:
            # Wyłącz przyciski jeśli nic nie jest wybrane
            self.run_selected_btn.config(state=tk.DISABLED)
            self.view_selected_btn.config(state=tk.DISABLED)

    def on_collector_double_click(self, event):
        """Obsługuje podwójne kliknięcie w collector - uruchamia collector."""
        item = self.collectors_tree.selection(
        )[0] if self.collectors_tree.selection() else None
        if item:
            collector_name = self.collectors_tree.item(item, "text")
            self.run_single_collector(collector_name)

    def on_collector_right_click(self, event):
        """Obsługuje prawy przycisk myszy - pokazuje menu kontekstowe."""
        item = self.collectors_tree.identify_row(event.y)
        if item:
            self.collectors_tree.selection_set(item)
            collector_name = self.collectors_tree.item(item, "text")
            self.selected_collector = collector_name
            try:
                self.collector_context_menu.tk_popup(
                    event.x_root, event.y_root)
            finally:
                self.collector_context_menu.grab_release()

    def run_selected_collector(self):
        """Uruchamia wybrany collector z menu kontekstowego."""
        if self.selected_collector:
            self.run_single_collector(self.selected_collector)

    def view_collector_data(self):
        """Wyświetla dane wybranego collectora."""
        if self.selected_collector:
            # Sprawdź cache
            if self.selected_collector in self.collector_data_cache:
                data = self.collector_data_cache[self.selected_collector]
                self.display_collector_data(self.selected_collector, data)
            elif self.last_collected_data:
                # Sprawdź w ostatnich danych
                collectors = self.last_collected_data.get("collectors", {})
                if self.selected_collector in collectors:
                    collector_result = collectors[self.selected_collector]
                    if isinstance(collector_result, dict):
                        data = collector_result.get("data")
                        if data:
                            self.display_collector_data(
                                self.selected_collector, data)
                        else:
                            messagebox.showinfo(
                                "No Data", f"No data available for {self.selected_collector}")
                    else:
                        self.display_collector_data(
                            self.selected_collector, collector_result)
                else:
                    messagebox.showinfo(
                        "No Data",
                        f"No data available for {self.selected_collector}. Please run the collector first.")
            else:
                messagebox.showinfo(
                    "No Data",
                    f"No data available for {self.selected_collector}. Please run a scan or the collector first.")

    def display_collector_data(self, collector_name: str, data: dict):
        """Wyświetla dane konkretnego collectora w czytelnej formie."""
        try:
            # Włącz edycję przed modyfikacją
            self.raw_data_text.config(state=tk.NORMAL)

            # Formatuj JSON w czytelny sposób
            formatted_json = json.dumps(
                data, indent=2, ensure_ascii=False, default=str)
            self.raw_data_text.delete(1.0, tk.END)

            # Nagłówek z informacją o collectorze
            header = f"=== {collector_name.upper()} DATA ===\n"
            header += f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            header += "=" * 60 + "\n\n"

            self.raw_data_text.insert(1.0, header + formatted_json)

            # Ustaw kolor tekstu dla lepszej czytelności
            self.raw_data_text.config(
                fg="#ffffff",
                bg="#1e1e1e",
                insertbackground="#ffffff")

            self.update_status(f"Displaying data for: {collector_name}")
        except Exception as e:
            logger.error(f"[GUI] Failed to display collector data: {e}")
            self.raw_data_text.config(state=tk.NORMAL)
            self.raw_data_text.delete(1.0, tk.END)
            self.raw_data_text.insert(
                1.0, f"Error displaying data for {collector_name}: {e}")

    def run_single_collector(self, collector_name: str):
        """Uruchamia pojedynczy collector."""
        if not collector_name:
            collector_name = self.selected_collector

        if not collector_name:
            messagebox.showwarning(
                "No Selection",
                "Please select a collector first")
            return

        registry = get_collector_registry()
        collector_info = registry.get(collector_name)

        if not collector_info:
            messagebox.showerror(
                "Error", f"Collector '{collector_name}' not found in registry")
            return

        # Wyłącz przyciski podczas zbierania
        self.scan_btn.config(state=tk.DISABLED)
        self.run_selected_btn.config(state=tk.DISABLED)
        self.view_selected_btn.config(state=tk.DISABLED)
        self.update_status(f"Running collector: {collector_name}...")
        self.update_collector_status(collector_name, "Running...")

        # Uruchom w osobnym wątku
        thread = Thread(
            target=self._run_single_collector_thread,
            args=(
                collector_name,
                collector_info),
            daemon=True)
        thread.start()

    def _run_single_collector_thread(
            self, collector_name: str, collector_info: dict):
        """Wątek uruchamiający pojedynczy collector."""
        logger.info(f"[GUI] Running single collector: {collector_name}")

        try:
            collector_func = collector_info["collect_func"]
            collector_result = collector_func()

            # Standaryzuj format
            if isinstance(collector_result,
                          dict) and "status" in collector_result:
                standardized_result = collector_result
            else:
                standardized_result = {
                    "status": "Collected",
                    "data": collector_result,
                    "error": None,
                    "timestamp": datetime.now().isoformat(),
                    "collector_name": collector_name,
                    "execution_time_ms": 0
                }

            # Aktualizuj GUI w głównym wątku
            self.root.after(
                0,
                self._update_collector_after_run,
                collector_name,
                standardized_result)

        except Exception as e:
            error_msg = f"{type(e).__name__}: {e}"
            logger.exception(f"[GUI] Collector {collector_name} failed")
            standardized_result = {
                "status": "Error",
                "data": None,
                "error": error_msg,
                "timestamp": datetime.now().isoformat(),
                "collector_name": collector_name,
                "execution_time_ms": 0
            }
            self.root.after(
                0,
                self._update_collector_after_run,
                collector_name,
                standardized_result)

    def _update_collector_after_run(self, collector_name: str, result: dict):
        """Aktualizuje GUI po uruchomieniu collectora (wywoływane w głównym wątku)."""
        status = result.get("status", "Unknown")
        error = result.get("error")
        data = result.get("data")

        self.update_collector_status(collector_name, status, error, result)

        # Automatycznie wyświetl dane jeśli collector się powiódł
        if status == "Collected" and data:
            self.display_collector_data(collector_name, data)
            self.update_status(
                f"Collector '{collector_name}' completed successfully")
        else:
            self.update_status(
                f"Collector '{collector_name}' failed: {error}" if error else f"Collector '{collector_name}' completed")

        self.scan_btn.config(state=tk.NORMAL)
        # Włącz przyciski jeśli collector jest wybrany
        if self.selected_collector:
            self.run_selected_btn.config(state=tk.NORMAL)
            self.view_selected_btn.config(state=tk.NORMAL)

    def refresh_collector_status(self):
        """Odświeża status wybranego collectora."""
        if self.selected_collector:
            # Jeśli mamy dane w cache, po prostu je wyświetl
            if self.selected_collector in self.collector_data_cache:
                self.view_collector_data()
            else:
                messagebox.showinfo(
                    "No Data",
                    f"No cached data for {self.selected_collector}. Please run the collector first.")


def main():
    """Główna funkcja uruchamiająca GUI MVP."""
    # Setup logger
    setup_logger(level=logging.INFO)
    logger = get_logger()

    logger.info("=" * 60)
    logger.info("Diagnostic Tool MVP - Starting GUI")
    logger.info("=" * 60)

    # Sprawdź i automatycznie zainstaluj brakujące pakiety
    from utils.requirements_check import install_missing_packages
    logger.info("Checking and installing requirements...")
    requirements_status = install_missing_packages(auto_install=True)
    if not requirements_status['all_installed']:
        logger.warning(
            "Some required packages are still missing after auto-installation")
        # W GUI nie blokujemy - tylko logujemy

    # Sprawdź uprawnienia administratora
    if not require_admin(auto_restart=True):
        logger.error("Administrator privileges required")
        print("\nNaciśnij Enter aby zakończyć...")
        input()
        sys.exit(1)

    # Utwórz główne okno
    root = tk.Tk()
    root.title("Diagnostic Tool MVP")
    root.geometry("1400x900")
    root.configure(bg="#2e2e2e")

    # Utwórz aplikację
    app = DiagnosticsGUIMVP(root)

    # Uruchom główną pętlę
    logger.info("[GUI] Starting main loop")
    root.mainloop()


if __name__ == "__main__":
    main()
