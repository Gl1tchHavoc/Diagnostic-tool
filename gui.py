import tkinter as tk
from tkinter import scrolledtext, messagebox
from threading import Thread
from modules import hardware

class DiagnosticsGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Super Diagnostics Tool")
        self.root.geometry("1600x1200")
        self.root.configure(bg="#2e2e2e")

        self.setup_widgets()

    def setup_widgets(self):
        # Scan Hardware Button
        self.scan_btn = tk.Button(
            self.root, text="Scan Hardware", command=self.start_hardware_scan,
            bg="#444444", fg="white", activebackground="#555555", activeforeground="white"
        )
        self.scan_btn.pack(pady=10)

        # Output Text
        self.output_text = scrolledtext.ScrolledText(
            self.root, width=200, height=60, bg="#1e1e1e", fg="white", insertbackground="white"
        )
        self.output_text.pack(padx=10, pady=10)

        # Status bar
        self.status = tk.Label(
            self.root, text="Ready", bd=1, relief=tk.SUNKEN, anchor=tk.W,
            bg="#444444", fg="white"
        )
        self.status.pack(side=tk.BOTTOM, fill=tk.X)

#----------------------------------------------------------------------------------------------------
    def start_hardware_scan(self):
        thread = Thread(target=self.run_hardware_scan)
        thread.start()

    def run_hardware_scan(self):
        self.status.config(text="Scanning Hardware...")
        self.scan_btn.config(state=tk.DISABLED)
        try:
            results = hardware.scan()
            formatted = hardware.format_results(results)

            # Sprawdzenie RAM i dodanie ostrzeżeń do wyników
            ram_slots = results.get("ram_slots", [])
            ram_warnings = hardware.check_ram_slot_layout(ram_slots)
            if ram_warnings:
                formatted += "\n=== RAM Warnings ===\n"
                for warn in ram_warnings:
                    formatted += f"⚠️ {warn}\n"

            self.display_results(formatted)
            self.status.config(text="Hardware Scan Completed")
        except Exception as e:
            messagebox.showerror("Error", str(e))
            self.status.config(text="Scan Failed")
        finally:
            self.scan_btn.config(state=tk.NORMAL)

    def display_results(self, text):
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert(tk.END, text)
#----------------------------------------------------------------------------------------------------

if __name__ == "__main__":
    root = tk.Tk()
    app = DiagnosticsGUI(root)
    root.mainloop()
