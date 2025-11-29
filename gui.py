import tkinter as tk
from tkinter import scrolledtext, messagebox
from threading import Thread
from core.orchestrator import run_full_scan

class DiagnosticsGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Super Diagnostics Tool")
        self.root.geometry("700x500")
        self.root.configure(bg="#2e2e2e")  # ciemne tło

        # Przycisk Full Scan
        self.scan_btn = tk.Button(
            root, text="Full Scan", command=self.start_scan,
            bg="#444444", fg="white", activebackground="#555555", activeforeground="white"
        )
        self.scan_btn.pack(pady=10)

        # Pole tekstowe do wyświetlania wyników
        self.output_text = scrolledtext.ScrolledText(
            root, width=80, height=25, bg="#1e1e1e", fg="white", insertbackground="white"
        )
        self.output_text.pack(padx=10, pady=10)

        # Status bar
        self.status = tk.Label(
            root, text="Ready", bd=1, relief=tk.SUNKEN, anchor=tk.W,
            bg="#444444", fg="white"
        )
        self.status.pack(side=tk.BOTTOM, fill=tk.X)

    def start_scan(self):
        # Uruchamiamy skan w osobnym wątku, żeby GUI nie zamarzło
        thread = Thread(target=self.run_scan)
        thread.start()

    def run_scan(self):
        self.status.config(text="Running Full Scan...")
        self.scan_btn.config(state=tk.DISABLED)
        try:
            results = run_full_scan()  # Orchestrator musi zwracać dict
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, str(results))
            self.status.config(text="Scan Completed")
        except Exception as e:
            messagebox.showerror("Error", str(e))
            self.status.config(text="Scan Failed")
        finally:
            self.scan_btn.config(state=tk.NORMAL)

if __name__ == "__main__":
    root = tk.Tk()
    app = DiagnosticsGUI(root)
    root.mainloop()
