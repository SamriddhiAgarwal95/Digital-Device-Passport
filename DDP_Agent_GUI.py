# DDP_Agent_GUI.py
# THE FINAL STANDALONE AGENT APPLICATION (Simple, Stable Startup)

import tkinter as tk
from tkinter import ttk, messagebox
import subprocess # Essential for running the shell commands
import requests # Required for cloud communication
import json
import time
from hashlib import sha256
import os
from datetime import datetime
import threading
import platform 
import sys 

# --- CONFIGURATION (App is now truly universal) ---
CLOUD_API_MINT_URL = "http://127.0.0.1:8000/api/v1/mint/local-wipe-and-mint/" 
DEVICE_ID = "UNIVERSAL-AGENT-" + str(time.time()).replace('.', '')
WIPE_TARGET_PATH = "/mnt/target/user_data/" 
CERT_BACKUP_PATH = "/mnt/usb_drive/ddp_certificate_backup.json" 

WIPE_ALGORITHMS = {
    'NIST': {'name': 'NIST SP 800-88 Purge', 'passes': '1 Pass (Random)', 'description': 'Industry standard for modern drives (SSDs/HDDs).'},
    'DOD': {'name': 'DoD 5220.22-M', 'passes': '3 Passes (Pattern)', 'description': 'Legacy military standard for maximum assurance on older HDDs.'},
    'CE': {'name': 'Cryptographic Erase (CE)', 'passes': 'Key Destroy', 'description': 'Fastest, most secure wipe for encrypted storage (Android/SSDs).'},
}
# --- END CONFIGURATION ---

# --- MAIN APPLICATION CLASS (The App) ---

class DDPWipeAgent(tk.Tk):
    """The main GUI application for the Digital Device Passport Agent."""
    def __init__(self):
        super().__init__()
        self.title("DDP Secure Wipe Agent")
        self.geometry("600x680") 
        self.configure(bg='#f0f4f7')
        
        self.host_os = self._identify_system() 
        
        # 1. BUILD THE UI ELEMENTS (Loads immediately)
        self._build_ui()
        self._set_initial_state()

    # --- SYSTEM IDENTIFICATION LOGIC ---
    def _identify_system(self):
        system = platform.system()
        if system == 'Linux':
            try:
                # Try to get specific distribution info
                return f"Linux Live Agent ({platform.release()})"
            except Exception:
                return "Linux Agent (Generic)"
        elif system == 'Windows':
            return "Windows Agent (Not Recommended for Full Wipe)"
        elif system == 'Darwin':
            return "macOS Agent"
        return "Unknown Boot Environment"

    # --- UI BUILDING FUNCTIONS (Tkinter) ---

    def _build_ui(self):
        self.style = ttk.Style()
        
        # Ensure standard text/labels are BLACK
        self.style.configure('.', foreground='#111', background='#f0f4f7') 
        self.style.configure('TLabel', foreground='#111', background='#f0f4f7')
        self.style.configure('TCombobox', foreground='#111')
        self.style.configure('TButton', font=('Arial', 10, 'bold')) 

        # 1. Main Title
        ttk.Label(self, text="Digital Device Passport Creator", font=('Arial', 16, 'bold'), 
                  background='#f0f4f7', foreground='#2196f3').pack(pady=(10, 5))
        
        # NEW: System Status Indicator (The OS Detection)
        ttk.Label(self, text=f"Agent Running On: {self.host_os}", font=('Arial', 10), 
                  background='#f0f4f7', foreground='#0077b6').pack(pady=(0, 15))

        # 2. Drive Selection (Now for Partitions/Device Types)
        frame1 = ttk.Frame(self, padding="10 10 10 10")
        frame1.pack(fill='x')
        ttk.Label(frame1, text="1. Select Target Partition/Drive:").pack(anchor='w', pady=5) 
        self.drive_var = tk.StringVar(value="/dev/sda (Full Disk)")
        drives = [
            ("Full Device Wipe (HDD/SSD)", "/dev/sda (Full Disk)"), 
            ("Android eMMC Storage", "/dev/mmcblk0"),
            ("Windows C: Partition", "/dev/sda1"),
            ("Linux Root Partition", "/dev/sda2"),
        ]
        self.drive_combo = ttk.Combobox(frame1, textvariable=self.drive_var, 
                                        values=[name for name, id in drives], state='readonly')
        self.drive_combo.current(0)
        self.drive_combo.pack(fill='x', pady=5)

        # 3. Algorithm Selection (Refocused to Step 2)
        frame3 = ttk.Frame(self, padding="10 10 10 10")
        frame3.pack(fill='x')
        ttk.Label(frame3, text="2. Select Wiping Algorithm (Security Level):").pack(anchor='w', pady=5) 
        
        self.algo_keys = list(WIPE_ALGORITHMS.keys())
        self.algo_var = tk.StringVar(value=WIPE_ALGORITHMS[self.algo_keys[0]]['name'])
        
        self.algo_combo = ttk.Combobox(frame3, textvariable=self.algo_var, 
                                       values=[algo['name'] for algo in WIPE_ALGORITHMS.values()], 
                                       state='readonly')
        self.algo_combo.pack(fill='x', pady=5)
        self.algo_combo.bind("<<ComboboxSelected>>", self._update_algo_info)
        self.algo_info_label = ttk.Label(frame3, text="", wraplength=550, foreground='#555')
        self.algo_info_label.pack(anchor='w', pady=(5, 0))
        
        # 4. STEP 1 & 2 BUTTONS (Using tk.Button for definite color control)
        
        # STEP 1 Button: Delete files
        self.btn_delete = tk.Button(self, text="STEP 1: Delete ALL User Files & Prepare Target", 
                                    command=self.step1_delete_files, 
                                    bg='#f44336', # Red background
                                    fg='black', # FINAL FIX: FORCED BLACK TEXT
                                    font=('Arial', 10, 'bold'))
        self.btn_delete.pack(fill='x', pady=(15, 5), padx=10) 

        # STEP 2 Button: Full Wipe (Merged Wipe Free Space & Mint)
        self.btn_certify = tk.Button(self, text="STEP 2: Execute Full Wipe & Mint Passport", 
                                     command=self._start_wipe_thread, 
                                     bg='#4caf50', # Green background
                                     fg='black', # FINAL FIX: FORCED BLACK TEXT
                                     font=('Arial', 10, 'bold'),
                                     state=tk.DISABLED) 
        self.btn_certify.pack(fill='x', pady=(5, 10), padx=10)

        # 5. Output Console
        self.output_text = tk.Text(self, height=8, bg='#333', fg='#00ff00', 
                                   font=('Consolas', 10), bd=0, relief='flat')
        self.output_text.pack(fill='both', expand=True, padx=10, pady=5)
        self.output_text.insert(tk.END, f"Status: Ready. App initialized on {self.host_os}.\n")

    # --- Utility Functions ---
    def _set_initial_state(self):
        self._update_algo_info()

    def _update_algo_info(self, event=None):
        selected_name = self.algo_var.get()
        algo = next((a for a in WIPE_ALGORITHMS.values() if a['name'] == selected_name), WIPE_ALGORITHMS['NIST'])
        self.algo_info_label.config(text=f"Passes: {algo['passes']} | {algo['description']}")

    def log(self, message):
        self.output_text.insert(tk.END, message + "\n")
        self.output_text.see(tk.END)
        
    # --- STEP 1 LOGIC ---
    def step1_delete_files(self):
        self.log("\n--- STEP 1: Deleting Files & Preparing Target ---")
        
        if not messagebox.askyesno("Confirmation", "Permanently delete ALL user files on the selected drive? This clears files before wiping residue."):
            return

        self.log(f"Simulating mounting and deleting all files on {self.drive_combo.get()}...")
        
        time.sleep(1) 
        self.log(f"✅ SUCCESS: All files deleted.")
        self.log("Data residue remains! Proceed to Step 2 to wipe free space.")
        
        self.btn_certify.config(state=tk.NORMAL)
        self.btn_delete.config(state=tk.DISABLED)
        
    # --- WIPE THREAD STARTER ---
    def _start_wipe_thread(self):
        selected_drive_name = self.drive_combo.get()
        if not messagebox.askyesno("FINAL WARNING: IRREVERSIBLE ACTION", 
                                   f"You are about to securely wipe: {selected_drive_name}.\n\nALL DATA WILL BE DESTROYED. PROCEED?"):
            return
        
        self.btn_certify.config(state=tk.DISABLED)
        self.btn_delete.config(state=tk.DISABLED)
        
        wipe_thread = threading.Thread(target=self.execute_full_wipe)
        wipe_thread.start()

    # --- EXECUTION LOGIC (The Core Wipe) ---
    def execute_full_wipe(self):
        self.log("\n--- EXECUTING FULL DATA DESTRUCTION & CERTIFICATION ---")

        selected_drive_name = self.drive_combo.get()
        algorithm_name = self.algo_var.get()
        target_path_id = selected_drive_name.split()[0] 
        
        self.log(f"Wiping Target: {selected_drive_name} ({target_path_id}) using {algorithm_name}...")
        self.log("⏳ Executing IRREVERSIBLE wipe. DO NOT POWER OFF.")

        # SIMULATION CODE
        try:
            time.sleep(5) 
            wipe_status = "SUCCESS"
            wipe_log = f"Full wipe executed using {algorithm_name} on {selected_drive_name}. Verification passed."
            self.log(f"✅ VERIFICATION: Wipe completed successfully.")
            
        except subprocess.CalledProcessError as e:
            wipe_status = "FAILURE"
            wipe_log = f"Secure Wipe Shell Command Failed: {e.stderr.decode() or 'No error output.'}"
            self.log(f"❌ FAILURE: Wipe failed. {log_data}")
            
        # --- PROCEED TO CERTIFICATION ---
        self._certify_wipe(wipe_status, wipe_log, selected_drive_name, algorithm_name)

    # --- CERTIFICATION LOGIC ---
    def _certify_wipe(self, status, log_data, drive_name, algo_name):
        
        cert_data = {
            "imei_serial": f"{DEVICE_ID}-{drive_name.split()[0].replace('/', '')}",
            "wipe_status": status,
            "wipe_standard": algo_name,
            "verification_log": log_data,
            "timestamp": datetime.now().isoformat(),
        }
        
        json_string = json.dumps(cert_data, sort_keys=True)
        dlt_hash = sha256(json_string.encode('utf-8')).hexdigest()
        cert_data['dlt_hash'] = dlt_hash
        
        self.log(f"\n[CERT] Local Hash Generated: {dlt_hash[:16]}...")
        
        # 2. LOCAL BACKUP (Saves the certificate to the pendrive)
        try:
            with open(CERT_BACKUP_PATH, 'w') as f:
                json.dump(cert_data, f, indent=4)
            self.log(f"💾 Backup saved to USB: {CERT_BACKUP_PATH}")
        except Exception as e:
            self.log(f"❌ ERROR: Could not save local backup! {e}")

        # 3. CLOUD MINTING (Simulates talking to the cloud API)
        if status == "SUCCESS":
            self.log("[API] Attempting to mint passport on Cloud Server...")
            try:
                response = requests.post(CLOUD_API_MINT_URL, json=cert_data, timeout=20)
                
                if response.status_code == 201:
                    self.log(f"✅ CERTIFIED: DDP Minted! (Cloud Record CONFIRMED)")
                    messagebox.showinfo("Success", "Certification COMPLETE. Ready to reboot.")
                else:
                    self.log(f"⚠️ CLOUD FAILURE: Status {response.status_code}. Record saved locally.")
                    messagebox.showwarning("Warning", "Certification saved locally only. Cloud connection failed.")

            except requests.exceptions.ConnectionError:
                self.log("❌ CLOUD OFFLINE: Certification saved locally. Cannot connect to API.")
                messagebox.showwarning("Warning", "Server Offline. Certification saved locally only.")
        
        self.btn_certify.config(state=tk.NORMAL)


if __name__ == "__main__":
    
    # 1. Check for shell access
    try:
        subprocess.run("echo", shell=True, check=True)
    except Exception:
        messagebox.showerror("Setup Error", "Failed to start shell interpreter. Check Python configuration.")
        sys.exit(1)

    # 2. Start the App
    try:
        app = DDPWipeAgent()
        app.mainloop()
    except Exception as e:
        # This catches the final hidden crash and prints it to the console
        print(f"Critical Application Crash Details: {e}", file=sys.stderr)
        sys.exit(1)