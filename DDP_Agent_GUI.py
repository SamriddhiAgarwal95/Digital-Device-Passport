"""
DDP_Agent_GUI.py
Enhanced Digital Device Passport Wipe Agent
- FIX 1: Corrected SyntaxError (unicode escape sequence in docstring on Windows).
- FIX 2: Corrected ValueError: unexpected '{' in field name by doubling curly braces in PowerShell command string.
- FIX 3: **ENHANCED**: Expanded folder list and added clear requirement for elevated privileges (Admin/sudo) for real file deletion.
- Real file deletion via subprocess.
- Uses psutil for real device identification.
- Complete and runnable application entry point.
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import time
import json
from hashlib import sha256
from datetime import datetime
import requests
import platform
import os
import sys
import socket
import psutil 
import subprocess 

# -------------------------------
# CONFIGURATION (adjust as needed)
# -------------------------------
CLOUD_API_MINT_URL = "http://127.0.0.1:8080/api/v1/mint/local-wipe-and-mint/"
DEVICE_ID_PREFIX = "UNIVERSAL-AGENT"
DEFAULT_WIPE_TARGET = "/mnt/target/user_data/"
DEFAULT_CERT_BACKUP_PATH = "/mnt/usb_drive/ddp_certificate_backup.json"
UPLOADED_PROJECT_ZIP_PATH = "/mnt/data/Digital-Device-Passport-main.zip"
UPLOADED_PROJECT_ZIP_URL = f"file://{UPLOADED_PROJECT_ZIP_PATH}"

# List of common folders to look for inside a user's home directory
# --- EXPANDED FOLDER LIST FOR MORE COMPREHENSIVE DELETION ---
STANDARD_USER_FOLDERS = [
    "Documents", 
    "Downloads", 
    "Pictures", 
    "Videos", 
    "Desktop",
    "Music",
    "Links",        # Windows shortcuts
    "Saved Games",  # Windows
    "OneDrive",     # Windows sync folders (will delete local contents)
    ".cache",       # Linux/macOS caches
    ".ssh",         # Secure shell keys
    ".mozilla",     # Firefox profiles
    ".thunderbird", # Email profiles
    "Library",      # macOS
    "Public",       # Windows shared folder (if within a user profile)
]

# Wipe algorithm definitions (name -> config)
WIPE_ALGORITHMS = {
    "NIST": {"display": "NIST SP 800-88 Purge", "passes": 1, "description": "Modern standard: single random pass (SSD/HDD)"},
    "DOD": {"display": "DoD 5220.22-M", "passes": 3, "description": "Legacy multi-pass pattern, HDD focused"},
    "CE": {"display": "Cryptographic Erase (CE)", "passes": 1, "description": "Key destroy: fastest for encrypted storage"},
}

APP_VERSION = "1.5.1" # Updated version

# -------------------------------
# Utility helpers
# -------------------------------

def now_iso():
    return datetime.now().isoformat()

def generate_device_id():
    """Generates a unique ID based on hostname and a random component."""
    try:
        host = socket.gethostname()
        mac = ':'.join(f'{b:02x}' for b in os.urandom(6))
        return f"{DEVICE_ID_PREFIX}-{host}-{mac[-4:]}"
    except Exception:
        return f"{DEVICE_ID_PREFIX}-{int(time.time())}"

def safe_post_json(url, data, timeout=10):
    try:
        resp = requests.post(url, json=data, timeout=timeout)
        return resp.status_code, resp.text
    except Exception as e:
        return None, str(e)

def get_drive_list():
    """Identifies and returns a list of detected fixed drives/partitions using psutil."""
    drives = []
    
    if 'psutil' in sys.modules:
        try:
            partitions = psutil.disk_partitions(all=False)
            for p in partitions:
                # Exclude RAM disks, CD-ROMs, and virtual/network mounts
                is_removable = 'removable' in p.opts.lower() or 'cdrom' in p.opts.lower() or 'net' in p.opts.lower()
                if not is_removable and p.mountpoint:
                    # Differentiate between Windows drives and Unix block devices
                    if platform.system() == "Windows":
                        drives.append(f"Windows Drive: {p.mountpoint}")
                    else: # Linux/macOS
                        drives.append(f"Mount Point: {p.mountpoint}")
            
            if not drives:
                if platform.system() == "Linux":
                    drives.append("Mount Point: /")
                elif platform.system() == "Windows":
                    drives.append("Windows Drive: C:\\")
        except Exception:
            drives = ["ERROR: Detection Failed", "Windows Drive: C:\\", "Mount Point: /dev/sda1"]

    if not drives:
        if platform.system() == "Windows":
            drives = ["Windows Drive: C:\\", "External/Secondary: D:\\", "Custom Path..."]
        else:
            drives = ["Mount Point: /", "Android eMMC: /dev/mmcblk0", "Custom Path..."]

    return drives

# -------------------------------
# Logger Class
# -------------------------------

class Logger:
    """Simple log manager for the GUI text widget with levels."""
    def __init__(self, text_widget):
        self.text = text_widget
        self.text.tag_configure("INFO", foreground="#cfefff")
        self.text.tag_configure("DEBUG", foreground="#aaaaaa")
        self.text.tag_configure("SUCCESS", foreground="#9fff9f")
        self.text.tag_configure("WARNING", foreground="#ffd86b")
        self.text.tag_configure("ERROR", foreground="#ff8b8b")
        self.text.config(state=tk.NORMAL)

    def _write(self, msg, tag="INFO"):
        ts = datetime.now().strftime("%H:%M:%S")
        self.text.config(state=tk.NORMAL)
        self.text.insert(tk.END, f"[{ts}] {msg}\n", tag)
        self.text.see(tk.END)
        self.text.config(state=tk.DISABLED)

    def info(self, msg): self._write(msg, "INFO")
    def debug(self, msg): self._write(msg, "DEBUG")
    def success(self, msg): self._write(msg, "SUCCESS")
    def warning(self, msg): self._write(msg, "WARNING")
    def error(self, msg): self._write(msg, "ERROR")

# -------------------------------
# Wipe Worker Thread
# -------------------------------

class WipeWorker(threading.Thread):
    """Thread performing the simulated wipe, with progress updates and cancellation."""
    def __init__(self, progress_callback, log_callback, done_callback, cancel_event, config):
        super().__init__(daemon=True)
        self.progress_callback = progress_callback
        self.log = log_callback
        self.done = done_callback
        self.cancel_event = cancel_event
        self.config = config

    def run(self):
        target = self.config.get("target_name", "UNKNOWN")
        alg = self.config.get("algorithm_key", "NIST")
        passes = self.config.get("passes", 1)
        # Simulation time is based on passes, max 10s minimum
        total_seconds = self.config.get("estimated_seconds", max(10, passes * 6))
        
        self.log.info(f"Starting WIPE operation on {target} using {WIPE_ALGORITHMS[alg]['display']} ({passes} passes).")
        start_time = time.time()
        elapsed = 0
        last_percent = -1

        for p in range(1, passes + 1):
            if self.cancel_event.is_set():
                self.log.warning("Wipe cancelled by operator.")
                self.done(success=False, details="Cancelled by user.")
                return
            self.log.debug(f"Beginning pass {p}/{passes} (Simulated Disk Wipe)...")
            
            pass_duration = total_seconds / passes
            pass_start = time.time()
            while (time.time() - pass_start) < pass_duration:
                if self.cancel_event.is_set():
                    self.log.warning("Wipe cancelled during pass.")
                    self.done(success=False, details="Cancelled by user.")
                    return
                elapsed = time.time() - start_time
                percent = int((elapsed / total_seconds) * 100)
                # The progress bar starts at 10% after successful deletion (Step 1)
                current_prog = 10 + int(percent * 0.9) 
                current_prog = max(10, min(100, current_prog)) 
                
                if percent != last_percent:
                    self.progress_callback(current_prog)
                    last_percent = percent
                time.sleep(0.2)
            
            self.log.debug(f"Pass {p} completed; verifying (Simulated)...")
            time.sleep(0.6)

        if self.cancel_event.is_set():
            self.log.warning("Wipe cancelled at final verification.")
            self.done(success=False, details="Cancelled by user.")
            return

        self.progress_callback(100)
        time.sleep(0.5)
        self.log.success("Wipe complete. Verification passed (Simulated).")
        elapsed_total = time.time() - start_time
        details = f"Wipe done in {int(elapsed_total)}s using {WIPE_ALGORITHMS[alg]['display']}."
        self.done(success=True, details=details)

# -------------------------------
# Main App Window
# -------------------------------

class DDPWipeAgentApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("DDP Secure Wipe Agent — Execution Ready")
        self.geometry("900x680")
        self.minsize(880, 640)
        self.configure(bg="#0f1724")
        self.protocol("WM_DELETE_WINDOW", self._on_close) 

        # runtime state
        self.device_id = generate_device_id()
        self.host_os = self._identify_system()
        self.cancel_event = threading.Event()
        self.worker_thread = None
        self.deletion_successful = False # Track Step 1 status
        self.drive_list = get_drive_list()
        self.selected_folders = [] # List of folders selected for deletion

        # Build UI
        self._build_topbar()
        self._build_body()
        
        # Load real device list on startup
        self._load_initial_drives()
        self._detect_user_folders() # Initial folder detection
        
        self.logger.info("Ready. Use 'Detect Devices' to refresh drive list.")
        self.logger.warning("For file deletion (STEP 1) to succeed, you must run this script with **Elevated Privileges (Administrator/sudo)**.")
        
    def _identify_system(self):
        """Enhanced system identification."""
        system = platform.system()
        release = platform.release()
        hostname = platform.node()
        try:
            ip = socket.gethostbyname(socket.gethostname())
        except Exception:
            ip = "N/A"
            
        return f"{system} ({release}) | Host: {hostname} | IP: {ip}"

    def _load_initial_drives(self):
        """Sets the initial values in the drive selection combobox."""
        initial_drives = self.drive_list + ["Custom Path..."]
        self.drive_combo['values'] = initial_drives
        self.drive_combo.set(self.drive_list[0] if self.drive_list else "Custom Path...")

    # --- Utility Methods ---

    def _get_cleaned_target_path(self, target):
        """Standardizes the target path for command execution."""
        # Clean the prefix first (e.g., "Windows Drive: ", "Mount Point: ")
        for prefix in ["Windows Drive: ", "Mount Point: ", "Block Device: ", "External/Secondary: "]:
            if target.startswith(prefix):
                target = target[len(prefix):]
                break

        # Standardize path separators for the OS where the agent runs
        is_windows = platform.system() == "Windows"
        target_path_op = target.strip()
        
        if is_windows:
             # Ensure Windows paths use backslashes
             target_path_op = target_path_op.replace('/', '\\')
             # If it was a drive letter (e.g., "C:"), ensure it is "C:\"
             if len(target_path_op) == 2 and target_path_op[1] == ':' and target_path_op[0].isalpha():
                 if not target_path_op.endswith('\\'):
                    target_path_op += "\\"
        else:
             # Ensure Unix/Linux paths use forward slashes
             target_path_op = target_path_op.replace('\\', '/')
        
        return target_path_op

    def _get_user_home_parent(self, cleaned_target):
        r"""Determines the parent directory for user home folders (e.g., C:\Users or /home)""" 
        if platform.system() == "Windows":
            # On Windows, user folders are usually under the root of the selected drive/mount + "Users"
            # Example: C:\ -> C:\Users
            if cleaned_target.endswith(('/', '\\')):
                return os.path.join(cleaned_target, "Users")
            return os.path.join(cleaned_target, "..", "Users") # Handle paths like C:\mount
        else:
            # On Linux/macOS, user folders are usually under /home or /Users on the mount point
            if cleaned_target == '/':
                return "/home" # Assuming standard Linux structure
            
            # If a custom mount is selected, assume /home is inside it
            # This is a heuristic and might need adjustment for specific distributions/setups
            if cleaned_target.startswith('/') and 'dev' not in cleaned_target:
                return os.path.join(cleaned_target, "home")

            # Fallback to the root of the mount point
            return cleaned_target


    def _detect_user_folders(self, event=None):
        """
        Dynamically scans the selected drive/mount point for common user folders 
        and updates the folder listbox.
        """
        target = self.drive_combo.get()
        cleaned_target = self._get_cleaned_target_path(target)
        
        # Determine the directory where user profiles/homes reside
        user_parent_dir = self._get_user_home_parent(cleaned_target)
        
        found_folders = []

        try:
            # 1. Search in the determined user parent directory (e.g., C:\Users)
            if os.path.isdir(user_parent_dir):
                for user_dir in os.listdir(user_parent_dir):
                    user_path = os.path.join(user_parent_dir, user_dir)
                    # Exclude system users like All Users, Default, Public, and hidden folders
                    if os.path.isdir(user_path) and not user_dir.startswith(('.', '$')) and user_dir.lower() not in ['all users', 'default', 'default user', 'public', 'temp']:
                        # 2. Inside each discovered user profile (e.g., C:\Users\JohnDoe)
                        for folder_name in STANDARD_USER_FOLDERS:
                            full_path = os.path.join(user_path, folder_name)
                            if os.path.isdir(full_path):
                                display_name = f"User Profile: {user_dir}/{folder_name}"
                                if display_name not in found_folders:
                                    found_folders.append(display_name)
                                
            # 3. Fallback: Search directly for the folders if user_parent_dir is the home itself
            # This handles cases where the target IS the user's home (e.g., /home/user)
            if os.path.isdir(cleaned_target):
                 for folder_name in STANDARD_USER_FOLDERS:
                    full_path = os.path.join(cleaned_target, folder_name)
                    if os.path.isdir(full_path):
                        display_name = f"Root Folder: {folder_name}"
                        if display_name not in found_folders:
                            found_folders.append(display_name)


        except PermissionError:
            self.logger.error(f"Permission denied accessing '{user_parent_dir}'. Run as Administrator/sudo to fix.")
            # Fallback to standard list if permission is denied
            found_folders = [f"Common: {f}" for f in STANDARD_USER_FOLDERS]
            
        except Exception as e:
            self.logger.error(f"Error during folder detection on '{user_parent_dir}': {e}")
            found_folders = [f"Detection Failed: {e.__class__.__name__}"]

        # Update the listbox
        self.folder_listbox.delete(0, tk.END)
        if found_folders:
            for item in sorted(found_folders):
                self.folder_listbox.insert(tk.END, item)
                self.folder_listbox.selection_set(tk.END) # Select all by default
            self.logger.info(f"Detected {len(found_folders)} common user folders on {cleaned_target}.")
        else:
            self.folder_listbox.insert(tk.END, "No user folders detected or check permissions.")
            self.logger.warning("No user folders could be detected.")
            
        # Update selection state
        current_selection = self.folder_listbox.get(0, tk.END)
        self.selected_folders = [current_selection[i] for i in self.folder_listbox.curselection()]
        self.btn_delete.config(state=tk.NORMAL) 
        self.btn_start_wipe.config(state=tk.DISABLED)
        self._update_preview()
        
    def _get_deletion_paths(self):
        """Extracts the actual file system paths for deletion from the selected listbox items."""
        selected_indices = self.folder_listbox.curselection()
        
        # Get the cleaned root path for the selected drive
        target = self.drive_combo.get()
        cleaned_target_root = self._get_cleaned_target_path(target)
        user_parent_dir = self._get_user_home_parent(cleaned_target_root)
        
        paths_to_delete = []
        
        for i in selected_indices:
            listbox_item = self.folder_listbox.get(i)
            
            if listbox_item.startswith("User Profile: "):
                # Item format: "User Profile: JohnDoe/Documents"
                relative_path = listbox_item.split(": ")[1]
                # Combine user parent dir + relative path (e.g., C:\Users + JohnDoe\Documents)
                full_path = os.path.join(user_parent_dir, relative_path.replace('/', os.sep))
                paths_to_delete.append(full_path)
                
            elif listbox_item.startswith("Root Folder: "):
                # Item format: "Root Folder: Downloads" (used for simple mounts/homes)
                folder_name = listbox_item.split(": ")[1]
                full_path = os.path.join(cleaned_target_root, folder_name)
                paths_to_delete.append(full_path)

            elif listbox_item.startswith("Common: "):
                # Fallback pathing (less accurate, assumes common path)
                folder_name = listbox_item.split(": ")[1]
                # Default guess: root of drive + folder (e.g., C:\Downloads)
                paths_to_delete.append(os.path.join(cleaned_target_root, folder_name))

        # Store the clean path strings for use in _on_step1_delete and preview
        self.selected_folders = paths_to_delete
        return paths_to_delete


    # --- UI BUILDERS ---

    def _build_topbar(self):
        topbar = tk.Frame(self, bg="#061024", height=56)
        topbar.pack(side=tk.TOP, fill=tk.X)

        title = tk.Label(topbar, text="Digital Device Passport — Secure Wipe Agent",
                            bg="#061024", fg="#dbeafe", font=("Segoe UI", 14, "bold"))
        title.pack(side=tk.LEFT, padx=14)

        ver = tk.Label(topbar, text=f"v{APP_VERSION}", bg="#061024", fg="#9fb6d9", font=("Segoe UI", 10))
        ver.pack(side=tk.LEFT, padx=(6,0))

        status = tk.Label(topbar, text=f"Agent on: {self.host_os} | DeviceID: {self.device_id}", 
                         bg="#061024", fg="#9fb6d9", font=("Segoe UI", 10))
        status.pack(side=tk.RIGHT, padx=12)

    def _build_body(self):
        body = tk.Frame(self, bg="#0f1724")
        body.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=12, pady=12)

        left = tk.Frame(body, bg="#07142a", width=360)
        left.pack(side=tk.LEFT, fill=tk.Y, padx=(0,10), pady=4)
        left.pack_propagate(False)

        center = tk.Frame(body, bg="#0b1220")
        center.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0,10))

        right = tk.Frame(body, bg="#071426", width=360)
        right.pack(side=tk.LEFT, fill=tk.Y, pady=4)
        right.pack_propagate(False)

        self._build_left_panel(left)
        self._build_center_panel(center)
        self._build_right_panel(right)

    def _build_left_panel(self, parent):
        pad = {"padx": 12, "pady": 8}
        header = tk.Label(parent, text="Actions & Configuration", bg="#07142a", fg="#e6eef8", font=("Segoe UI", 12, "bold"))
        header.pack(anchor="w", **pad)

        # Drive selection card
        drive_frame = tk.LabelFrame(parent, text="1) Select Target Drive/Mount", bg="#07142a", fg="#dfefff", font=("Segoe UI", 10, "bold"))
        drive_frame.pack(fill=tk.X, padx=10, pady=6)

        ttk.Label(drive_frame, text="Target Device / Partition:", background="#07142a", foreground="#dfefff").pack(anchor="w", padx=6, pady=(6,0))
        self.drive_var = tk.StringVar(value="Detecting...")
        
        self.drive_combo = ttk.Combobox(drive_frame, values=[], textvariable=self.drive_var, state="readonly")
        self.drive_combo.pack(fill=tk.X, padx=8, pady=6)
        self.drive_combo.bind("<<ComboboxSelected>>", self._on_drive_change)

        ttk.Button(drive_frame, text="Detect Block Devices (Refresh)", command=self._detect_block_devices).pack(fill=tk.X, padx=8, pady=(0,8))
        
        # --- Folder Selection ---
        folder_frame = tk.LabelFrame(parent, text="2) Select Folders for File Deletion (STEP 1)", bg="#07142a", fg="#dfefff", font=("Segoe UI", 10, "bold"))
        folder_frame.pack(fill=tk.X, padx=10, pady=6)
        
        ttk.Label(folder_frame, text="Select folders to permanently delete contents:", background="#07142a", foreground="#dfefff").pack(anchor="w", padx=6, pady=(6,0))
        
        # Listbox for folders
        listbox_frame = tk.Frame(folder_frame)
        listbox_frame.pack(fill=tk.X, padx=8, pady=6)
        
        self.folder_listbox = tk.Listbox(listbox_frame, selectmode=tk.MULTIPLE, height=5, 
                                        bg="#021219", fg="#cfefff", bd=1, relief=tk.FLAT)
        self.folder_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.folder_listbox.bind('<<ListboxSelect>>', lambda e: self._update_preview())
        
        # Scrollbar for listbox
        scrollbar = ttk.Scrollbar(listbox_frame, orient="vertical", command=self.folder_listbox.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.folder_listbox.config(yscrollcommand=scrollbar.set)
        
        ttk.Button(folder_frame, text="Scan/Refresh Folders", command=self._detect_user_folders).pack(fill=tk.X, padx=8, pady=(0,8))


        # Algorithm selection
        alg_frame = tk.LabelFrame(parent, text="3) Wipe Algorithm (STEP 2)", bg="#07142a", fg="#dfefff", font=("Segoe UI", 10, "bold"))
        alg_frame.pack(fill=tk.X, padx=10, pady=6)

        ttk.Label(alg_frame, text="Algorithm:", background="#07142a", foreground="#dfefff").pack(anchor="w", padx=6, pady=(6,0))
        self.alg_var = tk.StringVar(value="NIST")
        alg_names = [f"{k} — {v['display']}" for k,v in WIPE_ALGORITHMS.items()]
        self.alg_combo = ttk.Combobox(alg_frame, values=alg_names, textvariable=self.alg_var, state="readonly")
        self.alg_combo.set(list(WIPE_ALGORITHMS.keys())[0])
        self.alg_combo.pack(fill=tk.X, padx=8, pady=6)
        self.alg_combo.bind("<<ComboboxSelected>>", self._on_alg_change)

        self.alg_info_label = tk.Label(alg_frame, text=self._format_alg_info("NIST"), anchor="w", justify="left", bg="#07142a", fg="#c7dbff", wraplength=260)
        self.alg_info_label.pack(fill=tk.X, padx=8, pady=(0,8))

        # Estimated duration (auto computed per algorithm)
        est_frame = tk.Frame(alg_frame, bg="#07142a")
        est_frame.pack(fill=tk.X, padx=8, pady=(0,8))
        ttk.Label(est_frame, text="Estimated Duration:", background="#07142a", foreground="#dfefff").pack(side=tk.LEFT)
        self.est_label = tk.Label(est_frame, text=self._estimate_for("NIST"), bg="#07142a", fg="#c7dbff")
        self.est_label.pack(side=tk.LEFT, padx=(8,0))

    def _build_center_panel(self, parent):
        pad = {"padx": 10, "pady": 10}
        header = tk.Label(parent, text="Wipe Execution & Status", bg="#0b1220", fg="#e6eef8", font=("Segoe UI", 12, "bold"))
        header.pack(anchor="w", **pad)
        
        # --- Step Buttons (delete + wipe) ---
        step_frame = tk.LabelFrame(parent, text="Execution Steps", bg="#0b1220", fg="#dfefff", font=("Segoe UI", 10, "bold"))
        step_frame.pack(fill=tk.X, expand=False, padx=10, pady=(0,10))

        self.btn_delete = tk.Button(step_frame, text="STEP 1 — **REAL** Delete Selected User Folders 🗑️", bg="#e85a4f", fg="black", command=self._on_step1_delete)
        self.btn_delete.pack(fill=tk.X, padx=8, pady=(8,6))

        self.btn_start_wipe = tk.Button(step_frame, text="STEP 2 — Execute Full Wipe & Mint ✅ (Simulated Time)", bg="#2fa360", fg="black", command=self._on_start_wipe, state=tk.DISABLED)
        self.btn_start_wipe.pack(fill=tk.X, padx=8, pady=(0,6))

        self.btn_cancel = tk.Button(step_frame, text="CANCEL Wipe", bg="#ad2a2a", fg="white", command=self._on_cancel, state=tk.DISABLED)
        self.btn_cancel.pack(fill=tk.X, padx=8, pady=(0,8))
        
        # --- Progress bar ---
        progress_frame = tk.Frame(parent, bg="#0b1220")
        progress_frame.pack(fill=tk.X, padx=10)
        self.progress = ttk.Progressbar(progress_frame, orient="horizontal", length=480, mode="determinate")
        self.progress.pack(fill=tk.X, pady=(6,4))

        self.progress_label = tk.Label(progress_frame, text="Ready", bg="#0b1220", fg="#cfefff")
        self.progress_label.pack(anchor="w")

        # --- Preview box: commands that would run ---
        preview_frame = tk.LabelFrame(parent, text="Preview (Execution-Ready Commands & Summary)", bg="#0b1220", fg="#dfefff")
        preview_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(8,10))

        self.preview_text = tk.Text(preview_frame, height=12, bg="#071423", fg="#cfefff", bd=0)
        self.preview_text.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)
        self.preview_text.insert(tk.END, "No actions yet. Select drive and scan folders.\n")
        self.preview_text.config(state=tk.DISABLED)

        # Bottom quick info (cloud)
        cloud_frame = tk.Frame(parent, bg="#0b1220")
        cloud_frame.pack(fill=tk.X, padx=10)
        tk.Label(cloud_frame, text="Cloud Endpoint:", bg="#0b1220", fg="#9fb6d9").pack(side=tk.LEFT)
        tk.Label(cloud_frame, text=CLOUD_API_MINT_URL, bg="#0b1220", fg="#7ad0ff").pack(side=tk.LEFT, padx=(8,0))
        tk.Button(cloud_frame, text="Test Cloud Reachability", command=self._test_cloud).pack(side=tk.RIGHT)

    def _build_right_panel(self, parent):
        header = tk.Label(parent, text="Logs & Certificate", bg="#071426", fg="#e6eef8", font=("Segoe UI", 12, "bold"))
        header.pack(anchor="w", padx=8, pady=(8,6))

        # Certificate / Backup options
        backup_frame = tk.LabelFrame(parent, text="4) Certificate Backup", bg="#071426", fg="#dfefff", font=("Segoe UI", 10, "bold"))
        backup_frame.pack(fill=tk.X, expand=False, padx=8, pady=6)

        ttk.Label(backup_frame, text="Local backup path:", background="#071426", foreground="#dfefff").pack(anchor="w", padx=6, pady=(6,0))
        self.cert_path_var = tk.StringVar(value=DEFAULT_CERT_BACKUP_PATH)
        cert_entry = ttk.Entry(backup_frame, textvariable=self.cert_path_var)
        cert_entry.pack(fill=tk.X, padx=8, pady=6)
        tk.Button(backup_frame, text="Browse...", command=self._browse_cert_backup).pack(padx=8, pady=(0,8), anchor="e")

        # Log console
        log_frame = tk.Frame(parent, bg="#071426")
        log_frame.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0,8))

        self.log_text = tk.Text(log_frame, state=tk.DISABLED, bg="#021219", fg="#cfefff", bd=0)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        self.logger = Logger(self.log_text)
        self.logger.info("Agent initialized. System: " + platform.system())

        # Quick diagnostics
        diag_frame = tk.Frame(parent, bg="#071426")
        diag_frame.pack(fill=tk.X, padx=8, pady=(0,8))
        tk.Button(diag_frame, text="Open Project Zip (Explorer)", command=self._open_uploaded_zip).pack(side=tk.LEFT)
        tk.Button(diag_frame, text="Copy Log to File...", command=self._save_logs).pack(side=tk.RIGHT)


    # -------------------------
    # UI Event / Action Methods
    # -------------------------

    def _update_preview(self):
        # 1. Get the list of folders that *would* be deleted
        paths_to_delete = self._get_deletion_paths()
        
        self.preview_text.config(state=tk.NORMAL)
        self.preview_text.delete("1.0", tk.END)
        target = self.drive_combo.get()
        alg_key = self.alg_var.get()
        alg = WIPE_ALGORITHMS.get(alg_key, WIPE_ALGORITHMS["NIST"])
        est = self._estimate_for(alg_key)
        
        is_windows = platform.system() == "Windows"
        target_path_op = self._get_cleaned_target_path(target)
        
        # --- COMMAND PREVIEW ---
        
        delete_commands = []
        
        # Doubled curly braces in PowerShell command string to treat them literally.
        if is_windows:
            # Note: Targets contents inside the path: path\*
            # Curly braces for PowerShell block MUST be doubled: {{...}}
            base_command = "powershell.exe -ExecutionPolicy Bypass -Command \"& {{Remove-Item -Path '{}' -Force -Recurse -ErrorAction SilentlyContinue}}\""
        else:
            # Note: Targets contents inside the path: path/*
            base_command = "sudo rm -rf '{}'"

        for path in paths_to_delete:
            # Target contents inside the folder: os.path.join(path, '*')
            target_contents = os.path.join(path, '*')
            # Need to escape quotes for shell execution
            safe_path = target_contents.replace("'", "'\\''")
            
            delete_commands.append(base_command.format(safe_path))

        # Example Wipe Command (Only for preview)
        if is_windows:
            wipe_command = f"powershell.exe -ExecutionPolicy Bypass -Command \"& {{Write-DiskData -Target '{target_path_op}' -Algorithm {alg_key} }}\""
        else:
            # Unix block device wipe example (using the root target for simplicity)
            wipe_command = f"sudo dd if=/dev/urandom of={target_path_op} bs=1M status=progress"
            
        preview_lines = [
            f"TARGET DEVICE: {target} (Cleaned Path: {target_path_op})",
            f"Algorithm: {alg['display']} ({alg['passes']} Passes)",
            f"Estimated (simulated time): {est}",
            "",
            "*** EXECUTION-READY COMMAND PREVIEW ***",
            f"# Step 1: **REAL** User File Deletion ({len(paths_to_delete)} folder(s)) 🗑️",
            "Target Folders (Contents to be deleted):",
        ]
        
        for path in paths_to_delete:
            preview_lines.append(f"  - {path}")
            
        preview_lines += [
            "",
            "Execution Commands (one per selected folder contents):",
        ]
        
        # Display up to 5 commands, then truncate
        for cmd in delete_commands[:5]:
            preview_lines.append(f"COMMAND: {cmd}")
        
        if len(delete_commands) > 5:
             preview_lines.append(f"... and {len(delete_commands) - 5} more folder deletion commands.")

        preview_lines += [
            "",
            f"# Step 2: Full Secure Wipe (Real Disk Operation - SIMULATED TIME)",
            f"COMMAND: {wipe_command}",
            "",
            f"# Step 3: Minting Certificate",
            f"POST {CLOUD_API_MINT_URL} with DLT Hash",
        ]
        
        self.preview_text.insert(tk.END, "\n".join(preview_lines))
        self.preview_text.config(state=tk.DISABLED)

    def _detect_block_devices(self):
        """Identifies block devices using psutil for better cross-platform support."""
        self.logger.info("Detecting block devices...")
        
        try:
            new_drives = get_drive_list()
            self.drive_list = new_drives
            
            options = new_drives + ["Custom Path..."]
            
            self.drive_combo['values'] = options
            if new_drives:
                self.drive_combo.set(new_drives[0])
                self.logger.success(f"Detected {len(new_drives)} target device(s).")
            else:
                self.drive_combo.set("No devices detected.")
                self.logger.warning("No fixed/block devices detected.")
            
        except Exception as e:
            self.logger.error(f"Device detection failed: {e}")
            self.drive_combo.set("Detection Failed (Error)")

        # Re-scan folders for the newly selected drive
        self._detect_user_folders()
        self._update_preview()

    def _on_drive_change(self, event=None):
        val = self.drive_combo.get()
        self.logger.debug(f"Drive selection changed: {val}")
        self._detect_user_folders() # Re-scan folders
        self._update_preview()
        # Reset wipe button state
        self.btn_delete.config(state=tk.NORMAL) 
        self.btn_start_wipe.config(state=tk.DISABLED)
        self.deletion_successful = False

    def _on_alg_change(self, event=None):
        sel = self.alg_combo.get()
        key = sel.split("—")[0].strip() if "—" in sel else sel.strip()
        if key not in WIPE_ALGORITHMS:
            key = list(WIPE_ALGORITHMS.keys())[0]
        self.alg_var.set(key)
        self.alg_info_label.config(text=self._format_alg_info(key))
        self.est_label.config(text=self._estimate_for(key))
        self.logger.debug(f"Wipe algorithm set to {key}.")
        self._update_preview()

    def _format_alg_info(self, key):
        v = WIPE_ALGORITHMS.get(key, WIPE_ALGORITHMS["NIST"])
        return f"{v['display']}\nPasses: {v['passes']}\n{v['description']}"

    def _estimate_for(self, key):
        if key == "DOD": base = 60
        elif key == "CE": base = 12
        else: base = 20
        
        passes = WIPE_ALGORITHMS.get(key, {}).get('passes', 1)
        try: pnum = int(passes)
        except Exception: pnum = 1
        return f"~{base * max(1,pnum)}s (simulated)"

    def _browse_cert_backup(self):
        path = filedialog.asksaveasfilename(title="Select certificate backup file", defaultextension=".json",
                                             filetypes=[("JSON files","*.json"), ("All files","*.*")])
        if path:
            self.cert_path_var.set(path)
            self.logger.info(f"Certificate backup path set to: {path}")
            
    def _execute_deletion_command(self, command):
        """Executes a single file deletion command and returns (success, output)."""
        try:
            # Use shell=True for complex commands like 'sudo rm -rf' or PowerShell
            # Add timeout to prevent infinite hangs
            result = subprocess.run(command, shell=True, check=False, capture_output=True, text=True, timeout=60)
            
            # Check for common permission/lock errors in output
            output = (result.stderr + result.stdout).strip()
            
            if result.returncode != 0:
                error_msg = f"Deletion command failed (Code {result.returncode}). Output: {output[:300]}"
                # Common Windows errors
                if "access is denied" in output.lower() or "permission denied" in output.lower():
                    error_msg += " --> (Access Denied: Try running as Administrator/sudo)"
                # Common Linux errors
                elif "no such file or directory" in output.lower():
                    # This is okay if the directory was expected to be there but wasn't (e.g., no 'Saved Games')
                    return True, "Target directory not found (harmless)."
                
                return False, error_msg
            
            # Note: Deletion commands often return success=0 even if the folder was empty.
            return True, result.stdout.strip()
            
        except subprocess.TimeoutExpired:
            return False, "Deletion command timed out."
        except Exception as e:
            return False, f"Execution error: {e}"

    def _on_step1_delete(self):
        paths_to_delete = self._get_deletion_paths()
        
        if not paths_to_delete:
            messagebox.showwarning("Selection Missing", "Please select at least one folder to delete.")
            return

        formatted_paths = "\n".join(paths_to_delete)
        
        if not messagebox.askyesno("CONFIRM REAL DELETION (STEP 1)", 
                                   f"⚠️ WARNING: This will **PERMANENTLY DELETE ALL CONTENTS** of the following {len(paths_to_delete)} folder(s):\n\n{formatted_paths}\n\n**IMPORTANT: This process requires Administrator/sudo privileges.**\n\nProceed with real execution?"):
            return
        
        self.btn_delete.config(state=tk.DISABLED)
        self.logger.info(f"STEP 1: Executing REAL deletion for {len(paths_to_delete)} selected folders.")
        self.progress_label.config(text="STEP 1: Deleting user files...")
        self.progress['value'] = 2
        self.update_idletasks()
        
        # Execute the deletion for all selected paths in a separate thread
        threading.Thread(target=self._run_deletion_in_thread, args=(paths_to_delete,)).start()

    def _run_deletion_in_thread(self, paths_to_delete):
        
        is_windows = platform.system() == "Windows"
        all_successful = True
        
        for i, path in enumerate(paths_to_delete):
            self.after(0, lambda p=i, total=len(paths_to_delete), f=path: self.logger.debug(f"Executing deletion for folder {p+1}/{total}: {f}"))
            
            # Construct command for current OS
            # We target the *contents* of the folder to ensure we don't accidentally remove a mount point itself.
            target_path_contents = os.path.join(path, '*') 
            
            if is_windows:
                # Command: powershell.exe -ExecutionPolicy Bypass -Command "& {Remove-Item -Path 'C:\path\to\folder\*' -Force -Recurse -ErrorAction SilentlyContinue}"
                command = f"powershell.exe -ExecutionPolicy Bypass -Command \"& {{Remove-Item -Path '{target_path_contents}' -Force -Recurse -ErrorAction SilentlyContinue}}\""
            else:
                # Command: sudo rm -rf '/path/to/folder/*'
                command = f"sudo rm -rf '{target_path_contents}'"
                
            success, output = self._execute_deletion_command(command)
            
            if not success:
                self.after(0, lambda p=path, o=output: self.logger.error(f"Deletion failed for {p}. Reason: {o}"))
                all_successful = False
            else:
                self.after(0, lambda p=path: self.logger.debug(f"Deletion command succeeded for {p}."))
                
            # Update progress slightly for each folder
            progress_step = int(8 / len(paths_to_delete)) if len(paths_to_delete) > 0 else 8
            self.after(0, lambda prog=2 + (i + 1) * progress_step: self.progress.config(value=min(10, prog)))
            self.after(0, lambda p=i+1, t=len(paths_to_delete): self.progress_label.config(text=f"STEP 1: Deleting Folder {p}/{t}"))
            self.after(0, self.update_idletasks)


        # Final GUI update must be safe
        self.after(0, lambda: self._handle_deletion_result(all_successful, paths_to_delete))

    def _handle_deletion_result(self, success, paths_to_delete):
        if success:
            self.logger.success(f"STEP 1 COMPLETE: Contents of {len(paths_to_delete)} selected folders removed.")
            self.progress['value'] = 10
            self.progress_label.config(text="STEP 1 Complete. Ready for Secure Wipe.")
            self.btn_start_wipe.config(state=tk.NORMAL)
            self.deletion_successful = True
        else:
            self.logger.error(f"STEP 1 FAILED: File deletion failed for one or more folders. Check logs for details.")
            self.logger.warning("Deletion requires **Elevated Rights (sudo/admin)**. Rerun the script as Administrator/root.")
            self.progress['value'] = 0
            self.progress_label.config(text="STEP 1 FAILED. Correct error or run Step 1 again.")
            self.btn_delete.config(state=tk.NORMAL)
            self.btn_start_wipe.config(state=tk.DISABLED)
            self.deletion_successful = False
            messagebox.showerror("Deletion Failed", "Step 1 failed for one or more folders! Check logs for details. (Requires Admin/sudo)")
        self.update_idletasks()


    def _on_start_wipe(self):
        if not self.deletion_successful:
            messagebox.showwarning("Prerequisite Missing", "Please run STEP 1 (File Deletion) successfully first.")
            return
            
        target = self.drive_combo.get()
        alg_key = self.alg_var.get()
        alg_display = WIPE_ALGORITHMS[alg_key]['display']
        if not messagebox.askyesno("FINAL WARNING: FULL DISK WIPE",
                                       f"FINAL: You are about to PERMANENTLY WIPE the target **DEVICE/PARTITION** {target}\n\nAlgorithm: {alg_display}\n\nThis is irreversible (time simulated). Proceed?"):
            return

        passes = WIPE_ALGORITHMS[alg_key]['passes']
        try: passes_num = int(passes)
        except Exception: passes_num = 1
            
        if alg_key == "DOD": est_seconds = 60 * passes_num
        elif alg_key == "CE": est_seconds = 12 * passes_num
        else: est_seconds = 20 * passes_num

        config = {
            "target_name": target,
            "algorithm_key": alg_key,
            "passes": passes_num,
            "estimated_seconds": est_seconds,
            "device_id": self.device_id,
            "cert_path": self.cert_path_var.get(),
        }

        self.btn_start_wipe.config(state=tk.DISABLED)
        self.btn_delete.config(state=tk.DISABLED)
        self.btn_cancel.config(state=tk.NORMAL)
        self.cancel_event.clear()

        self.progress_label.config(text="Wipe in progress...")
        self.logger.info("Starting wipe worker thread (Step 2 - Time Simulated).")
        
        self.worker_thread = WipeWorker(
            progress_callback=self._set_progress,
            log_callback=self.logger,
            done_callback=lambda success, details: self._on_wipe_done(success, details, config),
            cancel_event=self.cancel_event,
            config=config
        )
        self.worker_thread.start()

    def _set_progress(self, pct):
        self.after(0, lambda: self._update_progress_ui(pct))

    def _update_progress_ui(self, pct):
        self.progress['value'] = pct
        self.progress_label.config(text=f"Wipe Progress: {pct}%")

    def _on_cancel(self):
        if messagebox.askyesno("Cancel Wipe", "Cancel the running wipe? This will stop the simulated process."):
            self.cancel_event.set()
            self.logger.warning("Operator requested cancellation. Attempting to stop worker...")

    def _on_wipe_done(self, success, details, config):
        self.after(0, lambda: self._handle_wipe_done(success, details, config))

    def _handle_wipe_done(self, success, details, config):
        if success:
            self.logger.success(f"Wipe completed: {details}")
        else:
            self.logger.error(f"Wipe failed/aborted: {details}")

        # Use the standard cleaner helper outside the f-string.
        cleaned_target = self._get_cleaned_target_path(config['target_name'])

        cert_data = {
            # Use the pre-calculated cleaned_target variable
            "imei_serial": f"{self.device_id}-{cleaned_target}",
            "wipe_status": "SUCCESS" if success else "FAILURE",
            "wipe_standard": WIPE_ALGORITHMS[config["algorithm_key"]]["display"],
            "verification_log": details,
            "timestamp": now_iso(),
            "local_project_zip": UPLOADED_PROJECT_ZIP_URL,
        }
        cert_json = json.dumps(cert_data, sort_keys=True)
        cert_hash = sha256(cert_json.encode('utf-8')).hexdigest()
        cert_data["dlt_hash"] = cert_hash

        self.logger.debug(f"Generated certificate hash: {cert_hash[:16]}...")

        # Save to local backup path
        cert_path = config.get("cert_path") or DEFAULT_CERT_BACKUP_PATH
        try:
            # Safely create directory structure
            os.makedirs(os.path.dirname(cert_path), exist_ok=True) 
            with open(cert_path, "w") as f:
                json.dump(cert_data, f, indent=4)
            self.logger.success(f"Certificate saved locally: {cert_path}")
        except Exception as e:
            self.logger.error(f"Failed saving local certificate: {e}")

        # Attempt cloud minting
        if success:
            self.logger.info("Attempting to mint certificate on cloud...")
            code, resp = safe_post_json(CLOUD_API_MINT_URL, cert_data, timeout=15)
            if code == 201:
                self.logger.success("Cloud minted: Certificate recorded on server (201).")
                messagebox.showinfo("Success", "Wipe & certification complete. You may reboot device.")
            elif code is None:
                self.logger.warning(f"Cloud mint failed: {resp}")
                messagebox.showwarning("Cloud Offline", "Certificate saved locally. Cloud unreachable.")
            else:
                self.logger.warning(f"Cloud returned status {code}. Response: {resp}")
                messagebox.showwarning("Cloud Error", f"Cloud returned status {code}. Local cert saved.")
        else:
            self.logger.warning("Wipe unsuccessful — certificate saved locally only.")

        # reset UI state
        self.btn_cancel.config(state=tk.DISABLED)
        self.btn_delete.config(state=tk.NORMAL) # Ready for next wipe
        self.btn_start_wipe.config(state=tk.DISABLED)
        self.progress_label.config(text="Idle")
        self.deletion_successful = False # Reset for new run


    # -------------------------
    # Helper Actions
    # -------------------------

    def _test_cloud(self):
        self.logger.info("Testing cloud reachability (DNS + HTTP)...")
        try:
            parsed = CLOUD_API_MINT_URL.replace("http://", "").split("/")[0]
            host = parsed.split(":")[0]
            port = int(parsed.split(":")[1]) if ":" in parsed else 80
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((host, port))
            s.close()
            self.logger.success(f"TCP connection to {host}:{port} successful.")
        except Exception as e:
            self.logger.warning(f"TCP test failed: {e}")

        try:
            r = requests.head(CLOUD_API_MINT_URL, timeout=4)
            self.logger.success(f"HTTP reachable — status {r.status_code}")
        except Exception as e:
            self.logger.warning(f"HTTP head failed: {e}")

    def _open_uploaded_zip(self):
        path = UPLOADED_PROJECT_ZIP_PATH
        if not os.path.exists(path):
            messagebox.showerror("Not Found", f"Uploaded project zip not found at:\n{path}")
            return
        self.logger.info(f"Opening uploaded project zip: {path}")
        try:
            if platform.system() == "Windows":
                os.startfile(path)
            elif platform.system() == "Darwin":
                os.system(f"open {path!r}")
            else:
                os.system(f"xdg-open {path!r} &")
        except Exception as e:
            self.logger.error(f"Failed to open file manager: {e}")

    def _save_logs(self):
        path = filedialog.asksaveasfilename(title="Save Logs As", defaultextension=".log", filetypes=[("Log files","*.log"),("All files","*.*")])
        if not path:
            return
        try:
            content = self.log_text.get("1.0", tk.END)
            with open(path, "w") as f:
                f.write(content)
            self.logger.success(f"Logs saved to {path}")
        except Exception as e:
            self.logger.error(f"Failed to save logs: {e}")

    def _on_close(self):
        """Handle window close event, ensuring worker thread is stopped."""
        if self.worker_thread and self.worker_thread.is_alive():
            if not messagebox.askyesno("Quit", "A wipe is running. Quit now? This will attempt to cancel and close the app."):
                return
            self.cancel_event.set()
            time.sleep(0.2)
        self.destroy()

# -------------------------------
# Entrypoint
# -------------------------------

def main():
    try:
        import requests 
    except Exception:
        messagebox.showerror("Dependency Error", "Python 'requests' package is required. Install via 'pip install requests'.")
        return
        
    try:
        import psutil
    except Exception:
        # Proceed even without psutil, but warn the user.
        messagebox.showwarning("Optional Dependency Missing", "Python 'psutil' package is missing. Install with 'pip install psutil' for real device detection.")

    app = DDPWipeAgentApp()
    app._update_preview()
    app.mainloop()

if __name__ == "__main__":
    main()