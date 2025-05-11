# 0xCipherLink by 0x4m4
# Secure File Transfer Tool
# www.0x4m4.com

import tkinter as tk
from tkinter import filedialog, ttk, messagebox
import socket
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import os
import struct
import threading
import json
import datetime
import re
import time
import zlib
import hashlib
from tkinter import scrolledtext
from PIL import Image, ImageTk
import io
import math

# Constants
BUFFER_SIZE = 8192
HISTORY_FILE = "transfer_history.json"
CONNECTION_TIMEOUT = 30
SETTINGS_FILE = "settings.json"
DEFAULT_SETTINGS = {
    "theme": "dark",
    "compression_level": 6,
    "verify_transfers": True,
    "auto_clear_history": False,
    "max_history_entries": 100,
    "default_port": 9999,
    "default_host": "127.0.0.1"
}

# Theme colors
THEMES = {
    "dark": {
        "bg": "#121212",
        "fg": "#00FF41",
        "secondary": "#008F11",
        "error": "#FF3333",
        "input_bg": "#1E1E1E",
        "button_bg": "#008F11",
        "button_fg": "#121212",
        "button_active": "#00FF41",
        "progress_bg": "#1E1E1E",
        "progress_fg": "#00FF41"
    },
    "light": {
        "bg": "#FFFFFF",
        "fg": "#000000",
        "secondary": "#0066CC",
        "error": "#FF0000",
        "input_bg": "#F0F0F0",
        "button_bg": "#0066CC",
        "button_fg": "#FFFFFF",
        "button_active": "#004C99",
        "progress_bg": "#F0F0F0",
        "progress_fg": "#0066CC"
    }
}

def derive_key(password):
    salt = b'salt_'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # Key length for AES-256
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def pad_data(data):
    """Pad data with a fixed block of padding"""
    # Always add a full block of padding (16 bytes)
    padding = bytes([0] * 16)  # Use zeros for padding
    return data + padding

def unpad_data(data):
    """Remove the fixed block of padding"""
    if len(data) < 16:
        raise ValueError("Data too short to contain padding")
    # Remove the last 16 bytes (the padding block)
    return data[:-16]

def compress_data(data):
    """Compress data with zlib and add header"""
    # Compress with zlib
    compressed = zlib.compress(data, level=6)
    # Add header to indicate compression
    return b'CMP' + compressed

def decompress_data(data):
    """Decompress data with header check"""
    # Check for compression header
    if data.startswith(b'CMP'):
        # Remove header and decompress
        return zlib.decompress(data[3:])
    else:
        # If no header, assume data is not compressed
        return data

def send_file(sock, files, password, update_progress):
    """Send multiple files with progress updates"""
    print("DEBUG: Starting send_file function")
    key = derive_key(password)
    
    # Calculate total size first
    total_bytes = sum(os.path.getsize(f) for f in files)
    bytes_sent = 0
    print(f"DEBUG: Total bytes to send: {total_bytes}")
    
    try:
        # Send number of files first
        print(f"DEBUG: Sending number of files: {len(files)}")
        sock.sendall(struct.pack('I', len(files)))
        
        # Send file metadata first
        for file_path in files:
            filename = os.path.basename(file_path)
            file_size = os.path.getsize(file_path)
            file_hash = calculate_file_hash(file_path)
            print(f"DEBUG: Sending metadata for file: {filename}")
            
            # Send filename length and filename
            filename_bytes = filename.encode('utf-8')
            print(f"DEBUG: Sending filename length: {len(filename_bytes)}")
            sock.sendall(struct.pack('I', len(filename_bytes)))
            sock.sendall(filename_bytes)
            
            # Send file size
            print(f"DEBUG: Sending file size: {file_size}")
            sock.sendall(struct.pack('Q', file_size))
            
            # Send file hash
            hash_bytes = file_hash.encode('utf-8')
            print(f"DEBUG: Sending hash length: {len(hash_bytes)}")
            sock.sendall(struct.pack('I', len(hash_bytes)))
            sock.sendall(hash_bytes)
            
            # Send IV placeholder
            print("DEBUG: Sending IV placeholder")
            sock.sendall(b'\x00' * 16)
        
        # Now send the actual files
        for file_path in files:
            print(f"DEBUG: Starting to send file: {os.path.basename(file_path)}")
            update_progress(0, f"Preparing {os.path.basename(file_path)}")
            
            with open(file_path, 'rb') as file:
                file_data = file.read()
                original_size = len(file_data)
                print(f"DEBUG: Original file size: {original_size}")
                
                # Calculate file hash for verification
                file_hash = calculate_file_hash(file_path)
                print(f"DEBUG: Original file hash: {file_hash}")
                
                # Pad the data
                print("DEBUG: Padding data")
                update_progress(10, "Encrypting...")
                padded_data = pad_data(file_data)
                print(f"DEBUG: Padded size: {len(padded_data)}")
                
                # Generate IV and encrypt
                iv = os.urandom(16)
                cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
                encryptor = cipher.encryptor()
                encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
                print(f"DEBUG: Encrypted size: {len(encrypted_data)}")
                
                # Send IV and encrypted data in one go
                print("DEBUG: Sending IV and encrypted data")
                sock.sendall(iv + encrypted_data)
                
                bytes_sent += len(encrypted_data) + 16
                progress = int(15 + (bytes_sent / total_bytes * 85))
                update_progress(progress, f"Sending {os.path.basename(file_path)}: {format_size(bytes_sent)}/{format_size(total_bytes)}")
                
                print(f"DEBUG: Successfully sent file: {os.path.basename(file_path)}")
                save_transfer_history('sent', os.path.basename(file_path), original_size)
                update_progress(100, f"Sent {os.path.basename(file_path)} successfully!")
        
        # Wait for acknowledgment from receiver
        print("DEBUG: Waiting for acknowledgment")
        try:
            ack = sock.recv(1)
            if not ack:
                print("DEBUG: No acknowledgment received")
                raise Exception("No acknowledgment from receiver")
            print("DEBUG: Received acknowledgment")
        except socket.timeout:
            print("DEBUG: Timeout waiting for acknowledgment")
            raise Exception("Timeout waiting for acknowledgment")
    
    except socket.timeout:
        print("DEBUG: Socket timeout in send_file")
        raise Exception("Connection timeout")
    except Exception as e:
        print(f"DEBUG: Error in send_file: {str(e)}")
        raise Exception(f"Error during file transfer: {str(e)}")
    finally:
        try:
            print("DEBUG: Closing sender socket")
            sock.close()
        except:
            print("DEBUG: Error closing sender socket")
            pass

def decrypt_data(key, data):
    """Decrypt data"""
    try:
        # Split IV and encrypted data
        iv = data[:16]
        encrypted_data = data[16:]
        print(f"DEBUG: Decrypting data - IV size: {len(iv)}, Encrypted size: {len(encrypted_data)}")
        
        # Decrypt
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
        print(f"DEBUG: Decrypted size: {len(decrypted_data)}")
        
        # Unpad
        try:
            unpadded_data = unpad_data(decrypted_data)
            print(f"DEBUG: Unpadded size: {len(unpadded_data)}")
            return unpadded_data
        except ValueError as e:
            print(f"DEBUG: Padding error: {str(e)}")
            print(f"DEBUG: Last few bytes: {decrypted_data[-16:]}")
            raise Exception(f"Invalid padding in decrypted data: {str(e)}")
    except Exception as e:
        print(f"DEBUG: Error in decrypt_data: {str(e)}")
        raise Exception(f"Error decrypting data: {str(e)}")

def receive_file(key, port, update_progress, settings):
    """Receive files from sender"""
    print("DEBUG: Starting receive_file function")
    host = '0.0.0.0'
    sock = None
    conn = None
    
    try:
        # Create socket
        print("DEBUG: Creating socket")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        sock.listen(1)
        
        update_progress(0, "Waiting for connection...")
        print("DEBUG: Waiting for connection on port", port)
        
        # Accept connection with timeout
        sock.settimeout(30)  # 30 second timeout
        conn, addr = sock.accept()
        conn.settimeout(30)  # Set timeout for the connection
        print(f"DEBUG: Accepted connection from {addr[0]}")
        update_progress(10, f"Connected to {addr[0]}")
        
        # Receive number of files
        print("DEBUG: Receiving number of files")
        num_files_data = conn.recv(4)
        if not num_files_data:
            print("DEBUG: No data received for number of files")
            raise Exception("Connection closed")
        num_files = struct.unpack('I', num_files_data)[0]
        print(f"DEBUG: Number of files to receive: {num_files}")
        
        total_bytes = 0
        bytes_received = 0
        
        # First pass: receive all metadata and calculate total size
        file_metadata = []
        for i in range(num_files):
            print(f"DEBUG: Receiving metadata for file {i+1}")
            # Receive filename length
            filename_len_data = conn.recv(4)
            if not filename_len_data:
                print("DEBUG: No data received for filename length")
                raise Exception("Connection closed")
            filename_len = struct.unpack('I', filename_len_data)[0]
            print(f"DEBUG: Filename length: {filename_len}")
            
            # Receive filename
            filename = conn.recv(filename_len).decode('utf-8', errors='replace')
            print(f"DEBUG: Filename: {filename}")
            
            # Receive file size
            file_size_data = conn.recv(8)
            if not file_size_data:
                print("DEBUG: No data received for file size")
                raise Exception("Connection closed")
            file_size = struct.unpack('Q', file_size_data)[0]
            print(f"DEBUG: File size: {file_size}")
            total_bytes += file_size
            
            # Receive file hash
            hash_len_data = conn.recv(4)
            if not hash_len_data:
                print("DEBUG: No data received for hash length")
                raise Exception("Connection closed")
            hash_len = struct.unpack('I', hash_len_data)[0]
            print(f"DEBUG: Hash length: {hash_len}")
            expected_hash = conn.recv(hash_len).decode('utf-8', errors='replace')
            print(f"DEBUG: Expected hash: {expected_hash}")
            
            # Receive IV
            iv = conn.recv(16)
            if not iv:
                print("DEBUG: No data received for IV")
                raise Exception("Connection closed")
            print("DEBUG: Received IV")
            
            file_metadata.append({
                'filename': filename,
                'size': file_size,
                'hash': expected_hash,
                'iv': iv
            })
        
        print(f"DEBUG: Total bytes to receive: {total_bytes}")
        
        # Second pass: receive file data
        for i, metadata in enumerate(file_metadata):
            print(f"DEBUG: Starting to receive file {i+1}: {metadata['filename']}")
            update_progress(20, f"Receiving {metadata['filename']}...")
            
            # Calculate expected encrypted size (original size + padding)
            block_size = 16
            padded_size = metadata['size'] + block_size  # Always add one block of padding
            print(f"DEBUG: Expected encrypted size: {padded_size}")
            
            # Receive encrypted data in chunks
            encrypted_data = bytearray(metadata['iv'])  # Start with IV
            remaining_bytes = padded_size
            chunk_size = 65536  # 64KB chunks
            
            try:
                while remaining_bytes > 0:
                    # Calculate chunk size for this iteration
                    current_chunk_size = min(chunk_size, remaining_bytes)
                    
                    # Receive chunk
                    chunk = conn.recv(current_chunk_size)
                    if not chunk:
                        print("DEBUG: No data received for chunk")
                        raise Exception("Connection closed")
                    
                    # Add chunk to encrypted data
                    encrypted_data.extend(chunk)
                    remaining_bytes -= len(chunk)
                    bytes_received += len(chunk)
                    
                    # Update progress
                    progress = int(20 + (bytes_received / total_bytes * 80))
                    update_progress(progress, f"Receiving {metadata['filename']}: {format_size(bytes_received)}/{format_size(total_bytes)}")
                
                print(f"DEBUG: Received encrypted data of size: {len(encrypted_data)}")
                
                # Decrypt data
                print("DEBUG: Decrypting data")
                update_progress(80, f"Decrypting {metadata['filename']}...")
                decrypted_data = decrypt_data(key, bytes(encrypted_data))
                
                # Save file
                print(f"DEBUG: Saving file: {metadata['filename']}")
                with open(metadata['filename'], 'wb') as f:
                    f.write(decrypted_data)
                
                # Verify file hash if enabled
                if settings["verify_transfers"]:
                    print("DEBUG: Verifying file hash")
                    actual_hash = calculate_file_hash(metadata['filename'])
                    print(f"DEBUG: Actual hash: {actual_hash}")
                    if actual_hash != metadata['hash']:
                        print(f"DEBUG: Hash verification failed. Expected: {metadata['hash']}, Got: {actual_hash}")
                        raise Exception(f"File verification failed for {metadata['filename']}")
                
                update_progress(100, f"Received {metadata['filename']}")
                print(f"DEBUG: Successfully received file: {metadata['filename']}")
            except socket.timeout:
                print("DEBUG: Socket timeout while receiving encrypted data")
                raise Exception("Connection timeout while receiving file data")
        
        update_progress(100, "Transfer completed successfully")
        print("DEBUG: Transfer completed successfully")
        
        # Send acknowledgment to sender
        print("DEBUG: Sending acknowledgment")
        conn.sendall(b'\x01')
        
    except socket.timeout:
        print("DEBUG: Socket timeout in receive_file")
        update_progress(-1, "Connection timeout")
    except Exception as e:
        print(f"DEBUG: Error in receive_file: {str(e)}")
        update_progress(-1, f"Error: {str(e)}")
    finally:
        # Clean up connections
        if conn:
            try:
                print("DEBUG: Closing connection socket")
                conn.close()
            except:
                print("DEBUG: Error closing connection socket")
                pass
        if sock:
            try:
                print("DEBUG: Closing listening socket")
                sock.close()
            except:
                print("DEBUG: Error closing listening socket")
                pass

def save_transfer_history(action, filename, size):
    """Save transfer details to history file"""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    try:
        if os.path.exists(HISTORY_FILE):
            with open(HISTORY_FILE, 'r') as f:
                history = json.load(f)
        else:
            history = []
            
        history.append({
            "action": action,
            "filename": filename,
            "size": size,
            "timestamp": timestamp
        })
        
        # Keep only last 100 entries
        if len(history) > 100:
            history = history[-100:]
            
        with open(HISTORY_FILE, 'w') as f:
            json.dump(history, f, indent=2)
    except Exception as e:
        print(f"Error saving history: {e}")

def load_transfer_history():
    """Load transfer history from file"""
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, 'r') as f:
                return json.load(f)
        except:
            return []
    return []

def get_password_strength(password):
    """Calculate password strength score (0-100)"""
    score = 0
    
    if len(password) >= 8:
        score += 20
    if len(password) >= 12:
        score += 10
    if re.search(r'[A-Z]', password):
        score += 20
    if re.search(r'[a-z]', password):
        score += 10
    if re.search(r'[0-9]', password):
        score += 20
    if re.search(r'[^A-Za-z0-9]', password):
        score += 20
        
    return min(score, 100)

def format_size(size):
    """Format byte size to human readable format"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024:
            return f"{size:.2f} {unit}"
        size /= 1024
    return f"{size:.2f} TB"

def load_settings():
    """Load settings from file or return defaults"""
    if os.path.exists(SETTINGS_FILE):
        try:
            with open(SETTINGS_FILE, 'r') as f:
                settings = json.load(f)
                # Merge with defaults to ensure all settings exist
                return {**DEFAULT_SETTINGS, **settings}
        except:
            return DEFAULT_SETTINGS
    return DEFAULT_SETTINGS

def save_settings(settings):
    """Save settings to file"""
    with open(SETTINGS_FILE, 'w') as f:
        json.dump(settings, f, indent=2)

def calculate_file_hash(file_path):
    """Calculate SHA-256 hash of a file"""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def format_speed(bytes_per_second):
    """Format transfer speed to human readable format"""
    if bytes_per_second < 1024:
        return f"{bytes_per_second:.2f} B/s"
    elif bytes_per_second < 1024 * 1024:
        return f"{bytes_per_second/1024:.2f} KB/s"
    elif bytes_per_second < 1024 * 1024 * 1024:
        return f"{bytes_per_second/(1024*1024):.2f} MB/s"
    else:
        return f"{bytes_per_second/(1024*1024*1024):.2f} GB/s"

def calculate_eta(bytes_remaining, speed):
    """Calculate estimated time remaining"""
    if speed <= 0:
        return "Calculating..."
    seconds = bytes_remaining / speed
    if seconds < 60:
        return f"{seconds:.0f} seconds"
    elif seconds < 3600:
        return f"{seconds/60:.0f} minutes"
    else:
        return f"{seconds/3600:.1f} hours"

class CipherLinkApp:
    def __init__(self, root):
        """Initialize the application"""
        self.root = root
        self.root.title("CipherShare")
        self.root.geometry("600x700")
        
        # Load settings
        self.settings = load_settings()
        self.theme = THEMES[self.settings["theme"]]
        
        # Initialize variables
        self.selected_files = []
        self.transfer_speed = 0
        self.start_time = None
        self.last_update_time = None
        self.bytes_transferred = 0
        self.settings_window = None
        
        # Create main container
        self.main_container = tk.Frame(self.root, bg=self.theme["bg"])
        self.main_container.pack(fill=tk.BOTH, expand=True)
        
        # Create widgets
        self.create_widgets()
        self.style_progress_bars()
        
        # Initial UI update
        self.update_mode()

    def setup_file_selection(self):
        """Setup file selection area"""
        # Create a frame for file selection
        selection_frame = tk.Frame(self.file_frame, bg=self.theme["bg"])
        selection_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Create drop target frame
        self.drop_target = tk.Frame(selection_frame, 
                                   bg=self.theme["input_bg"],
                                   highlightbackground=self.theme["secondary"],
                                   highlightthickness=2,
                                   height=100)  # Set explicit height
        self.drop_target.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        # Add drop target label
        self.drop_label = tk.Label(self.drop_target, 
                             text="Click here to select files",
                             bg=self.theme["input_bg"],
                             fg=self.theme["fg"],
                             font=('Courier', 12, 'bold'))
        self.drop_label.pack(expand=True)
        
        # Bind click event
        self.drop_target.bind('<Button-1>', self.add_files)
        self.drop_target.bind('<Enter>', self.on_hover_enter)
        self.drop_target.bind('<Leave>', self.on_hover_leave)
        
        # Make sure the file selection area is visible
        self.file_frame.lift()
    
    def on_hover_enter(self, event):
        """Handle hover enter event"""
        self.drop_target.configure(highlightbackground=self.theme["fg"])
        self.drop_label.configure(fg=self.theme["fg"])
    
    def on_hover_leave(self, event):
        """Handle hover leave event"""
        self.drop_target.configure(highlightbackground=self.theme["secondary"])
        self.drop_label.configure(fg=self.theme["fg"])
    
    def add_files(self, event=None):
        """Open file dialog to select files"""
        files = filedialog.askopenfilenames(
            title="Select files to transfer",
            filetypes=[("All files", "*.*")]
        )
        
        if files:
            for file_path in files:
                if file_path not in self.selected_files:
                    self.selected_files.append(file_path)
                    filename = os.path.basename(file_path)
                    size = os.path.getsize(file_path)
                    self.file_listbox.insert(tk.END, f"{filename} ({format_size(size)})")
            
            # Update action button text based on mode
            mode = self.mode_var.get().lower()
            self.action_btn.config(text=f"{mode.capitalize()} Files")
    
    def create_widgets(self):
        """Create and setup all widgets"""
        # Create title frame
        title_frame = tk.Frame(self.main_container, bg=self.theme["bg"])
        title_frame.pack(fill=tk.X, padx=10, pady=(10, 5))
        
        # App title and author
        title_label = tk.Label(title_frame, text="CipherShare", 
                              font=('Courier', 24, 'bold'),
                              bg=self.theme["bg"], fg=self.theme["fg"])
        title_label.pack(side=tk.LEFT)
        
        author_label = tk.Label(title_frame, text="Secure File Transfer Tool", 
                               font=('Courier', 12),
                               bg=self.theme["bg"], fg=self.theme["secondary"])
        author_label.pack(side=tk.LEFT, padx=(10, 0), pady=(10, 0))
        
        # Theme toggle and settings buttons
        buttons_frame = tk.Frame(title_frame, bg=self.theme["bg"])
        buttons_frame.pack(side=tk.RIGHT, pady=(5, 0))
        
        theme_btn = tk.Button(buttons_frame, text="🌓", 
                             command=self.toggle_theme,
                             bg=self.theme["button_bg"],
                             fg=self.theme["button_fg"],
                             relief=tk.FLAT)
        theme_btn.pack(side=tk.RIGHT, padx=5)
        
        settings_btn = tk.Button(buttons_frame, text="⚙️", 
                                command=self.show_settings,
                                bg=self.theme["button_bg"],
                                fg=self.theme["button_fg"],
                                relief=tk.FLAT)
        settings_btn.pack(side=tk.RIGHT, padx=5)
        
        # Mode selection frame
        mode_frame = tk.Frame(self.main_container, bg=self.theme["bg"])
        mode_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.mode_var = tk.StringVar(value="SEND")
        send_radio = tk.Radiobutton(mode_frame, text="SEND", 
                                   variable=self.mode_var,
                                   value="SEND",
                                   command=self.update_mode,
                                   bg=self.theme["bg"],
                                   fg=self.theme["fg"],
                                   selectcolor=self.theme["bg"])
        send_radio.pack(side=tk.LEFT, padx=(0, 20))
        
        receive_radio = tk.Radiobutton(mode_frame, text="RECEIVE",
                                      variable=self.mode_var,
                                      value="RECEIVE",
                                      command=self.update_mode,
                                      bg=self.theme["bg"],
                                      fg=self.theme["fg"],
                                      selectcolor=self.theme["bg"])
        receive_radio.pack(side=tk.LEFT)
        
        # Connection settings frame
        conn_frame = tk.Frame(self.main_container, bg=self.theme["bg"])
        conn_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Host entry
        host_label = tk.Label(conn_frame, text="Host:", 
                             bg=self.theme["bg"],
                             fg=self.theme["fg"])
        host_label.pack(side=tk.LEFT)
        
        self.host_var = tk.StringVar(value=self.settings["default_host"])
        self.host_entry = tk.Entry(conn_frame,
                                  textvariable=self.host_var,
                                  bg=self.theme["input_bg"],
                                  fg=self.theme["fg"],
                                  insertbackground=self.theme["fg"])
        self.host_entry.pack(side=tk.LEFT, padx=(5, 20))
        
        # Port entry
        port_label = tk.Label(conn_frame, text="Port:",
                             bg=self.theme["bg"],
                             fg=self.theme["fg"])
        port_label.pack(side=tk.LEFT)
        
        self.port_var = tk.StringVar(value=str(self.settings["default_port"]))
        self.port_entry = tk.Entry(conn_frame,
                                  textvariable=self.port_var,
                                  bg=self.theme["input_bg"],
                                  fg=self.theme["fg"],
                                  insertbackground=self.theme["fg"])
        self.port_entry.pack(side=tk.LEFT, padx=5)
        
        # Password frame
        pass_frame = tk.Frame(self.main_container, bg=self.theme["bg"])
        pass_frame.pack(fill=tk.X, padx=10, pady=5)
        
        pass_label = tk.Label(pass_frame, text="Password:",
                             bg=self.theme["bg"],
                             fg=self.theme["fg"])
        pass_label.pack(side=tk.LEFT)
        
        self.pass_var = tk.StringVar()
        self.pass_entry = tk.Entry(pass_frame,
                                  textvariable=self.pass_var,
                                  show="*",
                                  bg=self.theme["input_bg"],
                                  fg=self.theme["fg"],
                                  insertbackground=self.theme["fg"])
        self.pass_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        
        # File selection frame
        self.file_frame = tk.Frame(self.main_container, bg=self.theme["bg"])
        self.file_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # File selection area
        self.setup_file_selection()
        
        # File listbox with scrollbar
        listbox_frame = tk.Frame(self.file_frame, bg=self.theme["bg"])
        listbox_frame.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
        
        scrollbar = tk.Scrollbar(listbox_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.file_listbox = tk.Listbox(listbox_frame,
                                      bg=self.theme["input_bg"],
                                      fg=self.theme["fg"],
                                      selectmode=tk.EXTENDED,
                                      height=5,
                                      yscrollcommand=scrollbar.set)
        self.file_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        scrollbar.config(command=self.file_listbox.yview)
        
        # File buttons frame
        file_btn_frame = tk.Frame(self.file_frame, bg=self.theme["bg"])
        file_btn_frame.pack(fill=tk.X, pady=(5, 0))
        
        clear_btn = tk.Button(file_btn_frame, text="Clear Files",
                             command=self.clear_files,
                             bg=self.theme["button_bg"],
                             fg=self.theme["button_fg"])
        clear_btn.pack(side=tk.RIGHT)
        
        # Progress frame
        progress_frame = tk.Frame(self.main_container, bg=self.theme["bg"])
        progress_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(progress_frame,
                                          variable=self.progress_var,
                                          mode='determinate')
        self.progress_bar.pack(fill=tk.X)
        
        # Speed and ETA labels
        info_frame = tk.Frame(self.main_container, bg=self.theme["bg"])
        info_frame.pack(fill=tk.X, padx=10)
        
        self.speed_label = tk.Label(info_frame, text="Speed: 0 B/s",
                                   bg=self.theme["bg"],
                                   fg=self.theme["fg"])
        self.speed_label.pack(side=tk.LEFT)
        
        self.eta_label = tk.Label(info_frame, text="ETA: --:--",
                                 bg=self.theme["bg"],
                                 fg=self.theme["fg"])
        self.eta_label.pack(side=tk.RIGHT)
        
        # Status frame
        status_frame = tk.Frame(self.main_container, bg=self.theme["bg"])
        status_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.status_label = tk.Label(status_frame, text="Ready",
                                    bg=self.theme["bg"],
                                    fg=self.theme["fg"],
                                    wraplength=580,
                                    justify=tk.LEFT)
        self.status_label.pack(fill=tk.X)
        
        # Action button
        self.action_btn = tk.Button(self.main_container, text="Send Files",
                                   command=self.start_transfer,
                                   bg=self.theme["button_bg"],
                                   fg=self.theme["button_fg"])
        self.action_btn.pack(pady=10)
    
    def style_progress_bars(self):
        """Style progress bars"""
        style = ttk.Style()
        style.theme_use('default')
        style.configure("TProgressbar", thickness=10, troughcolor='#1E1E1E',
                       background='#00FF41', borderwidth=0)
    
    def update_mode(self):
        """Update UI based on selected mode"""
        mode = self.mode_var.get().lower()
        
        if mode == "send":
            # Show file selection area and enable host entry
            self.file_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
            self.host_entry.config(state=tk.NORMAL)
            self.action_btn.config(text="Send Files")
        else:  # receive mode
            # Hide file selection area and disable host entry
            self.file_frame.pack_forget()
            self.host_entry.config(state=tk.DISABLED)
            self.action_btn.config(text="Receive Files")
            # Clear any selected files
            self.clear_files()
    
    def clear_files(self):
        """Clear selected files list"""
        self.selected_files.clear()
        self.file_listbox.delete(0, tk.END)
        self.action_btn.config(text="Send Files")
    
    def update_password_strength(self, event=None):
        """Update password strength meter"""
        password = self.pass_var.get()
        strength = get_password_strength(password)
        
        self.pw_strength_bar['value'] = strength
        self.pw_strength_label.config(text=f"Strength: {strength}%")
        
        # Change color based on strength
        style = ttk.Style()
        if strength < 40:
            style.configure("TProgressbar", background='#FF3333')
        elif strength < 70:
            style.configure("TProgressbar", background='#FFCC00')
        else:
            style.configure("TProgressbar", background='#00FF41')
    
    def start_transfer(self):
        """Start the file transfer process"""
        # Disable UI during transfer
        self.set_ui_state(tk.DISABLED)
        
        try:
            # Get transfer mode
            mode = self.mode_var.get().lower()
            
            # Validate password
            password = self.pass_var.get()
            if not password:
                raise ValueError("Password is required")
            
            # Validate port
            try:
                port = int(self.port_var.get())
                if port < 1 or port > 65535:
                    raise ValueError("Port must be between 1 and 65535")
            except ValueError as e:
                raise ValueError("Invalid port number")
            
            # Mode specific validation
            if mode == "send":
                # Validate host for send mode
                host = self.host_var.get()
                if not host:
                    raise ValueError("Host is required for send mode")
                
                # Validate file selection
                if not self.selected_files:
                    raise ValueError("No files selected")
                
                # Start sender thread
                threading.Thread(target=self.send_files,
                               args=(host, port, password, self.selected_files),
                               daemon=True).start()
            else:
                # Start receiver thread
                threading.Thread(target=self.receive_files,
                               args=(port, password),
                               daemon=True).start()
                
        except Exception as e:
            self.update_status(str(e), error=True)
            self.set_ui_state(tk.NORMAL)
    
    def send_files(self, host, port, password, files):
        """Thread function for sending files"""
        try:
            self.update_status("Connecting to receiver...")
            sender_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sender_socket.settimeout(CONNECTION_TIMEOUT)
            sender_socket.connect((host, port))
            
            def update_progress(value, message=""):
                self.update_progress(value, message)
                if value >= 0:
                    total_bytes = sum(os.path.getsize(f) for f in files)
                    self.update_transfer_info(value * total_bytes / 100, total_bytes)
            
            # Initialize transfer info
            self.start_time = None
            self.bytes_transferred = 0
            self.transfer_speed = 0
            
            send_file(sender_socket, files, password, update_progress)
            
            sender_socket.close()
            self.update_status("Transfer completed successfully", success=True)
        except socket.timeout:
            self.update_status("Connection timed out", error=True)
        except ConnectionRefusedError:
            self.update_status("Connection refused. Is the receiver running?", error=True)
        except Exception as e:
            self.update_status(f"Error: {str(e)}", error=True)
        finally:
            # Re-enable UI
            self.root.after(0, lambda: self.set_ui_state(tk.NORMAL))
    
    def receive_files(self, port, password):
        """Thread function for receiving files"""
        try:
            key = derive_key(password)
            
            def update_progress(value, message=""):
                self.update_progress(value, message)
                if value >= 0:
                    # Estimate total bytes based on progress
                    total_bytes = 1000000  # Default estimate
                    self.update_transfer_info(value * total_bytes / 100, total_bytes)
            
            # Initialize transfer info
            self.start_time = None
            self.bytes_transferred = 0
            self.transfer_speed = 0
            
            receive_file(key, port, update_progress, self.settings)
        except Exception as e:
            self.update_status(f"Error: {str(e)}", error=True)
        finally:
            # Re-enable UI
            self.root.after(0, lambda: self.set_ui_state(tk.NORMAL))
    
    def update_progress(self, value, message=""):
        """Update progress bar and status label"""
        def update():
            if value < 0:
                # Error state
                self.progress_bar['value'] = 0
                self.update_status(message, error=True)
            else:
                self.progress_bar['value'] = value
                self.update_status(message)
        
        self.root.after(0, update)
    
    def update_status(self, message, error=False, success=False):
        """Update status label with optional color coding"""
        if error:
            self.status_label.config(text=message, fg='#FF3333')
        elif success:
            self.status_label.config(text=message, fg='#00FF41')
        else:
            self.status_label.config(text=message, fg='#008F11')
    
    def toggle_ui(self, enabled):
        """Enable or disable UI elements during operations"""
        state = tk.NORMAL if enabled else tk.DISABLED
        
        self.host_entry.config(state=state if self.mode_var.get() == "send" else tk.DISABLED)
        self.port_entry.config(state=state)
        self.pass_entry.config(state=state)
        self.file_listbox.config(state=state)
        self.action_btn.config(state=state)
    
    def show_history(self):
        """Display transfer history in a new window"""
        if self.history_window is not None and self.history_window.winfo_exists():
            self.history_window.lift()
            return
        
        history_data = load_transfer_history()
        
        self.history_window = tk.Toplevel(self.root)
        self.history_window.title("Transfer History")
        self.history_window.geometry('600x400')
        self.history_window.configure(bg='#121212')
        
        # Title
        title_label = tk.Label(self.history_window, text="Transfer History", 
                              font=('Courier', 16, 'bold'), bg='#121212', fg='#00FF41')
        title_label.pack(pady=10)
        
        # Create treeview
        columns = ('action', 'filename', 'size', 'timestamp')
        tree = ttk.Treeview(self.history_window, columns=columns, show='headings', height=15)
        
        # Define headings
        tree.heading('action', text='Action')
        tree.heading('filename', text='Filename')
        tree.heading('size', text='Size')
        tree.heading('timestamp', text='Timestamp')
        
        # Define columns
        tree.column('action', width=80, anchor='center')
        tree.column('filename', width=200)
        tree.column('size', width=100, anchor='center')
        tree.column('timestamp', width=180, anchor='center')
        
        # Add data
        for item in history_data:
            action = item['action'].upper()
            filename = item['filename']
            size = format_size(item['size'])
            timestamp = item['timestamp']
            
            tree.insert('', tk.END, values=(action, filename, size, timestamp))
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(self.history_window, orient=tk.VERTICAL, command=tree.yview)
        tree.configure(yscroll=scrollbar.set)
        
        # Pack
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y, pady=10)
        
        # Clear button
        clear_btn = tk.Button(self.history_window, text="CLEAR HISTORY",
                             command=lambda: self.clear_history(tree),
                             bg='#1E1E1E', fg='#FF3333', font=('Courier', 10),
                             highlightbackground='#FF3333', highlightthickness=1,
                             activebackground='#FF3333', activeforeground='#121212',
                             borderwidth=0, padx=10, pady=3)
        clear_btn.pack(pady=10)
        
        # Style the treeview
        style = ttk.Style()
        style.configure("Treeview", 
                       background="#1E1E1E", 
                       foreground="#00FF41", 
                       fieldbackground="#1E1E1E",
                       rowheight=25)
        
        style.configure("Treeview.Heading", 
                       background="#008F11", 
                       foreground="#121212", 
                       font=('Courier', 10, 'bold'))
        
        style.map('Treeview', background=[('selected', '#008F11')], 
                 foreground=[('selected', '#121212')])
    
    def clear_history(self, tree):
        """Clear transfer history"""
        # Clear treeview
        for item in tree.get_children():
            tree.delete(item)
        
        # Clear history file
        if os.path.exists(HISTORY_FILE):
            os.remove(HISTORY_FILE)

    def apply_theme(self):
        """Apply current theme to all widgets"""
        # Update root and main container
        self.root.configure(bg=self.theme["bg"])
        self.main_container.configure(bg=self.theme["bg"])
        
        # Update all widgets recursively
        def update_widget_theme(widget):
            try:
                widget.configure(bg=self.theme["bg"])
                
                # Update specific widget types
                if isinstance(widget, tk.Label):
                    widget.configure(fg=self.theme["fg"])
                elif isinstance(widget, tk.Entry):
                    widget.configure(
                        bg=self.theme["input_bg"],
                        fg=self.theme["fg"],
                        insertbackground=self.theme["fg"]
                    )
                elif isinstance(widget, tk.Button):
                    widget.configure(
                        bg=self.theme["button_bg"],
                        fg=self.theme["button_fg"]
                    )
                elif isinstance(widget, tk.Listbox):
                    widget.configure(
                        bg=self.theme["input_bg"],
                        fg=self.theme["fg"]
                    )
                elif isinstance(widget, tk.Checkbutton):
                    widget.configure(
                        fg=self.theme["fg"],
                        selectcolor=self.theme["bg"],
                        activebackground=self.theme["bg"],
                        activeforeground=self.theme["fg"]
                    )
                
                # Update children recursively
                for child in widget.winfo_children():
                    update_widget_theme(child)
            except:
                pass
        
        # Update all widgets
        update_widget_theme(self.root)
        
        # Update progress bar style
        self.style_progress_bars()
    
    def toggle_theme(self):
        """Toggle between dark and light themes"""
        self.settings["theme"] = "light" if self.settings["theme"] == "dark" else "dark"
        self.theme = THEMES[self.settings["theme"]]
        self.save_settings(self.settings)
        self.apply_theme()
    
    def show_settings(self):
        """Show settings window"""
        if self.settings_window is not None and self.settings_window.winfo_exists():
            self.settings_window.lift()
            return
        
        # Create settings window
        self.settings_window = tk.Toplevel(self.root)
        self.settings_window.title("Settings")
        self.settings_window.geometry("400x500")
        self.settings_window.resizable(False, False)
        self.settings_window.transient(self.root)
        self.settings_window.grab_set()
        
        # Configure window
        self.settings_window.configure(bg=self.theme["bg"])
        
        # Create settings frame
        settings_frame = tk.Frame(self.settings_window, bg=self.theme["bg"])
        settings_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Title
        title_label = tk.Label(settings_frame, text="Settings",
                              font=('Courier', 16, 'bold'),
                              bg=self.theme["bg"],
                              fg=self.theme["fg"])
        title_label.pack(pady=(0, 20))
        
        # Theme selection
        theme_frame = tk.Frame(settings_frame, bg=self.theme["bg"])
        theme_frame.pack(fill=tk.X, pady=5)
        
        theme_label = tk.Label(theme_frame, text="Theme:",
                              bg=self.theme["bg"],
                              fg=self.theme["fg"])
        theme_label.pack(side=tk.LEFT)
        
        theme_var = tk.StringVar(value=self.settings["theme"])
        theme_menu = tk.OptionMenu(theme_frame, theme_var, "dark", "light")
        theme_menu.config(bg=self.theme["button_bg"],
                         fg=self.theme["button_fg"],
                         activebackground=self.theme["button_bg"],
                         activeforeground=self.theme["button_fg"],
                         highlightthickness=0)
        theme_menu.pack(side=tk.RIGHT)
        
        # Default host
        host_frame = tk.Frame(settings_frame, bg=self.theme["bg"])
        host_frame.pack(fill=tk.X, pady=5)
        
        host_label = tk.Label(host_frame, text="Default Host:",
                             bg=self.theme["bg"],
                             fg=self.theme["fg"])
        host_label.pack(side=tk.LEFT)
        
        host_var = tk.StringVar(value=self.settings["default_host"])
        host_entry = tk.Entry(host_frame,
                             textvariable=host_var,
                             bg=self.theme["input_bg"],
                             fg=self.theme["fg"],
                             insertbackground=self.theme["fg"])
        host_entry.pack(side=tk.RIGHT)
        
        # Default port
        port_frame = tk.Frame(settings_frame, bg=self.theme["bg"])
        port_frame.pack(fill=tk.X, pady=5)
        
        port_label = tk.Label(port_frame, text="Default Port:",
                             bg=self.theme["bg"],
                             fg=self.theme["fg"])
        port_label.pack(side=tk.LEFT)
        
        port_var = tk.StringVar(value=str(self.settings["default_port"]))
        port_entry = tk.Entry(port_frame,
                             textvariable=port_var,
                             bg=self.theme["input_bg"],
                             fg=self.theme["fg"],
                             insertbackground=self.theme["fg"])
        port_entry.pack(side=tk.RIGHT)
        
        # Compression level
        comp_frame = tk.Frame(settings_frame, bg=self.theme["bg"])
        comp_frame.pack(fill=tk.X, pady=5)
        
        comp_label = tk.Label(comp_frame, text="Compression Level (0-9):",
                             bg=self.theme["bg"],
                             fg=self.theme["fg"])
        comp_label.pack(side=tk.LEFT)
        
        comp_var = tk.StringVar(value=str(self.settings["compression_level"]))
        comp_entry = tk.Entry(comp_frame,
                             textvariable=comp_var,
                             bg=self.theme["input_bg"],
                             fg=self.theme["fg"],
                             insertbackground=self.theme["fg"])
        comp_entry.pack(side=tk.RIGHT)
        
        # Verify transfers
        verify_frame = tk.Frame(settings_frame, bg=self.theme["bg"])
        verify_frame.pack(fill=tk.X, pady=5)
        
        verify_var = tk.BooleanVar(value=self.settings["verify_transfers"])
        verify_check = tk.Checkbutton(verify_frame,
                                     text="Verify File Transfers",
                                     variable=verify_var,
                                     bg=self.theme["bg"],
                                     fg=self.theme["fg"],
                                     selectcolor=self.theme["bg"],
                                     activebackground=self.theme["bg"],
                                     activeforeground=self.theme["fg"])
        verify_check.pack(side=tk.LEFT)
        
        # Save button
        save_btn = tk.Button(settings_frame,
                            text="Save Settings",
                            command=lambda: self.save_settings_changes(
                                theme_var.get(),
                                host_var.get(),
                                port_var.get(),
                                comp_var.get(),
                                verify_var.get()
                            ),
                            bg=self.theme["button_bg"],
                            fg=self.theme["button_fg"])
        save_btn.pack(pady=20)
    
    def save_settings_changes(self, theme, host, port, compression, verify):
        """Save changes made in settings window"""
        try:
            # Validate port
            try:
                port = int(port)
                if port < 1 or port > 65535:
                    raise ValueError("Port must be between 1 and 65535")
            except ValueError:
                raise ValueError("Invalid port number")
            
            # Validate compression level
            try:
                compression = int(compression)
                if compression < 0 or compression > 9:
                    raise ValueError("Compression level must be between 0 and 9")
            except ValueError:
                raise ValueError("Invalid compression level")
            
            # Update settings
            self.settings.update({
                "theme": theme,
                "default_host": host,
                "default_port": port,
                "compression_level": compression,
                "verify_transfers": verify
            })
            
            # Save settings
            self.save_settings(self.settings)
            
            # Apply theme if changed
            if theme != THEMES[self.theme]:
                self.theme = THEMES[theme]
                self.apply_theme()
            
            # Close settings window
            self.settings_window.destroy()
            self.settings_window = None
            
            # Show success message
            self.update_status("Settings saved successfully")
            
        except Exception as e:
            self.update_status(f"Failed to save settings: {str(e)}", error=True)

    def update_transfer_info(self, bytes_transferred, total_bytes):
        """Update transfer speed and ETA"""
        current_time = time.time()
        
        # Initialize start time if not set
        if self.start_time is None:
            self.start_time = current_time
            self.bytes_transferred = bytes_transferred
            return
        
        # Calculate time difference
        time_diff = current_time - self.start_time
        if time_diff > 0:
            # Calculate bytes difference
            bytes_diff = bytes_transferred - self.bytes_transferred
            self.transfer_speed = bytes_diff / time_diff
            
            # Update speed label
            self.speed_label.config(text=f"Speed: {format_speed(self.transfer_speed)}")
            
            # Update ETA if we have total bytes
            if total_bytes and total_bytes > 0:
                remaining_bytes = total_bytes - bytes_transferred
                if self.transfer_speed > 0:
                    eta = calculate_eta(remaining_bytes, self.transfer_speed)
                    self.eta_label.config(text=f"ETA: {eta}")
                else:
                    self.eta_label.config(text="ETA: Calculating...")
        
        # Update for next calculation
        self.start_time = current_time
        self.bytes_transferred = bytes_transferred

    def set_ui_state(self, state):
        """Set the state of UI elements"""
        self.host_entry.config(state=state if self.mode_var.get() == "send" else tk.DISABLED)
        self.port_entry.config(state=state)
        self.pass_entry.config(state=state)
        self.file_listbox.config(state=state)
        self.action_btn.config(state=state)
    
    def save_settings(self, settings):
        """Save settings to file"""
        try:
            with open(SETTINGS_FILE, 'w') as f:
                json.dump(settings, f, indent=4)
        except Exception as e:
            self.update_status(f"Failed to save settings: {str(e)}", error=True)

if __name__ == "__main__":
    root = tk.Tk()
    app = CipherLinkApp(root)
    root.mainloop()