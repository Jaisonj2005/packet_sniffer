import tkinter as tk
from tkinter import ttk, messagebox
import socket
import struct
import threading
import os
import platform
import datetime

# Global control flag
is_sniffing = False
sniffer_socket = None

def unpack_ipv4_header(data):
    # Unpack the first 20 bytes for the IPv4 Header
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    
    # Unpack TTL, Protocol, Source IP, and Target IP
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    
    src_ip = socket.inet_ntoa(src)
    target_ip = socket.inet_ntoa(target)
    
    return version, header_length, ttl, proto, src_ip, target_ip

def get_protocol_name(proto_num):
    protocols = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
    return protocols.get(proto_num, str(proto_num))

def sniff_packets():
    global is_sniffing, sniffer_socket
    
    # Get local machine IP
    try:
        host_ip = socket.gethostbyname(socket.gethostname())
    except socket.gaierror:
        host_ip = "127.0.0.1"

    try:
        # Create a raw socket (Windows requires IPPROTO_IP)
        if platform.system().lower() == 'windows':
            sniffer_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            sniffer_socket.bind((host_ip, 0))
            sniffer_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            # Enable promiscuous mode on Windows
            sniffer_socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        else:
            # Linux/Mac standard implementation
            sniffer_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

    except PermissionError:
        messagebox.showerror("Permission Denied", "Raw sockets require Administrator/root privileges!\nPlease restart your terminal or VS Code as Administrator.")
        reset_ui()
        return
    except Exception as e:
        messagebox.showerror("Socket Error", f"Failed to bind socket: {str(e)}")
        reset_ui()
        return

    count = 0
    while is_sniffing:
        try:
            # Set a timeout so the loop can exit if stopped
            sniffer_socket.settimeout(1.0)
            raw_data, addr = sniffer_socket.recvfrom(65535)
            
            # Parse the IPv4 Header
            version, header_length, ttl, proto, src_ip, target_ip = unpack_ipv4_header(raw_data)
            
            # Map protocol numbers to names
            proto_name = get_protocol_name(proto)
            packet_size = len(raw_data)
            timestamp = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
            
            count += 1
            
            # Insert into Treeview securely from the background thread
            tree.after(0, insert_packet, count, timestamp, src_ip, target_ip, proto_name, packet_size)
            lbl_status.after(0, update_status, f"Capturing... ({count} packets)")
            
        except socket.timeout:
            continue
        except Exception as e:
            if is_sniffing:
                print(f"Error reading packet: {e}")
            break

    # Disable promiscuous mode on exit
    if platform.system().lower() == 'windows' and sniffer_socket:
        sniffer_socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        sniffer_socket.close()

def insert_packet(count, time, src, dst, proto, size):
    # Keep the table from crashing memory by limiting to last 1000 packets
    if len(tree.get_children()) > 1000:
        tree.delete(tree.get_children()[0])
        
    item = tree.insert("", tk.END, values=(count, time, src, dst, proto, size))
    tree.yview_moveto(1) # Auto-scroll to bottom

def update_status(msg):
    lbl_status.config(text=msg)

def start_sniffing():
    global is_sniffing
    if is_sniffing: return
    
    is_sniffing = True
    btn_start.config(state=tk.DISABLED)
    btn_stop.config(state=tk.NORMAL)
    lbl_status.config(text="Initializing raw socket...", fg="#e67e22")
    
    tree.delete(*tree.get_children()) # Clear old capture
    
    threading.Thread(target=sniff_packets, daemon=True).start()

def stop_sniffing():
    global is_sniffing
    is_sniffing = False
    lbl_status.config(text="Capture Stopped", fg="#c0392b")
    btn_start.config(state=tk.NORMAL)
    btn_stop.config(state=tk.DISABLED)

def reset_ui():
    global is_sniffing
    is_sniffing = False
    btn_start.config(state=tk.NORMAL)
    btn_stop.config(state=tk.DISABLED)
    lbl_status.config(text="Ready", fg="#7f8c8d")

# --- Tkinter GUI Layout ---
root = tk.Tk()
root.title("NOC Toolkit - IPv4 Packet Sniffer")
root.geometry("700x500")
root.resizable(False, False)

frame = ttk.Frame(root, padding="15")
frame.pack(fill=tk.BOTH, expand=True)

lbl_title = tk.Label(frame, text="Raw Socket Packet Sniffer", font=("Helvetica", 13, "bold"))
lbl_title.pack(anchor="w", pady=(0, 5))

lbl_desc = tk.Label(frame, text="Captures and unpacks raw IPv4 frames passing through the NIC.", font=("Helvetica", 9), fg="#555")
lbl_desc.pack(anchor="w", pady=(0, 15))

# Controls
control_frame = tk.Frame(frame)
control_frame.pack(fill=tk.X, pady=(0, 10))

btn_start = tk.Button(control_frame, text="Start Capture", command=start_sniffing, bg="#2980b9", fg="white", font=("Helvetica", 9, "bold"), width=15)
btn_start.pack(side=tk.LEFT, padx=(0, 10))

btn_stop = tk.Button(control_frame, text="Stop Capture", command=stop_sniffing, bg="#c0392b", fg="white", font=("Helvetica", 9, "bold"), width=15, state=tk.DISABLED)
btn_stop.pack(side=tk.LEFT)

lbl_status = tk.Label(control_frame, text="Ready", font=("Helvetica", 9, "bold"), fg="#7f8c8d")
lbl_status.pack(side=tk.RIGHT, padx=(0, 5))

# Treeview Table (Wireshark style)
columns = ("no", "time", "source", "destination", "protocol", "length")
tree = ttk.Treeview(frame, columns=columns, show="headings", height=15)

tree.heading("no", text="No.")
tree.heading("time", text="Time")
tree.heading("source", text="Source IP")
tree.heading("destination", text="Destination IP")
tree.heading("protocol", text="Protocol")
tree.heading("length", text="Length")

tree.column("no", width=50, anchor="center")
tree.column("time", width=100, anchor="center")
tree.column("source", width=130, anchor="center")
tree.column("destination", width=130, anchor="center")
tree.column("protocol", width=80, anchor="center")
tree.column("length", width=60, anchor="center")

tree.pack(fill=tk.BOTH, expand=True, pady=(5, 0))

scrollbar = ttk.Scrollbar(tree, orient=tk.VERTICAL, command=tree.yview)
tree.configure(yscroll=scrollbar.set)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

root.mainloop()