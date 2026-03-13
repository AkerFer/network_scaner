import tkinter as tk
from tkinter import ttk
import socket
import subprocess
import threading
import re
import time
import queue

running = False
blocked_ips = set()
ips = []
data_queue = queue.Queue()

ip_stats = {}
packet_counter = {}

PING_SIZE = 64
SUSPICIOUS_TIME = 400
SUSPICIOUS_COUNT = 5
MAX_PACKETS = 100

BARCA_BLUE = "#004D98"
BARCA_RED = "#A50044"
BARCA_DARK = "#091442"

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    80: "HTTP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP"
}


def get_ip():
    global ips
    domain = domain_entry.get().strip()
    try:
        ips = socket.gethostbyname_ex(domain)[2]

        if domain == "localhost":
            ips = ["127.0.0.1"]

        if ips:
            ip_label.config(text="IP найден")
        else:
            ip_label.config(text="IP не найден")
    except:
        ips = []
        ip_label.config(text="IP не найден")

def clear_all():
    global running
    global ips

    running = False
    ips = []
    blocked_ips.clear()
    ip_stats.clear()
    packet_counter.clear()

    tree.delete(*tree.get_children())
    suspicious_list.delete(0, tk.END)
    blocked_list.delete(0, tk.END)
    port_tree.delete(*port_tree.get_children())

    domain_entry.delete(0, tk.END)
    ip_label.config(text="IPs:")

def parse_ping(output):
    time_val = None
    ttl = None
    t = re.search(r"time[=<](\d+)", output)
    tt = re.search(r"TTL=(\d+)", output)

    if t:
        time_val = int(t.group(1))
    if tt:
        ttl = int(tt.group(1))
    return time_val, ttl

def ping(ip):

    result = subprocess.run(
        ["ping", "-n", "1", "-l", str(PING_SIZE), ip],
        capture_output=True,
        text=True
    )
    time_val, ttl = parse_ping(result.stdout)
    return time_val, PING_SIZE, ttl

def check_suspicious(ip, time_val):
    if ip not in ip_stats:
        ip_stats[ip] = 0
    if time_val is None or time_val > SUSPICIOUS_TIME:
        ip_stats[ip] += 1
    else:
        ip_stats[ip] = 0
    if ip_stats[ip] >= SUSPICIOUS_COUNT:

        existing = suspicious_list.get(0, tk.END)
        if ip not in existing:
            suspicious_list.insert(tk.END, ip)

def ping_loop():
    global running
    while running:
        for ip in ips:
            if not running:
                break
            if ip in blocked_ips:
                continue
            if ip not in packet_counter:
                packet_counter[ip] = 0
            if packet_counter[ip] >= MAX_PACKETS:
                continue
            time_val, size, ttl = ping(ip)
            packet_counter[ip] += 1
            data_queue.put((ip, time_val, size, ttl))
            time.sleep(0.7)

def update_gui():
    try:
        while True:
            ip, time_val, size, ttl = data_queue.get_nowait()
            row = tree.insert("", "end", values=(ip, time_val, size, ttl))
            check_suspicious(ip, time_val)
            if time_val is not None and time_val > SUSPICIOUS_TIME:
                tree.item(row, tags=("bad",))
    except queue.Empty:
        pass
    root.after(100, update_gui)

def start():
    global running
    if running:
        return
    if not ips:
        return
    running = True
    threading.Thread(target=ping_loop, daemon=True).start()

def stop():
    global running
    running = False

def block_ip():
    selected = tree.selection()
    if not selected:
        return
    item = tree.item(selected[0])
    ip = item["values"][0]

    if ip not in blocked_ips:
        blocked_ips.add(ip)
        blocked_list.insert(tk.END, ip)

def block_suspicious():
    selection = suspicious_list.curselection()
    if not selection:
        return
    index = selection[0]
    ip = suspicious_list.get(index)
    if ip not in blocked_ips:
        blocked_ips.add(ip)
        blocked_list.insert(tk.END, ip)
    suspicious_list.delete(index)

def unblock_ip():
    selection = blocked_list.curselection()

    if not selection:
        return
    index = selection[0]
    ip = blocked_list.get(index)
    if ip in blocked_ips:
        blocked_ips.remove(ip)
    blocked_list.delete(index)

def scan_ports(ip):
    open_ports = []
    for port, service in COMMON_PORTS.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.3)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append((port, service))
            sock.close()
        except:
            pass
    return open_ports

def scan_selected_ports():
    selected = tree.selection()
    if not selected:
        return
    item = tree.item(selected[0])
    ip = item["values"][0]

    port_tree.delete(*port_tree.get_children())
    open_ports = scan_ports(ip)

    for port, service in open_ports:
        port_tree.insert("", "end", values=(port, service))

#гуи
root = tk.Tk()
root.title("Сетевой сканер")
root.geometry("1000x520")
root.configure(bg=BARCA_DARK)

style = ttk.Style()
style.configure("Modern.TButton", font=("Segoe UI", 10, "bold"), padding=5)

title = tk.Label(
    root,
    text="Сетевой сканер",
    font=("Segoe UI", 16, "bold"),
    fg="white",
    bg=BARCA_DARK
)

title.pack(pady=8)

top = tk.Frame(root, bg=BARCA_DARK)
top.pack(pady=5)

domain_entry = ttk.Entry(top, width=30)
domain_entry.pack(side="left", padx=5)

ttk.Button(top, text="GET IP", command=get_ip, style="Modern.TButton").pack(side="left", padx=5)
ttk.Button(top, text="CLEAR", command=clear_all, style="Modern.TButton").pack(side="left", padx=5)

ip_label = tk.Label(top, text="IPs:", fg="white", bg=BARCA_DARK)
ip_label.pack(side="left", padx=10)

main = tk.Frame(root, bg=BARCA_DARK)
main.pack(pady=8)

tk.Label(main, text="IP поток", fg="white", bg=BARCA_DARK).grid(row=0, column=0)
tk.Label(main, text="Подозрительные", fg="white", bg=BARCA_DARK).grid(row=0, column=1)
tk.Label(main, text="Заблокированные", fg="white", bg=BARCA_DARK).grid(row=0, column=2)
tk.Label(main, text="Порты", fg="white", bg=BARCA_DARK).grid(row=0, column=3)

columns = ("IP", "Time", "Size", "TTL")
tree = ttk.Treeview(main, columns=columns, show="headings", height=16)
for col in columns:
    tree.heading(col, text=col)
    tree.column(col, width=110)
tree.grid(row=1, column=0, padx=6)

tree.tag_configure("bad", background=BARCA_RED)

suspicious_list = tk.Listbox(main, width=22, height=16, bg=BARCA_BLUE, fg="white")
suspicious_list.grid(row=1, column=1, padx=6)

blocked_list = tk.Listbox(main, width=22, height=16, bg="#5a0000", fg="white")
blocked_list.grid(row=1, column=2, padx=6)

port_tree = ttk.Treeview(main, columns=("Port", "Service"), show="headings", height=16)
port_tree.heading("Port", text="Port")
port_tree.heading("Service", text="Service")
port_tree.column("Port", width=80)
port_tree.column("Service", width=100)
port_tree.grid(row=1, column=3, padx=6)

controls = tk.Frame(root, bg=BARCA_DARK)
controls.pack(pady=10)

ttk.Button(controls, text="START", command=start, style="Modern.TButton").pack(side="left", padx=5)
ttk.Button(controls, text="STOP", command=stop, style="Modern.TButton").pack(side="left", padx=5)
ttk.Button(controls, text="BLOCK", command=block_ip, style="Modern.TButton").pack(side="left", padx=5)
ttk.Button(controls, text="BLOCK SUS", command=block_suspicious, style="Modern.TButton").pack(side="left", padx=5)
ttk.Button(controls, text="UNBLOCK", command=unblock_ip, style="Modern.TButton").pack(side="left", padx=5)
ttk.Button(controls, text="SCAN PORTS", command=scan_selected_ports, style="Modern.TButton").pack(side="left", padx=5)

root.after(100, update_gui)
root.mainloop()