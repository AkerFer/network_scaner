import tkinter as tk
from tkinter import ttk
import socket
import subprocess
import threading
import time
import re

PING_DELAY = 0.2
DEFAULT_DOMAINS = ["google.com"]

BARCA_BLUE = "#004D98"
BARCA_RED = "#A50044"
BARCA_DARK = "#091442"
GREEN = "#00ff9c"

running = False
ips = []
blocked_ips = set()
suspicious_ips = set()
ip_stats = {}
packet_total = {}
packet_lost = {}

def parse_ping(output):
    t = re.search(r"time[=<]?(\d+\.?\d*)", output)
    ttl = re.search(r"ttl[=\s](\d+)", output, re.IGNORECASE)

    time_val = float(t.group(1)) if t else None
    ttl_val = int(ttl.group(1)) if ttl else None

    return time_val, ttl_val

def ping(ip):
    try:
        start = time.time()

        result = subprocess.run(
            ["ping", "-c", "1", "-W", "1", ip],
            capture_output=True,
            text=True,
            timeout=2
        )

        elapsed = time.time() - start

        time_val, ttl = parse_ping(result.stdout)

        if elapsed > 1.5:
            return None, None

        return time_val, ttl

    except:
        return None, None

def ping_loop():
    global running

    while running:
        for ip in ips:
            if not running:
                return

            if ip in blocked_ips:
                continue

            time_val, ttl = ping(ip)
            update_row(ip, time_val, ttl)

            packet_total[ip] = packet_total.get(ip, 0) + 1

            if time_val is None or time_val > 800:
                packet_lost[ip] = packet_lost.get(ip, 0) + 1
            else:
                packet_lost[ip] = packet_lost.get(ip, 0)

            total = packet_total[ip]
            lost = packet_lost[ip]

            if total >= 5:
                loss_percent = (lost / total) * 100

                if loss_percent >= 40 and ip not in suspicious_ips:
                    suspicious_ips.add(ip)
                    root.after(0, lambda ip=ip: suspicious_list.insert(tk.END, ip))

                packet_total[ip] = 0
                packet_lost[ip] = 0
            time.sleep(PING_DELAY)

def update_row(ip, time_val, ttl):
    if ip in blocked_ips:
        color = "bad"
    elif time_val is not None and time_val < 200:
        color = "good"
    elif time_val is not None and time_val < 500:
        color = "normal"
    else:
        color = "bad"
    root.after(0, lambda: insert_row(ip, time_val, ttl, color))

def insert_row(ip, time_val, ttl, color):
    row = tree.insert("", "end", values=(ip, time_val, ttl))

    if color == "good":
        tree.item(row, tags=("good",))
    elif color == "bad":
        tree.item(row, tags=("bad",))

def get_ip():
    global ips
    domain = entry.get()

    try:
        all_ips = []
        domain_ips = socket.gethostbyname_ex(domain)[2]
        all_ips.extend(domain_ips)

        for d in DEFAULT_DOMAINS:
            try:
                extra_ips = socket.gethostbyname_ex(d)[2]
                all_ips.extend(extra_ips)
            except:
                pass

        ips = list(set(all_ips))

        label.config(text=f"IPs: {len(ips)}")

        tree.delete(*tree.get_children())
        suspicious_list.delete(0, tk.END)

        ip_stats.clear()
        suspicious_ips.clear()

    except:
        label.config(text="Ошибка")

def start():
    global running
    running = True
    threading.Thread(target=ping_loop, daemon=True).start()

def stop():
    global running
    running = False

def block_ip():
    selected = tree.selection()
    if not selected:
        return

    ip = tree.item(selected[0])["values"][0]

    if ip in blocked_ips:
        return

    blocked_ips.add(ip)
    blocked_list.insert(tk.END, ip)

    subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])

def unblock_ip():
    selected = blocked_list.curselection()
    if not selected:
        return

    ip = blocked_list.get(selected[0])

    blocked_ips.remove(ip)
    blocked_list.delete(selected[0])

    subprocess.run(
        ["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
        stderr=subprocess.DEVNULL
    )

def clear_all():
    global running
    running = False

    tree.delete(*tree.get_children())
    suspicious_list.delete(0, tk.END)
    blocked_list.delete(0, tk.END)

    ip_stats.clear()
    suspicious_ips.clear()

root = tk.Tk()
root.title("Advanced Net Scanner")
root.geometry("1100x650")
root.configure(bg=BARCA_DARK)

title = tk.Label(root, text="NETWORK SCANNER", fg="white",
                 bg=BARCA_DARK, font=("Segoe UI", 16, "bold"))
title.pack(pady=10)

top = tk.Frame(root, bg=BARCA_DARK)
top.pack()

entry = ttk.Entry(top, width=30)
entry.pack(side="left", padx=5)

ttk.Button(top, text="GET IP", command=get_ip).pack(side="left")
ttk.Button(top, text="START", command=start).pack(side="left")
ttk.Button(top, text="STOP", command=stop).pack(side="left")

label = tk.Label(root, text="IPs:", fg="white", bg=BARCA_DARK)
label.pack()

main = tk.Frame(root, bg=BARCA_DARK)
main.pack(pady=10)

tk.Label(main, text="Ping Table", fg="white", bg=BARCA_DARK).grid(row=0, column=0)
tk.Label(main, text="Suspicious", fg="white", bg=BARCA_DARK).grid(row=0, column=1)
tk.Label(main, text="Blocked", fg="white", bg=BARCA_DARK).grid(row=0, column=2)

tree = ttk.Treeview(main, columns=("IP", "Time", "TTL"), show="headings", height=18)
tree.heading("IP", text="IP Address")
tree.heading("Time", text="Ping Time (ms)")
tree.heading("TTL", text="TTL")
tree.grid(row=1, column=0, padx=10)

tree.tag_configure("good", background=GREEN)
tree.tag_configure("bad", background="#ff4d4d")

suspicious_list = tk.Listbox(main, bg=BARCA_BLUE, fg="white", width=25)
suspicious_list.grid(row=1, column=1)

blocked_list = tk.Listbox(main, bg="#5a0000", fg="white", width=25)
blocked_list.grid(row=1, column=2)

controls = tk.Frame(root, bg=BARCA_DARK)
controls.pack(pady=10)

ttk.Button(controls, text="BLOCK", command=block_ip).pack(side="left", padx=5)
ttk.Button(controls, text="UNBLOCK", command=unblock_ip).pack(side="left", padx=5)
ttk.Button(controls, text="CLEAR", command=clear_all).pack(side="left", padx=5)
root.mainloop()