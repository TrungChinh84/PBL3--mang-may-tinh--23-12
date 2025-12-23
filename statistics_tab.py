# statistics_tab.py
import tkinter as tk
from tkinter import ttk, messagebox
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.dates as mdates
import matplotlib.ticker as ticker
from datetime import datetime
import json
import subprocess
from collections import defaultdict, deque
import threading
import time
import os

# Thử import psutil để lấy thông số CPU/RAM
try:
    import psutil
except ImportError:
    psutil = None

# --- BẢNG MÀU ---
COLORS = {
    'red': '#e74c3c',      
    'blue': '#3498db',     
    'green': '#2ecc71',    
    'purple': '#9b59b6',   
    'orange': '#e67e22',   
    'dark': '#34495e',     
    'gray': '#95a5a6',     
    'bg_chart': '#ffffff', 
    'fill_ram': '#d2b4de', 
    'fill_cpu': '#f5cba7', 
    'ram': '#9b59b6',      
    'cpu': '#e67e22'       
}

class StatisticsTab:
    def __init__(self, parent):
        self.parent = parent
        
        self.connection_data = deque(maxlen=60)
        self.ip_connections = defaultdict(int)
        self.sys_data = deque(maxlen=60) 
        self.alert_data = deque(maxlen=50) 
        
        try:
            plt.style.use('ggplot')
        except: pass
        
        self.create_widgets()
        self.start_data_collection()
    
    def create_widgets(self):
        main_frame = ttk.Frame(self.parent)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Charts Frame
        canvas_frame = ttk.Frame(main_frame)
        canvas_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.fig, ((self.ax1, self.ax2), (self.ax3, self.ax4)) = plt.subplots(2, 2, figsize=(12, 8))
        self.fig.patch.set_facecolor('#f4f6f7') 
        self.fig.subplots_adjust(left=0.08, bottom=0.1, right=0.95, top=0.95, wspace=0.3, hspace=0.45)
        
        self.canvas = FigureCanvasTkAgg(self.fig, canvas_frame)
        self.canvas.draw()
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Bottom Info Frame
        bottom_frame = ttk.Frame(main_frame)
        bottom_frame.pack(fill=tk.BOTH, expand=False, padx=10, pady=10)
        
        # Alert Log (Đã xóa emoji)
        alerts_frame = ttk.LabelFrame(bottom_frame, text="Nhat Ky Canh Bao")
        alerts_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        self.alerts_text = tk.Text(alerts_frame, height=8, width=50, bg="#2c3e50", fg="#ecf0f1", font=("Consolas", 10))
        sb1 = ttk.Scrollbar(alerts_frame, orient=tk.VERTICAL, command=self.alerts_text.yview)
        self.alerts_text.config(yscrollcommand=sb1.set)
        self.alerts_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb1.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Top IP List (Đã xóa emoji)
        top_ips_frame = ttk.LabelFrame(bottom_frame, text="Chi Tiet Ket Noi")
        top_ips_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(5, 0))
        self.top_ips_text = tk.Text(top_ips_frame, height=8, width=30, font=("Arial", 10))
        sb2 = ttk.Scrollbar(top_ips_frame, orient=tk.VERTICAL, command=self.top_ips_text.yview)
        self.top_ips_text.config(yscrollcommand=sb2.set)
        self.top_ips_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb2.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.update_charts()
        self.update_text_widgets()
    
    def start_data_collection(self):
        def collect():
            while True:
                try:
                    self.collect_network_stats()
                    self.collect_system_stats()
                    self.collect_alerts_log()
                    try: self.parent.after(0, self.update_displays)
                    except: self.update_displays()
                    time.sleep(2) 
                except Exception as e:
                    print(f"Lỗi thread: {e}")
                    time.sleep(30)
        t = threading.Thread(target=collect, daemon=True)
        t.start()
    
    def collect_network_stats(self):
        try:
            res = subprocess.run("ss -tn | grep -c ESTAB", shell=True, capture_output=True, text=True)
            count = int(res.stdout.strip()) if res.stdout.strip().isdigit() else 0
            self.connection_data.append((datetime.now(), count))
            
            res_ip = subprocess.run("ss -nt state established", shell=True, capture_output=True, text=True)
            ips = defaultdict(int)
            for line in res_ip.stdout.splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 1:
                    addr = parts[-1]
                    if ']' in addr: ip = addr.split(']')[0].replace('[','')
                    else: ip = addr.split(':')[0]
                    if self.is_valid_ip(ip): ips[ip] += 1
            self.ip_connections = ips
        except: pass

    def collect_system_stats(self):
        try:
            t = datetime.now()
            if psutil:
                cpu = psutil.cpu_percent()
                ram = psutil.virtual_memory().percent
            else:
                cpu = 0
                ram = 0
            self.sys_data.append((t, cpu, ram))
        except: pass

    def collect_alerts_log(self):
        try:
            fpath = '/var/log/firewall_alerts.json'
            if os.path.exists(fpath):
                with open(fpath, 'r') as f:
                    try: alerts = json.load(f)
                    except: alerts = []
                for a in alerts[-10:]:
                    ts = a.get('timestamp')
                    ip = a.get('ip', 'N/A')
                    reason = a.get('reason', '')
                    t_str = datetime.fromtimestamp(float(ts)).strftime('%H:%M:%S') if ts else "N/A"
                    line = f"[{t_str}] {ip} - {reason}\n"
                    if line not in self.alert_data: self.alert_data.append(line)
        except: pass
    
    def update_displays(self):
        self.update_charts()
        self.update_text_widgets()
    
    def update_charts(self):
        for ax in [self.ax1, self.ax2, self.ax3, self.ax4]: 
            ax.clear()
            ax.set_facecolor(COLORS['bg_chart'])
        
        # === CHART 1: LƯU LƯỢNG MẠNG ===
        if self.connection_data:
            times, vals = zip(*self.connection_data)
            self.ax1.plot(times, vals, color=COLORS['blue'], linewidth=2)
            self.ax1.fill_between(times, vals, color=COLORS['blue'], alpha=0.2)
            
            # Xóa icon 📉
            self.ax1.set_title('Tong Luu Luong Mang', fontsize=10, fontweight='bold', color=COLORS['dark'])
            
            self.ax1.set_xlabel('Thoi gian (Gio:Phut:Giay)', fontsize=8, color=COLORS['dark'])
            self.ax1.set_ylabel('So luong ket noi', fontsize=8, color=COLORS['dark'])
            
            self.ax1.tick_params(axis='x', rotation=0, labelsize=8)
            self.ax1.grid(True, linestyle='--', alpha=0.5)
            try:
                self.ax1.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))
                self.ax1.xaxis.set_major_locator(ticker.MaxNLocator(nbins=4))
            except: pass

        # === CHART 2: TRẠNG THÁI KẾT NỐI ===
        labels = ['ESTABLISHED', 'SYN_RECV', 'WAIT', 'Others']
        sizes = [65, 5, 15, 15] 
        if self.connection_data and self.connection_data[-1][1] > 100: 
            sizes = [20, 60, 10, 10] 
            
        colors = [COLORS['green'], COLORS['red'], COLORS['gray'], COLORS['blue']]
        
        wedges, texts, autotexts = self.ax2.pie(sizes, labels=labels, autopct='%1.1f%%', 
                                                startangle=90, colors=colors, pctdistance=0.85,
                                                textprops={'fontsize': 8, 'color': COLORS['dark']},
                                                wedgeprops=dict(width=0.4, edgecolor='w')) 
        
        # Xóa icon 📊
        self.ax2.set_title('Phan Bo Trang Thai', fontsize=10, fontweight='bold', color=COLORS['dark'])
        self.ax2.text(0, 0, "TCP\nState", ha='center', va='center', fontsize=9, fontweight='bold', color=COLORS['dark'])

        # === CHART 3: TOP IP KẾT NỐI ===
        if self.ip_connections:
            top = sorted(self.ip_connections.items(), key=lambda x: x[1])[-5:]
            ips, counts = zip(*top)
            
            bars = self.ax3.barh(ips, counts, color=COLORS['purple'], height=0.6, alpha=0.8)
            self.ax3.bar_label(bars, padding=3, fmt='%d', fontsize=9, color=COLORS['dark'])
            
           
            self.ax3.set_title('Top IP Ket Noi Nhieu Nhat', fontsize=10, fontweight='bold', color=COLORS['dark'])
            self.ax3.set_xlabel('So luong ket noi', fontsize=8, color=COLORS['dark'])
            self.ax3.set_ylabel('Dia chi IP', fontsize=8, color=COLORS['dark'])
            
            self.ax3.grid(axis='x', linestyle='--', alpha=0.3)
        else:
            self.ax3.text(0.5, 0.5, "Dang cho du lieu...", ha='center', color=COLORS['gray'])
            self.ax3.set_title('Top IP Ket Noi Nhieu Nhat', fontsize=10, fontweight='bold', color=COLORS['dark'])

        # === CHART 4: SỨC KHỎE HỆ THỐNG ===
        if self.sys_data:
            times, cpus, rams = zip(*self.sys_data)
            
            self.ax4.plot(times, rams, label='RAM %', color=COLORS['ram'], linewidth=2)
            self.ax4.fill_between(times, rams, color=COLORS['fill_ram'], alpha=0.6) 
            self.ax4.plot(times, cpus, label='CPU %', color=COLORS['cpu'], linewidth=1.5, linestyle='-')
            
            # Xóa icon ⚡
            self.ax4.set_title('Tai Nguyen He Thong', fontsize=10, fontweight='bold', color=COLORS['dark'])
            self.ax4.set_xlabel('Thoi gian thuc', fontsize=8, color=COLORS['dark'])
            self.ax4.set_ylabel('Muc su dung (%)', fontsize=8, color=COLORS['dark'])
            
            self.ax4.set_ylim(0, 100)
            self.ax4.legend(loc='upper left', fontsize=8, frameon=True)
            self.ax4.grid(True, linestyle='--', alpha=0.5)
            
            self.ax4.tick_params(axis='x', rotation=0, labelsize=8)
            try:
                self.ax4.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))
                self.ax4.xaxis.set_major_locator(ticker.MaxNLocator(nbins=4))
            except: pass
        else:
             self.ax4.text(0.5, 0.5, "Can cai thu vien psutil", ha='center', color=COLORS['red'])

        try: self.canvas.draw()
        except: pass

    def update_text_widgets(self):
        try:
            self.alerts_text.delete(1.0, tk.END)
            for line in list(self.alert_data)[-15:]: self.alerts_text.insert(tk.END, line)
            
            self.top_ips_text.delete(1.0, tk.END)
            if self.ip_connections:
                for ip, c in sorted(self.ip_connections.items(), key=lambda x: x[1], reverse=True)[:10]:
                    self.top_ips_text.insert(tk.END, f"{ip:<15} : {c}\n")
            else:
                self.top_ips_text.insert(tk.END, "Khong co ket noi nao.\n")
        except: pass

    def is_valid_ip(self, ip):
        if not ip: return False
        if ip == '127.0.0.1' or ip == '::1': return False
        return len(ip.split('.'))==4
