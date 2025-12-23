import tkinter as tk
from tkinter import ttk, messagebox
import subprocess

class FirewallTab:
    def __init__(self, parent):
        self.parent = parent
        
        # Biến lưu trữ dữ liệu lần quét trước để so sánh
        self.last_output = "" 
        
        # --- Khung chứa chính ---
        self.frame = ttk.Frame(parent)
        self.frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # --- Thanh công cụ (Buttons) ---
        self.toolbar = ttk.Frame(self.frame)
        self.toolbar.pack(fill=tk.X, pady=5)

        ttk.Button(self.toolbar, text="Làm Mới Ngay", command=self.force_refresh).pack(side=tk.LEFT, padx=5)
        ttk.Button(self.toolbar, text="Thêm Rule Mới", command=self.open_add_rule_window).pack(side=tk.LEFT, padx=5)
        ttk.Button(self.toolbar, text="Xóa Rule Đã Chọn", command=self.delete_rule).pack(side=tk.LEFT, padx=5)
        
        # Nút bật tắt tự động làm mới (Optional UI)
        self.auto_refresh_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(self.toolbar, text="Tự động cập nhật (3s)", variable=self.auto_refresh_var).pack(side=tk.RIGHT, padx=5)

        # --- Bảng hiển thị (Treeview) ---
        columns = ("chain", "num", "target", "prot", "opt", "source", "destination", "options")
        self.tree = ttk.Treeview(self.frame, columns=columns, show='headings', height=20)
        
        # Định nghĩa tiêu đề cột
        self.tree.heading("chain", text="Chain")
        self.tree.heading("num", text="No.")
        self.tree.heading("target", text="Hành Động")
        self.tree.heading("prot", text="Giao Thức")
        self.tree.heading("opt", text="Opt")
        self.tree.heading("source", text="Nguồn")
        self.tree.heading("destination", text="Đích")
        self.tree.heading("options", text="Thông tin thêm")

        # Căn chỉnh cột
        self.tree.column("chain", width=80, anchor=tk.CENTER)
        self.tree.column("num", width=50, anchor=tk.CENTER)
        self.tree.column("target", width=80, anchor=tk.CENTER)
        self.tree.column("prot", width=60, anchor=tk.CENTER)
        self.tree.column("opt", width=50, anchor=tk.CENTER)
        self.tree.column("source", width=120)
        self.tree.column("destination", width=120)
        self.tree.column("options", width=200)

        # Scrollbar
        scrollbar = ttk.Scrollbar(self.frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Load dữ liệu lần đầu
        self.load_rules()
        
        # BẮT ĐẦU VÒNG LẶP TỰ ĐỘNG
        self.auto_refresh_loop()

    def auto_refresh_loop(self):
        """Hàm này tự động chạy mỗi 3 giây"""
        try:
            # Chỉ chạy nếu Checkbox được tích và Cửa sổ còn tồn tại
            if self.auto_refresh_var.get() and self.frame.winfo_exists():
                self.load_rules(auto_mode=True)
            
            # Lên lịch chạy lại sau 3000ms (3 giây)
            self.frame.after(3000, self.auto_refresh_loop)
        except Exception:
            pass

    def force_refresh(self):
        """Khi bấm nút làm mới thủ công"""
        self.last_output = "" # Reset cache để ép buộc vẽ lại
        self.load_rules()

    def load_rules(self, auto_mode=False):
        """Đọc quy tắc từ iptables và hiển thị lên bảng"""
        try:
            # Lấy dữ liệu từ hệ thống
            result = subprocess.run(['iptables', '-L', '-n', '--line-numbers'], capture_output=True, text=True)
            current_output = result.stdout
            
            # KỸ THUẬT CHỐNG NHÁY (Anti-Flicker):
            # Nếu đang ở chế độ tự động và dữ liệu y hệt lần trước -> Không làm gì cả
            if auto_mode and current_output == self.last_output:
                return

            # Nếu dữ liệu khác, cập nhật lại biến lưu trữ
            self.last_output = current_output

            # --- Bắt đầu vẽ lại bảng ---
            # Xóa dữ liệu cũ
            for item in self.tree.get_children():
                self.tree.delete(item)

            lines = current_output.splitlines()
            current_chain = ""
            
            for line in lines:
                line = line.strip()
                if not line: continue
                
                if line.startswith("Chain"):
                    current_chain = line.split()[1]
                    continue
                
                if line.startswith("num"):
                    continue

                parts = line.split(maxsplit=6)
                if len(parts) >= 6:
                    num = parts[0]
                    target = parts[1]
                    prot = parts[2]
                    opt = parts[3]
                    source = parts[4]
                    dest = parts[5]
                    options = parts[6] if len(parts) > 6 else ""
                    
                    # Insert dòng mới
                    self.tree.insert("", tk.END, values=(current_chain, num, target, prot, opt, source, dest, options))

        except Exception as e:
            if not auto_mode: # Chỉ hiện lỗi nếu bấm thủ công để tránh spam popup
                messagebox.showerror("Lỗi", f"Không thể lấy danh sách iptables: {e}")

    def delete_rule(self):
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showwarning("Cảnh báo", "Vui lòng chọn một dòng để xóa!")
            return

        item_data = self.tree.item(selected_item)
        values = item_data['values']
        chain = values[0]
        num = values[1]

        confirm = messagebox.askyesno("Xác nhận", f"Bạn có chắc muốn xóa Rule #{num} trong Chain {chain}?")
        if confirm:
            try:
                subprocess.run(['iptables', '-D', chain, str(num)], check=True)
                messagebox.showinfo("Thành công", "Đã xóa quy tắc!")
                self.force_refresh() # Reload ngay lập tức
            except subprocess.CalledProcessError as e:
                messagebox.showerror("Lỗi", f"Không thể xóa quy tắc: {e}")

    def open_add_rule_window(self):
        win = tk.Toplevel(self.parent)
        win.title("Thêm Quy Tắc Mới")
        win.geometry("400x350")

        ttk.Label(win, text="Chain:").grid(row=0, column=0, padx=10, pady=5, sticky='w')
        chain_cb = ttk.Combobox(win, values=["INPUT", "OUTPUT", "FORWARD"], state="readonly")
        chain_cb.current(0)
        chain_cb.grid(row=0, column=1, padx=10, pady=5)

        ttk.Label(win, text="Hành động:").grid(row=1, column=0, padx=10, pady=5, sticky='w')
        action_cb = ttk.Combobox(win, values=["DROP", "ACCEPT", "REJECT"], state="readonly")
        action_cb.current(0)
        action_cb.grid(row=1, column=1, padx=10, pady=5)

        ttk.Label(win, text="Giao thức:").grid(row=2, column=0, padx=10, pady=5, sticky='w')
        prot_cb = ttk.Combobox(win, values=["tcp", "udp", "icmp", "all"])
        prot_cb.current(0)
        prot_cb.grid(row=2, column=1, padx=10, pady=5)

        ttk.Label(win, text="IP Nguồn:").grid(row=3, column=0, padx=10, pady=5, sticky='w')
        src_entry = ttk.Entry(win)
        src_entry.grid(row=3, column=1, padx=10, pady=5)
        ttk.Label(win, text="(VD: 192.168.1.5)").grid(row=3, column=2, padx=5, sticky='w')

        ttk.Label(win, text="Cổng Đích:").grid(row=4, column=0, padx=10, pady=5, sticky='w')
        port_entry = ttk.Entry(win)
        port_entry.grid(row=4, column=1, padx=10, pady=5)

        def save_rule():
            chain = chain_cb.get()
            action = action_cb.get()
            prot = prot_cb.get()
            src_ip = src_entry.get().strip()
            port = port_entry.get().strip()

            cmd = ['iptables', '-A', chain]
            if prot != 'all': cmd.extend(['-p', prot])
            if src_ip: cmd.extend(['-s', src_ip])
            if port:
                if prot in ['tcp', 'udp']: cmd.extend(['--dport', port])
                else:
                    messagebox.showwarning("Lỗi", "Cổng chỉ dùng cho TCP/UDP")
                    return
            cmd.extend(['-j', action])

            try:
                subprocess.run(cmd, check=True)
                messagebox.showinfo("Thành công", f"Đã thêm quy tắc vào {chain}")
                self.force_refresh() # Reload ngay sau khi thêm
                win.destroy()
            except subprocess.CalledProcessError as e:
                messagebox.showerror("Lỗi", f"Không thể thêm rule:\n{e}")

        ttk.Button(win, text="Lưu Quy Tắc", command=save_rule).grid(row=5, column=0, columnspan=2, pady=20)
