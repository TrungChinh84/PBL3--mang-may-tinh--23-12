#!/usr/bin/env python3
"""
Web Dashboard quản trị Firewall - PBL4
Chạy với quyền root: sudo python3 web_dashboard.py
"""

from flask import Flask, render_template, jsonify, request, session, redirect, url_for
from functools import wraps
import subprocess
import json
import os
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'PBL3_SUPER_SECRET_KEY' # Dùng để mã hóa session đăng nhập

# --- CẤU HÌNH PATH (Phải khớp với hệ thống của bạn) ---
ALERT_FILE = '/var/log/firewall_alerts.json'
CONFIG_FILE = '/etc/firewall_auto_block.json'
ADMIN_PASSWORD = 'quangnam92'  # Mật khẩu đăng nhập web

# --- DECORATOR KIỂM TRA ĐĂNG NHẬP ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

class FirewallManager:
    @staticmethod
    def is_valid_ip(ip):
        if not ip: return False
        parts = ip.split('.')
        if len(parts) != 4: return False
        try:
            return all(0 <= int(part) <= 255 for part in parts)
        except ValueError: return False

    @staticmethod
    def get_iptables_rules():
        try:
            result = subprocess.run(['iptables', '-L', 'INPUT', '-n', '--line-numbers'], capture_output=True, text=True)
            return result.stdout
        except Exception as e:
            return f"Error: {e}"

    @staticmethod
    def block_ip(ip):
        try:
            subprocess.run(['iptables', '-I', 'INPUT', '1', '-s', ip, '-j', 'DROP'], check=True)
            return True, f"Đã chặn IP {ip}"
        except Exception as e:
            return False, str(e)

    @staticmethod
    def unblock_ip(ip):
        try:
            subprocess.run(['iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'], check=True)
            return True, f"Đã gỡ chặn IP {ip}"
        except Exception as e:
            return False, str(e)

    @staticmethod
    def get_stats():
        alerts = []
        blocked_count = 0
        try:
            # Đếm số dòng DROP trong iptables
            res = subprocess.run("iptables -L INPUT -n | grep DROP | wc -l", shell=True, capture_output=True, text=True)
            blocked_count = int(res.stdout.strip())

            # Đọc alerts
            if os.path.exists(ALERT_FILE):
                with open(ALERT_FILE, 'r') as f:
                    alerts = json.load(f)
                    if isinstance(alerts, list):
                        alerts.sort(key=lambda x: x.get('timestamp', 0), reverse=True)
                        alerts = alerts[:20] # Lấy 20 cái mới nhất
        except: pass
        return blocked_count, alerts

# --- ROUTES ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        if request.form['password'] == ADMIN_PASSWORD:
            session['logged_in'] = True
            return redirect(url_for('index'))
        else:
            error = 'Sai mật khẩu!'
    
    # Trả về HTML login đẹp hơn
    login_html = '''
    <!DOCTYPE html>
    <html lang="vi">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Firewall Dashboard - Đăng Nhập</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
        <style>
            body {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            }
            
            .login-container {
                background: rgba(255, 255, 255, 0.95);
                border-radius: 20px;
                padding: 40px;
                box-shadow: 0 15px 35px rgba(0, 0, 0, 0.2);
                width: 100%;
                max-width: 450px;
                animation: fadeIn 0.5s ease;
            }
            
            @keyframes fadeIn {
                from { opacity: 0; transform: translateY(-20px); }
                to { opacity: 1; transform: translateY(0); }
            }
            
            .login-header {
                text-align: center;
                margin-bottom: 30px;
            }
            
            .login-icon {
                font-size: 50px;
                color: #667eea;
                margin-bottom: 15px;
            }
            
            .login-title {
                color: #333;
                font-weight: 700;
                font-size: 28px;
                margin-bottom: 5px;
            }
            
            .login-subtitle {
                color: #666;
                font-size: 16px;
            }
            
            .form-control {
                border-radius: 10px;
                padding: 12px 15px;
                border: 2px solid #e0e0e0;
                transition: all 0.3s;
            }
            
            .form-control:focus {
                border-color: #667eea;
                box-shadow: 0 0 0 0.25rem rgba(102, 126, 234, 0.25);
            }
            
            .btn-login {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                border: none;
                border-radius: 10px;
                padding: 12px;
                font-weight: 600;
                font-size: 16px;
                color: white;
                width: 100%;
                transition: all 0.3s;
                margin-top: 10px;
            }
            
            .btn-login:hover {
                transform: translateY(-2px);
                box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
            }
            
            .password-input {
                position: relative;
            }
            
            .password-icon {
                position: absolute;
                right: 15px;
                top: 50%;
                transform: translateY(-50%);
                color: #777;
                cursor: pointer;
            }
            
            .alert-danger {
                border-radius: 10px;
                border: none;
                background: linear-gradient(135deg, #ff416c 0%, #ff4b2b 100%);
                color: white;
            }
            
            .footer-text {
                text-align: center;
                margin-top: 20px;
                color: #777;
                font-size: 14px;
            }
        </style>
    </head>
    <body>
        <div class="login-container">
            <div class="login-header">
                <div class="login-icon">
                    <i class="fas fa-shield-alt"></i>
                </div>
                <h1 class="login-title">Firewall Dashboard</h1>
                <p class="login-subtitle">Hệ thống quản lý tường lửa</p>
            </div>
            
            <form method="POST">
                '''
    
    if error:
        login_html += f'''
                <div class="alert alert-danger alert-dismissible fade show" role="alert">
                    <i class="fas fa-exclamation-triangle me-2"></i>
                    {error}
                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="alert"></button>
                </div>
                '''
    
    login_html += '''
                <div class="mb-4">
                    <label class="form-label fw-semibold">
                        <i class="fas fa-key me-2"></i>Mật khẩu quản trị
                    </label>
                    <div class="password-input">
                        <input type="password" name="password" class="form-control" 
                               placeholder="Nhập mật khẩu" required autofocus>
                        <span class="password-icon" onclick="togglePassword()">
                            <i class="fas fa-eye"></i>
                        </span>
                    </div>
                    
                </div>
                
                <button type="submit" class="btn btn-login">
                    <i class="fas fa-sign-in-alt me-2"></i>ĐĂNG NHẬP
                </button>
                
                <div class="footer-text">
                    <i class="fas fa-lock me-1"></i>
                    Hệ thống bảo mật Firewall - PBL3
                </div>
            </form>
        </div>
        
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
        <script>
            function togglePassword() {
                const passwordInput = document.querySelector('input[name="password"]');
                const icon = document.querySelector('.password-icon i');
                
                if (passwordInput.type === 'password') {
                    passwordInput.type = 'text';
                    icon.classList.remove('fa-eye');
                    icon.classList.add('fa-eye-slash');
                } else {
                    passwordInput.type = 'password';
                    icon.classList.remove('fa-eye-slash');
                    icon.classList.add('fa-eye');
                }
            }
        </script>
    </body>
    </html>
    '''
    
    return login_html

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/api/status')
@login_required
def api_status():
    blocked_count, alerts = FirewallManager.get_stats()
    
    # Đọc trạng thái service
    service_status = "STOPPED"
    try:
        res = subprocess.run(['systemctl', 'is-active', 'firewall-auto-block'], capture_output=True, text=True)
        service_status = res.stdout.strip().upper()
    except: pass

    return jsonify({
        'blocked_count': blocked_count,
        'alerts': alerts,
        'service_status': service_status,
        'updated_at': datetime.now().strftime("%H:%M:%S")
    })

@app.route('/api/action', methods=['POST'])
@login_required
def api_action():
    data = request.json
    action = data.get('type')
    ip = data.get('ip', '').strip()

    if action == 'toggle_service':
        # Bật tắt service auto-block
        current = data.get('current_status')
        cmd = 'stop' if current == 'ACTIVE' else 'start'
        os.system(f"systemctl {cmd} firewall-auto-block")
        return jsonify({'success': True, 'message': f"Đã gửi lệnh {cmd} service"})

    if not FirewallManager.is_valid_ip(ip):
        return jsonify({'success': False, 'message': 'IP không hợp lệ'})

    if action == 'block':
        success, msg = FirewallManager.block_ip(ip)
    elif action == 'unblock':
        success, msg = FirewallManager.unblock_ip(ip)
    else:
        return jsonify({'success': False, 'message': 'Hành động không rõ'})

    return jsonify({'success': success, 'message': msg})

@app.route('/api/config', methods=['GET', 'POST'])
@login_required
def api_config():
    """Đọc và Ghi file config JSON"""
    if request.method == 'GET':
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r') as f:
                return jsonify(json.load(f))
        return jsonify({}) # Trả về rỗng nếu chưa có file

    if request.method == 'POST':
        try:
            new_config = request.json
            with open(CONFIG_FILE, 'w') as f:
                json.dump(new_config, f, indent=4)
            return jsonify({'success': True, 'message': 'Đã lưu cấu hình!'})
        except Exception as e:
            return jsonify({'success': False, 'message': str(e)})

@app.route('/api/rules')
@login_required
def api_rules():
    return jsonify({'rules': FirewallManager.get_iptables_rules()})

if __name__ == '__main__':
    # SSL context='adhoc' để chạy HTTPS nếu cần, nhưng chạy local HTTP cho dễ
    if os.geteuid() != 0:
        print("Vui lòng chạy với quyền ROOT (sudo)")
    else:
        app.run(host='0.0.0.0', port=5000, debug=True)
