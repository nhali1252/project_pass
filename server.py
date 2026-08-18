#!/usr/bin/env python3
"""
ADB Commander - Remote Admin Control Panel
Designed to run on Linux VMs
Exposed via Cloudflare Zero Trust Tunnel
"""
import hashlib
import json
import base64
import secrets
from datetime import datetime, timedelta, timezone  # <-- CHANGED for Python 3.9 compatibility
import os
import sqlite3
import socket
import threading
import time
from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# ================= DATABASE SETUP =================
def init_db():
    conn = sqlite3.connect('licenses.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS otp_codes
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  otp TEXT UNIQUE,
                  pc_name TEXT,
                  hardware_id TEXT,
                  created TEXT,
                  expiry TEXT,
                  duration INTEGER DEFAULT 5,
                  is_used INTEGER DEFAULT 0,
                  is_active INTEGER DEFAULT 1,
                  is_verified INTEGER DEFAULT 0,
                  session_id TEXT)''')
    conn.commit()
    conn.close()

init_db()

# ================= BACKGROUND CLEANUP =================
def cleanup_expired_otps():
    while True:
        try:
            conn = sqlite3.connect('licenses.db')
            c = conn.cursor()
            now = datetime.now(timezone.utc).isoformat()
            c.execute('UPDATE otp_codes SET is_active = 0 WHERE expiry < ? AND is_active = 1', (now,))
            conn.commit()
            conn.close()
        except Exception as e:
            pass
        time.sleep(10)

cleanup_thread = threading.Thread(target=cleanup_expired_otps, daemon=True)
cleanup_thread.start()

# ================= ROUTES =================
@app.route('/')
def index():
    conn = sqlite3.connect('licenses.db')
    c = conn.cursor()
    now = datetime.now(timezone.utc)

    # Pending OTPs
    c.execute('''SELECT otp, pc_name, created, is_used, is_verified, duration, expiry
                 FROM otp_codes WHERE is_active = 1 AND is_verified = 0 AND is_used = 0 ORDER BY created DESC''')
    pending_rows = c.fetchall()
    pending_otps = []
    for row in pending_rows:
        otp, pc_name, created, is_used, is_verified, duration, expiry = row
        expiry_dt = datetime.fromisoformat(expiry)
        rem = (expiry_dt - now).total_seconds()
        if rem < 0: rem = 0
        pending_otps.append((otp, pc_name, created, is_used, is_verified, duration, expiry, int(rem)))

    # Verified OTPs
    c.execute('''SELECT otp, pc_name, created, is_used, duration FROM otp_codes WHERE is_verified = 1 ORDER BY created DESC LIMIT 10''')
    verified_otps = c.fetchall()

    # Expired OTPs
    c.execute('''SELECT otp, pc_name, created, duration FROM otp_codes WHERE is_active = 0 AND is_verified = 0 ORDER BY created DESC LIMIT 10''')
    expired_otps = c.fetchall()

    # Statistics
    c.execute('SELECT COUNT(*) FROM otp_codes')
    total = c.fetchone()[0]
    c.execute('SELECT COUNT(*) FROM otp_codes WHERE is_verified = 1')
    verified_count = c.fetchone()[0]
    c.execute('SELECT COUNT(*) FROM otp_codes WHERE is_active = 1 AND is_verified = 0 AND is_used = 0')
    pending_count = c.fetchone()[0]
    conn.close()

    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>ADB Commander - Admin Panel</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body { 
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                background: linear-gradient(135deg, #0f0c29 0%, #302b63 50%, #24243e 100%);
                min-height: 100vh;
                padding: 20px;
                display: flex;
                justify-content: center;
                align-items: center;
            }
            .container {
                max-width: 1000px;
                width: 100%;
                background: rgba(255,255,255,0.05);
                backdrop-filter: blur(10px);
                border-radius: 20px;
                padding: 40px;
                border: 1px solid rgba(255,255,255,0.1);
                box-shadow: 0 20px 60px rgba(0,0,0,0.5);
            }
            .header {
                text-align: center;
                margin-bottom: 30px;
            }
            .header h1 {
                font-size: 36px;
                color: #fff;
                font-weight: 700;
                letter-spacing: 2px;
            }
            .header h1 span { color: #64ffda; }
            .header .subtitle { color: #8892b0; margin-top: 5px; font-size: 14px; }
            .header .server-info { color: #64ffda; font-size: 12px; margin-top: 5px; }
            .server-status { display: inline-block; padding: 4px 15px; border-radius: 20px; font-size: 12px; font-weight: 600; margin-top: 5px; }
            .server-status.online { background: rgba(100, 255, 218, 0.2); color: #64ffda; }
            .card {
                background: rgba(255,255,255,0.05);
                border-radius: 15px;
                padding: 25px;
                margin-bottom: 20px;
                border: 1px solid rgba(255,255,255,0.05);
            }
            .card h3 {
                color: #64ffda;
                font-size: 18px;
                margin-bottom: 15px;
                display: flex;
                align-items: center;
                gap: 10px;
            }
            .card h3 .badge {
                background: rgba(100,255,218,0.2);
                color: #64ffda;
                padding: 2px 12px;
                border-radius: 20px;
                font-size: 12px;
            }
            .input-group {
                display: flex;
                gap: 10px;
                flex-wrap: wrap;
                align-items: center;
            }
            .input-group input, .input-group select {
                padding: 14px 18px;
                background: rgba(255,255,255,0.05);
                border: 2px solid rgba(255,255,255,0.1);
                border-radius: 10px;
                color: #fff;
                font-size: 16px;
                outline: none;
                transition: border-color 0.3s;
                min-width: 100px;
            }
            .input-group input:focus, .input-group select:focus { border-color: #64ffda; }
            .input-group input::placeholder { color: #8892b0; }
            .input-group select option { background: #1a1a2e; color: #fff; }
            .btn {
                padding: 14px 30px;
                background: linear-gradient(135deg, #64ffda 0%, #00b4d8 100%);
                color: #0f0c29;
                border: none;
                border-radius: 10px;
                font-size: 16px;
                font-weight: 600;
                cursor: pointer;
                transition: transform 0.2s, box-shadow 0.2s;
                white-space: nowrap;
            }
            .btn:hover { transform: scale(1.02); box-shadow: 0 5px 20px rgba(100,255,218,0.3); }
            .btn-danger { background: linear-gradient(135deg, #ff6b6b 0%, #c0392b 100%); color: #fff; }
            .btn-danger:hover { box-shadow: 0 5px 20px rgba(255,107,107,0.3); }
            .btn-success { background: linear-gradient(135deg, #00b894 0%, #00a86b 100%); color: #fff; }
            .btn-success:hover { box-shadow: 0 5px 20px rgba(0,184,148,0.3); }
            .btn-sm { padding: 6px 15px; font-size: 12px; }
            .otp-display {
                background: rgba(100,255,218,0.1);
                border: 2px solid #64ffda;
                border-radius: 10px;
                padding: 20px;
                margin-top: 15px;
                text-align: center;
                display: none;
            }
            .otp-display .code {
                font-size: 56px;
                font-family: 'Courier New', monospace;
                color: #64ffda;
                font-weight: bold;
                letter-spacing: 15px;
                text-shadow: 0 0 30px rgba(100,255,218,0.3);
            }
            .otp-display .info { color: #8892b0; font-size: 12px; margin-top: 5px; }
            .otp-list { margin-top: 10px; }
            .otp-item {
                display: flex;
                justify-content: space-between;
                align-items: center;
                padding: 12px 15px;
                background: rgba(255,255,255,0.03);
                border-radius: 8px;
                margin-bottom: 8px;
                border-left: 3px solid #ffd93d;
                flex-wrap: wrap;
                gap: 10px;
            }
            .otp-item.verified { border-left-color: #64ffda; }
            .otp-item.expired { border-left-color: #ff6b6b; opacity: 0.6; }
            .otp-item .code { font-family: 'Courier New', monospace; font-size: 22px; font-weight: bold; color: #ffd93d; }
            .otp-item .code.verified { color: #64ffda; }
            .otp-item .code.expired { color: #ff6b6b; text-decoration: line-through; }
            .otp-item .info { color: #8892b0; font-size: 12px; }
            .otp-item .actions { display: flex; gap: 5px; flex-wrap: wrap; }
            .status { padding: 3px 12px; border-radius: 20px; font-size: 11px; font-weight: 600; }
            .status.pending { background: rgba(255,217,61,0.2); color: #ffd93d; }
            .status.verified { background: rgba(100,255,218,0.2); color: #64ffda; }
            .status.used { background: rgba(255,107,107,0.2); color: #ff6b6b; }
            .status.expired { background: rgba(255,107,107,0.2); color: #ff6b6b; }
            .stats { display: flex; gap: 20px; flex-wrap: wrap; justify-content: center; }
            .stat-item { text-align: center; padding: 10px 25px; background: rgba(255,255,255,0.03); border-radius: 10px; min-width: 80px; }
            .stat-item .number { font-size: 28px; font-weight: bold; color: #64ffda; }
            .stat-item .label { color: #8892b0; font-size: 11px; }
            .timer-text { color: #f0b24d; font-size: 12px; }
            .empty { color: #8892b0; text-align: center; padding: 20px; }
            .footer { text-align: center; color: #8892b0; font-size: 12px; margin-top: 20px; }
            .refresh { color: #64ffda; cursor: pointer; text-decoration: underline; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🔐 <span>ADB Commander</span></h1>
                <div class="subtitle">Remote Admin Control Panel</div>
                <div class="server-info">
                    Server: {{ server_name }} | IP: {{ server_ip }}
                    <span class="server-status online">✅ Online</span>
                </div>
            </div>

            <div class="card">
                <h3>🔄 Generate OTP</h3>
                <div class="input-group">
                    <input type="text" id="pcName" placeholder="Enter PC / Customer name..." value="Customer">
                    <input type="number" id="otpDuration" placeholder="Duration (minutes)" value="5" min="1" max="60" style="width: 150px;">
                    <button class="btn" onclick="generateOTP()">Generate OTP</button>
                </div>
                <div class="otp-display" id="otpDisplay">
                    <div class="code" id="otpCode">000000</div>
                    <div class="info" id="otpInfo">PC: Customer | Valid for 5 minutes</div>
                    <div style="margin-top: 10px;">
                        <button class="btn btn-success btn-sm" onclick="copyOTP()">📋 Copy OTP</button>
                        <button class="btn btn-sm" onclick="document.getElementById('otpDisplay').style.display='none'" style="background: rgba(255,255,255,0.1); color: #fff;">Close</button>
                    </div>
                </div>
            </div>

            <div class="card">
                <h3>⏳ Pending Verification <span class="badge">{{ pending_count }}</span></h3>
                <div class="otp-list">
                    {% if pending_otps %}
                        {% for otp in pending_otps %}
                        <div class="otp-item">
                            <div>
                                <div class="code">{{ otp[0] }}</div>
                                <div class="info">{{ otp[1] }} | {{ otp[2][:16] }} | {{ otp[5] }} min</div>
                                <div class="timer-text">⏱️ {{ (otp[7] // 60)|int }}m {{ (otp[7] % 60)|int }}s left</div>
                            </div>
                            <div class="actions">
                                <span class="status pending">⏳ Pending</span>
                                <button class="btn btn-success btn-sm" onclick="verifyOTP('{{ otp[0] }}')">✅ Verify</button>
                                <button class="btn btn-danger btn-sm" onclick="deleteOTP('{{ otp[0] }}')">🗑️</button>
                            </div>
                        </div>
                        {% endfor %}
                    {% else %}
                        <div class="empty">No pending OTPs</div>
                    {% endif %}
                </div>
            </div>

            <div class="card">
                <h3>✅ Verified OTPs <span class="badge">{{ verified_count }}</span></h3>
                <div class="otp-list">
                    {% if verified_otps %}
                        {% for otp in verified_otps %}
                        <div class="otp-item verified">
                            <div>
                                <div class="code verified">{{ otp[0] }}</div>
                                <div class="info">{{ otp[1] }} | {{ otp[2][:16] }} | {{ otp[4] }} min</div>
                            </div>
                            <div>
                                <span class="status verified">✅ Verified</span>
                            </div>
                        </div>
                        {% endfor %}
                    {% else %}
                        <div class="empty">No verified OTPs</div>
                    {% endif %}
                </div>
            </div>

            <div class="card">
                <h3>⏰ Expired OTPs</h3>
                <div class="otp-list">
                    {% if expired_otps %}
                        {% for otp in expired_otps %}
                        <div class="otp-item expired">
                            <div>
                                <div class="code expired">{{ otp[0] }}</div>
                                <div class="info">{{ otp[1] }} | {{ otp[2][:16] }} | {{ otp[3] }} min</div>
                            </div>
                            <div>
                                <span class="status expired">⏰ Expired</span>
                            </div>
                        </div>
                        {% endfor %}
                    {% else %}
                        <div class="empty">No expired OTPs</div>
                    {% endif %}
                </div>
            </div>

            <div class="card">
                <h3>📊 Statistics</h3>
                <div class="stats">
                    <div class="stat-item"><div class="number">{{ total }}</div><div class="label">Total</div></div>
                    <div class="stat-item"><div class="number">{{ pending_count }}</div><div class="label">Pending</div></div>
                    <div class="stat-item"><div class="number">{{ verified_count }}</div><div class="label">Verified</div></div>
                </div>
                <div style="text-align: center; margin-top: 15px;">
                    <button class="btn btn-danger btn-sm" onclick="clearAll()">🗑️ Clear All</button>
                    <span class="refresh" onclick="location.reload()" style="margin-left: 15px;">🔄 Refresh</span>
                </div>
            </div>

            <div class="footer"><span id="timerDisplay">⏰ Auto-refresh in 30s</span></div>
        </div>

        <script>
            let timer = 30, intervalId = null;
            function updateTimer() {
                if (timer <= 0) { location.reload(); return; }
                document.getElementById('timerDisplay').innerHTML = `⏰ Auto-refresh in ${timer}s`;
                timer--;
            }
            function startTimer() { if (intervalId) clearInterval(intervalId); timer = 30; intervalId = setInterval(updateTimer, 1000); }

            function generateOTP() {
                const name = document.getElementById('pcName').value || 'Customer';
                const duration = parseInt(document.getElementById('otpDuration').value) || 5;
                document.getElementById('otpDisplay').style.display = 'none';
                
                fetch('/generate_otp', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({pc_name: name, duration: duration})
                })
                .then(response => response.json())
                .then(data => {
                    if (data.status === 'success') {
                        document.getElementById('otpCode').textContent = data.otp;
                        document.getElementById('otpInfo').textContent = `PC: ${data.pc_name} | Valid for ${data.duration} minutes`;
                        document.getElementById('otpDisplay').style.display = 'block';
                        setTimeout(() => location.reload(), 2000);
                    } else {
                        alert('❌ Error: ' + data.error);
                    }
                })
                .catch(() => alert('❌ Connection error!'));
            }

            function verifyOTP(otp) {
                if (confirm('Verify OTP: ' + otp + '?')) {
                    fetch('/verify_otp', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({otp: otp})
                    })
                    .then(response => response.json())
                    .then(data => {
                        if (data.status === 'success') { alert('✅ OTP verified! Client will unlock.'); location.reload(); }
                        else { alert('❌ ' + data.error); }
                    });
                }
            }

            function deleteOTP(otp) {
                if (confirm('Delete OTP: ' + otp + '?')) {
                    fetch('/delete_otp', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({otp: otp})
                    })
                    .then(response => response.json())
                    .then(data => { if (data.status === 'success') { alert('✅ OTP deleted!'); location.reload(); } });
                }
            }

            function copyOTP() {
                const code = document.getElementById('otpCode').textContent;
                if (navigator.clipboard) { navigator.clipboard.writeText(code); alert('📋 OTP copied: ' + code); }
                else { alert('📋 OTP: ' + code); }
            }

            function clearAll() {
                if (confirm('Delete ALL OTPs?')) {
                    if (confirm('⚠️ ARE YOU SURE?')) {
                        fetch('/clear_all', {method: 'POST'})
                        .then(response => response.json())
                        .then(data => { if (data.status === 'success') { alert('✅ All OTPs cleared!'); location.reload(); } });
                    }
                }
            }

            document.getElementById('pcName').addEventListener('keypress', function(e) {
                if (e.key === 'Enter') generateOTP();
            });
            startTimer();
        </script>
    </body>
    </html>
    ''', 
    server_name=socket.gethostname(),
    server_ip=socket.gethostbyname(socket.gethostname()),
    pending_otps=pending_otps,
    verified_otps=verified_otps,
    expired_otps=expired_otps,
    total=total,
    pending_count=pending_count,
    verified_count=verified_count)

@app.route('/generate_otp', methods=['POST'])
def generate_otp():
    try:
        data = request.get_json() or {}
        pc_name = data.get('pc_name', 'Customer')
        duration = data.get('duration', 5)
        otp = ''.join(secrets.choice('0123456789') for _ in range(6))
        conn = sqlite3.connect('licenses.db')
        c = conn.cursor()
        c.execute('DELETE FROM otp_codes WHERE is_active = 0')
        expiry = (datetime.now(timezone.utc) + timedelta(minutes=duration)).isoformat()
        c.execute('''INSERT INTO otp_codes (otp, pc_name, duration, created, expiry) VALUES (?, ?, ?, ?, ?)''',
                  (otp, pc_name, duration, datetime.now(timezone.utc).isoformat(), expiry))
        conn.commit()
        conn.close()
        return jsonify({'status': 'success', 'otp': otp, 'pc_name': pc_name, 'duration': duration})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/verify_otp', methods=['POST'])
def verify_otp():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Empty request body'}), 400
        otp = data.get('otp', '').strip()
        conn = sqlite3.connect('licenses.db')
        c = conn.cursor()
        c.execute('''SELECT otp, is_used, is_verified, is_active, expiry FROM otp_codes WHERE otp = ?''', (otp,))
        result = c.fetchone()
        if not result: conn.close(); return jsonify({'error': 'OTP not found!'}), 401
        _, is_used, is_verified, is_active, expiry = result
        if not is_active: return jsonify({'error': 'OTP inactive!'}), 401
        if is_used: return jsonify({'error': 'OTP already used!'}), 401
        if is_verified: return jsonify({'error': 'OTP already verified!'}), 401
        if datetime.now(timezone.utc) > datetime.fromisoformat(expiry):
            c.execute('UPDATE otp_codes SET is_active = 0 WHERE otp = ?', (otp,))
            conn.commit(); conn.close()
            return jsonify({'error': 'OTP expired!'}), 401
        c.execute('UPDATE otp_codes SET is_verified = 1, is_active = 1 WHERE otp = ?', (otp,))
        conn.commit(); conn.close()
        return jsonify({'status': 'success', 'message': 'OTP verified! Client can now unlock.'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/check_otp', methods=['POST'])
def check_otp():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Empty request body'}), 400
        otp = data.get('otp', '').strip()
        conn = sqlite3.connect('licenses.db')
        c = conn.cursor()
        c.execute('''SELECT otp, is_verified, is_used, expiry, is_active, duration FROM otp_codes WHERE otp = ?''', (otp,))
        result = c.fetchone()
        if not result: conn.close(); return jsonify({'error': 'Invalid OTP!'}), 401
        _, is_verified, is_used, expiry, is_active, duration = result
        if not is_active: return jsonify({'error': 'OTP inactive!'}), 401
        if is_used: return jsonify({'error': 'OTP already used!'}), 401
        if datetime.now(timezone.utc) > datetime.fromisoformat(expiry):
            c.execute('UPDATE otp_codes SET is_active = 0 WHERE otp = ?', (otp,))
            conn.commit(); conn.close()
            return jsonify({'error': 'OTP expired!'}), 401
        conn.close()
        if is_verified: return jsonify({'status': 'verified', 'message': '✅ OTP verified! Access granted.', 'duration': duration})
        else: return jsonify({'status': 'pending', 'message': '⏳ Waiting for admin verification...', 'duration': duration})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/delete_otp', methods=['POST'])
def delete_otp():
    try: 
        data = request.get_json()
        if not data: return jsonify({'error': 'Empty request'}), 400
        conn = sqlite3.connect('licenses.db')
        c = conn.cursor()
        c.execute('DELETE FROM otp_codes WHERE otp = ?', (data.get('otp', '').strip(),))
        conn.commit()
        conn.close()
        return jsonify({'status': 'success'})
    except: return jsonify({'error': 'Failed'}), 500

@app.route('/clear_all', methods=['POST'])
def clear_all():
    try: 
        conn = sqlite3.connect('licenses.db')
        c = conn.cursor()
        c.execute('DELETE FROM otp_codes')
        conn.commit()
        conn.close()
        return jsonify({'status': 'success'})
    except: return jsonify({'error': 'Failed'}), 500

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'healthy', 'timestamp': datetime.now(timezone.utc).isoformat(), 'server': socket.gethostname()})

if __name__ == '__main__':
    print("\n" + "=" * 70)
    print("  🔐 ADB COMMANDER CONTROL PANEL - READY TO DEPLOY")
    print("=" * 70)
    print("  1. Install the Tunnel Connector Service (Already Done)")
    print("  2. Starting Flask on port 5000...")
    print("  3. Go to Cloudflare Zero Trust Dashboard -> Access -> Tunnels")
    print("  4. Click your tunnel -> Add Public Hostname")
    print("  5. Set Service to: localhost:5000")
    print("=" * 70)
    app.run(host='0.0.0.0', port=5000, debug=False)
