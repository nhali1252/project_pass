#!/usr/bin/env python3
"""
ADB Commander - Master Control Panel
FULL FIX: CORS & API added for Lovable compatibility.
"""
import secrets
import os
import sqlite3
import socket
import threading
import time
import logging
import subprocess
import json
from pathlib import Path
from datetime import datetime, timedelta, timezone
from flask import Flask, request, jsonify, render_template_string, redirect, url_for, session
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash

# ================= Logging =================
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ================= Flask App =================
app = Flask(__name__)

# 🔥 CRITICAL FIXES FOR CROSS-ORIGIN (LOVABLE) LOGIN:
app.config.update(
    SECRET_KEY=os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32)),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="None",  # 🔥 Lovable থেকে কুকি পাঠানোর জন্য বাধ্যতামূলক
    SESSION_COOKIE_SECURE=True,      # 🔥 HTTPS (api.alii.uk) এর জন্য বাধ্যতামূলক
    PERMANENT_SESSION_LIFETIME=timedelta(days=7),
)
# 🔥 `supports_credentials=True` যুক্ত করা আবশ্যক
CORS(app, supports_credentials=True) 

# ================= Admin password (set via environment) =================
ADMIN_PASSWORD_HASH = os.environ.get("ADMIN_PASSWORD_HASH")
if not ADMIN_PASSWORD_HASH:
    raise RuntimeError(
        "ADMIN_PASSWORD_HASH is missing. Generate it with:\n"
        "python -c \"from werkzeug.security import generate_password_hash; "
        "print(generate_password_hash('YourAdminPassword'))\""
    )

# ================= Helper Functions =================
def hash_password(pwd: str) -> str:
    return generate_password_hash(pwd)

def verify_password(input_pwd: str, stored_hash: str) -> bool:
    return check_password_hash(stored_hash, input_pwd)

# ================= Database =================
def init_db():
    conn = sqlite3.connect('licenses.db', timeout=20)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        pc_name TEXT NOT NULL,
        hardware_id TEXT NOT NULL,
        location TEXT,
        is_active INTEGER DEFAULT 0,
        activated_at TEXT,
        deactivated_at TEXT,
        session_token TEXT UNIQUE,
        last_seen TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS device_reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        serial TEXT NOT NULL,
        state TEXT,
        device_model TEXT,
        reported_at TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS user_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        action TEXT NOT NULL,
        details TEXT,
        timestamp TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
    )''')
    # Set default client password (global_password_hash) if not exists
    c.execute("SELECT value FROM settings WHERE key = 'global_password_hash'")
    if not c.fetchone():
        c.execute("INSERT INTO settings (key, value) VALUES ('global_password_hash', ?)", (hash_password("admin123"),))
    conn.commit()
    conn.close()
    logger.info("Database initialized.")

init_db()

# ================= Offline monitor =================
def mark_offline_users():
    while True:
        time.sleep(10)
        try:
            conn = sqlite3.connect('licenses.db', timeout=10)
            c = conn.cursor()
            cutoff = (datetime.now(timezone.utc) - timedelta(seconds=30)).isoformat()
            c.execute("UPDATE users SET is_active = 0, deactivated_at = ? WHERE is_active = 1 AND last_seen < ?", (datetime.now(timezone.utc).isoformat(), cutoff))
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Offline monitor error: {e}")

threading.Thread(target=mark_offline_users, daemon=True).start()

# ================= Client API =================
@app.route('/api/client/verify', methods=['POST'])
def client_verify():
    conn = None
    try:
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "message": "Invalid Request"}), 400

        pc_name = data.get('pc_name', '').strip()
        hardware_id = data.get('hardware_id', '').strip()
        password = data.get('password', '').strip()

        if not pc_name or not hardware_id or not password:
            return jsonify({"success": False, "message": "Missing required fields"}), 400

        conn = sqlite3.connect('licenses.db', timeout=10)
        c = conn.cursor()
        c.execute("SELECT value FROM settings WHERE key = 'global_password_hash'")
        result = c.fetchone()
        
        if not result:
            return jsonify({"success": False, "message": "Global password not configured."}), 401

        stored_hash = result[0]
        if not verify_password(password, stored_hash):
            return jsonify({"success": False, "message": "Invalid global password"}), 401

        now = datetime.now(timezone.utc).isoformat()
        token = secrets.token_urlsafe(32)
        last_seen = now
        client_ip = request.remote_addr  # 🔥 ক্লায়েন্টের আইপি অ্যাড্রেস ক্যাপচার করা

        # 🔥 লোকেশন (IP) যুক্ত করা হয়েছে
        c.execute("INSERT INTO users (pc_name, hardware_id, location, is_active, activated_at, session_token, last_seen) VALUES (?, ?, ?, 1, ?, ?, ?)", 
                  (pc_name, hardware_id, client_ip, now, token, last_seen))
        user_id = c.lastrowid
        
        c.execute("INSERT INTO user_history (user_id, action, details, timestamp) VALUES (?, ?, ?, ?)", 
                  (user_id, "ACTIVATE", f"New Instance: {pc_name}", now))
        conn.commit()
        logger.info(f"New user activated: {pc_name} (ID: {user_id})")
        return jsonify({"success": True, "message": "New instance activated", "session_token": token})
    except Exception as e:
        logger.error(f"Verify error: {e}")
        return jsonify({"success": False, "message": str(e)}), 500
    finally:
        if conn: conn.close()

@app.route('/api/client/status', methods=['POST'])
def client_status():
    conn = None
    try:
        data = request.get_json()
        token = data.get('session_token')
        if not token: return jsonify({"error": "Missing token"}), 400

        conn = sqlite3.connect('licenses.db', timeout=10)
        c = conn.cursor()
        c.execute("SELECT is_active FROM users WHERE session_token = ?", (token,))
        result = c.fetchone()
        if not result:
            return jsonify({"active": False, "message": "Invalid session"}), 200

        now = datetime.now(timezone.utc).isoformat()
        c.execute("UPDATE users SET last_seen = ? WHERE session_token = ?", (now, token))
        conn.commit()
        return jsonify({"active": bool(result[0])}), 200
    except Exception as e:
        logger.error(f"Status error: {e}")
        return jsonify({"active": False, "message": str(e)}), 500
    finally:
        if conn: conn.close()

@app.route('/api/client/device_info', methods=['POST'])
def client_device_info():
    conn = None
    try:
        data = request.get_json()
        token = data.get('session_token')
        devices = data.get('devices', [])

        if not token: return jsonify({"error": "Missing token"}), 400

        conn = sqlite3.connect('licenses.db', timeout=10)
        c = conn.cursor()
        c.execute("SELECT id FROM users WHERE session_token = ?", (token,))
        user = c.fetchone()
        if not user:
            return jsonify({"error": "Invalid session"}), 401

        user_id = user[0]
        c.execute("DELETE FROM device_reports WHERE user_id = ?", (user_id,))
        now = datetime.now(timezone.utc).isoformat()
        for dev in devices:
            c.execute("INSERT INTO device_reports (user_id, serial, state, device_model, reported_at) VALUES (?, ?, ?, ?, ?)",
                      (user_id, dev.get("serial", "Unknown"), dev.get("state", "Unknown"), dev.get("model", "Unknown"), now))
        conn.commit()
        logger.info(f"Device info updated for user {user_id}: {len(devices)} devices")
        return jsonify({"success": True, "message": "Devices info updated"}), 200
    except Exception as e:
        logger.error(f"Device info error: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        if conn: conn.close()

# ================= Admin API =================
@app.route('/api/admin/users', methods=['GET'])
def admin_get_users():
    if not session.get('dashboard_logged_in'):
        return jsonify({"error": "Unauthorized"}), 401
    try:
        conn = sqlite3.connect('licenses.db', timeout=10)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute('''
            SELECT u.id, u.pc_name, u.location, u.is_active, u.activated_at, u.deactivated_at,
            (SELECT device_model FROM device_reports WHERE user_id = u.id ORDER BY reported_at DESC LIMIT 1) as device_model
            FROM users u ORDER BY u.id DESC
        ''')
        rows = c.fetchall()
        return jsonify({"users": [dict(row) for row in rows]}), 200
    finally:
        conn.close()

@app.route('/api/admin/deactivate', methods=['POST'])
def admin_deactivate():
    if not session.get('dashboard_logged_in'):
        return jsonify({"error": "Unauthorized"}), 401
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        if not user_id: return jsonify({"error": "User ID required"}), 400

        now = datetime.now(timezone.utc).isoformat()
        conn = sqlite3.connect('licenses.db', timeout=10)
        c = conn.cursor()
        c.execute("UPDATE users SET is_active = 0, session_token = NULL, last_seen = NULL, deactivated_at = ? WHERE id = ?", (now, user_id))
        c.execute("INSERT INTO user_history (user_id, action, details, timestamp) VALUES (?, ?, ?, ?)", 
                  (user_id, "DEACTIVATE", f"Admin deactivated instance {user_id}", now))
        conn.commit()
        logger.info(f"User {user_id} deactivated by admin")
        return jsonify({"success": True, "message": "Instance deactivated successfully"}), 200
    except Exception as e:
        logger.error(f"Deactivate error: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

@app.route('/api/admin/set_password', methods=['POST'])
def admin_set_password():
    if not session.get('dashboard_logged_in'):
        return jsonify({"error": "Unauthorized"}), 401
    try:
        data = request.get_json()
        new_password = data.get('new_password')
        if not new_password or len(new_password) < 8:
            return jsonify({"error": "Password must be at least 8 characters"}), 400
        
        now = datetime.now(timezone.utc).isoformat()
        new_hash = hash_password(new_password)
        conn = sqlite3.connect('licenses.db', timeout=10)
        c = conn.cursor()
        c.execute("INSERT INTO settings (key, value) VALUES ('global_password_hash', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", (new_hash,))
        c.execute("UPDATE users SET session_token = NULL, last_seen = NULL, is_active = 0, deactivated_at = ? WHERE is_active = 1", (now,))
        c.execute("INSERT INTO user_history (user_id, action, details, timestamp) VALUES (?, ?, ?, ?)", 
                  (None, "GLOBAL_PASSWORD_CHANGE", f"Global password changed by admin", now))
        conn.commit()
        logger.info("Global password changed by admin")
        return jsonify({"success": True, "message": "Global password updated successfully."}), 200
    except Exception as e:
        logger.error(f"Set password error: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

@app.route('/api/admin/history', methods=['GET'])
def admin_get_history():
    if not session.get('dashboard_logged_in'):
        return jsonify({"error": "Unauthorized"}), 401
    try:
        conn = sqlite3.connect('licenses.db', timeout=10)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute('''
            SELECT h.id, COALESCE(u.pc_name, 'SYSTEM') AS pc_name, h.action, h.details, h.timestamp
            FROM user_history h LEFT JOIN users u ON h.user_id = u.id
            ORDER BY h.timestamp DESC LIMIT 50
        ''')
        rows = c.fetchall()
        return jsonify({"history": [dict(row) for row in rows]}), 200
    finally:
        conn.close()

# ================= 🔥 NEW: JSON Admin Login (for Lovable) =================
@app.route('/api/admin/login', methods=['POST'])
def api_admin_login():
    data = request.get_json()
    password = data.get('password', '')
    if verify_password(password, ADMIN_PASSWORD_HASH):
        session.clear()
        session["dashboard_logged_in"] = True
        session.permanent = True
        return jsonify({"success": True, "message": "Login successful"})
    else:
        return jsonify({"success": False, "message": "Invalid password"}), 401

# ================= 🔥 Signature Generator (for Lovable) =================
@app.route('/api/admin/generate_signature', methods=['POST'])
def admin_generate_signature():
    if not session.get('dashboard_logged_in'):
        return jsonify({"error": "Unauthorized"}), 401
    try:
        data = request.get_json()
        challenge = data.get('challenge', '').strip()
        if not challenge:
            return jsonify({"error": "Challenge required"}), 400

        script_path = os.path.join(os.path.dirname(__file__), "make_password_blob.py")
        if not os.path.exists(script_path):
            return jsonify({"error": "make_password_blob.py not found on server."}), 500

        result = subprocess.run(
            ['python3', script_path, challenge],
            capture_output=True, text=True, timeout=10,
            cwd=os.path.dirname(__file__)
        )
        if result.returncode == 0:
            return jsonify({"signature": result.stdout.strip()}), 200
        else:
            return jsonify({"error": f"Script error: {result.stderr.strip()}"}), 500
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Signature generation timed out."}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ================= Health Check =================
@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'healthy', 'timestamp': datetime.now(timezone.utc).isoformat(), 'server': socket.gethostname()})

# ================= Admin HTML Login & Dashboard =================
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == "POST":
        entered_password = request.form.get("password", "")
        if not entered_password:
            error = "Please enter your password."
        elif check_password_hash(ADMIN_PASSWORD_HASH, entered_password):
            session.clear()
            session["dashboard_logged_in"] = True
            session.permanent = True
            return redirect(url_for("index"))
        else:
            error = "Invalid password."
    return render_template_string(LOGIN_PAGE, error=error)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/')
def index():
    if not session.get('dashboard_logged_in'):
        return redirect(url_for('login'))
    return render_template_string(DASHBOARD_HTML)

# ================= 🔥 External Global Password Protected HTML Page: /code =================
@app.route('/code', methods=['GET', 'POST'])
def code_generator():
    global_password = ""
    challenge = ""
    output = ""
    error = ""
    
    if request.method == 'POST':
        global_password = request.form.get('global_password', '').strip()
        challenge = request.form.get('challenge', '').strip()

        if not global_password:
            error = "Please enter the Global Password."
        else:
            conn = sqlite3.connect('licenses.db', timeout=5)
            c = conn.cursor()
            c.execute("SELECT value FROM settings WHERE key = 'global_password_hash'")
            result = c.fetchone()
            conn.close()

            if not result:
                error = "Global password is not configured in the system."
            else:
                stored_hash = result[0]
                if not verify_password(global_password, stored_hash):
                    error = "Invalid Global Password."
                elif not challenge:
                    error = "Please enter a valid 16-character challenge."
                else:
                    try:
                        script_path = os.path.join(os.path.dirname(__file__), "make_password_blob.py")
                        if not os.path.exists(script_path):
                            error = "make_password_blob.py not found on server."
                        else:
                            result = subprocess.run(
                                ['python3', script_path, challenge],
                                capture_output=True, text=True, timeout=10,
                                cwd=os.path.dirname(__file__)
                            )
                            if result.returncode == 0:
                                output = result.stdout.strip()
                            else:
                                error = f"Script error (code {result.returncode}): {result.stderr.strip()}"
                    except subprocess.TimeoutExpired:
                        error = "Signature generation timed out."
                    except Exception as e:
                        error = f"Execution error: {e}"

    return render_template_string(CODE_PAGE, 
                                   global_password=global_password,
                                   challenge=challenge, 
                                   output=output, 
                                   error=error)

# ================= UI Templates =================
LOGIN_PAGE = r'''<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="color-scheme" content="dark">
  <title>Admin login</title>
  <style>
    :root{color-scheme:dark;--bg:#080b14;--panel:#111827;--line:#263247;--text:#eef2ff;--muted:#9aa8bf;--brand:#8b5cf6;--brand2:#06b6d4;--danger:#fb7185}
    *{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px;background:radial-gradient(circle at 20% 10%,#1d1740,transparent 35%),var(--bg);color:var(--text);font:15px/1.5 Inter,ui-sans-serif,system-ui,-apple-system,Segoe UI,sans-serif}
    .box{width:min(100%,410px);padding:34px;border:1px solid var(--line);border-radius:24px;background:color-mix(in srgb,var(--panel) 92%,transparent);box-shadow:0 24px 70px #0008;backdrop-filter:blur(16px)}
    .logo{width:52px;height:52px;display:grid;place-items:center;border-radius:16px;background:linear-gradient(135deg,var(--brand),var(--brand2));font-size:25px;margin-bottom:22px}.eyebrow{color:#a5b4fc;font-size:12px;text-transform:uppercase;letter-spacing:.14em;font-weight:800}h1{margin:7px 0 8px;font-size:29px;letter-spacing:-.03em}p{margin:0 0 24px;color:var(--muted)}label{display:block;margin:0 0 8px;font-weight:700}input{width:100%;padding:13px 14px;border:1px solid var(--line);border-radius:12px;background:#0b1120;color:var(--text);outline:0;font:inherit}input:focus{border-color:var(--brand2);box-shadow:0 0 0 4px #06b6d422}button{width:100%;margin-top:16px;padding:13px;border:0;border-radius:12px;background:linear-gradient(135deg,var(--brand),var(--brand2));color:white;font:800 15px inherit;cursor:pointer}button:hover{filter:brightness(1.1)}.error{margin-top:15px;padding:11px 13px;border-radius:10px;background:#7f1d1d55;color:#fecdd3;border:1px solid #fb718566}
  </style>
</head>
<body><main class="box"><div class="logo">🔐</div><div class="eyebrow">Secure workspace</div><h1>Admin panel</h1><p>Sign in to manage connected devices and activity.</p><form method="post" autocomplete="on"><label for="password">Admin password</label><input id="password" type="password" name="password" placeholder="Enter your password" autocomplete="current-password" required autofocus><button type="submit">Sign in</button></form>{% if error %}<div class="error" role="alert">{{ error }}</div>{% endif %}</main></body>
</html>'''

DASHBOARD_HTML = r'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="dark"><title>Admin panel</title>
<style>
:root{color-scheme:dark;--bg:#080b14;--panel:#111827;--panel2:#0d1424;--line:#263247;--text:#eef2ff;--muted:#9aa8bf;--brand:#8b5cf6;--cyan:#06b6d4;--green:#34d399;--red:#fb7185;--yellow:#fbbf24}*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 85% 0,#1e1642,transparent 30%),var(--bg);color:var(--text);font:14px/1.5 Inter,ui-sans-serif,system-ui,-apple-system,Segoe UI,sans-serif}.shell{width:min(1400px,100%);margin:auto;padding:24px}.topbar{display:flex;justify-content:space-between;align-items:center;gap:18px;margin-bottom:24px}.brand{display:flex;align-items:center;gap:12px}.mark{width:44px;height:44px;display:grid;place-items:center;border-radius:14px;background:linear-gradient(135deg,var(--brand),var(--cyan));font-size:21px}h1,h2,h3{margin:0;letter-spacing:-.025em}h1{font-size:24px}.sub{color:var(--muted);margin-top:3px}.logout{color:#fecdd3;text-decoration:none;border:1px solid #fb718544;padding:9px 13px;border-radius:10px}.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-bottom:18px}.card{background:linear-gradient(145deg,#141d31,#0e1525);border:1px solid var(--line);border-radius:18px;padding:20px;box-shadow:0 12px 35px #0002}.stat-label{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.08em}.stat-value{font-size:28px;font-weight:850;margin-top:7px}.card h2{font-size:17px;margin-bottom:15px}.toolbar{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:15px}.tabs{display:flex;gap:8px}.tab{border:1px solid var(--line);background:var(--panel2);color:var(--muted);padding:9px 14px;border-radius:10px;cursor:pointer;font:700 13px inherit}.tab.active{color:#fff;background:linear-gradient(135deg,#6d43cf,#087f9d);border-color:transparent}.table-wrap{overflow:auto;border:1px solid var(--line);border-radius:13px}table{width:100%;border-collapse:collapse;min-width:900px}th,td{padding:13px 14px;text-align:left;border-bottom:1px solid #26324799;white-space:nowrap}th{color:#a5b4fc;background:#0b1120;font-size:12px;text-transform:uppercase;letter-spacing:.06em}tr:last-child td{border-bottom:0}td{color:#dbe4f5}.status{display:inline-flex;align-items:center;gap:6px;font-weight:750}.active{color:var(--green)}.inactive{color:var(--red)}.btn{border:0;border-radius:9px;padding:9px 12px;color:#fff;background:#2563eb;cursor:pointer;font:750 13px inherit}.btn:hover,.tab:hover{filter:brightness(1.12)}.danger{background:#be123c}.refresh{background:#334155}.settings{display:flex;gap:10px;align-items:center}.settings input{max-width:360px;flex:1}input{padding:11px 12px;border:1px solid var(--line);border-radius:10px;background:#0b1120;color:#fff;outline:0;font:inherit}input:focus{border-color:var(--cyan);box-shadow:0 0 0 4px #06b6d422}.message{min-height:22px;margin-top:10px;color:var(--muted)}.empty{text-align:center;color:var(--muted);padding:25px}.hidden{display:none!important}@media(max-width:800px){.shell{padding:15px}.topbar{align-items:flex-start}.grid{grid-template-columns:1fr}.settings{align-items:stretch;flex-direction:column}.settings input{max-width:none;width:100%}.settings .btn{width:100%}}
</style></head>
<body><main class="shell">
<header class="topbar"><div class="brand"><div class="mark">🔐</div><div><h1>Admin panel</h1><div class="sub">Device access and audit activity</div></div></div><a class="logout" href="/logout">Log out</a></header>
<section class="grid"><div class="card"><div class="stat-label">Total users</div><div class="stat-value" id="total-users">—</div></div><div class="card"><div class="stat-label">Active devices</div><div class="stat-value active" id="active-users">—</div></div><div class="card"><div class="stat-label">Last sync</div><div class="stat-value" id="last-sync" style="font-size:18px">—</div></div></section>
<section class="card"><h2>Global client password</h2><div class="settings"><input id="newPwd" type="password" minlength="8" placeholder="New password (minimum 8 characters)" autocomplete="new-password"><button class="btn" id="passwordBtn">Update password</button></div><div id="msg" class="message" role="status" aria-live="polite"></div></section>
<section class="card" style="margin-top:18px"><div class="toolbar"><div class="tabs"><button class="tab active" data-tab="users">Users</button><button class="tab" data-tab="history">History</button></div><button class="btn refresh" id="refreshBtn">↻ Refresh</button></div>
<div id="tab-users"><div class="table-wrap"><table><thead><tr><th>ID</th><th>PC name</th><th>Location</th><th>Device model</th><th>Status</th><th>Activated</th><th>Deactivated</th><th>Action</th></tr></thead><tbody id="users-body"></tbody></table></div></div>
<div id="tab-history" class="hidden"><div class="table-wrap"><table><thead><tr><th>ID</th><th>PC name</th><th>Action</th><th>Details</th><th>Timestamp</th></tr></thead><tbody id="history-body"></tbody></table></div></div></section></main>
<script>
'use strict';
let busy=false;
const $=id=>document.getElementById(id);
const escapeHTML=value=>String(value??'-').replace(/[&<>'"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));
async function api(url,options={}){const r=await fetch(url,{credentials:'same-origin',...options});if(r.status===401||r.status===403){location.href='/login';throw Error('Session expired');}let data={};try{data=await r.json()}catch{}if(!r.ok)throw Error(data.error||`Request failed (${r.status})`);return data}
function cell(value){const td=document.createElement('td');td.textContent=value??'-';return td}
async function fetchUsers(){const data=await api('/api/admin/users');const body=$('users-body');body.replaceChildren();const users=Array.isArray(data.users)?data.users:[];$('total-users').textContent=users.length;$('active-users').textContent=users.filter(u=>Boolean(u.is_active)).length;$('last-sync').textContent=new Date().toLocaleTimeString();if(!users.length){body.innerHTML='<tr><td colspan="8" class="empty">No users found.</td></tr>';return}users.forEach(u=>{const tr=document.createElement('tr');[u.id,u.pc_name,u.location,u.device_model].forEach(v=>tr.appendChild(cell(v)));const status=cell('');status.innerHTML=`<span class="status ${u.is_active?'active':'inactive'}">${u.is_active?'● Active':'● Inactive'}</span>`;tr.appendChild(status);tr.appendChild(cell(u.activated_at));tr.appendChild(cell(u.deactivated_at));const action=document.createElement('td');if(u.is_active){const b=document.createElement('button');b.className='btn danger';b.textContent='Deactivate';b.onclick=()=>deactivate(u.id);action.appendChild(b)}else action.textContent='Deactivated';tr.appendChild(action);body.appendChild(tr)})}
async function fetchHistory(){const data=await api('/api/admin/history');const body=$('history-body');body.replaceChildren();const history=Array.isArray(data.history)?data.history:[];if(!history.length){body.innerHTML='<tr><td colspan="5" class="empty">No history yet.</td></tr>';return}history.forEach(h=>{const tr=document.createElement('tr');[h.id,h.pc_name,h.action,h.details,h.timestamp].forEach(v=>tr.appendChild(cell(v)));body.appendChild(tr)})}
async function refresh(){if(busy)return;busy=true;try{await Promise.all([fetchUsers(),fetchHistory()])}catch(e){$('msg').textContent=e.message}finally{busy=false}}
async function deactivate(id){if(!window.confirm('Deactivate this device?'))return;try{await api('/api/admin/deactivate',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({user_id:id})});await refresh()}catch(e){$('msg').textContent=e.message}}
$('passwordBtn').onclick=async()=>{const pwd=$('newPwd').value;if(pwd.length<8){$('msg').textContent='Use at least 8 characters.';return}try{const d=await api('/api/admin/set_password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({new_password:pwd})});$('msg').textContent=d.message||'Password updated.';$('newPwd').value=''}catch(e){$('msg').textContent=e.message}}
$('refreshBtn').onclick=refresh;document.querySelectorAll('.tab').forEach(button=>button.onclick=()=>{document.querySelectorAll('.tab').forEach(b=>b.classList.remove('active'));document.querySelectorAll('[id^="tab-"]').forEach(x=>x.classList.add('hidden'));button.classList.add('active');$('tab-'+button.dataset.tab).classList.remove('hidden')});
refresh();setInterval(refresh,10000);
</script></body></html>'''

# ================= 🔥 External Code Generator UI (Uses Global Password) =================
CODE_PAGE = r'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="dark"><title>Global Code Generator</title>
<style>
:root{color-scheme:dark;--bg:#080b14;--panel:#111827;--panel2:#0d1424;--line:#263247;--text:#eef2ff;--muted:#9aa8bf;--brand:#8b5cf6;--cyan:#06b6d4;--green:#34d399;--red:#fb7185;--yellow:#fbbf24}*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 85% 0,#1e1642,transparent 30%),var(--bg);color:var(--text);font:14px/1.5 Inter,ui-sans-serif,system-ui,-apple-system,Segoe UI,sans-serif}.shell{width:min(800px,100%);margin:auto;padding:24px}.topbar{display:flex;justify-content:space-between;align-items:center;gap:18px;margin-bottom:24px}.brand{display:flex;align-items:center;gap:12px}.mark{width:44px;height:44px;display:grid;place-items:center;border-radius:14px;background:linear-gradient(135deg,var(--brand),var(--cyan));font-size:21px}h1{margin:0;font-size:24px}.logout{display:none}.card{background:linear-gradient(145deg,#141d31,#0e1525);border:1px solid var(--line);border-radius:18px;padding:20px;box-shadow:0 12px 35px #0002}.form-group{margin-bottom:15px}label{display:block;margin-bottom:5px;font-weight:700;color:var(--muted)}input{width:100%;padding:11px 12px;border:1px solid var(--line);border-radius:10px;background:#0b1120;color:#fff;outline:0;font:inherit;box-sizing:border-box}input:focus{border-color:var(--cyan);box-shadow:0 0 0 4px #06b6d422}.btn{display:inline-block;padding:11px 20px;border:0;border-radius:10px;background:linear-gradient(135deg,var(--brand),#6366f1);color:#fff;font-weight:700;cursor:pointer}.btn:hover{filter:brightness(1.1)}.output-box{background:#0b1120;padding:15px;border-radius:10px;border:1px solid var(--line);margin-top:10px;font-family:monospace;overflow-x:auto;white-space:pre-wrap;word-break:break-all}.error{color:var(--red)}.success{color:var(--green)}.empty{text-align:center;color:var(--muted);padding:25px}.note{color:var(--muted);font-size:13px;margin-bottom:15px}
</style>
</head>
<body><main class="shell">
<header class="topbar"><div class="brand"><div class="mark">🔐</div><div><h1>Code Generator</h1><div class="sub">Protected by Global Client Password</div></div></div></header>
<section class="card"><h2>Challenge‑Response Signature</h2>
<p class="note">Enter the same global password used by the ADB Commander client software to generate a signature.</p>
<form method="post" autocomplete="off">
<div class="form-group"><label for="global_password">Global Password</label><input type="password" id="global_password" name="global_password" value="{{ global_password }}" placeholder="Enter the global password" required></div>
<div class="form-group"><label for="challenge">Challenge</label><input type="text" id="challenge" name="challenge" value="{{ challenge }}" placeholder="e.g. a1b2c3d4e5f6g7h8" pattern="[a-z0-9]{16}" title="16 lowercase alphanumeric characters" required></div>
<button class="btn" type="submit">Generate Signature</button>
</form>
{% if error %}
<div class="output-box error">{{ error }}</div>
{% elif output %}
<div class="output-box success">{{ output }}</div>
{% endif %}
</section></main></body>
</html>'''

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
