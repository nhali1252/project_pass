#!/usr/bin/env python3
"""
ADB Commander - Master Control Panel
Final Version:
- No default global password (must be set via dashboard)
"""
import hashlib
import json
import secrets
import os
import sqlite3
import socket
import threading
import time
from datetime import datetime, timedelta, timezone
from flask import Flask, request, jsonify, render_template_string, redirect, url_for, session
from flask_cors import CORS

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
CORS(app)

# ================= কনফিগারেশন =================
# শুধুমাত্র ড্যাশবোর্ড লগইনের জন্য পাসওয়ার্ড
ADMIN_PASSWORD = "admin123"

# ================= হ্যাশ ফাংশন =================
def hash_password(pwd: str) -> str:
    return hashlib.sha256(pwd.encode()).hexdigest()

def verify_password(input_pwd: str, stored_hash: str) -> bool:
    return hash_password(input_pwd) == stored_hash

# ================= ডেটাবেস সেটআপ =================
def init_db():
    conn = sqlite3.connect('licenses.db')
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
        user_id INTEGER NOT NULL,
        action TEXT,
        details TEXT,
        timestamp TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )''')

    # শুধুমাত্র ড্যাশবোর্ড পাসওয়ার্ড হ্যাশ সেট করা হবে (global_password_hash ইচ্ছাকৃতভাবে বাদ দেওয়া হয়েছে)
    c.execute("SELECT value FROM settings WHERE key = 'dashboard_password'")
    if not c.fetchone():
        c.execute("INSERT INTO settings (key, value) VALUES ('dashboard_password', ?)", (hash_password(ADMIN_PASSWORD),))

    conn.commit()
    conn.close()

init_db()

# ================= অফলাইন ডিটেক্টর থ্রেড =================
def mark_offline_users():
    while True:
        time.sleep(10)
        try:
            conn = sqlite3.connect('licenses.db')
            c = conn.cursor()
            cutoff = (datetime.now(timezone.utc) - timedelta(seconds=30)).isoformat()
            c.execute("UPDATE users SET is_active = 0, deactivated_at = ? WHERE is_active = 1 AND last_seen < ?", (datetime.now(timezone.utc).isoformat(), cutoff))
            conn.commit()
            conn.close()
        except:
            pass

threading.Thread(target=mark_offline_users, daemon=True).start()

# ================= ক্লায়েন্ট API =================
@app.route('/api/client/verify', methods=['POST'])
def client_verify():
    try:
        data = request.get_json()
        if not data: return jsonify({"success": False, "message": "Invalid Request"}), 400

        pc_name = data.get('pc_name')
        hardware_id = data.get('hardware_id')
        password = data.get('password', '').strip()

        if not pc_name or not hardware_id or not password:
            return jsonify({"success": False, "message": "Missing required fields"}), 400

        # লঞ্চারের ডামি চেক
        if pc_name == "LauncherInstance" and hardware_id == "LauncherOnlyID":
            return jsonify({"success": True, "message": "Launcher validated", "session_token": "launcher_dummy"}), 200

        conn = sqlite3.connect('licenses.db')
        c = conn.cursor()
        c.execute("SELECT value FROM settings WHERE key = 'global_password_hash'")
        result = c.fetchone()
        
        # যদি গ্লোবাল পাসওয়ার্ড এখনও সেট করা না থাকে
        if not result:
            conn.close()
            return jsonify({"success": False, "message": "Global password not configured. Please set it in the Admin Panel."}), 401

        stored_hash = result[0]
        
        if not verify_password(password, stored_hash):
            conn.close()
            return jsonify({"success": False, "message": "Invalid global password"}), 401

        now = datetime.now(timezone.utc).isoformat()
        token = secrets.token_urlsafe(32)
        last_seen = now

        c.execute("INSERT INTO users (pc_name, hardware_id, is_active, activated_at, session_token, last_seen) VALUES (?, ?, 1, ?, ?, ?)", 
                  (pc_name, hardware_id, now, token, last_seen))
        user_id = c.lastrowid
        
        c.execute("INSERT INTO user_history (user_id, action, details, timestamp) VALUES (?, ?, ?, ?)", 
                  (user_id, "ACTIVATE", f"New Instance: {pc_name}", now))
        
        conn.commit()
        conn.close()
        return jsonify({"success": True, "message": "New instance activated", "session_token": token})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/api/client/status', methods=['POST'])
def client_status():
    try:
        data = request.get_json()
        token = data.get('session_token')
        if not token: return jsonify({"error": "Missing token"}), 400
        if token == "launcher_dummy": return jsonify({"active": True}), 200

        conn = sqlite3.connect('licenses.db')
        c = conn.cursor()
        c.execute("SELECT is_active FROM users WHERE session_token = ?", (token,))
        result = c.fetchone()
        if not result:
            conn.close()
            return jsonify({"active": False, "message": "Invalid session"}), 200

        now = datetime.now(timezone.utc).isoformat()
        c.execute("UPDATE users SET last_seen = ? WHERE session_token = ?", (now, token))
        conn.commit()
        conn.close()
        return jsonify({"active": bool(result[0])}), 200
    except Exception as e:
        return jsonify({"active": False, "message": str(e)}), 500

@app.route('/api/client/device_info', methods=['POST'])
def client_device_info():
    try:
        data = request.get_json()
        token = data.get('session_token')
        devices = data.get('devices', [])

        if not token: return jsonify({"error": "Missing token"}), 400
        if token == "launcher_dummy": return jsonify({"success": True}), 200

        conn = sqlite3.connect('licenses.db')
        c = conn.cursor()
        c.execute("SELECT id FROM users WHERE session_token = ?", (token,))
        user = c.fetchone()
        if not user:
            conn.close()
            return jsonify({"error": "Invalid session"}), 401

        user_id = user[0]
        c.execute("DELETE FROM device_reports WHERE user_id = ?", (user_id,))
        now = datetime.now(timezone.utc).isoformat()
        for dev in devices:
            c.execute("INSERT INTO device_reports (user_id, serial, state, device_model, reported_at) VALUES (?, ?, ?, ?, ?)",
                      (user_id, dev.get("serial", "Unknown"), dev.get("state", "Unknown"), dev.get("model", "Unknown"), now))
        conn.commit()
        conn.close()
        return jsonify({"success": True, "message": "Devices info updated"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ================= অ্যাডমিন API =================
@app.route('/api/admin/users', methods=['GET'])
def admin_get_users():
    if not session.get('dashboard_logged_in'):
        return jsonify({"error": "Unauthorized"}), 401

    conn = sqlite3.connect('licenses.db')
    c = conn.cursor()
    c.execute('''
        SELECT 
            u.id, u.pc_name, u.location, u.is_active, u.activated_at, u.deactivated_at,
            (SELECT device_model FROM device_reports WHERE user_id = u.id ORDER BY reported_at DESC LIMIT 1) as device_model
        FROM users u
        ORDER BY u.id DESC
    ''')
    rows = c.fetchall()
    conn.close()

    users = []
    for row in rows:
        users.append({
            "id": row[0],
            "pc_name": row[1],
            "location": row[2] or "-",
            "is_active": bool(row[3]),
            "activated_at": row[4] or "-",
            "deactivated_at": row[5] or "-",
            "device_model": row[6] or "Unknown"
        })
    return jsonify({"users": users}), 200

@app.route('/api/admin/deactivate', methods=['POST'])
def admin_deactivate():
    if not session.get('dashboard_logged_in'):
        return jsonify({"error": "Unauthorized"}), 401
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        if not user_id: return jsonify({"error": "User ID required"}), 400

        now = datetime.now(timezone.utc).isoformat()
        conn = sqlite3.connect('licenses.db')
        c = conn.cursor()
        c.execute("UPDATE users SET is_active = 0, deactivated_at = ? WHERE id = ?", (now, user_id))
        c.execute("INSERT INTO user_history (user_id, action, details, timestamp) VALUES (?, ?, ?, ?)", 
                  (user_id, "DEACTIVATE", f"Admin deactivated instance {user_id}", now))
        conn.commit()
        conn.close()
        return jsonify({"success": True, "message": "Instance deactivated successfully"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/admin/set_password', methods=['POST'])
def admin_set_password():
    if not session.get('dashboard_logged_in'):
        return jsonify({"error": "Unauthorized"}), 401
    try:
        data = request.get_json()
        new_password = data.get('new_password')
        if not new_password or len(new_password) < 4:
            return jsonify({"error": "Password must be at least 4 characters"}), 400
        
        now = datetime.now(timezone.utc).isoformat()
        hashed = hash_password(new_password)
        conn = sqlite3.connect('licenses.db')
        c = conn.cursor()
        
        # 1. পাসওয়ার্ড হ্যাশ আপডেট করা
        c.execute("UPDATE settings SET value = ? WHERE key = 'global_password_hash'", (hashed,))
        
        # 2. পুরানো সব সেশন টোকেন রিসেট করে অফলাইন করা (পুরানো পাসওয়ার্ড বাতিল)
        c.execute("UPDATE users SET session_token = NULL, last_seen = NULL, is_active = 0, deactivated_at = ? WHERE is_active = 1", (now,))
        
        # 3. ইতিহাসে লগ করা
        c.execute("INSERT INTO user_history (user_id, action, details, timestamp) VALUES (?, ?, ?, ?)", 
                  (0, "GLOBAL_PASSWORD_CHANGE", f"New global password set by admin", now))
        
        conn.commit()
        conn.close()
        return jsonify({"success": True, "message": "Global password updated successfully. All active clients are offline."}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/admin/history', methods=['GET'])
def admin_get_history():
    if not session.get('dashboard_logged_in'):
        return jsonify({"error": "Unauthorized"}), 401
    conn = sqlite3.connect('licenses.db')
    c = conn.cursor()
    c.execute('''
        SELECT h.id, u.pc_name, h.action, h.details, h.timestamp
        FROM user_history h
        JOIN users u ON h.user_id = u.id
        ORDER BY h.timestamp DESC
        LIMIT 50
    ''')
    rows = c.fetchall()
    conn.close()
    history = [{"id": r[0], "pc_name": r[1], "action": r[2], "details": r[3], "timestamp": r[4]} for r in rows]
    return jsonify({"history": history}), 200

# ================= /health এন্ডপয়েন্ট =================
@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'healthy', 
        'timestamp': datetime.now(timezone.utc).isoformat(), 
        'server': socket.gethostname()
    })

# ================= ড্যাশবোর্ড লগইন =================
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        password = request.form.get('password')
        conn = sqlite3.connect('licenses.db')
        c = conn.cursor()
        c.execute("SELECT value FROM settings WHERE key = 'dashboard_password'")
        result = c.fetchone()
        stored_hash = result[0] if result else ""
        conn.close()
        if verify_password(password, stored_hash):
            session['dashboard_logged_in'] = True
            return redirect(url_for('index'))
        else:
            return render_template_string(LOGIN_PAGE, error="Invalid password")
    return render_template_string(LOGIN_PAGE, error=None)

@app.route('/logout')
def logout():
    session.pop('dashboard_logged_in', None)
    return redirect(url_for('login'))

@app.route('/')
def index():
    if not session.get('dashboard_logged_in'):
        return redirect(url_for('login'))
    return render_template_string(DASHBOARD_HTML)

# ================= এইচটিএমএল টেমপ্লেট =================
LOGIN_PAGE = '''
<!DOCTYPE html>
<html>
<head><title>Admin Panel Login</title>
<style>
body { font-family: sans-serif; background: #111827; color: #f9fafb; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
.login-box { background: #1f2937; padding: 40px; border-radius: 12px; width: 300px; box-shadow: 0 10px 30px rgba(0,0,0,0.5); text-align: center; }
h2 { color: #64ffda; margin-bottom: 20px; }
input { width: 100%; padding: 12px; margin: 10px 0; background: #111827; border: 1px solid #374151; border-radius: 6px; color: #fff; }
button { width: 100%; padding: 12px; background: #22c55e; border: none; border-radius: 6px; color: #fff; font-weight: bold; cursor: pointer; }
button:hover { background: #16a34a; }
.error { color: #fca5a5; margin-top: 10px; font-size: 14px; }
</style>
</head>
<body>
<div class="login-box">
<h2>🔐 Admin Panel</h2>
<form method="post">
<input type="password" name="password" placeholder="Enter Dashboard Password" required>
<button type="submit">Login</button>
</form>
{% if error %}<div class="error">{{ error }}</div>{% endif %}
</div>
</body>
</html>
'''

DASHBOARD_HTML = '''
<!DOCTYPE html>
<html>
<head>
<title>Admin Panel</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: sans-serif; background: #111827; color: #f9fafb; padding: 20px; }
.container { max-width: 1200px; margin: 0 auto; background: #1f2937; border-radius: 12px; padding: 30px; box-shadow: 0 10px 30px rgba(0,0,0,0.5); }
.header { text-align: center; margin-bottom: 30px; }
.header h1 { font-size: 28px; color: #fff; }
.header h1 span { color: #64ffda; }
.card { background: #111827; border-radius: 8px; padding: 20px; margin-bottom: 20px; border: 1px solid #374151; }
.card h3 { color: #64ffda; margin-bottom: 15px; }
.input-group { display: flex; gap: 10px; flex-wrap: wrap; }
input { padding: 10px; background: #1f2937; border: 1px solid #374151; border-radius: 6px; color: #fff; flex: 1; min-width: 200px; }
.btn { padding: 10px 20px; background: #22c55e; color: #fff; border: none; border-radius: 6px; cursor: pointer; font-weight: bold; }
.btn:hover { background: #16a34a; }
.btn-danger { background: #ef4444; }
.btn-danger:hover { background: #dc2626; }
table { width: 100%; border-collapse: collapse; margin-top: 10px; }
th, td { border: 1px solid #374151; padding: 12px; text-align: left; }
th { background: #111827; color: #64ffda; }
.status-active { color: #22c55e; }
.status-inactive { color: #ef4444; }
.empty { text-align: center; color: #6b7280; padding: 20px; }
.tabs { display: flex; gap: 10px; margin-bottom: 20px; }
.tab-btn { padding: 8px 16px; background: #374151; border: none; color: #fff; cursor: pointer; border-radius: 6px; }
.tab-btn.active { background: #64ffda; color: #111827; }
.hidden { display: none; }
</style>
</head>
<body>
<div class="container">
<div class="header">
<h1>🔐 <span>Admin Panel</span></h1>
<p style="color: #9ca3af;">Manage global password, users, devices & history</p>
<a href="/logout" style="color: #fca5a5; float: right; text-decoration: none;">Logout</a>
</div>

<div class="tabs">
<button class="tab-btn active" onclick="switchTab('users')">👤 Users & Devices</button>
<button class="tab-btn" onclick="switchTab('history')">📜 History</button>
</div>

<div id="tab-users">
<div class="card">
<h3>🔑 Change Global Password</h3>
<div class="input-group">
<input type="password" id="newPwd" placeholder="Enter new global password">
<button class="btn" onclick="updatePassword()">Update Password</button>
</div>
<div id="msg" style="margin-top: 10px; font-size: 14px;"></div>
</div>

<div class="card">
<h3>👥 Connected Users & Devices</h3>
<div style="overflow-x: auto;">
<table>
<thead>
<tr>
<th>ID</th><th>PC Name</th><th>Device Model</th><th>Location</th><th>Status</th><th>Activated At</th><th>Deactivated At</th><th>Action</th>
</tr>
</thead>
<tbody id="users-body"></tbody>
</table>
</div>
<div id="loader" class="empty">Loading...</div>
</div>
</div>

<div id="tab-history" class="hidden">
<div class="card">
<h3>📜 User History</h3>
<div style="overflow-x: auto;">
<table>
<thead>
<tr><th>ID</th><th>PC Name</th><th>Action</th><th>Details</th><th>Timestamp</th></tr>
</thead>
<tbody id="history-body"></tbody>
</table>
</div>
</div>
</div>
</div>

<script>
let AUTH = 'logged_in';

function switchTab(tab) {
document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
document.querySelectorAll('.tabs + * .hidden').forEach(e => e.classList.add('hidden'));
document.getElementById('tab-' + tab).classList.remove('hidden');
event.target.classList.add('active');
}

async function fetchUsers() {
const r = await fetch('/api/admin/users');
if (!r.ok) { location.href = '/login'; return; }
const data = await r.json();
const tbody = document.getElementById('users-body');
tbody.innerHTML = '';
if(data.users.length === 0) {
tbody.innerHTML = '<tr><td colspan="8" class="empty">No users registered yet.</td></tr>';
return;
}
data.users.forEach(u => {
const tr = document.createElement('tr');
const statusHTML = u.is_active ? `<span class="status-active">✅ Active</span>` : `<span class="status-inactive">❌ Inactive</span>`;
let actionHTML = u.is_active ? `<button class="btn btn-danger btn-sm" onclick="deactivateUser(${u.id})">Deactivate</button>` : `<span style="color: #6b7280;">Deactivated</span>`;
tr.innerHTML = `
<td>${u.id}</td>
<td>${u.pc_name}</td>
<td>${u.device_model}</td>
<td>${u.location}</td>
<td>${statusHTML}</td>
<td>${u.activated_at}</td>
<td>${u.deactivated_at}</td>
<td>${actionHTML}</td>
`;
tbody.appendChild(tr);
});
}

async function deactivateUser(id) {
if (!confirm('Deactivate this instance? Other instances on this PC will stay active.')) return;
const r = await fetch('/api/admin/deactivate', {
method: 'POST',
headers: { 'Content-Type': 'application/json' },
body: JSON.stringify({ user_id: id })
});
if (r.ok) { alert('Instance deactivated.'); fetchUsers(); fetchHistory(); } else { alert('Failed.'); }
}

async function updatePassword() {
const pwd = document.getElementById('newPwd').value.trim();
if (!pwd || pwd.length < 4) {
document.getElementById('msg').innerHTML = '<span style="color: #fca5a5;">Minimum 4 characters!</span>';
return;
}
const r = await fetch('/api/admin/set_password', {
method: 'POST',
headers: { 'Content-Type': 'application/json' },
body: JSON.stringify({ new_password: pwd })
});
const data = await r.json();
if (r.ok) {
document.getElementById('msg').innerHTML = `<span style="color: #86efac;">✅ ${data.message}</span>`;
document.getElementById('newPwd').value = '';
} else {
document.getElementById('msg').innerHTML = `<span style="color: #fca5a5;">❌ ${data.error}</span>`;
}
}

async function fetchHistory() {
const r = await fetch('/api/admin/history');
if (!r.ok) { return; }
const data = await r.json();
const tbody = document.getElementById('history-body');
tbody.innerHTML = '';
data.history.forEach(h => {
const tr = document.createElement('tr');
tr.innerHTML = `<td>${h.id}</td><td>${h.pc_name}</td><td>${h.action}</td><td>${h.details}</td><td>${h.timestamp}</td>`;
tbody.appendChild(tr);
});
}

fetchUsers();
fetchHistory();
setInterval(() => { fetchUsers(); fetchHistory(); }, 5000);
</script>
</body>
</html>
'''

if __name__ == '__main__':
    print("\n" + "=" * 70)
    print("  🔐 ADMIN PANEL - RUNNING (No default client password)")
    print("=" * 70)
    app.run(host='0.0.0.0', port=5000, debug=False)
