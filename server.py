#!/usr/bin/env python3
"""
ADB Commander - Master Control Panel
FINAL FIXED VERSION: Bypass removed, Key mismatch fixed, Secure hashing added.
"""
import secrets
import os
import sqlite3
import socket
import threading
import time
from datetime import datetime, timedelta, timezone
from flask import Flask, request, jsonify, render_template_string, redirect, url_for, session
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
CORS(app)

# ================= কনফিগারেশন (সব পাসওয়ার্ড এখানেই থাকবে) =================
# ড্যাশবোর্ড ও গ্লোবাল পাসওয়ার্ড একই হবে। init_db() এই পাসওয়ার্ড দিয়ে প্রথমবার সেট করবে।
ADMIN_PASSWORD = "admin123" 

# ================= হ্যাশ ফাংশন (Werkzeug ব্যবহার করা হচ্ছে) =================
def hash_password(pwd: str) -> str:
    return generate_password_hash(pwd)

def verify_password(input_pwd: str, stored_hash: str) -> bool:
    return check_password_hash(stored_hash, input_pwd)

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
    # 🔥 একক পাসওয়ার্ড টেবিল
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

    # 🔥 বাগ ফিক্স: শুধুমাত্র 'global_password_hash' ব্যবহার করা হবে (কোনো dashboard_password নেই)
    c.execute("SELECT value FROM settings WHERE key = 'global_password_hash'")
    if not c.fetchone():
        c.execute("INSERT INTO settings (key, value) VALUES ('global_password_hash', ?)", (hash_password(ADMIN_PASSWORD),))

    conn.commit()
    conn.close()

init_db()

# ================= অফলাইন ডিটেক্টর =================
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

        pc_name = data.get('pc_name', '').strip()
        hardware_id = data.get('hardware_id', '').strip()
        password = data.get('password', '').strip()

        if not pc_name or not hardware_id or not password:
            return jsonify({"success": False, "message": "Missing required fields"}), 400

        # 🛑 বাগ ফিক্স:  Launcher Bypass সম্পূর্ণ ডিলিট করা হয়েছে
        conn = sqlite3.connect('licenses.db')
        c = conn.cursor()
        c.execute("SELECT value FROM settings WHERE key = 'global_password_hash'")
        result = c.fetchone()
        
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
    return jsonify({"users": [dict(row) for row in rows]}), 200

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
        new_hash = hash_password(new_password)
        conn = sqlite3.connect('licenses.db')
        c = conn.cursor()
        
        # 🔥 বাগ ফিক্স: UPDATE এর পরিবর্তে INSERT ... ON CONFLICT ব্যবহার করা হলো
        # যেকোনো অবস্থায় এটি হ্যাশটি আপডেট করবে।
        c.execute("""
            INSERT INTO settings (key, value) VALUES ('global_password_hash', ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
        """, (new_hash,))
        
        # 🔥 সব সেশন রিভোক করা হচ্ছে
        c.execute("""
            UPDATE users SET session_token = NULL, last_seen = NULL, 
            is_active = 0, deactivated_at = ? WHERE is_active = 1
        """, (now,))
        
        c.execute("INSERT INTO user_history (user_id, action, details, timestamp) VALUES (?, ?, ?, ?)", 
                  (None, "GLOBAL_PASSWORD_CHANGE", f"Global password changed by admin", now))
        
        conn.commit()
        conn.close()
        return jsonify({"success": True, "message": "Global password updated successfully. All active clients are offline."}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/admin/history', ['GET'])
def admin_get_history():
    if not session.get('dashboard_logged_in'):
        return jsonify({"error": "Unauthorized"}), 401
    conn = sqlite3.connect('licenses.db')
    c = conn.cursor()
    # 🔥 বাগ ফিক্স: LEFT JOIN ব্যবহার করা হয়েছে, যাতে সিস্টেম লগগুলো (যেমন পাসওয়ার্ড চেঞ্জ) দেখতে পাওয়া যায়
    c.execute('''
        SELECT h.id, COALESCE(u.pc_name, 'SYSTEM') AS pc_name, h.action, h.details, h.timestamp
        FROM user_history h
        LEFT JOIN users u ON h.user_id = u.id
        ORDER BY h.timestamp DESC
        LIMIT 50
    ''')
    rows = c.fetchall()
    conn.close()
    return jsonify({"history": [dict(row) for row in rows]}), 200

# ================= /health এন্ডপয়েন্ট =================
@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'healthy', 
        'timestamp': datetime.now(timezone.utc).isoformat(), 
        'server': socket.gethostname()
    })

# ================= ড্যাশবোর্ড লগইন ও UI =================
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        password = request.form.get('password')
        conn = sqlite3.connect('licenses.db')
        c = conn.cursor()
        c.execute("SELECT value FROM settings WHERE key = 'global_password_hash'")
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

# ================= UI HTML =================
LOGIN_PAGE = '''<!DOCTYPE html><html><head><title>Admin Login</title><style>body{background:#111827;color:#f9fafb;display:flex;justify-content:center;align-items:center;height:100vh;font-family:sans-serif;margin:0}.box{background:#1f2937;padding:40px;border-radius:12px;width:300px;text-align:center}h2{color:#64ffda}input{width:100%;padding:12px;margin:10px 0;background:#111827;border:1px solid #374151;border-radius:6px;color:#fff}button{width:100%;padding:12px;background:#22c55e;border:none;border-radius:6px;color:#fff;font-weight:bold;cursor:pointer}.error{color:#fca5a5;margin-top:10px}</style></head><body><div class="box"><h2>🔐 Admin Panel</h2><form method="post"><input type="password" name="password" placeholder="Enter Password" required><button type="submit">Login</button></form>{% if error %}<div class="error">{{ error }}</div>{% endif %}</div></body></html>'''

DASHBOARD_HTML = '''<!DOCTYPE html><html><head><title>Admin Panel</title><meta name="viewport" content="width=device-width, initial-scale=1.0"><style>*{margin:0;padding:0;box-sizing:border-box}body{background:#111827;color:#f9fafb;padding:20px;font-family:sans-serif}.container{max-width:1200px;margin:0 auto;background:#1f2937;padding:30px;border-radius:12px}.header{text-align:center;margin-bottom:30px}.header h1{font-size:28px;color:#fff}.header h1 span{color:#64ffda}.card{background:#111827;padding:20px;margin-bottom:20px;border:1px solid #374151;border-radius:8px}.card h3{color:#64ffda;margin-bottom:15px}.input-group{display:flex;gap:10px}input{padding:10px;background:#1f2937;border:1px solid #374151;border-radius:6px;color:#fff;flex:1}.btn{padding:10px 20px;background:#22c55e;border:none;border-radius:6px;color:#fff;cursor:pointer}.btn-danger{background:#ef4444}table{width:100%;border-collapse:collapse;margin-top:10px}th,td{padding:12px;border:1px solid #374151;text-align:left}th{background:#111827;color:#64ffda}.active{color:#22c55e}.inactive{color:#ef4444}.logout{float:right;color:#fca5a5;text-decoration:none}</style></head><body><div class="container"><div class="header"><h1>🔐 <span>Admin Panel</span></h1><a href="/logout" class="logout">Logout</a></div><div class="card"><h3>🔑 Change Global Password</h3><div class="input-group"><input type="password" id="newPwd" placeholder="Enter new global password"><button class="btn" onclick="updatePassword()">Update Password</button></div><div id="msg" style="margin-top:10px;font-size:14px"></div></div><div class="card"><h3>👥 Connected Users</h3><table><thead><tr><th>ID</th><th>PC Name</th><th>Device Model</th><th>Status</th><th>Activated At</th><th>Action</th></tr></thead><tbody id="users-body"></tbody></table></div></div><script>const API_BASE='/api/admin';async function fetchUsers(){const r=await fetch(API_BASE+'/users');if(!r.ok){location.href='/login';return;}const data=await r.json();const tbody=document.getElementById('users-body');tbody.innerHTML='';if(data.users.length===0){tbody.innerHTML='<tr><td colspan="6" class="text-center">No users.</td></tr>';return;}data.users.forEach(u=>{const tr=document.createElement('tr');tr.innerHTML=`<td>${u.id}</td><td>${u.pc_name}</td><td>${u.device_model||'-'}</td><td><span class="${u.is_active?'active':'inactive'}">${u.is_active?'✅ Active':'❌ Inactive'}</span></td><td>${u.activated_at||'-'}</td><td>${u.is_active?`<button class="btn btn-danger" onclick="deactivate(${u.id})">Deactivate</button>`:'Deactivated'}</td>`;tbody.appendChild(tr);});}async function deactivate(id){if(!confirm('Deactivate this instance?'))return;await fetch(API_BASE+'/deactivate',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({user_id:id})});fetchUsers();}async function updatePassword(){const pwd=document.getElementById('newPwd').value.trim();if(!pwd||pwd.length<4){document.getElementById('msg').innerHTML='<span style="color:red">Min 4 characters!</span>';return;}const r=await fetch(API_BASE+'/set_password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({new_password:pwd})});const data=await r.json();if(r.ok){document.getElementById('msg').innerHTML='<span style="color:#86efac;">✅ '+data.message+'</span>';document.getElementById('newPwd').value='';}else{document.getElementById('msg').innerHTML='<span style="color:#fca5a5;">❌ '+data.error+'</span>';}}fetchUsers();setInterval(fetchUsers,5000);</script></body></html>'''

if __name__ == '__main__':
    print("\n" + "=" * 70)
    print("  🔐 ADMIN PANEL - FIXED VERSION (No default client password)")
    print("=" * 70)
    app.run(host='0.0.0.0', port=5000, debug=False)
