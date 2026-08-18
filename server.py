#!/usr/bin/env python3
"""
ADB Commander - Master Control Panel
Complete System with ADB Device Tracking
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
from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# ================= কনফিগারেশন =================
ADMIN_PASSWORD = "admin123"

# ================= ডেটাবেস সেটআপ =================
def init_db():
    conn = sqlite3.connect('licenses.db')
    c = conn.cursor()
    # ইউজার টেবিল
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        pc_name TEXT NOT NULL,
        hardware_id TEXT UNIQUE NOT NULL,
        location TEXT,
        is_active INTEGER DEFAULT 0,
        activated_at TEXT,
        deactivated_at TEXT,
        session_token TEXT UNIQUE
    )''')
    # সেটিংস টেবিল
    c.execute('''CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)''')
    
    # **NEW**: ডিভাইস রিপোর্ট টেবিল
    c.execute('''CREATE TABLE IF NOT EXISTS device_reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        serial TEXT NOT NULL,
        state TEXT,
        reported_at TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )''')
    
    c.execute("SELECT value FROM settings WHERE key = 'global_password_hash'")
    if not c.fetchone():
        default_hash = hashlib.sha256("admin123".encode()).hexdigest()
        c.execute("INSERT INTO settings (key, value) VALUES ('global_password_hash', ?)", (default_hash,))
    
    conn.commit()
    conn.close()

init_db()

def hash_password(pwd: str) -> str:
    return hashlib.sha256(pwd.encode()).hexdigest()

def verify_password(input_pwd: str, stored_hash: str) -> bool:
    return hash_password(input_pwd) == stored_hash

# ================= ক্লায়েন্ট API =================
@app.route('/api/client/verify', methods=['POST'])
def client_verify():
    try:
        data = request.get_json()
        if not data: return jsonify({"success": False, "message": "Invalid Request"}), 400

        pc_name = data.get('pc_name')
        hardware_id = data.get('hardware_id')
        password = data.get('password')

        if not pc_name or not hardware_id or not password:
            return jsonify({"success": False, "message": "Missing required fields"}), 400

        conn = sqlite3.connect('licenses.db')
        c = conn.cursor()
        c.execute("SELECT value FROM settings WHERE key = 'global_password_hash'")
        result = c.fetchone()
        stored_hash = result[0] if result else ""
        
        if not verify_password(password, stored_hash):
            conn.close()
            return jsonify({"success": False, "message": "Invalid global password"}), 401

        now = datetime.now(timezone.utc).isoformat()
        token = secrets.token_urlsafe(32)
        
        c.execute("SELECT id, is_active FROM users WHERE hardware_id = ?", (hardware_id,))
        user = c.fetchone()

        if user:
            user_id, is_active = user
            if is_active == 1:
                conn.close()
                return jsonify({"success": True, "message": "Software is already active", "session_token": token})
            else:
                c.execute("UPDATE users SET is_active = 1, activated_at = ?, deactivated_at = NULL, session_token = ? WHERE id = ?", (now, token, user_id))
                conn.commit(); conn.close()
                return jsonify({"success": True, "message": "Reactivated successfully", "session_token": token})
        else:
            c.execute("INSERT INTO users (pc_name, hardware_id, is_active, activated_at, session_token) VALUES (?, ?, 1, ?, ?)", (pc_name, hardware_id, now, token))
            conn.commit(); conn.close()
            return jsonify({"success": True, "message": "New user activated", "session_token": token})
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
        conn.close()

        if not result: return jsonify({"active": False, "message": "Invalid session"}), 200
        return jsonify({"active": bool(result[0])}), 200
    except Exception as e:
        return jsonify({"active": False, "message": str(e)}), 500

# **NEW**: ক্লায়েন্ট থেকে ADB ডিভাইস লিস্ট গ্রহণ করা
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
        
        # আগের সব ডিভাইস রিপোর্ট ডিলিট করে নতুন ডাটা সেভ করা (যাতে ড্যাশবোর্ডে ডুপ্লিকেট না আসে)
        c.execute("DELETE FROM device_reports WHERE user_id = ?", (user_id,))
        now = datetime.now(timezone.utc).isoformat()
        for dev in devices:
            c.execute("INSERT INTO device_reports (user_id, serial, state, reported_at) VALUES (?, ?, ?, ?)", 
                      (user_id, dev.get("serial", "Unknown"), dev.get("state", "Unknown"), now))
        
        conn.commit()
        conn.close()
        return jsonify({"success": True, "message": "Devices info updated"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ================= অ্যাডমিন API =================
@app.route('/api/admin/users', methods=['GET'])
def admin_get_users():
    auth = request.headers.get("Authorization")
    if auth != f"Bearer {ADMIN_PASSWORD}":
        return jsonify({"error": "Unauthorized"}), 401

    conn = sqlite3.connect('licenses.db')
    c = conn.cursor()
    c.execute("SELECT id, pc_name, location, is_active, activated_at, deactivated_at FROM users ORDER BY id DESC")
    rows = c.fetchall()
    conn.close()

    users = [{"id": r[0], "pc_name": r[1], "location": r[2] or "-", "is_active": bool(r[3]), "activated_at": r[4] or "-", "deactivated_at": r[5] or "-"} for r in rows]
    return jsonify({"users": users}), 200

# **NEW**: ড্যাশবোর্ডের জন্য ADB ডিভাইস রিপোর্ট ডাটা
@app.route('/api/admin/devices', methods=['GET'])
def admin_get_devices():
    auth = request.headers.get("Authorization")
    if auth != f"Bearer {ADMIN_PASSWORD}":
        return jsonify({"error": "Unauthorized"}), 401

    conn = sqlite3.connect('licenses.db')
    c = conn.cursor()
    # ইউজার ও তাদের ডিভাইসগুলো জয়েন করে বের করা
    c.execute('''
        SELECT u.pc_name, dr.serial, dr.state, dr.reported_at 
        FROM device_reports dr 
        JOIN users u ON dr.user_id = u.id 
        ORDER BY dr.reported_at DESC
    ''')
    rows = c.fetchall()
    conn.close()

    devices = [{"pc_name": r[0], "serial": r[1], "state": r[2], "reported_at": r[3]} for r in rows]
    return jsonify({"devices": devices}), 200

@app.route('/api/admin/deactivate', methods=['POST'])
def admin_deactivate():
    auth = request.headers.get("Authorization")
    if auth != f"Bearer {ADMIN_PASSWORD}":
        return jsonify({"error": "Unauthorized"}), 401
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        if not user_id: return jsonify({"error": "User ID required"}), 400

        now = datetime.now(timezone.utc).isoformat()
        conn = sqlite3.connect('licenses.db')
        c = conn.cursor()
        c.execute("UPDATE users SET is_active = 0, deactivated_at = ? WHERE id = ?", (now, user_id))
        conn.commit(); conn.close()
        return jsonify({"success": True, "message": "User deactivated successfully"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/admin/set_password', methods=['POST'])
def admin_set_password():
    auth = request.headers.get("Authorization")
    if auth != f"Bearer {ADMIN_PASSWORD}":
        return jsonify({"error": "Unauthorized"}), 401
    try:
        data = request.get_json()
        new_password = data.get('new_password')
        if not new_password or len(new_password) < 4:
            return jsonify({"error": "Password must be at least 4 characters"}), 400

        hashed = hash_password(new_password)
        conn = sqlite3.connect('licenses.db')
        c = conn.cursor()
        c.execute("UPDATE settings SET value = ? WHERE key = 'global_password_hash'", (hashed,))
        conn.commit(); conn.close()
        return jsonify({"success": True, "message": "Global password updated successfully"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ================= ড্যাশবোর্ড (HTML UI) =================
@app.route('/')
def index():
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>ADB Commander - Control Panel Website Dashboard</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body { 
                font-family: sans-serif; background: #111827; color: #f9fafb;
                padding: 20px; display: flex; justify-content: center; align-items: center; min-height: 100vh;
            }
            .container { max-width: 1200px; width: 100%; background: #1f2937; border-radius: 12px; padding: 30px; box-shadow: 0 10px 30px rgba(0,0,0,0.5); }
            .header { text-align: center; margin-bottom: 30px; }
            .header h1 { font-size: 28px; color: #fff; }
            .header h1 span { color: #64ffda; }
            .card { background: #111827; border-radius: 8px; padding: 20px; margin-bottom: 20px; border: 1px solid #374151; }
            .card h3 { color: #64ffda; margin-bottom: 15px; }
            .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
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
            .badge { background: #1e3a8a; padding: 4px 8px; border-radius: 12px; font-size: 12px; color: #93c5fd; }
            @media (max-width: 800px) { .grid-2 { grid-template-columns: 1fr; } }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🔐 <span>ADB Commander</span> Control Panel Website Dashboard</h1>
                <p style="color: #9ca3af; font-size: 14px;">Monitor Users & Connected ADB Devices</p>
            </div>

            <div class="card">
                <h3>🔑 Change Global Password</h3>
                <p style="color: #9ca3af; font-size: 13px; margin-bottom: 10px;">এখানে নতুন পাসওয়ার্ড দিন। এই পাসওয়ার্ড দিয়ে সবাই সফটওয়্যার ওপেন করতে পারবে।</p>
                <div class="input-group">
                    <input type="password" id="newPwd" placeholder="Enter new password">
                    <button class="btn" onclick="updatePassword()">Update Password</button>
                </div>
                <div id="msg" style="margin-top: 10px; font-size: 14px;"></div>
            </div>

            <div class="grid-2">
                <div class="card">
                    <h3>👥 Connected Users <span class="badge" id="userCount">0</span></h3>
                    <div style="overflow-x: auto;">
                        <table>
                            <thead>
                                <tr>
                                    <th>ID</th><th>PC Name</th><th>Location</th><th>Status</th><th>Action</th>
                                </tr>
                            </thead>
                            <tbody id="users-body"></tbody>
                        </table>
                    </div>
                </div>

                <div class="card">
                    <h3>🖥️ Connected ADB Devices <span class="badge" id="deviceCount">0</span></h3>
                    <div style="overflow-x: auto;">
                        <table>
                            <thead>
                                <tr>
                                    <th>PC Name</th><th>Device Serial</th><th>State</th><th>Last Seen</th>
                                </tr>
                            </thead>
                            <tbody id="devices-body"></tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>

        <script>
            const API_BASE = '/api/admin';
            const AUTH = 'Bearer admin123';
            let userCountEl = document.getElementById('userCount');
            let deviceCountEl = document.getElementById('deviceCount');

            async function fetchData() {
                // Fetch Users
                const uRes = await fetch(API_BASE + '/users', { headers: { 'Authorization': AUTH } });
                const uData = await uRes.json();
                const tbody = document.getElementById('users-body');
                tbody.innerHTML = '';
                userCountEl.innerText = uData.users.length;
                
                if(uData.users.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="5" class="empty">No users registered yet.</td></tr>';
                } else {
                    uData.users.forEach(u => {
                        const tr = document.createElement('tr');
                        const statusHTML = u.is_active ? `<span class="status-active">✅ Active</span>` : `<span class="status-inactive">❌ Inactive</span>`;
                        let actionHTML = u.is_active ? `<button class="btn btn-danger btn-sm" onclick="deactivateUser(${u.id})">Deactivate</button>` : `<span style="color: #6b7280; font-size: 12px;">Deactivated</span>`;
                        tr.innerHTML = `<td>${u.id}</td><td>${u.pc_name}</td><td>${u.location}</td><td>${statusHTML}</td><td>${actionHTML}</td>`;
                        tbody.appendChild(tr);
                    });
                }

                // Fetch ADB Devices
                const dRes = await fetch(API_BASE + '/devices', { headers: { 'Authorization': AUTH } });
                const dData = await dRes.json();
                const dBody = document.getElementById('devices-body');
                dBody.innerHTML = '';
                deviceCountEl.innerText = dData.devices.length;

                if(dData.devices.length === 0) {
                    dBody.innerHTML = '<tr><td colspan="4" class="empty">No ADB devices reported yet.</td></tr>';
                } else {
                    dData.devices.forEach(d => {
                        const tr = document.createElement('tr');
                        tr.innerHTML = `<td>${d.pc_name}</td><td>${d.serial}</td><td>${d.state}</td><td>${d.reported_at}</td>`;
                        dBody.appendChild(tr);
                    });
                }
            }

            async function deactivateUser(id) {
                if (!confirm('Are you sure you want to deactivate this user?')) return;
                const r = await fetch(API_BASE + '/deactivate', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'Authorization': AUTH },
                    body: JSON.stringify({ user_id: id })
                });
                if (r.ok) { alert('User deactivated successfully!'); fetchData(); } else { alert('Failed to deactivate user.'); }
            }

            async function updatePassword() {
                const pwd = document.getElementById('newPwd').value.trim();
                if(!pwd || pwd.length < 4) {
                    document.getElementById('msg').innerHTML = '<span style="color: #fca5a5;">Password must be at least 4 characters!</span>';
                    return;
                }
                const r = await fetch(API_BASE + '/set_password', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'Authorization': AUTH },
                    body: JSON.stringify({ new_password: pwd })
                });
                const data = await r.json();
                if(r.ok) { document.getElementById('msg').innerHTML = `<span style="color: #86efac;">✅ ${data.message}</span>`; document.getElementById('newPwd').value = ''; } 
                else { document.getElementById('msg').innerHTML = `<span style="color: #fca5a5;">❌ ${data.error}</span>`; }
            }

            // প্রতি ৫ সেকেন্ডে অটো রিফ্রেশ (লাইভ ডাটা দেখার জন্য)
            fetchData();
            setInterval(fetchData, 5000);
        </script>
    </body>
    </html>
    ''')

if __name__ == '__main__':
    print("\n" + "=" * 70)
    print("  🔐 ADB COMMANDER CONTROL PANEL DASHBOARD")
    print("=" * 70)
    app.run(host='0.0.0.0', port=5000, debug=False)
