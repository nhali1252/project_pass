#!/usr/bin/env python3
"""
ADB Commander - Master Control Panel
Complete System with Global Password & Remote Deactivation
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
ADMIN_PASSWORD = "admin123"  # ড্যাশবোর্ড API অ্যাক্সেসের জন্য পাসওয়ার্ড (পরবর্তীতে পরিবর্তন করতে পারেন)

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
    # সেটিংস টেবিল (যেখানে গ্লোবাল পাসওয়ার্ড হ্যাশ সংরক্ষিত থাকবে)
    c.execute('''CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)''')
    
    # যদি গ্লোবাল পাসওয়ার্ড আগে থেকে না থাকে, তাহলে 'admin123' দিয়ে ডিফল্ট সেট করি
    c.execute("SELECT value FROM settings WHERE key = 'global_password_hash'")
    if not c.fetchone():
        default_hash = hashlib.sha256("admin123".encode()).hexdigest()
        c.execute("INSERT INTO settings (key, value) VALUES ('global_password_hash', ?)", (default_hash,))
    
    conn.commit()
    conn.close()

init_db()

# ================= হেল্পার ফাংশন =================
def hash_password(pwd: str) -> str:
    return hashlib.sha256(pwd.encode()).hexdigest()

def verify_password(input_pwd: str, stored_hash: str) -> bool:
    return hash_password(input_pwd) == stored_hash

# ================= ক্লায়েন্ট সফটওয়্যার API (এন্ডপয়েন্ট) =================
@app.route('/api/client/verify', methods=['POST'])
def client_verify():
    """
    ক্লায়েন্ট সফটওয়্যার থেকে এই API কল হবে।
    পিসি নেম, হার্ডওয়্যার আইডি এবং গ্লোবাল পাসওয়ার্ড পাঠাবে।
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "message": "Invalid Request"}), 400

        pc_name = data.get('pc_name')
        hardware_id = data.get('hardware_id')
        password = data.get('password')

        if not pc_name or not hardware_id or not password:
            return jsonify({"success": False, "message": "Missing required fields"}), 400

        # 1. পাসওয়ার্ড মিলিয়ে দেখা
        conn = sqlite3.connect('licenses.db')
        c = conn.cursor()
        c.execute("SELECT value FROM settings WHERE key = 'global_password_hash'")
        result = c.fetchone()
        stored_hash = result[0] if result else ""
        
        if not verify_password(password, stored_hash):
            conn.close()
            return jsonify({"success": False, "message": "Invalid global password"}), 401

        # 2. হার্ডওয়্যার আইডি দিয়ে ইউজার খুঁজে বের করা অথবা নতুন তৈরি করা
        now = datetime.now(timezone.utc).isoformat()
        token = secrets.token_urlsafe(32)
        
        c.execute("SELECT id, is_active, session_token FROM users WHERE hardware_id = ?", (hardware_id,))
        user = c.fetchone()

        if user:
            user_id, is_active, existing_token = user
            if is_active == 1:
                conn.close()
                return jsonify({"success": True, "message": "Software is already active", "session_token": existing_token})
            else:
                # পুনরায় অ্যাক্টিভ করা (যদি আগে ডিএক্টিভেট করা হয়ে থাকে)
                c.execute("UPDATE users SET is_active = 1, activated_at = ?, deactivated_at = NULL, session_token = ? WHERE id = ?", (now, token, user_id))
                conn.commit()
                conn.close()
                return jsonify({"success": True, "message": "Reactivated successfully", "session_token": token})
        else:
            # নতুন ইউজার অটো-ক্রিয়েট
            c.execute("INSERT INTO users (pc_name, hardware_id, is_active, activated_at, session_token) VALUES (?, ?, 1, ?, ?)", (pc_name, hardware_id, now, token))
            conn.commit()
            conn.close()
            return jsonify({"success": True, "message": "New user activated", "session_token": token})

    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route('/api/client/status', methods=['POST'])
def client_status():
    """
    ক্লায়েন্ট সফটওয়্যার ১০ সেকেন্ড পর পর এই API কল করবে।
    ড্যাশবোর্ড থেকে ডিএক্টিভেট করলে, এই API 'active': False রিটার্ন করবে এবং সফটওয়্যার বন্ধ হয়ে যাবে।
    """
    try:
        data = request.get_json()
        token = data.get('session_token')
        if not token:
            return jsonify({"error": "Missing token"}), 400

        conn = sqlite3.connect('licenses.db')
        c = conn.cursor()
        c.execute("SELECT is_active FROM users WHERE session_token = ?", (token,))
        result = c.fetchone()
        conn.close()

        if not result:
            return jsonify({"active": False, "message": "Invalid session"}), 200

        is_active = result[0]
        return jsonify({"active": bool(is_active)}), 200

    except Exception as e:
        return jsonify({"active": False, "message": str(e)}), 500

# ================= অ্যাডমিন ড্যাশবোর্ড API =================
@app.route('/api/admin/users', methods=['GET'])
def admin_get_users():
    """ড্যাশবোর্ড থেকে ইউজার লিস্ট দেখার জন্য"""
    auth = request.headers.get("Authorization")
    if auth != f"Bearer {ADMIN_PASSWORD}":
        return jsonify({"error": "Unauthorized"}), 401

    conn = sqlite3.connect('licenses.db')
    c = conn.cursor()
    c.execute("SELECT id, pc_name, location, is_active, activated_at, deactivated_at FROM users ORDER BY id DESC")
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
            "deactivated_at": row[5] or "-"
        })
    return jsonify({"users": users}), 200


@app.route('/api/admin/deactivate', methods=['POST'])
def admin_deactivate():
    """ড্যাশবোর্ড থেকে একটি নির্দিষ্ট ইউজারকে ডিএক্টিভেট করার জন্য"""
    auth = request.headers.get("Authorization")
    if auth != f"Bearer {ADMIN_PASSWORD}":
        return jsonify({"error": "Unauthorized"}), 401

    try:
        data = request.get_json()
        user_id = data.get('user_id')
        if not user_id:
            return jsonify({"error": "User ID required"}), 400

        now = datetime.now(timezone.utc).isoformat()
        conn = sqlite3.connect('licenses.db')
        c = conn.cursor()
        c.execute("UPDATE users SET is_active = 0, deactivated_at = ? WHERE id = ?", (now, user_id))
        conn.commit()
        conn.close()
        return jsonify({"success": True, "message": "User deactivated successfully"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/admin/set_password', methods=['POST'])
def admin_set_password():
    """ড্যাশবোর্ড থেকে নতুন গ্লোবাল পাসওয়ার্ড সেট করার জন্য"""
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
        conn.commit()
        conn.close()
        return jsonify({"success": True, "message": "Global password updated successfully"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ================= অ্যাডমিন ড্যাশবোর্ড (HTML UI) =================
@app.route('/')
def index():
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>ADB Commander - Control Panel</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body { 
                font-family: sans-serif; background: #111827; color: #f9fafb;
                padding: 20px; display: flex; justify-content: center; align-items: center; min-height: 100vh;
            }
            .container { max-width: 1000px; width: 100%; background: #1f2937; border-radius: 12px; padding: 30px; box-shadow: 0 10px 30px rgba(0,0,0,0.5); }
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
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🔐 <span>ADB Commander</span> Control Panel</h1>
                <p style="color: #9ca3af; font-size: 14px;">Manage global password & monitor users</p>
            </div>

            <div class="card">
                <h3>🔑 Change Global Password</h3>
                <p style="color: #9ca3af; font-size: 13px; margin-bottom: 10px;">এখানে নতুন পাসওয়ার্ড দিন। এই পাসওয়ার্ড দিয়ে সবাই সফটওয়্যার ওপেন করতে পারবে (যতক্ষণ না অ্যাডমিন পরিবর্তন করছেন)।</p>
                <div class="input-group">
                    <input type="password" id="newPwd" placeholder="Enter new password">
                    <button class="btn" onclick="updatePassword()">Update Password</button>
                </div>
                <div id="msg" style="margin-top: 10px; font-size: 14px;"></div>
            </div>

            <div class="card">
                <h3>👥 Connected Users</h3>
                <div style="overflow-x: auto;">
                    <table>
                        <thead>
                            <tr>
                                <th>ID</th><th>PC Name</th><th>Location</th><th>Status</th><th>Activated At</th><th>Deactivated At</th><th>Action</th>
                            </tr>
                        </thead>
                        <tbody id="users-body"></tbody>
                    </table>
                </div>
                <div id="loader" class="empty">Loading users...</div>
            </div>
        </div>

        <script>
            const API_BASE = '/api/admin';
            const AUTH = 'Bearer admin123';

            async function fetchUsers() {
                document.getElementById('loader').style.display = 'block';
                const r = await fetch(API_BASE + '/users', { headers: { 'Authorization': AUTH } });
                if (!r.ok) { alert('Failed to fetch users'); document.getElementById('loader').style.display = 'none'; return; }
                const data = await r.json();
                document.getElementById('loader').style.display = 'none';
                
                const tbody = document.getElementById('users-body');
                tbody.innerHTML = '';
                
                if(data.users.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="7" class="empty">No users registered yet.</td></tr>';
                    return;
                }

                data.users.forEach(u => {
                    const tr = document.createElement('tr');
                    const statusHTML = u.is_active 
                        ? `<span class="status-active">✅ Active</span>` 
                        : `<span class="status-inactive">❌ Inactive</span>`;
                    
                    let actionHTML = '';
                    if(u.is_active) {
                        actionHTML = `<button class="btn btn-danger btn-sm" onclick="deactivateUser(${u.id})">Deactivate</button>`;
                    } else {
                        actionHTML = `<span style="color: #6b7280; font-size: 12px;">Deactivated</span>`;
                    }

                    tr.innerHTML = `
                        <td>${u.id}</td>
                        <td>${u.pc_name}</td>
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
                if (!confirm('Are you sure you want to deactivate this user?')) return;
                const r = await fetch(API_BASE + '/deactivate', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'Authorization': AUTH },
                    body: JSON.stringify({ user_id: id })
                });
                if (r.ok) {
                    alert('User deactivated successfully! The software on their PC will close immediately.');
                    fetchUsers();
                } else {
                    alert('Failed to deactivate user.');
                }
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
                if(r.ok) {
                    document.getElementById('msg').innerHTML = `<span style="color: #86efac;">✅ ${data.message}</span>`;
                    document.getElementById('newPwd').value = '';
                } else {
                    document.getElementById('msg').innerHTML = `<span style="color: #fca5a5;">❌ ${data.error}</span>`;
                }
            }

            fetchUsers();
        </script>
    </body>
    </html>
    ''')

# ================= রান করা =================
if __name__ == '__main__':
    print("\n" + "=" * 70)
    print("  🔐 ADB COMMANDER MASTER CONTROL PANEL - RUNNING")
    print("=" * 70)
    app.run(host='0.0.0.0', port=5000, debug=False)
