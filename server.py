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

ADMIN_PASSWORD = "admin123"

def init_db():
    conn = sqlite3.connect('licenses.db')
    c = conn.cursor()
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
    c.execute('''CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)''')
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

@app.route('/api/admin/users', methods=['GET'])
def admin_get_users():
    auth = request.headers.get("Authorization")
    if auth != f"Bearer {ADMIN_PASSWORD}": return jsonify({"error": "Unauthorized"}), 401
    conn = sqlite3.connect('licenses.db')
    c = conn.cursor()
    c.execute("SELECT id, pc_name, location, is_active, activated_at, deactivated_at FROM users ORDER BY id DESC")
    rows = c.fetchall()
    conn.close()
    users = [{"id": r[0], "pc_name": r[1], "location": r[2] or "-", "is_active": bool(r[3]), "activated_at": r[4] or "-", "deactivated_at": r[5] or "-"} for r in rows]
    return jsonify({"users": users}), 200

@app.route('/api/admin/deactivate', methods=['POST'])
def admin_deactivate():
    auth = request.headers.get("Authorization")
    if auth != f"Bearer {ADMIN_PASSWORD}": return jsonify({"error": "Unauthorized"}), 401
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
    if auth != f"Bearer {ADMIN_PASSWORD}": return jsonify({"error": "Unauthorized"}), 401
    try:
        data = request.get_json()
        new_password = data.get('new_password')
        if not new_password or len(new_password) < 4: return jsonify({"error": "Password must be at least 4 characters"}), 400
        hashed = hash_password(new_password)
        conn = sqlite3.connect('licenses.db')
        c = conn.cursor()
        c.execute("UPDATE settings SET value = ? WHERE key = 'global_password_hash'", (hashed,))
        conn.commit(); conn.close()
        return jsonify({"success": True, "message": "Global password updated successfully"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# =============== 🔥 THIS IS THE MISSING ENDPOINT ===============
@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'healthy', 
        'timestamp': datetime.now(timezone.utc).isoformat(), 
        'server': socket.gethostname()
    })
# ================================================================

@app.route('/')
def index():
    return render_template_string('''... (Your HTML Dashboard Code goes here - The one from previous messages) ...''')

if __name__ == '__main__':
    print("\n" + "=" * 70)
    print("  🔐 ADB COMMANDER MASTER CONTROL PANEL - RUNNING")
    print("=" * 70)
    app.run(host='0.0.0.0', port=5000, debug=False)
