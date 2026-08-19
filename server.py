#!/usr/bin/env python3
"""Secure license server and admin dashboard."""

import logging
import os
import secrets
import socket
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import Flask, jsonify, redirect, render_template_string, request, session, url_for
from flask_cors import CORS
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("LICENSE_DB_PATH", os.path.join(BASE_DIR, "licenses.db"))
ADMIN_PASSWORD = os.environ.get("INITIAL_ADMIN_PASSWORD")
SECRET_KEY = os.environ.get("FLASK_SECRET_KEY")
ALLOWED_ORIGINS = [x.strip() for x in os.environ.get("ALLOWED_ORIGINS", "").split(",") if x.strip()]
OFFLINE_AFTER_SECONDS = int(os.environ.get("OFFLINE_AFTER_SECONDS", "45"))

if not SECRET_KEY:
    raise RuntimeError("FLASK_SECRET_KEY environment variable is required")
if not ADMIN_PASSWORD:
    raise RuntimeError("INITIAL_ADMIN_PASSWORD environment variable is required on first setup")

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "1") == "1",
    SESSION_COOKIE_SAMESITE="Lax",
    MAX_CONTENT_LENGTH=64 * 1024,
)
CORS(app, resources={r"/api/*": {"origins": ALLOWED_ORIGINS}} if ALLOWED_ORIGINS else {})

logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
logger = logging.getLogger("license-server")


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def db_connection():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def hash_password(password):
    return generate_password_hash(password)


def verify_password(password, stored_hash):
    try:
        return bool(stored_hash) and check_password_hash(stored_hash, password)
    except ValueError:
        return False


def get_setting(conn, key):
    row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else None


def set_setting(conn, key, value):
    conn.execute("""
        INSERT INTO settings(key, value) VALUES (?, ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value
    """, (key, value))


def write_history(conn, user_id, action, details):
    conn.execute("""
        INSERT INTO user_history(user_id, action, details, timestamp)
        VALUES (?, ?, ?, ?)
    """, (user_id, action, details, now_iso()))


def init_db():
    conn = db_connection()
    try:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pc_name TEXT NOT NULL,
                hardware_id TEXT NOT NULL,
                location TEXT,
                is_active INTEGER NOT NULL DEFAULT 0,
                activated_at TEXT,
                deactivated_at TEXT,
                session_token TEXT UNIQUE,
                last_seen TEXT
            );
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS device_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                serial TEXT NOT NULL,
                state TEXT,
                device_model TEXT,
                reported_at TEXT,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS user_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action TEXT NOT NULL,
                details TEXT,
                timestamp TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
            );
            CREATE INDEX IF NOT EXISTS idx_users_session_token ON users(session_token);
            CREATE INDEX IF NOT EXISTS idx_users_last_seen ON users(last_seen);
            CREATE INDEX IF NOT EXISTS idx_device_reports_user ON device_reports(user_id);
            CREATE INDEX IF NOT EXISTS idx_history_timestamp ON user_history(timestamp);
        """)

        old_dashboard = get_setting(conn, "dashboard_password")
        global_hash = get_setting(conn, "global_password_hash")

        if not global_hash and old_dashboard:
            global_hash = old_dashboard
        if not global_hash:
            global_hash = hash_password(ADMIN_PASSWORD)
        set_setting(conn, "global_password_hash", global_hash)
        conn.execute("DELETE FROM settings WHERE key = 'dashboard_password'")
        conn.commit()
    finally:
        conn.close()


def require_dashboard(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("dashboard_logged_in"):
            return jsonify({"error": "Unauthorized"}), 401
        return view(*args, **kwargs)
    return wrapped


def mark_offline_users():
    while True:
        time.sleep(10)
        try:
            cutoff = (datetime.now(timezone.utc) - timedelta(seconds=OFFLINE_AFTER_SECONDS)).isoformat()
            now = now_iso()
            conn = db_connection()
            conn.execute("""
                UPDATE users
                SET is_active = 0, deactivated_at = ?
                WHERE is_active = 1 AND (last_seen IS NULL OR last_seen < ?)
            """, (now, cutoff))
            conn.commit()
            conn.close()
        except Exception:
            logger.exception("Offline monitor failed")


init_db()
threading.Thread(target=mark_offline_users, daemon=True, name="offline-monitor").start()


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


@app.route("/health")
def health_check():
    return jsonify({"status": "healthy", "timestamp": now_iso(), "server": socket.gethostname()})


@app.route("/api/client/verify", methods=["POST"])
def client_verify():
    data = request.get_json(silent=True) or {}
    pc_name = str(data.get("pc_name", "")).strip()
    hardware_id = str(data.get("hardware_id", "")).strip()
    password = str(data.get("password", ""))

    if not pc_name or not hardware_id or not password:
        return jsonify({"success": False, "message": "Missing required fields"}), 400

    conn = db_connection()
    try:
        stored_hash = get_setting(conn, "global_password_hash")
        if not stored_hash or not verify_password(password, stored_hash):
            return jsonify({"success": False, "message": "Invalid global password"}), 401

        now = now_iso()
        token = secrets.token_urlsafe(32)
        cur = conn.execute("""
            INSERT INTO users(pc_name, hardware_id, is_active, activated_at, session_token, last_seen)
            VALUES (?, ?, 1, ?, ?, ?)
        """, (pc_name, hardware_id, 1, now, token, now))
        write_history(conn, cur.lastrowid, "ACTIVATE", f"New instance: {pc_name}")
        conn.commit()
        return jsonify({"success": True, "message": "Instance activated", "session_token": token})
    except sqlite3.Error:
        conn.rollback()
        logger.exception("Client verification database error")
        return jsonify({"success": False, "message": "Internal server error"}), 500
    finally:
        conn.close()


@app.route("/api/client/status", methods=["POST"])
def client_status():
    data = request.get_json(silent=True) or {}
    token = str(data.get("session_token", "")).strip()
    if not token or len(token) > 256:
        return jsonify({"active": False, "message": "Invalid token"}), 400

    conn = db_connection()
    try:
        row = conn.execute("SELECT is_active FROM users WHERE session_token = ?", (token,)).fetchone()
        if not row:
            return jsonify({"active": False, "message": "Invalid session"}), 200
        conn.execute("UPDATE users SET last_seen = ? WHERE session_token = ?", (now_iso(), token))
        conn.commit()
        return jsonify({"active": bool(row["is_active"])}), 200
    finally:
        conn.close()


@app.route("/api/client/device_info", methods=["POST"])
def client_device_info():
    data = request.get_json(silent=True) or {}
    token = str(data.get("session_token", "")).strip()
    devices = data.get("devices", [])
    if not token or not isinstance(devices, list) or len(devices) > 100:
        return jsonify({"error": "Invalid request"}), 400

    conn = db_connection()
    try:
        user = conn.execute("SELECT id FROM users WHERE session_token = ?", (token,)).fetchone()
        if not user:
            return jsonify({"error": "Invalid session"}), 401
        conn.execute("DELETE FROM device_reports WHERE user_id = ?", (user["id"],))
        timestamp = now_iso()
        for device in devices:
            if not isinstance(device, dict):
                continue
            conn.execute("""
                INSERT INTO device_reports(user_id, serial, state, device_model, reported_at)
                VALUES (?, ?, ?, ?, ?)
            """, (
                user["id"],
                str(device.get("serial", "Unknown"))[:255],
                str(device.get("state", "Unknown"))[:100],
                str(device.get("model", "Unknown"))[:255],
                timestamp,
            ))
        conn.commit()
        return jsonify({"success": True, "message": "Device information updated"})
    finally:
        conn.close()


@app.route("/api/admin/users")
@require_dashboard
def admin_get_users():
    conn = db_connection()
    try:
        rows = conn.execute("""
            SELECT u.id, u.pc_name, u.hardware_id, u.location, u.is_active,
                   u.activated_at, u.deactivated_at,
                   (SELECT device_model FROM device_reports d
                    WHERE d.user_id = u.id
                    ORDER BY d.reported_at DESC LIMIT 1) AS device_model
            FROM users u ORDER BY u.id DESC
        """).fetchall()
        return jsonify({"users": [dict(row) | {"is_active": bool(row["is_active"])} for row in rows]})
    finally:
        conn.close()


@app.route("/api/admin/deactivate", methods=["POST"])
@require_dashboard
def admin_deactivate():
    data = request.get_json(silent=True) or {}
    try:
        user_id = int(data.get("user_id"))
    except (TypeError, ValueError):
        return jsonify({"error": "Valid user ID required"}), 400

    conn = db_connection()
    try:
        timestamp = now_iso()
        cur = conn.execute("""
            UPDATE users
            SET is_active = 0, session_token = NULL, last_seen = NULL, deactivated_at = ?
            WHERE id = ?
        """, (timestamp, user_id))
        if cur.rowcount == 0:
            return jsonify({"error": "User not found"}), 404
        write_history(conn, user_id, "DEACTIVATE", f"Admin deactivated instance {user_id}")
        conn.commit()
        return jsonify({"success": True, "message": "Instance deactivated"})
    finally:
        conn.close()


@app.route("/api/admin/set_password", methods=["POST"])
@require_dashboard
def admin_set_password():
    data = request.get_json(silent=True) or {}
    new_password = str(data.get("new_password", ""))
    if len(new_password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400

    conn = db_connection()
    try:
        timestamp = now_iso()
        set_setting(conn, "global_password_hash", hash_password(new_password))
        conn.execute("""
            UPDATE users
            SET session_token = NULL, last_seen = NULL,
                is_active = 0, deactivated_at = ?
            WHERE session_token IS NOT NULL OR is_active = 1
        """, (timestamp,))
        write_history(conn, None, "GLOBAL_PASSWORD_CHANGE", "Global password changed; all sessions revoked")
        conn.commit()
        return jsonify({"success": True, "message": "Password updated and all sessions revoked"})
    finally:
        conn.close()


@app.route("/api/admin/history")
@require_dashboard
def admin_get_history():
    conn = db_connection()
    try:
        rows = conn.execute("""
            SELECT h.id, COALESCE(u.pc_name, 'SYSTEM') AS pc_name,
                   h.action, h.details, h.timestamp
            FROM user_history h LEFT JOIN users u ON h.user_id = u.id
            ORDER BY h.timestamp DESC LIMIT 100
        """).fetchall()
        return jsonify({"history": [dict(row) for row in rows]})
    finally:
        conn.close()


LOGIN_PAGE = """
<!doctype html><html><head><meta charset='utf-8'><title>Admin Login</title>
<style>body{font-family:system-ui;background:#07131c;color:white;display:grid;place-items:center;height:100vh}form{background:#102432;padding:32px;border-radius:16px;width:min(360px,90vw)}input,button{width:100%;padding:12px;margin-top:12px;box-sizing:border-box}button{cursor:pointer;background:#1f7a4a;color:white;border:0;border-radius:8px}.error{color:#ff7777}</style></head>
<body><form method='post'><h2>Admin Login</h2>{% if error %}<p class='error'>{{ error }}</p>{% endif %}<input type='password' name='password' placeholder='Password' required autofocus><button>Sign in</button></form></body></html>
"""

DASHBOARD_HTML = """
<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>License Dashboard</title>
<style>body{font-family:system-ui;margin:0;background:#07131c;color:#eef}main{max-width:1200px;margin:auto;padding:24px}section{background:#102432;padding:20px;border-radius:14px;margin:16px 0}button{padding:9px 13px;border:0;border-radius:8px;cursor:pointer}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:9px;border-bottom:1px solid #29404d;font-size:14px}.danger{background:#a33;color:#fff}.ok{color:#4ade80}.off{color:#fb7185}input{padding:9px;border-radius:7px;border:1px solid #456;background:#07131c;color:#fff}</style></head>
<body><main><p><a href='/logout' style='color:#9ad'>Logout</a></p><h1>License Dashboard</h1><section><h2>Change global password</h2><input id='newpw' type='password' minlength='8' placeholder='At least 8 characters'><button onclick='changePassword()'>Update password</button><p id='msg'></p></section><section><h2>Users</h2><div style='overflow:auto'><table><thead><tr><th>ID</th><th>PC</th><th>Hardware</th><th>Device</th><th>Status</th><th>Action</th></tr></thead><tbody id='users'></tbody></table></div></section><section><h2>History</h2><pre id='history' style='white-space:pre-wrap'></pre></section></main>
<script>
async function load(){const u=await fetch('/api/admin/users');const d=await u.json();document.querySelector('#users').innerHTML=(d.users||[]).map(x=>`<tr><td>${x.id}</td><td>${esc(x.pc_name)}</td><td>${esc(x.hardware_id)}</td><td>${esc(x.device_model||'-')}</td><td class='${x.is_active?'ok':'off'}'>${x.is_active?'Active':'Offline'}</td><td><button class='danger' onclick='deactivate(${x.id})'>Deactivate</button></td></tr>`).join('');const h=await fetch('/api/admin/history');document.querySelector('#history').textContent=JSON.stringify(h.data||h,null,2)}
function esc(s){return String(s??'').replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]))}
async function deactivate(id){if(!confirm('Deactivate this instance?'))return;await fetch('/api/admin/deactivate',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({user_id:id})});load()}
async function changePassword(){const p=document.querySelector('#newpw').value;const r=await fetch('/api/admin/set_password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({new_password:p})});const d=await r.json();document.querySelector('#msg').textContent=d.message||d.error||'Done';if(r.ok){setTimeout(()=>location.href='/logout',1000)}}
load();setInterval(load,15000)
</script></body></html>
"""


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        password = request.form.get("password", "")
        conn = db_connection()
        try:
            stored_hash = get_setting(conn, "global_password_hash")
        finally:
            conn.close()
        if verify_password(password, stored_hash):
            session.clear()
            session["dashboard_logged_in"] = True
            return redirect(url_for("index"))
        return render_template_string(LOGIN_PAGE, error="Invalid password"), 401
    return render_template_string(LOGIN_PAGE, error=None)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
def index():
    if not session.get("dashboard_logged_in"):
        return redirect(url_for("login"))
    return render_template_string(DASHBOARD_HTML)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=False)
