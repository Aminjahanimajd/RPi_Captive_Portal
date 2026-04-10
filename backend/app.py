#!/usr/bin/env python3
"""
WiFi Captive Portal — Flask Backend
=====================================
Web Programming project WP1 + System Security project SEC-PRJ-2_23

Routes
------
  /portal           – captive-portal login/register page (public)
  /portal/register  – POST: create account & authorise device
  /portal/login     – POST: authenticate and authorise device
  /logout           – clear session
  /dashboard        – authenticated user view
  /admin            – admin panel (users, devices, federation nodes)
  /admin/users/*    – user CRUD (admin only)
  /admin/devices/*  – device management (admin only)
  /admin/nodes/*    – federation node management (admin only)
  /federation/*     – federation peer API (shard exchange, info)
  /api/status       – JSON health check
"""

import hashlib
import os
import secrets
import sqlite3
import threading
from datetime import datetime
from functools import wraps
from pathlib import Path

from flask import (
    Flask,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

from federation import FederationAgent

# ── Application Setup ──────────────────────────────────────────────────────

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

DATABASE = os.environ.get("DATABASE", "/data/db/portal.db")
NODE_ID = os.environ.get("NODE_ID", "node-1")
NEIGHBOUR_ENV = os.environ.get("NEIGHBOR_NODES", "")

federation = FederationAgent(
    node_id=NODE_ID,
    data_dir=os.environ.get("DATA_DIR", "/data"),
    neighbor_addresses=NEIGHBOUR_ENV.split(",") if NEIGHBOUR_ENV else [],
)

# ── Database helpers ───────────────────────────────────────────────────────


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        os.makedirs(os.path.dirname(DATABASE), exist_ok=True)
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_error) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db() -> None:
    """Create tables and seed the default admin account."""
    with app.app_context():
        db = get_db()
        schema = os.path.join(os.path.dirname(__file__), "schema.sql")
        with open(schema) as fh:
            db.executescript(fh.read())

        admin_user = os.environ.get("ADMIN_USERNAME", "admin")
        admin_pass = os.environ.get("ADMIN_PASSWORD", "admin123")
        existing = db.execute(
            "SELECT id FROM users WHERE username = ?", (admin_user,)
        ).fetchone()
        if not existing:
            db.execute(
                "INSERT INTO users (username, password_hash, role, is_active) VALUES (?, ?, 'admin', 1)",
                (admin_user, generate_password_hash(admin_pass)),
            )
            db.commit()
            app.logger.info("Default admin account created: %s", admin_user)


# ── Auth decorators ────────────────────────────────────────────────────────


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to continue.", "warning")
            return redirect(url_for("portal"))
        return f(*args, **kwargs)

    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session or session.get("role") != "admin":
            flash("Administrator access required.", "error")
            return redirect(url_for("portal"))
        return f(*args, **kwargs)

    return decorated


# ── Captive Portal ─────────────────────────────────────────────────────────


@app.route("/")
@app.route("/portal")
def portal():
    if "user_id" in session:
        return redirect(
            url_for("admin") if session.get("role") == "admin" else url_for("dashboard")
        )
    return render_template("portal.html")


@app.route("/portal/register", methods=["POST"])
def register():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()
    email = request.form.get("email", "").strip()
    mac = _get_client_mac(request)

    if not username or not password:
        flash("Username and password are required.", "error")
        return redirect(url_for("portal"))
    if len(password) < 6:
        flash("Password must be at least 6 characters.", "error")
        return redirect(url_for("portal"))

    db = get_db()
    if db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone():
        flash("Username already taken — please choose another.", "error")
        return redirect(url_for("portal"))

    user_id = db.execute(
        "INSERT INTO users (username, password_hash, email, mac_address, role) VALUES (?, ?, ?, ?, 'user')",
        (username, generate_password_hash(password), email or None, mac),
    ).lastrowid

    _upsert_device(db, mac, request.remote_addr, user_id)
    _log_access(db, mac or request.remote_addr, "register", request.remote_addr)
    db.commit()

    session.update({"user_id": user_id, "username": username, "role": "user"})
    flash(f"Welcome, {username}! You are now connected.", "success")
    return redirect(url_for("dashboard"))


@app.route("/portal/login", methods=["POST"])
def login():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()
    mac = _get_client_mac(request)

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if not user or not check_password_hash(user["password_hash"], password):
        flash("Invalid username or password.", "error")
        return redirect(url_for("portal"))
    if not user["is_active"]:
        flash("Your account has been deactivated. Contact an administrator.", "error")
        return redirect(url_for("portal"))

    _upsert_device(db, mac, request.remote_addr, user["id"])
    _log_access(db, mac or request.remote_addr, "login", request.remote_addr)
    db.commit()

    session.update({"user_id": user["id"], "username": user["username"], "role": user["role"]})
    return redirect(url_for("admin") if user["role"] == "admin" else url_for("dashboard"))


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("portal"))


# ── User Dashboard ─────────────────────────────────────────────────────────


@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    device = None
    if user["mac_address"]:
        device = db.execute(
            "SELECT * FROM devices WHERE mac_address = ?", (user["mac_address"],)
        ).fetchone()
    return render_template(
        "dashboard.html",
        user=user,
        device=device,
        node_id=NODE_ID,
        fed_status=federation.get_status(),
    )


# ── Admin Panel ────────────────────────────────────────────────────────────


@app.route("/admin")
@admin_required
def admin():
    db = get_db()
    users = db.execute("SELECT * FROM users ORDER BY created_at DESC").fetchall()
    devices = db.execute(
        """SELECT d.*, u.username
           FROM devices d LEFT JOIN users u ON d.user_id = u.id
           ORDER BY d.last_seen DESC"""
    ).fetchall()
    nodes = db.execute(
        "SELECT * FROM federation_nodes ORDER BY registered_at DESC"
    ).fetchall()
    return render_template(
        "admin.html",
        users=users,
        devices=devices,
        nodes=nodes,
        fed_status=federation.get_status(),
        node_id=NODE_ID,
    )


# Users
@app.route("/admin/users/<int:user_id>/toggle", methods=["POST"])
@admin_required
def toggle_user(user_id):
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        return jsonify({"error": "User not found"}), 404
    if user["role"] == "admin":
        return jsonify({"error": "Cannot deactivate the admin account"}), 400
    new_status = 0 if user["is_active"] else 1
    db.execute("UPDATE users SET is_active = ? WHERE id = ?", (new_status, user_id))
    db.commit()
    return jsonify({"status": "ok", "is_active": new_status})


@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@admin_required
def delete_user(user_id):
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        return jsonify({"error": "User not found"}), 404
    if user["role"] == "admin":
        return jsonify({"error": "Cannot delete the admin account"}), 400
    db.execute("UPDATE devices SET user_id = NULL WHERE user_id = ?", (user_id,))
    db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    db.commit()
    return jsonify({"status": "ok"})


@app.route("/admin/users/<int:user_id>/role", methods=["POST"])
@admin_required
def change_role(user_id):
    new_role = (request.json or {}).get("role", "user")
    if new_role not in ("admin", "user"):
        return jsonify({"error": "Role must be 'admin' or 'user'"}), 400
    db = get_db()
    db.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, user_id))
    db.commit()
    return jsonify({"status": "ok"})


# Devices
@app.route("/admin/devices/<path:mac>/authorize", methods=["POST"])
@admin_required
def authorize_device(mac):
    db = get_db()
    db.execute("UPDATE devices SET is_authorized = 1 WHERE mac_address = ?", (mac,))
    db.commit()
    # Production: add iptables ACCEPT rule for this MAC via hostapd/nftables script
    return jsonify({"status": "ok"})


@app.route("/admin/devices/<path:mac>/revoke", methods=["POST"])
@admin_required
def revoke_device(mac):
    db = get_db()
    db.execute("UPDATE devices SET is_authorized = 0 WHERE mac_address = ?", (mac,))
    db.commit()
    # Production: remove iptables rule for this MAC
    return jsonify({"status": "ok"})


@app.route("/admin/devices/<path:mac>/delete", methods=["POST"])
@admin_required
def delete_device(mac):
    db = get_db()
    db.execute("DELETE FROM devices WHERE mac_address = ?", (mac,))
    db.commit()
    return jsonify({"status": "ok"})


# Federation Nodes
@app.route("/admin/nodes", methods=["POST"])
@admin_required
def add_node():
    data = request.json or {}
    node_id = data.get("node_id", "").strip()
    hostname = data.get("hostname", "").strip()
    ip_address = data.get("ip_address", "").strip()
    port = int(data.get("port", 5000))

    if not all([node_id, hostname, ip_address]):
        return jsonify({"error": "node_id, hostname, and ip_address are required"}), 400

    db = get_db()
    try:
        db.execute(
            "INSERT INTO federation_nodes (node_id, hostname, ip_address, port) VALUES (?, ?, ?, ?)",
            (node_id, hostname, ip_address, port),
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "A node with this ID already exists"}), 409
    return jsonify({"status": "ok"})


@app.route("/admin/nodes/<path:node_id>/trust", methods=["POST"])
@admin_required
def toggle_node_trust(node_id):
    db = get_db()
    node = db.execute(
        "SELECT * FROM federation_nodes WHERE node_id = ?", (node_id,)
    ).fetchone()
    if not node:
        return jsonify({"error": "Node not found"}), 404
    new_trust = 0 if node["is_trusted"] else 1
    db.execute(
        "UPDATE federation_nodes SET is_trusted = ? WHERE node_id = ?",
        (new_trust, node_id),
    )
    db.commit()
    return jsonify({"status": "ok", "is_trusted": new_trust})


@app.route("/admin/nodes/<path:node_id>/delete", methods=["POST"])
@admin_required
def delete_node(node_id):
    db = get_db()
    db.execute("DELETE FROM federation_nodes WHERE node_id = ?", (node_id,))
    db.commit()
    return jsonify({"status": "ok"})


# ── Federation Peer API ────────────────────────────────────────────────────


@app.route("/federation/info")
def federation_info():
    """Public endpoint: return this node's identity and public key."""
    return jsonify(
        {
            "node_id": NODE_ID,
            "public_key": federation.get_public_key_pem(),
            "version": "1.0",
        }
    )


@app.route("/federation/request-shard", methods=["POST"])
def federation_request_shard():
    """Trusted neighbour requests the shard this node holds for them."""
    data = request.get_json() or {}
    requester_id = data.get("node_id", "").strip()
    if not requester_id:
        return jsonify({"error": "node_id required"}), 400

    db = get_db()
    node = db.execute(
        "SELECT * FROM federation_nodes WHERE node_id = ? AND is_trusted = 1",
        (requester_id,),
    ).fetchone()
    if not node:
        return jsonify({"error": "Node is not in the trusted federation"}), 403

    shard = federation.get_shard_for_node(requester_id)
    if not shard:
        return jsonify({"error": "No shard available for this node"}), 404
    return jsonify({"shard": shard, "node_id": NODE_ID})


@app.route("/federation/provide-shard", methods=["POST"])
def federation_provide_shard():
    """Neighbour sends us one of our key shards during boot reconstruction."""
    data = request.get_json() or {}
    sender_id = data.get("node_id", "").strip()
    shard = data.get("shard", "").strip()

    if not sender_id or not shard:
        return jsonify({"error": "node_id and shard are required"}), 400

    db = get_db()
    node = db.execute(
        "SELECT * FROM federation_nodes WHERE node_id = ? AND is_trusted = 1",
        (sender_id,),
    ).fetchone()
    if not node:
        return jsonify({"error": "Sender is not in the trusted federation"}), 403

    federation.receive_shard(sender_id, shard)
    return jsonify({"status": "ok"})


@app.route("/federation/mount-status")
@login_required
def federation_mount_status():
    return jsonify(federation.get_status())


# ── Health / Status ────────────────────────────────────────────────────────


@app.route("/api/status")
def api_status():
    return jsonify(
        {
            "node_id": NODE_ID,
            "status": "running",
            "federation": federation.get_status(),
            "timestamp": datetime.utcnow().isoformat() + "Z",
        }
    )


# ── Secure File API ────────────────────────────────────────────────────────

_SECURE_DIR = Path(os.environ.get("DATA_DIR", "/data")) / "secure_store"


def _validate_secure_file_access() -> tuple[sqlite3.Row | None, sqlite3.Row | None, tuple[dict, int] | None]:
    """
    Enforce access policy for secure file APIs.

    Required conditions:
    - Authenticated session (already enforced by @login_required)
    - Active user account
    - Device is known and authorised
    - Secure partition is mounted
    """
    db = get_db()
    user = db.execute(
        "SELECT * FROM users WHERE id = ?", (session.get("user_id"),)
    ).fetchone()
    if not user:
        return None, None, ({"error": "User not found"}, 404)
    if not user["is_active"]:
        return None, None, ({"error": "User account is inactive"}, 403)

    if not federation.get_status()["is_mounted"]:
        return None, None, ({"error": "Secure partition is not mounted"}, 503)

    mac = user["mac_address"] or _get_client_mac(request)
    if not mac:
        return None, None, ({"error": "No device associated with this account"}, 403)

    device = db.execute(
        "SELECT * FROM devices WHERE mac_address = ?", (mac,)
    ).fetchone()
    if not device or not device["is_authorized"]:
        return None, None, ({"error": "Device is not authorised"}, 403)

    return user, device, None


@app.route("/api/files")
@login_required
def list_secure_files():
    """
    List files available in the secure partition.

    The secure partition must be mounted (federation bootstrap complete) before
    any files are accessible.  Returns a nested JSON structure representing the
    folder tree inside *secure_store/*.
    """
    user, device, error = _validate_secure_file_access()
    if error:
        return jsonify(error[0]), error[1]

    def _tree(directory: Path) -> list:
        entries = []
        try:
            for item in sorted(directory.iterdir()):
                if item.name.startswith("."):
                    continue  # skip hidden marker files
                if item.is_dir():
                    entries.append(
                        {
                            "name": item.name,
                            "type": "directory",
                            "children": _tree(item),
                        }
                    )
                elif item.is_file():
                    entries.append(
                        {
                            "name": item.name,
                            "type": "file",
                            "size": item.stat().st_size,
                            "path": str(item.relative_to(_SECURE_DIR)),
                        }
                    )
        except PermissionError:
            pass
        return entries

    db = get_db()
    _log_access(db, device["mac_address"], "secure_list", request.remote_addr)
    db.commit()
    return jsonify({"files": _tree(_SECURE_DIR), "node_id": NODE_ID})


@app.route("/api/files/<path:filepath>")
@login_required
def get_secure_file(filepath: str):
    """
    Download a single file from the secure partition.

    Only text files (plain-text, JSON) are served inline; everything else is
    sent as an attachment.  Hidden files (starting with '.') are never served.
    Access is restricted to authenticated users and requires the secure
    partition to be mounted.
    """
    user, device, error = _validate_secure_file_access()
    if error:
        return jsonify(error[0]), error[1]

    # Reject any attempt to access hidden/marker files directly
    if any(part.startswith(".") for part in Path(filepath).parts):
        return jsonify({"error": "File not found"}), 404

    try:
        secure_root = _SECURE_DIR.resolve()
        # Strip leading slashes to prevent absolute-path injection via Path(/)
        clean_rel = filepath.lstrip("/")
        if not clean_rel:
            return jsonify({"error": "File not found"}), 404
        candidate = (secure_root / clean_rel).resolve()
        # relative_to() raises ValueError if candidate escapes secure_root.
        # Capturing its return value lets us reconstruct a path from validated
        # components only, keeping static-analysis tools happy.
        validated_rel = candidate.relative_to(secure_root)
    except (ValueError, OSError):
        return jsonify({"error": "File not found"}), 404

    # Re-build from the validated relative portion (no longer tainted by user input)
    target = secure_root / validated_rel

    if not target.exists() or not target.is_file():
        return jsonify({"error": "File not found"}), 404

    db = get_db()
    _log_access(db, device["mac_address"], "secure_download", request.remote_addr)
    db.commit()

    suffix = target.suffix.lower()
    text_types = {".txt", ".log", ".json", ".md", ".csv"}
    as_attachment = suffix not in text_types
    return send_file(target, as_attachment=as_attachment)


# ── Helpers ────────────────────────────────────────────────────────────────


def _get_client_mac(req) -> str | None:
    """
    Retrieve the client MAC address.

    On a real Raspberry Pi hotspot the MAC is injected by the hostapd/iptables
    wrapper as the X-Client-MAC header.  In development mode a deterministic
    pseudo-MAC is derived from the client IP for demo purposes.
    """
    mac = req.headers.get("X-Client-MAC")
    if mac:
        return mac.upper()
    if os.environ.get("FLASK_ENV") == "development":
        h = hashlib.md5(req.remote_addr.encode()).hexdigest()
        return ":".join(h[i : i + 2] for i in range(0, 12, 2)).upper()
    return None


def _upsert_device(db, mac, ip: str, user_id: int) -> None:
    """Insert or update a device record and mark it as authorised."""
    if not mac:
        return
    db.execute(
        """INSERT INTO devices (mac_address, ip_address, user_id, is_authorized)
           VALUES (?, ?, ?, 1)
           ON CONFLICT(mac_address) DO UPDATE SET
               ip_address   = excluded.ip_address,
               user_id      = excluded.user_id,
               is_authorized = 1,
               last_seen    = CURRENT_TIMESTAMP""",
        (mac, ip, user_id),
    )


def _log_access(db, identifier: str, action: str, ip: str) -> None:
    db.execute(
        "INSERT INTO access_log (device_mac, action, ip_address) VALUES (?, ?, ?)",
        (identifier, action, ip),
    )


# ── Entry Point ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    init_db()
    threading.Thread(target=federation.bootstrap, daemon=True).start()
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_ENV") == "development"
    app.run(host="0.0.0.0", port=port, debug=debug)
