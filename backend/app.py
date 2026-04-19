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
import hmac
import os
import secrets
import sqlite3
import threading
import time
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from urllib.parse import urlparse

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

from federation import FederationAgent, federation_payload_signature
from membership import MembershipManager
from runtime_profile import load_runtime_profile

# ── Application Setup ──────────────────────────────────────────────────────

ACTIVE_RUNTIME_PROFILE = load_runtime_profile()

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

MEMBERSHIP_DATA_DIR = os.environ.get(
    "MEMBERSHIP_DATA_DIR",
    os.path.join(os.environ.get("DATA_DIR", "/data"), "membership"),
)
MEMBERSHIP_COORDINATOR_NODE_ID = os.environ.get("MEMBERSHIP_COORDINATOR_NODE_ID", NODE_ID)
membership = MembershipManager(
    node_id=NODE_ID,
    data_dir=MEMBERSHIP_DATA_DIR,
    coordinator_hint=MEMBERSHIP_COORDINATOR_NODE_ID,
)

FEDERATION_ALLOW_UNSIGNED = os.environ.get("FEDERATION_ALLOW_UNSIGNED", "0") == "1"
FEDERATION_MAX_SKEW_SECONDS = int(os.environ.get("FEDERATION_MAX_SKEW_SECONDS", "120"))
FEDERATION_SHARED_SECRET = os.environ.get("FEDERATION_SHARED_SECRET", "").strip()


def _ensure_schema_migrations(db: sqlite3.Connection) -> None:
    """Apply lightweight schema migrations for federation security metadata."""
    existing_cols = {
        row["name"]
        for row in db.execute("PRAGMA table_info(federation_nodes)").fetchall()
    }
    if "shared_secret" not in existing_cols:
        db.execute("ALTER TABLE federation_nodes ADD COLUMN shared_secret TEXT")

    db.execute(
        """
        CREATE TABLE IF NOT EXISTS federation_nonce_log (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            node_id   TEXT NOT NULL,
            nonce     TEXT NOT NULL,
            seen_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(node_id, nonce)
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS federation_trust_audit (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            endpoint  TEXT NOT NULL,
            node_id   TEXT NOT NULL,
            decision  TEXT NOT NULL,
            reason    TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    db.commit()


def _federation_signing_secret_for_node(node_row: sqlite3.Row | None) -> str:
    if node_row and node_row["shared_secret"]:
        return str(node_row["shared_secret"])
    return FEDERATION_SHARED_SECRET


def _bootstrap_membership_from_db(db: sqlite3.Connection) -> None:
    """Ensure MembershipManager reflects existing federation_nodes rows."""
    rows = db.execute(
        "SELECT node_id, hostname, ip_address, port, is_trusted FROM federation_nodes"
    ).fetchall()

    for row in rows:
        node_id = row["node_id"]
        if not membership.node_exists(node_id):
            success, msg = membership.node_join_request(
                node_id=node_id,
                hostname=row["hostname"],
                ip_address=row["ip_address"],
                port=int(row["port"]),
            )
            if not success:
                app.logger.warning(
                    "Membership bootstrap join failed for %s: %s",
                    node_id,
                    msg,
                )
                continue

        member = membership.get_member(node_id)
        if row["is_trusted"] and member and not member.is_trusted:
            success, msg = membership.approve_node_join(node_id)
            if not success:
                app.logger.warning(
                    "Membership bootstrap trust failed for %s: %s",
                    node_id,
                    msg,
                )


def _verify_federation_payload_signature(
    db: sqlite3.Connection,
    payload: dict,
    sender_id: str,
    node_row: sqlite3.Row | None,
) -> tuple[bool, str]:
    """Verify signature + timestamp skew + nonce uniqueness for federation payloads."""
    signature = str(payload.get("signature", "")).strip()
    nonce = str(payload.get("nonce", "")).strip()
    timestamp_raw = payload.get("timestamp")

    if not signature or not nonce or timestamp_raw is None:
        if FEDERATION_ALLOW_UNSIGNED:
            app.logger.warning("Unsigned federation payload accepted due to FEDERATION_ALLOW_UNSIGNED=1")
            return True, ""
        return False, "Missing federation signature metadata"

    try:
        timestamp = int(timestamp_raw)
    except (TypeError, ValueError):
        return False, "Invalid federation timestamp"

    now = int(time.time())
    if abs(now - timestamp) > FEDERATION_MAX_SKEW_SECONDS:
        return False, "Federation request timestamp outside allowed skew"

    signing_secret = _federation_signing_secret_for_node(node_row)
    if not signing_secret:
        return False, "No federation signing secret configured for sender"

    expected_sig = federation_payload_signature(payload, signing_secret)
    if not hmac.compare_digest(signature, expected_sig):
        return False, "Invalid federation request signature"

    try:
        db.execute(
            "INSERT INTO federation_nonce_log (node_id, nonce) VALUES (?, ?)",
            (sender_id, nonce),
        )
        db.execute(
            "DELETE FROM federation_nonce_log WHERE seen_at < datetime('now', '-1 day')"
        )
        db.commit()
    except sqlite3.IntegrityError:
        return False, "Federation request replay detected"

    return True, ""


def _audit_federation_trust_event(
    db: sqlite3.Connection,
    endpoint: str,
    node_id: str,
    decision: str,
    reason: str,
) -> None:
    """Persist direct-trust decisions for federation request auditing."""
    try:
        db.execute(
            "INSERT INTO federation_trust_audit (endpoint, node_id, decision, reason) VALUES (?, ?, ?, ?)",
            (endpoint, node_id, decision, reason),
        )
        db.commit()
    except sqlite3.Error as exc:
        app.logger.warning("Failed to write federation trust audit event: %s", exc)


def _validate_direct_trust_payload(payload: dict) -> tuple[bool, str]:
    """Reject any payload that implies transitive/delegated trust."""
    forbidden_transitive_keys = [
        "via_node",
        "via_path",
        "trust_chain",
        "delegated_by",
        "transitive",
    ]
    for key in forbidden_transitive_keys:
        value = payload.get(key)
        if value not in (None, "", [], {}, False):
            return False, f"Direct trust only: transitive field '{key}' is not allowed"
    return True, ""


def _is_directly_trusted_member(node_id: str) -> bool:
    member = membership.get_member(node_id)
    return bool(member and member.is_trusted)


def _build_logical_graph(db: sqlite3.Connection) -> dict:
    """Build a logical trust/communication graph for the admin UI."""
    membership_summary = membership.summary()
    member_rows = membership_summary["members"]["list"]

    nodes = []
    edges = []
    member_by_id = {}
    for member in member_rows:
        node_id = member["node_id"]
        member_by_id[node_id] = member
        nodes.append(
            {
                "id": node_id,
                "label": member.get("hostname") or node_id,
                "is_trusted": bool(member.get("is_trusted")),
                "is_local": node_id == NODE_ID,
            }
        )

    for node_id, member in member_by_id.items():
        if node_id == NODE_ID:
            continue
        if member.get("is_trusted"):
            edges.append(
                {
                    "source": NODE_ID,
                    "target": node_id,
                    "type": "direct-trust",
                    "status": "active",
                }
            )

    rows = db.execute(
        "SELECT node_id, hostname, ip_address, port FROM federation_nodes"
    ).fetchall()
    lookup = {}
    for row in rows:
        node_id = row["node_id"]
        host_port = f"{row['hostname']}:{row['port']}"
        ip_port = f"{row['ip_address']}:{row['port']}"
        lookup[host_port] = node_id
        lookup[ip_port] = node_id

    diagnostics = federation.get_neighbor_diagnostics()
    for metric in diagnostics:
        neighbour = str(metric.get("neighbor", "")).strip()
        if not neighbour:
            continue

        parsed = urlparse(neighbour if "://" in neighbour else f"http://{neighbour}")
        endpoint = parsed.netloc or parsed.path
        target_id = lookup.get(endpoint, endpoint)

        if not any(node["id"] == target_id for node in nodes):
            nodes.append(
                {
                    "id": target_id,
                    "label": target_id,
                    "is_trusted": False,
                    "is_local": False,
                }
            )

        edges.append(
            {
                "source": NODE_ID,
                "target": target_id,
                "type": "communication",
                "status": "healthy" if metric.get("failures", 0) == 0 else "degraded",
                "score": metric.get("score"),
            }
        )

    trusted_count = sum(1 for n in nodes if n["is_trusted"])
    return {
        "graph": {
            "nodes": nodes,
            "edges": edges,
        },
        "summary": {
            "node_count": len(nodes),
            "edge_count": len(edges),
            "trusted_count": trusted_count,
        },
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }

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
        _ensure_schema_migrations(db)
        _bootstrap_membership_from_db(db)

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
        membership_status=membership.summary(),
        node_id=NODE_ID,
    )


@app.route("/admin/membership")
@admin_required
def admin_membership_status():
    """Return membership summary for admin UI/API consumers."""
    return jsonify(membership.summary())


@app.route("/admin/membership/epochs")
@admin_required
def admin_membership_epochs():
    """Return current epoch and epoch history for admin diagnostics."""
    current = membership.get_current_epoch()
    history = membership.get_epoch_history()
    return jsonify(
        {
            "current_epoch": current.to_dict() if current else None,
            "epoch_history": [epoch.to_dict() for epoch in history],
            "epoch_history_count": len(history),
        }
    )


@app.route("/admin/membership/leader")
@admin_required
def admin_membership_leader():
    """Return coordinator/leader diagnostics for epoch transition orchestration."""
    return jsonify(membership.coordination_status())


@app.route("/admin/membership/rekey", methods=["POST"])
@admin_required
def admin_membership_rekey():
    """Run a coordinated rekey action as the local node."""
    data = request.json or {}
    process_pending = bool(data.get("process_pending", False))

    if process_pending:
        success, msg = membership.process_pending_rekeys(requester_node_id=NODE_ID)
    else:
        change_type = str(data.get("change_type", "rotation")).strip() or "rotation"
        affected_node_id = str(data.get("affected_node_id", "admin-triggered")).strip() or "admin-triggered"
        force = bool(data.get("force", False))
        success, msg = membership.coordinate_membership_rekey(
            change_type=change_type,
            affected_node_id=affected_node_id,
            requester_node_id=NODE_ID,
            force=force,
        )

    if not success:
        return jsonify({"error": msg, "coordination": membership.coordination_status()}), 409

    return jsonify(
        {
            "status": "ok",
            "message": msg,
            "coordination": membership.coordination_status(),
            "membership": membership.summary(),
        }
    )


@app.route("/admin/membership/catchup", methods=["POST"])
@admin_required
def admin_membership_catchup():
    """Apply remote catch-up state to local membership and federation context."""
    data = request.json or {}
    epoch_payload = data.get("epoch") or {}
    federation_payload = data.get("federation") or {}
    source_node_id = str(data.get("source_node_id", "")).strip() or None

    if not epoch_payload or not federation_payload:
        return jsonify({"error": "epoch and federation payloads are required"}), 400

    epoch_ok, epoch_msg = membership.accept_remote_epoch_transition(
        epoch_payload,
        source_node_id=source_node_id,
    )
    if not epoch_ok:
        return jsonify({"error": epoch_msg}), 409

    fed_ok, fed_msg = federation.apply_catchup_payload(federation_payload)
    if not fed_ok:
        return jsonify({"error": fed_msg}), 409

    return jsonify(
        {
            "status": "ok",
            "membership": membership.summary(),
            "federation": federation.get_status(),
        }
    )


@app.route("/admin/federation/neighbors")
@admin_required
def admin_federation_neighbors():
    """Return neighbor score diagnostics used for ranked federation exchange."""
    return jsonify(
        {
            "neighbors": federation.get_neighbor_diagnostics(),
            "ranked_neighbors": federation.get_ranked_neighbors(),
        }
    )


@app.route("/admin/graph")
@admin_required
def admin_graph():
    """Return logical federation/membership graph (no physical topology parameters)."""
    db = get_db()
    return jsonify(_build_logical_graph(db))


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
    shared_secret = str(data.get("shared_secret", "")).strip() or None

    if not all([node_id, hostname, ip_address]):
        return jsonify({"error": "node_id, hostname, and ip_address are required"}), 400

    db = get_db()
    try:
        db.execute(
            "INSERT INTO federation_nodes (node_id, hostname, ip_address, port, shared_secret) VALUES (?, ?, ?, ?, ?)",
            (node_id, hostname, ip_address, port, shared_secret),
        )

        success, msg = membership.node_join_request(
            node_id=node_id,
            hostname=hostname,
            ip_address=ip_address,
            port=port,
        )
        if not success:
            db.rollback()
            return jsonify({"error": msg}), 409

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

    if not membership.node_exists(node_id):
        success, msg = membership.node_join_request(
            node_id=node["node_id"],
            hostname=node["hostname"],
            ip_address=node["ip_address"],
            port=int(node["port"]),
        )
        if not success:
            return jsonify({"error": msg}), 409

    new_trust = 0 if node["is_trusted"] else 1

    if new_trust == 1:
        success, msg = membership.approve_node_join(node_id)
        if not success:
            return jsonify({"error": msg}), 409
    else:
        success, msg = membership.node_leave_request(node_id)
        if not success:
            return jsonify({"error": msg}), 409

    db.execute(
        "UPDATE federation_nodes SET is_trusted = ? WHERE node_id = ?",
        (new_trust, node_id),
    )
    db.commit()
    return jsonify(
        {
            "status": "ok",
            "is_trusted": new_trust,
            "membership": membership.summary(),
        }
    )


@app.route("/admin/nodes/<path:node_id>/delete", methods=["POST"])
@admin_required
def delete_node(node_id):
    db = get_db()
    node = db.execute(
        "SELECT * FROM federation_nodes WHERE node_id = ?", (node_id,)
    ).fetchone()
    if not node:
        return jsonify({"error": "Node not found"}), 404

    if membership.node_exists(node_id):
        success, msg = membership.node_leave_request(node_id)
        if not success:
            return jsonify({"error": msg}), 409

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

    direct_ok, direct_reason = _validate_direct_trust_payload(data)
    if not direct_ok:
        db = get_db()
        _audit_federation_trust_event(db, "/federation/request-shard", requester_id, "rejected", direct_reason)
        return jsonify({"error": direct_reason}), 403

    db = get_db()
    node = db.execute(
        "SELECT * FROM federation_nodes WHERE node_id = ? AND is_trusted = 1",
        (requester_id,),
    ).fetchone()
    if not node:
        _audit_federation_trust_event(
            db,
            "/federation/request-shard",
            requester_id,
            "rejected",
            "Node is not in the trusted federation",
        )
        return jsonify({"error": "Node is not in the trusted federation"}), 403

    if not _is_directly_trusted_member(requester_id):
        _audit_federation_trust_event(
            db,
            "/federation/request-shard",
            requester_id,
            "rejected",
            "Node not directly trusted in membership state",
        )
        return jsonify({"error": "Node not directly trusted in membership state"}), 403

    is_valid, reason = _verify_federation_payload_signature(db, data, requester_id, node)
    if not is_valid:
        app.logger.warning("Rejected /federation/request-shard from %s: %s", requester_id, reason)
        _audit_federation_trust_event(db, "/federation/request-shard", requester_id, "rejected", reason)
        return jsonify({"error": reason}), 403

    shard_payload = federation.get_shard_payload_for_node(requester_id)
    if not shard_payload:
        _audit_federation_trust_event(
            db,
            "/federation/request-shard",
            requester_id,
            "rejected",
            "No shard available for this node",
        )
        return jsonify({"error": "No shard available for this node"}), 404
    _audit_federation_trust_event(db, "/federation/request-shard", requester_id, "accepted", "direct trust validated")
    return jsonify(
        {
            "shard": shard_payload["shard"],
            "share_x": shard_payload["share_x"],
            "epoch_id": shard_payload.get("epoch_id"),
            "threshold_k": shard_payload.get("threshold_k"),
            "total_shares_n": shard_payload.get("total_shares_n"),
            "node_id": NODE_ID,
        }
    )


@app.route("/federation/provide-shard", methods=["POST"])
def federation_provide_shard():
    """Neighbour sends us one of our key shards during boot reconstruction."""
    data = request.get_json() or {}
    sender_id = data.get("node_id", "").strip()
    shard = data.get("shard", "").strip()
    share_x = data.get("share_x")
    epoch_id = data.get("epoch_id")

    if not sender_id or not shard:
        return jsonify({"error": "node_id and shard are required"}), 400

    direct_ok, direct_reason = _validate_direct_trust_payload(data)
    if not direct_ok:
        db = get_db()
        _audit_federation_trust_event(db, "/federation/provide-shard", sender_id or "unknown", "rejected", direct_reason)
        return jsonify({"error": direct_reason}), 403

    if share_x is not None:
        try:
            share_x = int(share_x)
        except (TypeError, ValueError):
            return jsonify({"error": "share_x must be an integer"}), 400

    db = get_db()
    node = db.execute(
        "SELECT * FROM federation_nodes WHERE node_id = ? AND is_trusted = 1",
        (sender_id,),
    ).fetchone()
    if not node:
        _audit_federation_trust_event(
            db,
            "/federation/provide-shard",
            sender_id,
            "rejected",
            "Sender is not in the trusted federation",
        )
        return jsonify({"error": "Sender is not in the trusted federation"}), 403

    if not _is_directly_trusted_member(sender_id):
        _audit_federation_trust_event(
            db,
            "/federation/provide-shard",
            sender_id,
            "rejected",
            "Sender not directly trusted in membership state",
        )
        return jsonify({"error": "Sender not directly trusted in membership state"}), 403

    is_valid, reason = _verify_federation_payload_signature(db, data, sender_id, node)
    if not is_valid:
        app.logger.warning("Rejected /federation/provide-shard from %s: %s", sender_id, reason)
        _audit_federation_trust_event(db, "/federation/provide-shard", sender_id, "rejected", reason)
        return jsonify({"error": reason}), 403

    federation.receive_shard(
        sender_node_id=sender_id,
        shard_b64=shard,
        share_x=share_x,
        epoch_id=epoch_id,
    )
    _audit_federation_trust_event(db, "/federation/provide-shard", sender_id, "accepted", "direct trust validated")
    return jsonify({"status": "ok"})


@app.route("/federation/catchup", methods=["POST"])
def federation_catchup():
    """Provide latest epoch + assigned-share payload to trusted rejoining nodes."""
    data = request.get_json() or {}
    requester_id = data.get("node_id", "").strip()
    if not requester_id:
        return jsonify({"error": "node_id required"}), 400

    direct_ok, direct_reason = _validate_direct_trust_payload(data)
    if not direct_ok:
        db = get_db()
        _audit_federation_trust_event(db, "/federation/catchup", requester_id, "rejected", direct_reason)
        return jsonify({"error": direct_reason}), 403

    db = get_db()
    node = db.execute(
        "SELECT * FROM federation_nodes WHERE node_id = ? AND is_trusted = 1",
        (requester_id,),
    ).fetchone()
    if not node:
        _audit_federation_trust_event(db, "/federation/catchup", requester_id, "rejected", "Node is not in the trusted federation")
        return jsonify({"error": "Node is not in the trusted federation"}), 403

    if not _is_directly_trusted_member(requester_id):
        _audit_federation_trust_event(
            db,
            "/federation/catchup",
            requester_id,
            "rejected",
            "Node not directly trusted in membership state",
        )
        return jsonify({"error": "Node not directly trusted in membership state"}), 403

    is_valid, reason = _verify_federation_payload_signature(db, data, requester_id, node)
    if not is_valid:
        app.logger.warning("Rejected /federation/catchup from %s: %s", requester_id, reason)
        _audit_federation_trust_event(db, "/federation/catchup", requester_id, "rejected", reason)
        return jsonify({"error": reason}), 403

    epoch = membership.get_current_epoch()
    if not epoch:
        _audit_federation_trust_event(db, "/federation/catchup", requester_id, "rejected", "No active epoch available")
        return jsonify({"error": "No active epoch available"}), 404

    catchup_payload = federation.get_catchup_payload_for_node(requester_id)
    if not catchup_payload:
        _audit_federation_trust_event(
            db,
            "/federation/catchup",
            requester_id,
            "rejected",
            "No catch-up payload available for node",
        )
        return jsonify({"error": "No catch-up payload available for node"}), 404

    _audit_federation_trust_event(db, "/federation/catchup", requester_id, "accepted", "direct trust validated")

    return jsonify(
        {
            "source_node_id": NODE_ID,
            "epoch": epoch.to_dict(),
            "federation": catchup_payload,
        }
    )


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
            "runtime_profile": ACTIVE_RUNTIME_PROFILE,
            "federation": federation.get_status(),
            "membership": membership.summary(),
            "timestamp": datetime.now(timezone.utc).isoformat(),
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
