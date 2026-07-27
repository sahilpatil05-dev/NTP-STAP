"""
NTP-SCTAP Route Definitions.

Registers all HTTP endpoints on the Flask application. Routes are
grouped by concern:

  - **Pages** — HTML views rendered via Jinja2 templates.
  - **API**  — JSON endpoints for programmatic access.
  - **Health** — Operational status checks.
  - **Packets** — Packet history and inspection.
  - **Messages** — Message log retrieval.
  - **Sessions** — Session management.
  - **Threats** — Threat alerts and analysis.
  - **Analytics** — Metrics and dashboard data.
"""

import io
import json
import platform
import sys
import base64
from datetime import datetime, timezone
import ipaddress
from flask import Flask, jsonify, render_template, request, send_file

from config.settings import get_config
from database.manager import get_db
from dashboard.manager import get_dashboard_manager
from utils.logger import get_logger
from utils.helpers import iso_timestamp

logger = get_logger("backend.routes")

# ── Constants ────────────────────────────────────────────────────

MAX_PACKETS_LIMIT = 500
MAX_MESSAGES_LIMIT = 500
MAX_THREATS_LIMIT = 500
MAX_ERRORS_LIMIT = 200
MAX_ANALYTICS_LIMIT = 200
MIN_PASSWORD_LENGTH = 8
DEFAULT_PACKET_LIMIT = 50
DEFAULT_SESSION_LIMIT = 100
DEFAULT_ANALYTICS_LIMIT = 50


def _bytes_to_hex(data):
    """
    Recursively convert bytes into hex strings so the object
    becomes JSON serializable. Handles custom objects like sqlite3.Row.
    """
    if isinstance(data, bytes):
        return data.hex()

    if isinstance(data, dict):
        return {k: _bytes_to_hex(v) for k, v in data.items()}

    if isinstance(data, (list, tuple)):
        converted = [_bytes_to_hex(v) for v in data]
        return tuple(converted) if isinstance(data, tuple) else converted

    # Handle sqlite3.Row and other mapping-like objects
    try:
        return {k: _bytes_to_hex(data[k]) for k in data.keys()}
    except (AttributeError, TypeError):
        pass

    return data


def _validate_password(password: str) -> tuple[bool, str]:
    """Validate password format and length. Returns (valid, error_message)."""
    if not password or len(password.strip()) == 0:
        return False, "Password cannot be empty."
    if len(password) < MIN_PASSWORD_LENGTH:
        return False, f"Password must be at least {MIN_PASSWORD_LENGTH} characters."
    return True, ""


def _validate_port(port: int) -> tuple[bool, str]:
    """Validate port number. Returns (valid, error_message)."""
    try:
        port_int = int(port)
        if port_int < 1 or port_int > 65535:
            return False, "Port must be between 1 and 65535."
        return True, ""
    except (TypeError, ValueError):
        return False, "Port must be a valid integer."


def _validate_host(host: str) -> tuple[bool, str]:
    """Validate IP address or hostname. Returns (valid, error_message)."""
    try:
        ipaddress.ip_address(host)
        return True, ""
    except ValueError:
        return False, "Invalid IP address."


def _update_realtime_dashboard(socketio) -> None:
    """Update all connected clients with latest analytics."""
    try:
        db = get_db()
        from analytics.engine import AnalyticsEngine
        
        ae = AnalyticsEngine()
        metrics = ae.calculate_metrics()
        socketio.emit("analytics_activity", metrics)
    except Exception:
        logger.exception("Failed to update realtime dashboard")


def register_routes(app: Flask) -> None:
    """Attach all route handlers to *app*."""

    cfg = get_config()

    # ── Page Routes ──────────────────────────────────────────────────

    @app.route("/")
    def index():
        """Serve the home page."""
        return render_template("index.html", config=cfg)

    # ── Health / Status API ──────────────────────────────────────────

    @app.route("/api/health")
    def health():
        """Lightweight liveness probe."""
        return jsonify({"status": "healthy", "timestamp": iso_timestamp()})

    @app.route("/api/status")
    def status():
        """Comprehensive system status."""
        db = get_db()
        db_stats = db.get_stats()

        return jsonify({
            "application": {
                "name": cfg.APP_NAME,
                "version": cfg.APP_VERSION,
                "debug": cfg.DEBUG,
                "uptime_check": iso_timestamp(),
            },
            "system": {
                "python_version": sys.version,
                "platform": platform.platform(),
                "architecture": platform.machine(),
            },
            "database": db_stats,
            "network": {
                "send_port": cfg.NTP_SEND_PORT,
                "listen_port": cfg.NTP_LISTEN_PORT,
                "target_host": cfg.NTP_TARGET_HOST,
            },
            "crypto": {
                "algorithm": cfg.CRYPTO_ALGORITHM,
                "key_length_bits": cfg.CRYPTO_KEY_LENGTH * 8,
            },
        })

    @app.route("/api/config")
    def get_configuration():
        """Return non-secret configuration values."""
        return jsonify(cfg.as_dict())

    # ── Packets API ─────────────────────────────────────────────────

    @app.route("/api/packets")
    def get_packets():
        """Return recent packet logs.

        Query parameters:
            limit:     Max rows (default 50, max 500).
            direction: 'sent' or 'received' (optional filter).
        """
        db = get_db()
        limit = min(int(request.args.get("limit", DEFAULT_PACKET_LIMIT)), MAX_PACKETS_LIMIT)
        direction = request.args.get("direction")

        if direction and direction in ("sent", "received"):
            rows = db.query(
                "SELECT id, session_id, direction, source_host, source_port, "
                "dest_host, dest_port, packet_size, payload_status, "
                "encryption_status, validation, created_at "
                "FROM packets WHERE direction = ? ORDER BY created_at DESC LIMIT ?",
                (direction, limit),
            )
        else:
            rows = db.query(
                "SELECT id, session_id, direction, source_host, source_port, "
                "dest_host, dest_port, packet_size, payload_status, "
                "encryption_status, validation, created_at "
                "FROM packets ORDER BY created_at DESC LIMIT ?",
                (limit,),
            )

        return jsonify({"packets": rows, "count": len(rows)})

    @app.route("/api/packets/<packet_id>")
    def get_packet(packet_id: str):
        """Return a single packet record (without raw_data for bandwidth)."""
        db = get_db()
        row = db.query_one(
            "SELECT id, session_id, direction, source_host, source_port, "
            "dest_host, dest_port, packet_size, payload_status, "
            "encryption_status, validation, created_at "
            "FROM packets WHERE id = ?",
            (packet_id,),
        )
        if not row:
            return jsonify({"status": "error", "error": "Packet not found"}), 404
        return jsonify({"status": "success", "data": row})

    # ── Messages API ────────────────────────────────────────────────

    @app.route("/api/messages")
    def get_messages():
        """Return recent message logs."""
        db = get_db()
        limit = min(int(request.args.get("limit", DEFAULT_PACKET_LIMIT)), MAX_MESSAGES_LIMIT)
        direction = request.args.get("direction")

        if direction and direction in ("sent", "received"):
            rows = db.query(
                "SELECT id, session_id, packet_id, direction, plaintext, "
                "status, created_at "
                "FROM messages WHERE direction = ? ORDER BY created_at DESC LIMIT ?",
                (direction, limit),
            )
        else:
            rows = db.query(
                "SELECT id, session_id, packet_id, direction, plaintext, "
                "status, created_at "
                "FROM messages ORDER BY created_at DESC LIMIT ?",
                (limit,),
            )

        return jsonify({"messages": rows, "count": len(rows)})

    # ── Sessions API ────────────────────────────────────────────────

    @app.route("/api/sessions")
    def get_sessions():
        """Return all communication sessions."""
        db = get_db()
        rows = db.query(
            "SELECT id, status, sender_host, receiver_host, packets_sent, "
            "packets_received, started_at, ended_at "
            "FROM sessions ORDER BY started_at DESC LIMIT ?",
            (DEFAULT_SESSION_LIMIT,)
        )
        return jsonify({"sessions": rows, "count": len(rows)})

    # ── Threats API ─────────────────────────────────────────────────

    @app.route("/api/threats")
    def get_threats():
        """Return threat detection alerts."""
        db = get_db()
        limit = min(int(request.args.get("limit", DEFAULT_PACKET_LIMIT)), MAX_THREATS_LIMIT)
        severity = request.args.get("severity")

        if severity:
            rows = db.query(
                "SELECT id, packet_id, session_id, threat_level, confidence, "
                "alert_reason, severity, recommendation, detected_at "
                "FROM threats WHERE severity = ? ORDER BY detected_at DESC LIMIT ?",
                (severity, limit),
            )
        else:
            rows = db.query(
                "SELECT id, packet_id, session_id, threat_level, confidence, "
                "alert_reason, severity, recommendation, detected_at "
                "FROM threats ORDER BY detected_at DESC LIMIT ?",
                (limit,),
            )

        return jsonify({"threats": rows, "count": len(rows)})

    @app.route("/api/threats/summary")
    def get_threats_summary():
        """Return aggregated threat statistics."""
        db = get_db()
        total = db.count("threats")
        critical = db.count("threats", "threat_level = 'critical'")
        high = db.count("threats", "threat_level = 'high'")
        medium = db.count("threats", "threat_level = 'medium'")
        low = db.count("threats", "threat_level = 'low'")

        return jsonify({
            "total": total,
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
        })

    # ── Analytics API ───────────────────────────────────────────────

    @app.route("/api/analytics")
    def get_analytics():
        """Return the latest analytics metrics."""
        db = get_db()

        # Try to get fresh metrics from the analytics engine
        try:
            from analytics.engine import AnalyticsEngine
            engine = AnalyticsEngine()
            metrics = engine.calculate_metrics()
        except Exception as e:
            logger.warning("Analytics calculation failed: %s", e)
            metrics = {}

        # Supplement with threat stats
        metrics["threats_total"] = db.count("threats")
        metrics["threats_critical"] = db.count("threats", "threat_level = 'critical'")
        metrics["active_sessions"] = db.count("sessions", "status = 'active'")
        metrics["total_errors"] = db.count("errors")

        return jsonify(metrics)

    @app.route("/api/analytics/history")
    def get_analytics_history():
        """Return historical analytics snapshots for charting."""
        db = get_db()
        metric_name = request.args.get("metric", "packets_sent")
        limit = min(int(request.args.get("limit", DEFAULT_ANALYTICS_LIMIT)), MAX_ANALYTICS_LIMIT)

        rows = db.query(
            "SELECT metric_name, metric_value, unit, recorded_at "
            "FROM analytics WHERE metric_name = ? ORDER BY recorded_at DESC LIMIT ?",
            (metric_name, limit),
        )

        return jsonify({"metric": metric_name, "data": rows})

    # ── Errors API ──────────────────────────────────────────────────

    @app.route("/api/errors")
    def get_errors():
        """Return recent error logs."""
        db = get_db()
        limit = min(int(request.args.get("limit", DEFAULT_PACKET_LIMIT)), MAX_ERRORS_LIMIT)
        rows = db.query(
            "SELECT id, error_type, module, message, created_at "
            "FROM errors ORDER BY created_at DESC LIMIT ?",
            (limit,),
        )
        return jsonify({"errors": rows, "count": len(rows)})

    # ── Dashboard Summary API ───────────────────────────────────────

    @app.route("/api/dashboard")
    def get_dashboard():
        """Single endpoint returning all data the dashboard needs."""
        db = get_db()

        packets_sent = db.count("packets", "direction = 'sent'")
        packets_received = db.count("packets", "direction = 'received'")
        messages_sent = db.count("messages", "direction = 'sent'")
        messages_received = db.count("messages", "direction = 'received'")
        threats_total = db.count("threats")
        threats_critical = db.count("threats", "threat_level = 'critical'")
        active_sessions = db.count("sessions", "status = 'active'")
        total_errors = db.count("errors")

        # Recent activity (last 10 packets)
        recent_packets = db.query(
            "SELECT id, direction, source_host, dest_host, packet_size, "
            "payload_status, validation, created_at "
            "FROM packets ORDER BY created_at DESC LIMIT 10"
        )

        # Recent threats (last 5)
        recent_threats = db.query(
            "SELECT id, threat_level, alert_reason, severity, confidence, detected_at "
            "FROM threats ORDER BY detected_at DESC LIMIT 5"
        )

        return jsonify({
            "stats": {
                "packets_sent": packets_sent,
                "packets_received": packets_received,
                "messages_sent": messages_sent,
                "messages_received": messages_received,
                "threats_total": threats_total,
                "threats_critical": threats_critical,
                "active_sessions": active_sessions,
                "total_errors": total_errors,
            },
            "recent_packets": recent_packets,
            "recent_threats": recent_threats,
            "config": cfg.as_dict(),
        })

    # ── Message Transmission API ──────────────────────────────────────

    @app.route("/api/messages/send", methods=["POST"])
    def send_covert_message():
        """Encrypt, pack, and transmit a message."""
        
        # Validate request is JSON
        if not request.is_json:
            return jsonify({
                "status": "error",
                "error": "Request must be JSON."
            }), 400

        data = request.get_json() or {}

        plaintext = (data.get("plaintext") or "").strip()
        password = (data.get("password") or "").strip()
        target_host = (data.get("target_host") or cfg.NTP_TARGET_HOST).strip()
        target_port = data.get("target_port", cfg.NTP_SEND_PORT)

        # -------- Message Validation --------
        if not plaintext:
            return jsonify({
                "status": "error",
                "error": "Message cannot be empty."
            }), 400

        if len(plaintext) > 10000:
            return jsonify({
                "status": "error",
                "error": "Message exceeds maximum length (10000 characters)."
            }), 400

        # -------- Password Validation --------
        password_valid, password_error = _validate_password(password)
        if not password_valid:
            return jsonify({
                "status": "error",
                "error": password_error
            }), 400

        # -------- Port Validation --------
        port_valid, port_error = _validate_port(target_port)
        if not port_valid:
            return jsonify({
                "status": "error",
                "error": port_error
            }), 400

        # -------- Host/IP Validation --------
        host_valid, host_error = _validate_host(target_host)
        if not host_valid:
            return jsonify({
                "status": "error",
                "error": host_error
            }), 400

        # -------- Synchronize Receiver Password --------
        try:
            from backend.app_factory import socketio
            
            mgr = get_dashboard_manager()
            
            # If password changed, restart receiver with new password
            if mgr.current_password != password:
                def on_message_recovered(plaintext: str, session_id: str) -> None:
                    socketio.emit("message_activity", {
                        "plaintext": plaintext,
                        "session_id": session_id,
                        "direction": "received",
                        "status": "decrypted",
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    })
                    _update_realtime_dashboard(socketio)
                
                success = mgr.start_receiver(
                    password=password,
                    message_callback=on_message_recovered
                )
                
                if not success:
                    return jsonify({
                        "status": "error",
                        "error": "Failed to restart receiver with the new password."
                    }), 500

            # -------- Encryption & Transmission --------
            from crypto.engine import CryptoEngine
            from sender.manager import SenderManager

            crypto = CryptoEngine(password=password)

            sender = SenderManager(
                crypto_engine=crypto,
                target_host=target_host,
                target_port=int(target_port)
            )

            msg_id = sender.send_message(plaintext)

            db = get_db()

            # Fetch latest packet and message for real-time updates
            pkt = db.query_one(
                "SELECT * FROM packets ORDER BY created_at DESC LIMIT 1"
            )

            msg = db.query_one(
                "SELECT * FROM messages ORDER BY created_at DESC LIMIT 1"
            )

            if pkt:
                socketio.emit("packet_activity", pkt)

            if msg:
                socketio.emit("message_activity", msg)

            # Update real-time dashboard
            _update_realtime_dashboard(socketio)

            return jsonify({
                "status": "success",
                "message_id": msg_id
            })

        except Exception as e:
            logger.exception("Failed to send covert message: %s", e)
            return jsonify({
                "status": "error",
                "error": "Transmission failed. Please try again."
            }), 500

    # ── Receiver Control API ──────────────────────────────────────────

    @app.route("/api/receiver/control", methods=["POST"])
    def control_receiver():
        """Start or stop the background UDP receiver thread."""
        
        if not request.is_json:
            return jsonify({"status": "error", "error": "Request must be JSON."}), 400

        data = request.get_json() or {}
        action = data.get("action")
        password = (data.get("password") or "").strip()

        if action not in ("start", "stop"):
            return jsonify({
                "status": "error",
                "error": "Invalid action. Must be 'start' or 'stop'."
            }), 400

        if action == "start":
            password_valid, password_error = _validate_password(password)
            if not password_valid:
                return jsonify({
                    "status": "error",
                    "error": password_error
                }), 400

        mgr = get_dashboard_manager()
        from backend.app_factory import socketio

        try:
            if action == "start":
                # Real-time decryption message recovery callback
                def on_message_recovered(plaintext: str, session_id: str) -> None:
                    socketio.emit("message_activity", {
                        "plaintext": plaintext,
                        "session_id": session_id,
                        "direction": "received",
                        "status": "decrypted",
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    })
                    _update_realtime_dashboard(socketio)

                success = mgr.start_receiver(password=password, message_callback=on_message_recovered)
            else:
                success = mgr.stop_receiver()

            if success:
                socketio.emit("system_monitoring", mgr.get_metrics())
                return jsonify({
                    "status": "success",
                    "receiver_running": mgr.is_receiver_running()
                })
            else:
                return jsonify({
                    "status": "error",
                    "error": f"Failed to {action} receiver."
                }), 500

        except Exception as e:
            logger.exception("Failed to control receiver: %s", e)
            return jsonify({
                "status": "error",
                "error": "Receiver control failed. Please try again."
            }), 500

    @app.route("/api/receiver/status")
    def receiver_status():
        """Retrieve current receiver running status."""
        mgr = get_dashboard_manager()
        return jsonify({
            "status": "success",
            "receiver_running": mgr.is_receiver_running(),
            "bind_host": "0.0.0.0",
            "bind_port": cfg.NTP_LISTEN_PORT
        })

    # ── Packet Inspection API ─────────────────────────────────────────

    @app.route("/api/packets/<packet_id>/inspect")
    def inspect_packet(packet_id: str):
        """Detailed packet inspection and parsing."""
        db = get_db()
        pkt = db.query_one("SELECT * FROM packets WHERE id = ?", (packet_id,))
        if not pkt:
            return jsonify({
                "status": "error",
                "error": "Packet not found"
            }), 404

        raw_data = pkt.get("raw_data")
        if not raw_data:
            return jsonify({
                "status": "error",
                "error": "Raw data missing from packet log"
            }), 400

        try:
            from protocol.packet import NTPPacket
            packet = NTPPacket.unpack(raw_data)

            # Format hex dump
            hex_part = " ".join(f"{b:02x}" for b in raw_data)
            hex_dump_lines = []
            for i in range(0, len(raw_data), 16):
                chunk = raw_data[i:i+16]
                h_vals = " ".join(f"{b:02x}" for b in chunk)
                h_padded = h_vals.ljust(47)
                a_vals = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
                hex_dump_lines.append(f"{i:04x}  {h_padded}  |{a_vals}|")
            hex_dump = "\n".join(hex_dump_lines)

            # Convert NTP timestamps
            def to_ntp_float(val: int) -> float:
                return (val >> 32) + ((val & 0xFFFFFFFF) / 4294967296.0)

            ref_t = to_ntp_float(packet.ref_timestamp)
            org_t = to_ntp_float(packet.origin_timestamp)
            rec_t = to_ntp_float(packet.recv_timestamp)
            tx_t = to_ntp_float(packet.tx_timestamp)

            # Try to resolve Ref ID
            ref_id_str = ""
            try:
                ref_id_str = packet.ref_id.decode("ascii")
                if not ref_id_str.isprintable():
                    ref_id_str = ".".join(str(b) for b in packet.ref_id)
            except Exception:
                ref_id_str = ".".join(str(b) for b in packet.ref_id)

            # Extract timeline if exists in metadata
            timeline = {}
            try:
                metadata = json.loads(pkt.get("metadata_json") or "{}")
                timeline = metadata.get("timeline", {})
            except Exception:
                pass

            # Threat and message associations
            threat = db.query_one("SELECT * FROM threats WHERE packet_id = ?", (packet_id,))
            message = db.query_one("SELECT * FROM messages WHERE packet_id = ?", (packet_id,))

            # Convert Row objects to dicts for safe serialization
            threat_data = _bytes_to_hex(dict(threat)) if threat else None
            message_data = _bytes_to_hex(dict(message)) if message else None

            response = {
                "status": "success",
                "packet": {
                    "id": pkt["id"],
                    "session_id": pkt["session_id"],
                    "direction": pkt["direction"],
                    "source_host": pkt["source_host"],
                    "source_port": pkt["source_port"],
                    "dest_host": pkt["dest_host"],
                    "dest_port": pkt["dest_port"],
                    "packet_size": pkt["packet_size"],
                    "payload_status": pkt["payload_status"],
                    "encryption_status": pkt["encryption_status"],
                    "validation": pkt["validation"],
                    "created_at": pkt["created_at"],
                },
                "fields": {
                    "leap": packet.leap,
                    "version": packet.version,
                    "mode": packet.mode,
                    "stratum": packet.stratum,
                    "poll": packet.poll,
                    "precision": packet.precision,
                    "root_delay": packet.root_delay,
                    "root_dispersion": packet.root_dispersion,
                    "ref_id": ref_id_str,
                    "ref_id_hex": packet.ref_id.hex(),
                    "ref_timestamp": ref_t,
                    "origin_timestamp": org_t,
                    "recv_timestamp": rec_t,
                    "tx_timestamp": tx_t,
                    "extension_length": len(packet.extension_data)
                },
                "hex_dump": hex_dump,
                "hex_raw": hex_part,
                "timeline": timeline,
                "threat": threat_data,
                "message": message_data
            }

            # Debug: Verify response is JSON serializable
            try:
                json.dumps(_bytes_to_hex(response))
            except TypeError as e:
                logger.error("Response contains non-serializable object: %s", e)
                raise

            return jsonify(_bytes_to_hex(response))
        except Exception as e:
            logger.exception("Failed to inspect packet: %s", e)
            return jsonify({
                "status": "error",
                "error": "Packet inspection failed."
            }), 500

    # ── Session Replay API ────────────────────────────────────────────

    @app.route("/api/sessions/<session_id>/replay")
    def replay_session(session_id: str):
        """Return chronological transmission flow for session replay."""
        db = get_db()
        session = db.query_one("SELECT * FROM sessions WHERE id = ?", (session_id,))
        if not session:
            return jsonify({
                "status": "error",
                "error": "Session not found"
            }), 404

        packets = db.query(
            "SELECT id, direction, source_host, source_port, dest_host, dest_port, "
            "packet_size, payload_status, encryption_status, validation, "
            "metadata_json, created_at FROM packets WHERE session_id = ? "
            "ORDER BY created_at ASC",
            (session_id,)
        )

        steps = []
        for p in packets:
            p_id = p["id"]
            # Find related threats and messages
            threat = db.query_one("SELECT * FROM threats WHERE packet_id = ?", (p_id,))
            msg = db.query_one("SELECT * FROM messages WHERE packet_id = ?", (p_id,))

            # Timeline
            timeline = {}
            try:
                metadata = json.loads(p.get("metadata_json") or "{}")
                timeline = metadata.get("timeline", {})
            except Exception:
                pass

            # Serialize message ciphertext as hex
            ciphertext_size = 0
            if msg and msg.get("ciphertext"):
                ciphertext = msg.get("ciphertext")
                ciphertext_size = len(ciphertext) if isinstance(ciphertext, bytes) else len(ciphertext.encode())

            # Convert Row objects to dicts for safe serialization
            threat_data = _bytes_to_hex(dict(threat)) if threat else None
            msg_data = _bytes_to_hex(dict(msg)) if msg else None

            steps.append({
                "packet_id": p_id,
                "direction": p["direction"],
                "source": f"{p['source_host']}:{p['source_port']}",
                "destination": f"{p['dest_host']}:{p['dest_port']}",
                "size": p["packet_size"],
                "payload_status": p["payload_status"],
                "encryption_status": p["encryption_status"],
                "validation": p["validation"],
                "created_at": p["created_at"],
                "timeline": timeline,
                "message": msg_data.get("plaintext") if msg_data else None,
                "ciphertext_size": ciphertext_size,
                "threat": threat_data
            })

        response = {
            "status": "success",
            "session": dict(session) if session else None,
            "steps": steps,
            "count": len(steps)
        }

        # Debug: Verify response is JSON serializable
        try:
            json.dumps(_bytes_to_hex(response))
        except TypeError as e:
            logger.error("Response contains non-serializable object: %s", e)
            raise

        return jsonify(_bytes_to_hex(response))

    # ── Export Center API ─────────────────────────────────────────────

    @app.route("/api/export")
    def export_data():
        """Export system tables as JSON, CSV, or PDF formats."""
        domain = request.args.get("domain", "packets")
        export_format = request.args.get("format", "json")

        if domain not in ("packets", "threats", "sessions", "analytics", "config"):
            return jsonify({"status": "error", "error": "Invalid domain specification"}), 400
        if export_format not in ("json", "csv", "pdf"):
            return jsonify({"status": "error", "error": "Invalid format specification"}), 400

        db = get_db()
        data = []
        headers = []

        if domain == "packets":
            data = db.query("SELECT * FROM packets ORDER BY created_at DESC LIMIT 500")
            headers = ["id", "session_id", "direction", "source_host", "source_port", "dest_host", "dest_port", "packet_size", "payload_status", "encryption_status", "validation", "created_at"]
        elif domain == "threats":
            data = db.query("SELECT * FROM threats ORDER BY detected_at DESC LIMIT 500")
            headers = ["id", "packet_id", "session_id", "threat_level", "confidence", "alert_reason", "severity", "recommendation", "detected_at"]
        elif domain == "sessions":
            data = db.query("SELECT * FROM sessions ORDER BY started_at DESC LIMIT 200")
            headers = ["id", "status", "sender_host", "receiver_host", "packets_sent", "packets_received", "started_at", "ended_at"]
        elif domain == "analytics":
            data = db.query("SELECT * FROM analytics ORDER BY recorded_at DESC LIMIT 500")
            headers = ["id", "metric_name", "metric_value", "unit", "recorded_at"]
        elif domain == "config":
            data = [{"key": k, "value": v, "description": "System Setting", "updated_at": datetime.now(timezone.utc).isoformat()} for k, v in cfg.as_dict().items()]
            headers = ["key", "value", "description", "updated_at"]

        # Serialize exports
        try:
            from utils.exporter import export_to_json, export_to_csv, generate_pdf_report

            filename = f"sctap_{domain}_{iso_timestamp()[:10]}"

            if export_format == "json":
                json_str = export_to_json(data)
                mem_file = io.BytesIO(json_str.encode("utf-8"))
                return send_file(
                    mem_file,
                    mimetype="application/json",
                    as_attachment=True,
                    download_name=f"{filename}.json"
                )

            elif export_format == "csv":
                csv_str = export_to_csv(headers, data)
                mem_file = io.BytesIO(csv_str.encode("utf-8"))
                return send_file(
                    mem_file,
                    mimetype="text/csv",
                    as_attachment=True,
                    download_name=f"{filename}.csv"
                )

            elif export_format == "pdf":
                pdf_bytes = generate_pdf_report(domain, data)
                mem_file = io.BytesIO(pdf_bytes)
                return send_file(
                    mem_file,
                    mimetype="application/pdf",
                    as_attachment=True,
                    download_name=f"{filename}.pdf"
                )

        except Exception as e:
            logger.exception("Failed to export data: %s", e)
            return jsonify({
                "status": "error",
                "error": "Export failed. Please try again."
            }), 500

    # ── System Monitor Standalone API ─────────────────────────────────

    @app.route("/api/system/monitoring")
    def get_system_monitoring():
        """Retrieve real-time platform system performance stats."""
        mgr = get_dashboard_manager()
        return jsonify({
            "status": "success",
            "data": mgr.get_metrics()
        })

    # ── Error handlers ───────────────────────────────────────────────

    @app.errorhandler(404)
    def not_found(error):
        if request.path.startswith("/api/"):
            return jsonify({
                "status": "error",
                "error": "Not found",
                "path": request.path
            }), 404
        return render_template("index.html", config=cfg), 404

    @app.errorhandler(500)
    def internal_error(error):
        logger.error("Internal server error: %s", error)
        return jsonify({
            "status": "error",
            "error": "Internal server error"
        }), 500

    logger.info("Routes registered successfully")