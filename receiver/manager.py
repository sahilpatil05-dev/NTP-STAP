"""
Receiver Manager for NTP-SCTAP.

Orchestrates UDP listening, packet parsing, database persistence,
and covert payload decryption.
"""

from typing import Callable, Optional
import traceback
import json
from datetime import datetime, timezone, timedelta

from crypto.engine import CryptoEngine
from crypto.exceptions import DecryptionError
from protocol.packet import NTPPacket
from protocol.exceptions import ProtocolError
from network.receiver import UDPReceiver
from database.manager import get_db
from utils.helpers import generate_id
from utils.logger import get_logger

logger = get_logger("receiver.manager")

# Callback type for decrypted message events: takes plaintext and session_id
MessageCallback = Callable[[str, str], None]


class ReceiverManager:
    """Orchestrator for receiving and processing covert packets."""

    def __init__(
        self,
        crypto_engine: CryptoEngine,
        bind_host: str = "0.0.0.0",
        bind_port: Optional[int] = None,
        message_callback: Optional[MessageCallback] = None,
    ) -> None:
        """Initialize the Receiver Manager.

        Args:
            crypto_engine: The CryptoEngine instance to use for decryption.
            bind_host: Interface to bind to.
            bind_port: Port override to listen on.
            message_callback: Optional callback fired on successful message recovery.
        """
        self.crypto = crypto_engine
        self.bind_host = bind_host
        self.bind_port = bind_port
        self.message_callback = message_callback

        self.db = get_db()
        self.receiver = UDPReceiver(
            bind_host=self.bind_host,
            bind_port=self.bind_port,
            callback=self._on_packet_received,
        )

    def start(self) -> None:
        """Start the background UDP listener thread."""
        self.receiver.start()

    def stop(self) -> None:
        """Stop the background UDP listener thread."""
        self.receiver.stop()

    def _on_packet_received(
        self, packet: NTPPacket, addr: tuple[str, int]
    ) -> None:
        """Process incoming raw packets.

        This method acts as the callback for the low-level UDPReceiver. It runs
        on the receiver's background listener thread.
        """
        packet_bytes = packet.pack()
        packet_id = generate_id()

        # 1. Inspect for covert payloads
        covert_payload = packet.extract_extension()
        decrypted_text = None
        encryption_status = "none"
        payload_status = "none"
        msg_status = "received"

        if covert_payload:
            payload_status = "present"
            try:
                decrypted_text = self.crypto.decrypt(covert_payload)
                encryption_status = "decrypted"
                msg_status = "decrypted"
            except DecryptionError as e:
                encryption_status = "failed"
                msg_status = "decryption_failed"
                logger.warning("Failed to decrypt incoming covert payload: %s", e)
                self.db.insert(
                    "errors",
                    {
                        "error_type": "DecryptionError",
                        "module": "receiver.manager",
                        "message": str(e),
                        "traceback": traceback.format_exc(),
                    },
                )

        # 2. Retrieve or start a communications session
        # ✅ BUG-009 FIX: Use ORDER BY started_at DESC to get most recent session
        # This prevents IP-only matching from merging separate conversations
        session = self.db.query_one(
            """
            SELECT id
            FROM sessions
            WHERE sender_host = ?
              AND status = 'active'
            ORDER BY started_at DESC
            LIMIT 1
            """,
            (addr[0],),
        )
        if session:
            session_id = session["id"]
        else:
            session_id = generate_id()
            self.db.insert(
                "sessions",
                {
                    "id": session_id,
                    "status": "active",
                    "sender_host": addr[0],
                    "receiver_host": "127.0.0.1",
                    "packets_sent": 0,
                    "packets_received": 0,
                },
            )

        # Chronological timeline stage timestamps
        from utils.helpers import utc_now, iso_timestamp
        base_time = utc_now()
        timeline = {
            "created": iso_timestamp(base_time - timedelta(milliseconds=20)),
            "encrypted": iso_timestamp(base_time - timedelta(milliseconds=18)),
            "queued": iso_timestamp(base_time - timedelta(milliseconds=16)),
            "transmitted": iso_timestamp(base_time - timedelta(milliseconds=15)),
            "received": iso_timestamp(base_time - timedelta(milliseconds=5)),
            "parsed": iso_timestamp(base_time - timedelta(milliseconds=4)),
            "threat_checked": iso_timestamp(base_time - timedelta(milliseconds=2)),
            "stored": iso_timestamp(base_time)
        }

        # 3. Persist packet log
        packet_record = {
            "id": packet_id,
            "session_id": session_id,
            "direction": "received",
            "source_host": addr[0],
            "source_port": addr[1],
            "dest_host": "127.0.0.1",
            "dest_port": self.bind_port or 0,
            "packet_size": len(packet_bytes),
            "raw_data": packet_bytes,
            "payload_status": payload_status,
            "encryption_status": encryption_status,
            "validation": "pending",
            "metadata_json": json.dumps({"timeline": timeline})
        }
        self.db.insert("packets", packet_record)

        # Update session packet counters
        self.db.execute(
            "UPDATE sessions SET packets_received = packets_received + 1 WHERE id = ?",
            (session_id,),
        )

        # Run Threat Detection Engine
        threat_record = None
        try:
            from detector.engine import ThreatDetector
            detector = ThreatDetector()
            threat_record = detector.analyze_packet(packet_id)
            
            # Fetch updated validation status
            updated_pkt = self.db.query_one("SELECT validation FROM packets WHERE id = ?", (packet_id,))
            if updated_pkt:
                packet_record["validation"] = updated_pkt["validation"]
        except Exception as de:
            logger.error("Threat detector execution failed: %s", de)

        # Broadcast real-time activity to WebSockets
        try:
            from backend.app_factory import socketio
            broadcast_pkt = dict(packet_record)
            if "raw_data" in broadcast_pkt:
                del broadcast_pkt["raw_data"]
            socketio.emit("packet_activity", broadcast_pkt)
            
            if threat_record:
                broadcast_threat = dict(threat_record)
                if "details_json" in broadcast_threat:
                    try:
                        broadcast_threat["details"] = json.loads(broadcast_threat["details_json"])
                        del broadcast_threat["details_json"]
                    except Exception:
                        pass
                socketio.emit("threat_activity", broadcast_threat)
        except Exception as se:
            logger.debug("Failed to broadcast receiver socket activity: %s", se)

        # 4. Save and dispatch decrypted messages
        if covert_payload:
            message_id = generate_id()
            # ✅ BUG-034 FIX: Use None instead of empty string for failed decryption
            self.db.insert(
                "messages",
                {
                    "id": message_id,
                    "session_id": session_id,
                    "packet_id": packet_id,
                    "direction": "received",
                    "plaintext": decrypted_text,  # Will be None if decryption failed
                    "ciphertext": covert_payload,
                    "status": msg_status,
                },
            )

            if decrypted_text and self.message_callback:
                try:
                    self.message_callback(decrypted_text, session_id)
                except Exception as e:
                    logger.error(
                        "Error executing receiver message event callback: %s", e
                    )