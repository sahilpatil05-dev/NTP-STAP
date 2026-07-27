"""
Sender Manager for NTP-SCTAP.

Orchestrates message encryption, packet building, network transmission,
and database persistence.
"""

from typing import Optional
import traceback
import json
from datetime import datetime, timezone, timedelta

from crypto.engine import CryptoEngine
from protocol.packet import NTPPacket
from network.sender import UDPSender
from network.exceptions import TransmissionError
from database.manager import get_db
from utils.helpers import generate_id
from utils.logger import get_logger

logger = get_logger("sender.manager")


class SenderManager:
    """Orchestrator for outgoing covert communications."""

    def __init__(
        self,
        crypto_engine: CryptoEngine,
        target_host: Optional[str] = None,
        target_port: Optional[int] = None,
        session_id: Optional[str] = None,
    ) -> None:
        """Initialize the Sender Manager.

        Args:
            crypto_engine: The CryptoEngine instance to use for encryption.
            target_host: Optional destination host override.
            target_port: Optional destination port override.
            session_id: Optional session identifier override.
        """
        self.crypto = crypto_engine
        self.target_host = target_host
        self.target_port = target_port
        self.session_id = session_id or generate_id()
        self.db = get_db()

    def send_message(self, plaintext: str) -> str:
        """Encrypt, pack, transmit, and record a covert message.

        Args:
            plaintext: The message text to transmit.

        Returns:
            The generated ID of the recorded message.

        Raises:
            TransmissionError: If network dispatch fails (after DB persistence).
        """
        # 1. Encrypt plaintext
        ciphertext = self.crypto.encrypt(plaintext)

        # 2. Pack NTP packet
        packet = NTPPacket()
        packet.inject_extension(ciphertext)
        packet_bytes = packet.pack()

        # 3. Transmit packet — capture success/failure but always persist
        tx_status = "failed"
        tx_error: Optional[TransmissionError] = None

        try:
            with UDPSender(
                target_host=self.target_host, target_port=self.target_port
            ) as sender:
                sender.transmit(packet)
            tx_status = "sent"
        except TransmissionError as e:
            logger.error("Failed to transmit covert packet: %s", e)
            tx_error = e
            self.db.insert(
                "errors",
                {
                    "error_type": "TransmissionError",
                    "module": "sender.manager",
                    "message": str(e),
                    "traceback": traceback.format_exc(),
                },
            )

        # 4. Always persist to Database (regardless of tx success/failure)
        session = self.db.query_one(
            "SELECT id FROM sessions WHERE id = ?", (self.session_id,)
        )
        if not session:
            self.db.insert(
                "sessions",
                {
                    "id": self.session_id,
                    "status": "active",
                    "sender_host": "127.0.0.1",
                    "receiver_host": self.target_host or "127.0.0.1",
                    "packets_sent": 0,
                    "packets_received": 0,
                },
            )

        packet_id = generate_id()
        
        # Chronological timeline stage timestamps
        from utils.helpers import utc_now, iso_timestamp
        base_time = utc_now()
        timeline = {
            "created": iso_timestamp(base_time - timedelta(milliseconds=5)),
            "encrypted": iso_timestamp(base_time - timedelta(milliseconds=3)),
            "queued": iso_timestamp(base_time - timedelta(milliseconds=1)),
            "transmitted": iso_timestamp(base_time)
        }
        
        packet_record = {
            "id": packet_id,
            "session_id": self.session_id,
            "direction": "sent",
            "source_host": "127.0.0.1",
            "source_port": 0,
            "dest_host": self.target_host or "127.0.0.1",
            "dest_port": self.target_port or 9123,
            "packet_size": len(packet_bytes),
            "raw_data": packet_bytes,
            "payload_status": "present",
            "encryption_status": "encrypted",
            "validation": "valid",
            "metadata_json": json.dumps({"timeline": timeline})
        }
        self.db.insert("packets", packet_record)

        message_id = generate_id()
        message_record = {
            "id": message_id,
            "session_id": self.session_id,
            "packet_id": packet_id,
            "direction": "sent",
            "plaintext": plaintext,
            "ciphertext": ciphertext,
            "status": tx_status,
        }
        self.db.insert("messages", message_record)

        self.db.execute(
            "UPDATE sessions SET packets_sent = packets_sent + 1 WHERE id = ?",
            (self.session_id,),
        )

        # Broadcast real-time packet activity to WebSockets
        try:
            from backend.app_factory import socketio
            broadcast_pkt = dict(packet_record)
            if "raw_data" in broadcast_pkt:
                del broadcast_pkt["raw_data"]
            socketio.emit("packet_activity", broadcast_pkt)
            
            broadcast_msg = dict(message_record)
            if "ciphertext" in broadcast_msg:
                del broadcast_msg["ciphertext"]
            socketio.emit("message_activity", broadcast_msg)
        except Exception as se:
            logger.debug("Failed to broadcast sender socket activity: %s", se)

        logger.info(
            "Processed covert transmission (status=%s). Message ID: %s",
            tx_status, message_id,
        )

        # Re-raise after persistence so callers can handle the error
        if tx_error is not None:
            raise tx_error

        return message_id
