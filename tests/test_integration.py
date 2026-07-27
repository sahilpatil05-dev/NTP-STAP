"""
Integration tests for the NTP-SCTAP system.
Wires together all subsystems (networking, cryptography, database, threat detection, and analytics).
"""

import socket
import threading
import time
import pytest
from unittest.mock import patch, MagicMock

from config.settings import get_config
from database.manager import get_db, reset_db
from crypto.engine import CryptoEngine
from protocol.packet import NTPPacket
from sender.manager import SenderManager
from receiver.manager import ReceiverManager
from detector.engine import ThreatDetector
from analytics.engine import AnalyticsEngine
from utils.helpers import generate_id, iso_timestamp

@pytest.fixture(autouse=True)
def setup_teardown_db():
    db = get_db()
    db.initialize()
    yield
    reset_db()

class TestIntegrationPipeline:
    """End-to-end and component integration tests."""

    def test_send_and_receive_integration(self) -> None:
        """
        Verify the end-to-end data flow using the network, crypto, protocol,
        receiver, and database.
        
        Send pipeline: Encrypt -> Pack -> Network Send -> Persist
        Receive pipeline: Network Receive -> Parse -> Decrypt -> Threat Detect -> Persist
        """
        crypto = CryptoEngine(password="integration-secret")
        db = get_db()

        received_messages = []
        receive_event = threading.Event()

        def on_message_recovered(plaintext: str, session_id: str) -> None:
            received_messages.append((plaintext, session_id))
            receive_event.set()

        # Initialize the ReceiverManager on an ephemeral port
        receiver = ReceiverManager(
            crypto_engine=crypto,
            bind_host="127.0.0.1",
            bind_port=0,
            message_callback=on_message_recovered,
        )
        receiver.start()
        
        # Get actual bound port
        actual_port = receiver.receiver._sock.getsockname()[1]
        # Make sure bind_port matches the actual socket port for correctness in logs
        receiver.bind_port = actual_port

        try:
            # Initialize SenderManager targeting the receiver
            session_id = "integration-session-xyz"
            sender = SenderManager(
                crypto_engine=crypto,
                target_host="127.0.0.1",
                target_port=actual_port,
                session_id=session_id,
            )

            # Send a covert message
            msg_content = "Covert transmission test message!"
            msg_id = sender.send_message(msg_content)
            assert msg_id is not None

            # Wait for receiver callback to trigger
            success = receive_event.wait(timeout=3.0)
            assert success is True, "Receiver did not recover the message in time"

            # Verify recovered plaintext
            assert len(received_messages) == 1
            rec_text, rec_sess_id = received_messages[0]
            assert rec_text == msg_content
            assert rec_sess_id is not None

            # Verify Database logs:
            # Sender message
            tx_msg = db.query_one("SELECT * FROM messages WHERE id = ?", (msg_id,))
            assert tx_msg is not None
            assert tx_msg["plaintext"] == msg_content
            assert tx_msg["direction"] == "sent"
            assert tx_msg["status"] == "sent"

            # Receiver message
            rx_msg = db.query_one("SELECT * FROM messages WHERE direction = 'received'")
            assert rx_msg is not None
            assert rx_msg["plaintext"] == msg_content
            assert rx_msg["status"] == "decrypted"

            # Sender packet
            tx_pkt = db.query_one("SELECT * FROM packets WHERE id = ?", (tx_msg["packet_id"],))
            assert tx_pkt is not None
            assert tx_pkt["direction"] == "sent"
            assert tx_pkt["payload_status"] == "present"
            assert tx_pkt["encryption_status"] == "encrypted"

            # Receiver packet
            rx_pkt = db.query_one("SELECT * FROM packets WHERE direction = 'received'")
            assert rx_pkt is not None
            assert rx_pkt["payload_status"] == "present"
            assert rx_pkt["encryption_status"] == "decrypted"
            # Threat detector validation check should have run automatically
            assert rx_pkt["validation"] in ("valid", "suspicious", "malicious")

        finally:
            receiver.stop()

    def test_threat_detection_and_analytics_pipeline(self) -> None:
        """
        Verify the Threat Detection and Analytics Engines integration.
        Seeds malicious and normal traffic, runs threat detection,
        and verifies analytics calculates correct summaries.
        """
        db = get_db()
        detector = ThreatDetector()
        analytics = AnalyticsEngine()

        # Seed a session
        session_id = "analytics-integration-session"
        db.insert("sessions", {
            "id": session_id,
            "status": "active",
            "sender_host": "127.0.0.1",
            "receiver_host": "127.0.0.1",
            "packets_sent": 0,
            "packets_received": 0,
        })

        # 1. Seed a packet with timing anomaly (burst)
        from datetime import datetime, timedelta, timezone
        base_time = datetime.now(timezone.utc)
        packet = NTPPacket()
        raw_pkt = packet.pack()

        # Insert 6 packets separated by 2 milliseconds (burst anomaly)
        pkt_ids = []
        for i in range(6):
            ts = (base_time - timedelta(seconds=20) + timedelta(milliseconds=i * 2)).isoformat()
            pkt_id = generate_id()
            db.insert("packets", {
                "id": pkt_id,
                "session_id": session_id,
                "direction": "received",
                "source_host": "192.168.9.9",
                "source_port": 123,
                "dest_host": "127.0.0.1",
                "dest_port": 9124,
                "packet_size": len(raw_pkt),
                "raw_data": raw_pkt,
                "payload_status": "none",
                "encryption_status": "none",
                "validation": "pending",
                "created_at": ts,
            })
            pkt_ids.append(pkt_id)

        # Run ThreatDetector on the last packet of the burst
        threat = detector.analyze_packet(pkt_ids[-1])
        assert threat is not None
        assert "burst" in threat["alert_reason"].lower() or "timing" in threat["alert_reason"].lower()
        assert threat["threat_level"] in ("low", "medium", "high", "critical")

        # Verify database threat log count
        assert db.count("threats") >= 1

        # 2. Seed a packet with a covert payload
        covert_pkt = NTPPacket()
        covert_pkt.inject_extension(b"secret integration test payload")
        raw_covert = covert_pkt.pack()
        covert_pkt_id = generate_id()
        db.insert("packets", {
            "id": covert_pkt_id,
            "session_id": session_id,
            "direction": "received",
            "source_host": "192.168.9.9",
            "source_port": 123,
            "dest_host": "127.0.0.1",
            "dest_port": 9124,
            "packet_size": len(raw_covert),
            "raw_data": raw_covert,
            "payload_status": "present",
            "encryption_status": "none",
            "validation": "pending",
            "created_at": (base_time - timedelta(seconds=10)).isoformat(),
        })

        # Run ThreatDetector on the covert packet
        threat_covert = detector.analyze_packet(covert_pkt_id)
        assert threat_covert is not None
        assert "covert" in threat_covert["alert_reason"].lower() or "extension" in threat_covert["alert_reason"].lower()

        # Update session counters manually to match seeded packets
        db.execute("UPDATE sessions SET packets_received = 7 WHERE id = ?", (session_id,))

        # Run Analytics Engine calculation
        metrics = analytics.calculate_metrics()
        assert metrics is not None
        assert metrics["packets_received"] == 7
        # Fetch latest metrics snapshot
        latest = analytics.get_latest_metrics()
        assert latest is not None
        assert latest["packets_received"] == 7.0
