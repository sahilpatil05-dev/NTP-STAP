"""
Tests for the ReceiverManager module.
"""

import pytest
from unittest.mock import MagicMock, patch

from crypto.engine import CryptoEngine
from receiver.manager import ReceiverManager
from protocol.packet import NTPPacket
from database.manager import get_db, reset_db


@pytest.fixture(autouse=True)
def setup_teardown_db():
    db = get_db()
    db.initialize()
    yield
    reset_db()


class TestReceiverManager:
    """Test suite for ReceiverManager."""

    def test_on_packet_received_normal(self) -> None:
        """Verify normal callback execution, message decryption and DB persistence."""
        crypto = CryptoEngine(password="strong-password")
        callback_called = []

        def dummy_callback(plaintext: str, session_id: str) -> None:
            callback_called.append((plaintext, session_id))

        manager = ReceiverManager(
            crypto_engine=crypto,
            bind_port=9124,
            message_callback=dummy_callback,
        )

        # Build dummy packet containing encrypted message
        packet = NTPPacket()
        encrypted_data = crypto.encrypt("Secret message")
        packet.inject_extension(encrypted_data)

        # Call internal method directly to simulate socket receiver callback trigger
        manager._on_packet_received(packet, ("127.0.0.1", 30000))

        # Verify callback execution
        assert len(callback_called) == 1
        assert callback_called[0][0] == "Secret message"
        session_id = callback_called[0][1]

        db = get_db()
        # Verify packet persisted in database
        pkt = db.query_one("SELECT * FROM packets WHERE direction = 'received'")
        assert pkt is not None
        assert pkt["source_host"] == "127.0.0.1"
        assert pkt["source_port"] == 30000
        assert pkt["payload_status"] == "present"
        assert pkt["encryption_status"] == "decrypted"

        # Verify message persisted in database
        msg = db.query_one("SELECT * FROM messages WHERE direction = 'received'")
        assert msg is not None
        assert msg["plaintext"] == "Secret message"
        assert msg["status"] == "decrypted"

        # Verify session updated
        session = db.query_one("SELECT * FROM sessions WHERE id = ?", (session_id,))
        assert session is not None
        assert session["packets_received"] == 1

    def test_on_packet_received_decryption_failure(self) -> None:
        """Verify handling of invalid or corrupted ciphertext."""
        crypto = CryptoEngine(password="strong-password")
        manager = ReceiverManager(
            crypto_engine=crypto,
            bind_port=9124,
        )

        packet = NTPPacket()
        # Inject junk extension field that won't decrypt correctly
        packet.inject_extension(b"corrupted ciphertext payload data")

        manager._on_packet_received(packet, ("127.0.0.1", 30000))

        db = get_db()
        # Verify packet is persisted with failed decryption status
        pkt = db.query_one("SELECT * FROM packets WHERE direction = 'received'")
        assert pkt is not None
        assert pkt["payload_status"] == "present"
        assert pkt["encryption_status"] == "failed"

        # Message status should be recorded as decryption failed
        msg = db.query_one("SELECT * FROM messages WHERE direction = 'received'")
        assert msg is not None
        assert msg["plaintext"] is None
        assert msg["status"] == "decryption_failed"

        # Check errors table
        err = db.query_one("SELECT * FROM errors WHERE module = 'receiver.manager'")
        assert err is not None
        assert "DecryptionError" in err["error_type"]

    def test_receiver_start_stop(self) -> None:
        """Verify lifecycle controls of underlying UDPReceiver."""
        crypto = CryptoEngine(password="strong-password")
        manager = ReceiverManager(
            crypto_engine=crypto,
            bind_port=9124,
            message_callback=lambda p, s: None,
        )

        with patch.object(manager.receiver, "start") as mock_start, \
             patch.object(manager.receiver, "stop") as mock_stop:
            manager.start()
            mock_start.assert_called_once()

            manager.stop()
            mock_stop.assert_called_once()
