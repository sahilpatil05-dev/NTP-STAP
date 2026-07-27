"""
Tests for the SenderManager module.
"""

import socket
import pytest
from unittest.mock import MagicMock, patch

from crypto.engine import CryptoEngine
from sender.manager import SenderManager
from network.exceptions import TransmissionError
from database.manager import get_db, reset_db


@pytest.fixture(autouse=True)
def setup_teardown_db():
    db = get_db()
    db.initialize()
    yield
    reset_db()


class TestSenderManager:
    """Test suite for SenderManager."""

    def test_send_message_success(self) -> None:
        """Verify normal message sending path and database persistence."""
        crypto = CryptoEngine(password="strong-password")
        # Start a local sender
        manager = SenderManager(
            crypto_engine=crypto,
            target_host="127.0.0.1",
            target_port=9123,
            session_id="session-123",
        )

        # Mock the socket transmission to avoid sending real network packets
        with patch("network.sender.socket.socket") as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket
            mock_socket.sendto.return_value = 56  # returns bytes sent

            msg_id = manager.send_message("Hello, Covert Channel!")

            assert msg_id is not None
            # Assert call to socket
            mock_socket.sendto.assert_called_once()

        db = get_db()
        # Verify database record
        msg = db.query_one("SELECT * FROM messages WHERE id = ?", (msg_id,))
        assert msg is not None
        assert msg["plaintext"] == "Hello, Covert Channel!"
        assert msg["status"] == "sent"
        assert msg["session_id"] == "session-123"

        packet = db.query_one("SELECT * FROM packets WHERE id = ?", (msg["packet_id"],))
        assert packet is not None
        assert packet["direction"] == "sent"
        assert packet["dest_port"] == 9123

        session = db.query_one("SELECT * FROM sessions WHERE id = ?", ("session-123",))
        assert session is not None
        assert session["packets_sent"] == 1

    def test_send_message_transmission_failure(self) -> None:
        """Verify failure behavior when transmission fails."""
        crypto = CryptoEngine(password="strong-password")
        manager = SenderManager(
            crypto_engine=crypto,
            target_host="127.0.0.1",
            target_port=9123,
            session_id="session-123",
        )

        # Mock socket to raise OSError
        with patch("network.sender.socket.socket") as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket
            mock_socket.sendto.side_effect = OSError("Network unreachable")

            with pytest.raises(TransmissionError):
                manager.send_message("Hello, Covert Channel!")

        db = get_db()
        # Message should still be persisted but status = failed
        msg = db.query_one("SELECT * FROM messages WHERE plaintext = ?", ("Hello, Covert Channel!",))
        assert msg is not None
        assert msg["status"] == "failed"

        # Verification of logged error in the errors table
        err = db.query_one("SELECT * FROM errors WHERE module = 'sender.manager'")
        assert err is not None
        assert "TransmissionError" in err["error_type"]
