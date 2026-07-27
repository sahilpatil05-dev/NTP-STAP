"""
Tests for the AnalyticsEngine module.
"""

import pytest

from analytics.engine import AnalyticsEngine
from database.manager import get_db, reset_db


@pytest.fixture(autouse=True)
def setup_teardown_db():
    db = get_db()
    db.initialize()
    yield
    reset_db()


class TestAnalyticsEngine:
    """Test suite for AnalyticsEngine."""

    def test_calculate_metrics_empty(self) -> None:
        """Verify metric calculation when database contains no traffic."""
        engine = AnalyticsEngine()
        metrics = engine.calculate_metrics()

        assert metrics["packets_sent"] == 0
        assert metrics["packets_received"] == 0
        assert metrics["messages_sent"] == 0
        assert metrics["messages_received"] == 0
        assert metrics["avg_packet_size_sent"] == 0.0
        assert metrics["avg_packet_size_received"] == 0.0
        assert metrics["decryption_success_rate"] == 100.0  # Safe division by zero

    def test_calculate_metrics_with_data(self) -> None:
        """Verify metric calculation under standard traffic workload."""
        db = get_db()
        engine = AnalyticsEngine()

        # Seed session first to satisfy foreign key constraints
        db.insert("sessions", {
            "id": "session-1",
            "status": "active",
            "sender_host": "127.0.0.1",
            "receiver_host": "127.0.0.1",
        })

        # Seed packets
        db.insert("packets", {
            "session_id": "session-1",
            "direction": "sent",
            "source_host": "127.0.0.1",
            "source_port": 0,
            "dest_host": "127.0.0.1",
            "dest_port": 9123,
            "packet_size": 48,
        })
        db.insert("packets", {
            "session_id": "session-1",
            "direction": "sent",
            "source_host": "127.0.0.1",
            "source_port": 0,
            "dest_host": "127.0.0.1",
            "dest_port": 9123,
            "packet_size": 96,
        })
        db.insert("packets", {
            "session_id": "session-1",
            "direction": "received",
            "source_host": "127.0.0.1",
            "source_port": 3000,
            "dest_host": "127.0.0.1",
            "dest_port": 9124,
            "packet_size": 100,
        })

        # Seed messages
        db.insert("messages", {
            "session_id": "session-1",
            "direction": "sent",
            "status": "sent",
        })
        db.insert("messages", {
            "session_id": "session-1",
            "direction": "received",
            "status": "decrypted",
        })
        db.insert("messages", {
            "session_id": "session-1",
            "direction": "received",
            "status": "decryption_failed",
        })

        metrics = engine.calculate_metrics()

        assert metrics["packets_sent"] == 2
        assert metrics["packets_received"] == 1
        assert metrics["messages_sent"] == 1
        assert metrics["messages_received"] == 2
        assert metrics["avg_packet_size_sent"] == 72.0  # (48+96)/2
        assert metrics["avg_packet_size_received"] == 100.0
        assert metrics["decryption_success_rate"] == 50.0  # 1 decrypted out of 2 attempts

        # Fetch latest metrics from DB
        latest = engine.get_latest_metrics()
        assert latest["packets_sent"] == 2.0
        assert latest["packets_received"] == 1.0
        assert latest["decryption_success_rate"] == 50.0
