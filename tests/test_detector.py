"""
Tests for the Threat Detection Engine.

Covers:
  - Covert extension field detection
  - Protocol header integrity checks
  - Packet size anomaly detection
  - Timing burst pattern analysis
  - Clean packet validation
  - Missing packet error handling
"""

import struct
import pytest
from unittest.mock import patch, MagicMock

from config.settings import Config, reset_config
from database.manager import DatabaseManager, reset_db
from protocol.packet import NTPPacket
from detector.engine import ThreatDetector
from detector.exceptions import AnalysisError
from utils.helpers import generate_id, iso_timestamp


@pytest.fixture()
def detector(db: DatabaseManager) -> ThreatDetector:
    """Return a ThreatDetector backed by a test database."""
    return ThreatDetector()


def _insert_standard_packet(db: DatabaseManager, **overrides) -> str:
    """Helper: insert a standard NTP packet record and return its ID."""
    packet = NTPPacket()
    raw = packet.pack()
    pkt_id = generate_id()
    record = {
        "id": pkt_id,
        "session_id": None,
        "direction": "received",
        "source_host": "192.168.1.50",
        "source_port": 123,
        "dest_host": "127.0.0.1",
        "dest_port": 9124,
        "packet_size": len(raw),
        "raw_data": raw,
        "payload_status": "none",
        "encryption_status": "none",
        "validation": "pending",
        "created_at": iso_timestamp(),
    }
    record.update(overrides)
    db.insert("packets", record)
    return record["id"]


def _insert_covert_packet(db: DatabaseManager, **overrides) -> str:
    """Helper: insert an NTP packet with a covert extension field."""
    packet = NTPPacket()
    packet.inject_extension(b"secret_payload_data_here")
    raw = packet.pack()
    pkt_id = generate_id()
    record = {
        "id": pkt_id,
        "session_id": None,
        "direction": "received",
        "source_host": "10.0.0.5",
        "source_port": 123,
        "dest_host": "127.0.0.1",
        "dest_port": 9124,
        "packet_size": len(raw),
        "raw_data": raw,
        "payload_status": "present",
        "encryption_status": "none",
        "validation": "pending",
        "created_at": iso_timestamp(),
    }
    record.update(overrides)
    db.insert("packets", record)
    return record["id"]


# ── Clean Packet (No Threats) ────────────────────────────────────────

class TestCleanPacket:
    """A standard NTP client packet should not trigger any threat."""

    def test_clean_packet_returns_none(self, detector, db):
        pkt_id = _insert_standard_packet(db)
        result = detector.analyze_packet(pkt_id)
        assert result is None

    def test_clean_packet_marked_valid(self, detector, db):
        pkt_id = _insert_standard_packet(db)
        detector.analyze_packet(pkt_id)
        row = db.query_one("SELECT validation FROM packets WHERE id = ?", (pkt_id,))
        assert row["validation"] == "valid"


# ── Covert Extension Detection ──────────────────────────────────────

class TestCovertExtension:
    """Packets with the 0x7363 extension field should trigger detection."""

    def test_covert_extension_detected(self, detector, db):
        pkt_id = _insert_covert_packet(db)
        result = detector.analyze_packet(pkt_id)
        assert result is not None
        assert result["threat_level"] in ("medium", "critical")
        assert "covert" in result["alert_reason"].lower() or "extension" in result["alert_reason"].lower()

    def test_covert_with_failed_decryption_is_critical(self, detector, db):
        pkt_id = _insert_covert_packet(db, encryption_status="failed")
        result = detector.analyze_packet(pkt_id)
        assert result is not None
        assert result["threat_level"] == "critical"

    def test_threat_persisted_to_database(self, detector, db):
        pkt_id = _insert_covert_packet(db)
        detector.analyze_packet(pkt_id)
        count = db.count("threats")
        assert count >= 1

    def test_packet_marked_suspicious(self, detector, db):
        pkt_id = _insert_covert_packet(db)
        detector.analyze_packet(pkt_id)
        row = db.query_one("SELECT validation FROM packets WHERE id = ?", (pkt_id,))
        assert row["validation"] in ("suspicious", "malicious")


# ── Protocol Header Anomalies ───────────────────────────────────────

class TestHeaderAnomalies:
    """Non-standard NTP version/mode should trigger low/medium alerts."""

    def test_non_standard_version(self, detector, db):
        packet = NTPPacket()
        packet.version = 3
        raw = packet.pack()
        pkt_id = _insert_standard_packet(db, raw_data=raw)
        result = detector.analyze_packet(pkt_id)
        assert result is not None
        assert "version" in result["alert_reason"].lower()

    def test_abnormal_mode(self, detector, db):
        packet = NTPPacket()
        packet.mode = 7  # Private/control
        raw = packet.pack()
        pkt_id = _insert_standard_packet(db, raw_data=raw)
        result = detector.analyze_packet(pkt_id)
        assert result is not None
        assert "mode" in result["alert_reason"].lower()


# ── Missing Packet ──────────────────────────────────────────────────

class TestMissingPacket:
    """Analyzing a non-existent packet should raise AnalysisError."""

    def test_missing_packet_raises(self, detector):
        with pytest.raises(AnalysisError, match="not found"):
            detector.analyze_packet("nonexistent-id")


# ── Timing Burst Detection ──────────────────────────────────────────

class TestTimingBurst:
    """Rapid packet bursts from the same source should trigger timing alerts."""

    def test_burst_pattern_detected(self, detector, db):
        """Insert many packets with close timestamps, then analyze the latest."""
        from datetime import datetime, timedelta, timezone

        base = datetime.now(timezone.utc)
        source = "10.99.99.1"
        packet = NTPPacket()
        raw = packet.pack()

        # Insert 10 packets with 5ms spacing (well below default 50ms threshold)
        for i in range(10):
            ts = (base + timedelta(milliseconds=i * 5)).isoformat()
            db.insert("packets", {
                "id": generate_id(),
                "direction": "received",
                "source_host": source,
                "source_port": 123,
                "dest_host": "127.0.0.1",
                "dest_port": 9124,
                "packet_size": len(raw),
                "raw_data": raw,
                "payload_status": "none",
                "encryption_status": "none",
                "validation": "pending",
                "created_at": ts,
            })

        # Insert the "current" packet to analyze
        current_ts = (base + timedelta(milliseconds=55)).isoformat()
        current_id = generate_id()
        db.insert("packets", {
            "id": current_id,
            "direction": "received",
            "source_host": source,
            "source_port": 123,
            "dest_host": "127.0.0.1",
            "dest_port": 9124,
            "packet_size": len(raw),
            "raw_data": raw,
            "payload_status": "none",
            "encryption_status": "none",
            "validation": "pending",
            "created_at": current_ts,
        })

        result = detector.analyze_packet(current_id)
        assert result is not None
        assert "burst" in result["alert_reason"].lower() or "timing" in result["alert_reason"].lower()

    def test_no_burst_with_normal_spacing(self, detector, db):
        """Well-spaced packets should not trigger timing alerts."""
        from datetime import datetime, timedelta, timezone

        base = datetime.now(timezone.utc)
        source = "172.16.0.1"
        packet = NTPPacket()
        raw = packet.pack()

        # Insert 6 packets with 2-second spacing (well above threshold)
        for i in range(6):
            ts = (base + timedelta(seconds=i * 2)).isoformat()
            db.insert("packets", {
                "id": generate_id(),
                "direction": "received",
                "source_host": source,
                "source_port": 123,
                "dest_host": "127.0.0.1",
                "dest_port": 9124,
                "packet_size": len(raw),
                "raw_data": raw,
                "payload_status": "none",
                "encryption_status": "none",
                "validation": "pending",
                "created_at": ts,
            })

        current_ts = (base + timedelta(seconds=14)).isoformat()
        current_id = generate_id()
        db.insert("packets", {
            "id": current_id,
            "direction": "received",
            "source_host": source,
            "source_port": 123,
            "dest_host": "127.0.0.1",
            "dest_port": 9124,
            "packet_size": len(raw),
            "raw_data": raw,
            "payload_status": "none",
            "encryption_status": "none",
            "validation": "pending",
            "created_at": current_ts,
        })

        result = detector.analyze_packet(current_id)
        assert result is None
