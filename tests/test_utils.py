"""
Tests for utils.helpers module.

Validates:
  - ID generation format and uniqueness
  - Timestamp functions
  - Hex conversion round-trip
  - String truncation
  - Safe integer conversion
"""

from datetime import datetime, timezone

from utils.helpers import (
    generate_id,
    utc_now,
    format_timestamp,
    iso_timestamp,
    bytes_to_hex,
    hex_to_bytes,
    truncate,
    safe_int,
)


class TestGenerateId:
    """Verify unique ID generation."""

    def test_default_length(self) -> None:
        uid = generate_id()
        assert len(uid) == 12

    def test_with_prefix(self) -> None:
        uid = generate_id("pkt")
        assert uid.startswith("pkt-")
        assert len(uid) == 16  # "pkt-" + 12

    def test_uniqueness(self) -> None:
        ids = {generate_id() for _ in range(1000)}
        assert len(ids) == 1000


class TestTimestamps:
    """Verify timestamp helpers."""

    def test_utc_now_is_aware(self) -> None:
        dt = utc_now()
        assert dt.tzinfo is not None

    def test_format_timestamp(self) -> None:
        dt = datetime(2025, 1, 15, 10, 30, 0, tzinfo=timezone.utc)
        formatted = format_timestamp(dt)
        assert "2025-01-15" in formatted
        assert "10:30:00" in formatted

    def test_iso_timestamp_format(self) -> None:
        ts = iso_timestamp()
        assert "T" in ts  # ISO-8601 contains 'T' separator


class TestHexConversion:
    """Verify hex <-> bytes round-trip."""

    def test_bytes_to_hex(self) -> None:
        result = bytes_to_hex(b"\x1a\x2b\x3c")
        assert result == "1a 2b 3c"

    def test_hex_to_bytes(self) -> None:
        result = hex_to_bytes("1a 2b 3c")
        assert result == b"\x1a\x2b\x3c"

    def test_round_trip(self) -> None:
        original = b"\xde\xad\xbe\xef"
        assert hex_to_bytes(bytes_to_hex(original)) == original


class TestTruncate:
    """Verify string truncation."""

    def test_short_string_unchanged(self) -> None:
        assert truncate("hello", 10) == "hello"

    def test_long_string_truncated(self) -> None:
        result = truncate("a" * 100, 20)
        assert len(result) == 20
        assert result.endswith("...")


class TestSafeInt:
    """Verify safe integer conversion."""

    def test_valid_int(self) -> None:
        assert safe_int("42") == 42

    def test_none_returns_default(self) -> None:
        assert safe_int(None) == 0

    def test_invalid_returns_default(self) -> None:
        assert safe_int("abc", default=-1) == -1

    def test_float_truncated(self) -> None:
        assert safe_int(3.7) == 3
