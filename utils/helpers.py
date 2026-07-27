"""
NTP-SCTAP Common Helper Functions.

Pure utility functions with no side effects and no internal-project
dependencies. These are safe to import from any module without risk of
circular imports.
"""

import uuid
from datetime import datetime, timezone
from typing import Union


def generate_id(prefix: str = "") -> str:
    """Generate a unique identifier.

    Args:
        prefix: Optional short string prepended to the UUID
                (e.g. ``"pkt"`` → ``"pkt-a1b2c3d4"``).

    Returns:
        A unique string suitable for database primary keys.
    """
    uid = uuid.uuid4().hex[:12]
    return f"{prefix}-{uid}" if prefix else uid


def utc_now() -> datetime:
    """Return the current UTC timestamp (timezone-aware)."""
    return datetime.now(timezone.utc)


def format_timestamp(dt: datetime, fmt: str = "%Y-%m-%d %H:%M:%S UTC") -> str:
    """Format a datetime object into a human-readable string.

    Args:
        dt:  A datetime instance. Naive datetimes are assumed UTC and
             will be normalized to UTC timezone.
        fmt: strftime format string.

    Returns:
        Formatted timestamp string.
    """
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.strftime(fmt)


def iso_timestamp(dt: datetime | None = None) -> str:
    """Return an ISO-8601 formatted timestamp string.

    Args:
        dt: Optional datetime; defaults to ``utc_now()``.
    """
    if dt is None:
        dt = utc_now()
    return dt.isoformat()


def bytes_to_hex(data: bytes, separator: str = " ") -> str:
    """Convert raw bytes to a hex-dump string.

    Args:
        data:      Raw bytes to convert.
        separator: Character placed between hex byte pairs.

    Returns:
        e.g. ``"1a 2b 3c 4d"``
    """
    return separator.join(f"{b:02x}" for b in data)


def hex_to_bytes(hex_string: str) -> bytes:
    """Convert a hex string back to bytes (ignores whitespace and colons)."""
    cleaned = "".join(hex_string.split()).replace(":", "")
    return bytes.fromhex(cleaned)


def truncate(text: str, max_length: int = 80, suffix: str = "...") -> str:
    """Truncate a string for display purposes.

    Args:
        text:       String to truncate.
        max_length: Maximum length of the returned string.
        suffix:     Suffix appended if truncation occurs.

    Returns:
        Truncated string that does not exceed max_length.
    """
    if max_length <= len(suffix):
        return suffix[:max_length]

    if len(text) <= max_length:
        return text

    return text[: max_length - len(suffix)] + suffix


def safe_int(value: Union[str, int, float, None], default: int = 0) -> int:
    """Safely convert a value to int, returning *default* on failure."""
    try:
        return int(value)  # type: ignore[arg-type]
    except (ValueError, TypeError):
        return default