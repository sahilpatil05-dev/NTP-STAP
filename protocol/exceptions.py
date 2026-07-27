"""
NTP-SCTAP Protocol Exception Hierarchy.

All protocol-related errors inherit from ``ProtocolError``.
"""

class ProtocolError(Exception):
    """Base exception for all protocol operations."""

class PacketMalformedError(ProtocolError):
    """Raised when an NTP packet cannot be parsed (e.g. too short)."""

class PayloadCapacityError(ProtocolError):
    """Raised when attempting to inject a payload larger than the field capacity."""
