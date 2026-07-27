"""
NTP-SCTAP Protocol Module.

Handles generation and parsing of standard NTPv4 packets (RFC 5905),
along with covert payload injection and extraction capabilities.

Public API:
    NTPPacket            — NTP packet generation and parsing
    ProtocolError        — Base exception
    PacketMalformedError — Raised on parse failure
    PayloadCapacityError — Raised when injection exceeds field limits
"""

from protocol.packet import NTPPacket
from protocol.exceptions import (
    ProtocolError,
    PacketMalformedError,
    PayloadCapacityError,
)

__all__ = [
    "NTPPacket",
    "ProtocolError",
    "PacketMalformedError",
    "PayloadCapacityError",
]
