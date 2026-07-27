"""
NTP-SCTAP Network Exception Hierarchy.

All networking-related errors inherit from ``NetworkError``.
"""

class NetworkError(Exception):
    """Base exception for all networking operations."""

class TransmissionError(NetworkError):
    """Raised when sending a packet fails."""

class ListenerError(NetworkError):
    """Raised when the UDP listener encounters a fatal error."""
