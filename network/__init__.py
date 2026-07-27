"""
NTP-SCTAP Network Module.

Provides UDP transmission and background reception for NTP packets.

Public API:
    UDPSender         — Socket client for sending packets
    UDPReceiver       — Background thread for listening to packets
    NetworkError      — Base exception
    TransmissionError — Raised on send failures
    ListenerError     — Raised on bind or thread failures
"""

from network.sender import UDPSender
from network.receiver import UDPReceiver
from network.exceptions import (
    NetworkError,
    TransmissionError,
    ListenerError,
)

__all__ = [
    "UDPSender",
    "UDPReceiver",
    "NetworkError",
    "TransmissionError",
    "ListenerError",
]
