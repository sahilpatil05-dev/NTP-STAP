"""
NTP-SCTAP UDP Sender.

Handles transmitting packed NTPv4 packets to a target destination.
"""

import socket

from config.settings import get_config
from utils.logger import get_logger
from protocol.packet import NTPPacket
from network.exceptions import TransmissionError

logger = get_logger("network.sender")


class UDPSender:
    """UDP Socket Sender for NTP-SCTAP.
    
    Creates an IPv4 UDP socket and transmits serialized NTP packets to
    the configured target host and port.
    """

    def __init__(self, target_host: str | None = None, target_port: int | None = None) -> None:
        """Initialize the UDP Sender.
        
        Args:
            target_host: Optional override for NTP_TARGET_HOST
            target_port: Optional override for NTP_SEND_PORT
        """
        cfg = get_config()
        self.target_host = target_host or cfg.NTP_TARGET_HOST
        self.target_port = target_port or cfg.NTP_SEND_PORT
        
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # Set a timeout so we don't block forever on DNS resolution or OS buffers
            self.sock.settimeout(2.0)
            logger.info("UDPSender initialized for target %s:%d", self.target_host, self.target_port)
        except OSError as e:
            logger.error("Failed to create UDP socket: %s", e)
            raise TransmissionError(f"Socket creation failed: {e}") from e

    def transmit(self, packet: NTPPacket) -> int:
        """Serialize and send an NTPPacket to the target.
        
        Args:
            packet: The NTPPacket instance to send.
            
        Returns:
            The number of bytes transmitted.
            
        Raises:
            TransmissionError: If the socket fails to send the data.
        """
        try:
            raw_data = packet.pack()
            bytes_sent = self.sock.sendto(raw_data, (self.target_host, self.target_port))
            logger.debug("Transmitted %d bytes to %s:%d", bytes_sent, self.target_host, self.target_port)
            return bytes_sent
        except Exception as e:
            logger.error("Transmission failed to %s:%d - %s", self.target_host, self.target_port, e)
            raise TransmissionError(f"Failed to transmit packet: {e}") from e

    def close(self) -> None:
        """Close the underlying UDP socket."""
        try:
            self.sock.close()
            logger.debug("UDPSender socket closed")
        except OSError:
            pass

    def __enter__(self) -> "UDPSender":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()
