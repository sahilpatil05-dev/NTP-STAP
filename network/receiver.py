"""
NTP-SCTAP UDP Receiver.

Listens for incoming NTPv4 packets on a background thread.
"""

import socket
import threading
from typing import Callable, Optional

from config.settings import get_config
from utils.logger import get_logger
from protocol.packet import NTPPacket
from protocol.exceptions import ProtocolError
from network.exceptions import ListenerError

logger = get_logger("network.receiver")

# Callback type: takes an NTPPacket and a source address tuple (ip, port)
PacketCallback = Callable[[NTPPacket, tuple[str, int]], None]


class UDPReceiver:
    """Background UDP Listener for incoming NTP packets.
    
    Runs continuously in a daemon thread, reading packets from the socket,
    parsing them, and passing valid packets to a registered callback.
    """

    def __init__(
        self,
        bind_host: str = "0.0.0.0",
        bind_port: int | None = None,
        callback: PacketCallback | None = None,
    ) -> None:
        """Initialize the UDP Receiver.
        
        Args:
            bind_host: The interface to bind to (default "0.0.0.0" for all interfaces).
            bind_port: Optional override for NTP_LISTEN_PORT.
            callback: The function to call when a valid packet is received.
        """
        cfg = get_config()
        self.bind_host = bind_host
        self.bind_port = bind_port or cfg.NTP_LISTEN_PORT
        self.buffer_size = cfg.UDP_BUFFER_SIZE
        self.callback = callback
        
        self._sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._running: bool = False

    def start(self) -> None:
        """Bind the socket and start the background listening thread."""
        if self._running:
            logger.warning("UDPReceiver is already running")
            return
            
        if not self.callback:
            raise ListenerError("Cannot start UDPReceiver without a registered callback")

        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # Short timeout so the thread can exit cleanly when _running becomes False
            self._sock.settimeout(1.0)
            self._sock.bind((self.bind_host, self.bind_port))
        except OSError as e:
            logger.error("Failed to bind UDP socket on %s:%d: %s", self.bind_host, self.bind_port, e)
            if self._sock:
                self._sock.close()
            raise ListenerError(f"Socket bind failed: {e}") from e

        self._running = True
        self._thread = threading.Thread(
            target=self._listen_loop,
            name="UDPReceiverThread",
            daemon=True
        )
        self._thread.start()
        logger.info("UDPReceiver started on %s:%d (daemon thread)", self.bind_host, self.bind_port)

    def stop(self) -> None:
        """Signal the listener thread to stop and close the socket."""
        if not self._running:
            return
            
        logger.info("Stopping UDPReceiver...")
        self._running = False
        
        # ✅ FIXED: Close socket first to interrupt recvfrom() immediately
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        
        # Then wait for thread to exit
        if self._thread:
            self._thread.join(timeout=3.0)
            
        logger.debug("UDPReceiver stopped cleanly")

    def _listen_loop(self) -> None:
        """The main loop executed by the background thread."""
        while self._running:
            try:
                if not self._sock:
                    break
                    
                data, addr = self._sock.recvfrom(self.buffer_size)
                self._handle_packet(data, addr)
                
            except socket.timeout:
                # Expected timeout, allows the loop to check self._running flag
                continue
            except OSError as e:
                # Socket was likely closed intentionally during stop()
                if self._running:
                    logger.error("Socket error in listener loop: %s", e)
                break
            except Exception as e:
                logger.exception("Unexpected error in listener loop: %s", e)

    def _handle_packet(self, data: bytes, addr: tuple[str, int]) -> None:
        """Parse raw data and dispatch to the callback."""
        logger.debug("Received %d bytes from %s:%d", len(data), addr[0], addr[1])
        try:
            packet = NTPPacket.unpack(data)
            
            # ✅ OPTIONAL: Wrap callback to catch exceptions separately
            if self.callback:
                try:
                    self.callback(packet, addr)
                except Exception:
                    logger.exception("Packet callback failed for %s:%d", addr[0], addr[1])
        except ProtocolError as e:
            logger.warning("Rejected malformed packet from %s:%d - %s", addr[0], addr[1], e)