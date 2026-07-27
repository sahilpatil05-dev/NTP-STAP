"""
Tests for the networking module.

Coverage:
  - UDP Sender initialization and error handling
  - UDP Receiver lifecycle (start, stop, daemon thread behavior)
  - End-to-end localhost transmission (Sender -> Receiver)
"""

import socket
import threading
import time

import pytest

from network.sender import UDPSender
from network.receiver import UDPReceiver
from network.exceptions import TransmissionError, ListenerError
from protocol.packet import NTPPacket


# ═════════════════════════════════════════════════════════════════════
# UDP Sender Tests
# ═════════════════════════════════════════════════════════════════════

class TestUDPSender:
    """Verify UDPSender behavior."""

    def test_sender_initialization(self) -> None:
        # Use arbitrary unprivileged port for init test
        sender = UDPSender(target_host="127.0.0.1", target_port=30000)
        assert sender.target_host == "127.0.0.1"
        assert sender.target_port == 30000
        sender.close()

    def test_sender_context_manager(self) -> None:
        with UDPSender(target_host="127.0.0.1", target_port=30000) as sender:
            assert sender.sock.fileno() != -1
        # Socket should be closed after exit
        assert sender.sock.fileno() == -1


# ═════════════════════════════════════════════════════════════════════
# UDP Receiver Tests
# ═════════════════════════════════════════════════════════════════════

class TestUDPReceiver:
    """Verify UDPReceiver lifecycle."""

    def test_cannot_start_without_callback(self) -> None:
        receiver = UDPReceiver(bind_host="127.0.0.1", bind_port=0)
        with pytest.raises(ListenerError, match="without a registered callback"):
            receiver.start()

    def test_start_and_stop_cleanly(self) -> None:
        def dummy_cb(packet, addr):
            pass

        receiver = UDPReceiver(bind_host="127.0.0.1", bind_port=0, callback=dummy_cb)
        receiver.start()
        
        # Verify thread is running
        assert receiver._thread is not None
        assert receiver._thread.is_alive()
        assert receiver._running is True
        
        receiver.stop()
        
        # Verify thread shut down
        assert not receiver._thread.is_alive()
        assert receiver._running is False
        assert receiver._sock is None

    def test_start_already_running_is_noop(self) -> None:
        def dummy_cb(packet, addr):
            pass

        receiver = UDPReceiver(bind_host="127.0.0.1", bind_port=0, callback=dummy_cb)
        receiver.start()
        thread_id = receiver._thread.ident
        
        # Start again should be a no-op, same thread id
        receiver.start()
        assert receiver._thread.ident == thread_id
        
        receiver.stop()


# ═════════════════════════════════════════════════════════════════════
# End-to-End Transmission Tests
# ═════════════════════════════════════════════════════════════════════

class TestEndToEndNetworking:
    """Verify packets sent via UDPSender are parsed by UDPReceiver."""

    def test_localhost_transmission(self) -> None:
        # 1. Setup Receiver
        received_packets = []
        receive_event = threading.Event()
        
        def on_packet(packet: NTPPacket, addr: tuple[str, int]) -> None:
            received_packets.append(packet)
            receive_event.set()

        # Bind to port 0 to get an OS-assigned ephemeral port
        receiver = UDPReceiver(bind_host="127.0.0.1", bind_port=0, callback=on_packet)
        receiver.start()
        
        # Get the actual assigned port
        actual_port = receiver._sock.getsockname()[1]

        try:
            # 2. Setup Sender using the dynamically assigned port
            with UDPSender(target_host="127.0.0.1", target_port=actual_port) as sender:
                # 3. Create and transmit packet
                packet = NTPPacket()
                packet.inject_extension(b"NetworkIntegrationTest")
                sender.transmit(packet)
            
            # 4. Wait for receiver to process it
            success = receive_event.wait(timeout=2.0)
            assert success is True, "Timeout waiting for packet reception"
            
            # 5. Verify received data
            assert len(received_packets) == 1
            rx_packet = received_packets[0]
            assert rx_packet.extract_extension() == b"NetworkIntegrationTest"
            
        finally:
            # Always ensure the background thread is cleaned up
            receiver.stop()
