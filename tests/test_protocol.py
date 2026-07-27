"""
Tests for the protocol module.

Coverage:
  - NTP packet parsing and generation
  - Covert Channel 1: Extension Field payload injection/extraction
  - Covert Channel 2: Timestamp fractional payload injection/extraction
  - Error handling (malformed packets, payload capacity)
  - End-to-end integration: Crypto encrypt -> Pack -> Unpack -> Decrypt
"""

import struct

import pytest

from protocol.packet import NTPPacket
from protocol.exceptions import PacketMalformedError, PayloadCapacityError
from crypto.engine import CryptoEngine


# ═════════════════════════════════════════════════════════════════════
# Packet Header Tests
# ═════════════════════════════════════════════════════════════════════

class TestNTPPacketHeader:
    """Verify basic NTP header pack/unpack."""

    def test_default_packet_size(self) -> None:
        packet = NTPPacket()
        data = packet.pack()
        assert len(data) == 48

    def test_default_fields(self) -> None:
        packet = NTPPacket()
        assert packet.mode == 3
        assert packet.version == 4
        assert packet.leap == 0

    def test_pack_unpack_roundtrip(self) -> None:
        packet = NTPPacket()
        packet.stratum = 2
        packet.poll = 4
        packet.ref_timestamp = 0x1122334455667788
        
        data = packet.pack()
        unpacked = NTPPacket.unpack(data)
        
        assert unpacked.stratum == 2
        assert unpacked.poll == 4
        assert unpacked.ref_timestamp == 0x1122334455667788

    def test_unpack_malformed_too_short(self) -> None:
        with pytest.raises(PacketMalformedError, match="too short"):
            NTPPacket.unpack(b"\x00" * 47)


# ═════════════════════════════════════════════════════════════════════
# Covert Channel 1: Extension Field Tests
# ═════════════════════════════════════════════════════════════════════

class TestExtensionFieldInjection:
    """Verify payload injection into extension fields."""

    def test_inject_extract_roundtrip(self) -> None:
        packet = NTPPacket()
        payload = b"secret_extension_payload"
        
        packet.inject_extension(payload)
        extracted = packet.extract_extension()
        
        assert extracted == payload

    def test_extension_padding(self) -> None:
        """Verify the extension field maintains 4-byte alignment."""
        packet = NTPPacket()
        # 3 bytes payload, requires 1 byte padding
        packet.inject_extension(b"123")
        
        data = packet.pack()
        assert len(data) % 4 == 0
        assert len(data) == 48 + 8 + 4  # header + ext_header + padded_payload

    def test_empty_extension(self) -> None:
        packet = NTPPacket()
        packet.inject_extension(b"")
        assert packet.extract_extension() == b""

    def test_pack_unpack_with_extension(self) -> None:
        packet = NTPPacket()
        packet.inject_extension(b"hello world!")
        
        data = packet.pack()
        unpacked = NTPPacket.unpack(data)
        
        assert unpacked.extract_extension() == b"hello world!"


# ═════════════════════════════════════════════════════════════════════
# Covert Channel 2: Timestamp Fractional Tests
# ═════════════════════════════════════════════════════════════════════

class TestTimestampInjection:
    """Verify payload injection into timestamp fractional parts."""

    def test_inject_extract_roundtrip_full(self) -> None:
        packet = NTPPacket()
        payload = b"16_byte_payload!"
        
        packet.inject_timestamps(payload)
        extracted = packet.extract_timestamps(length=16)
        
        assert extracted == payload

    def test_inject_extract_roundtrip_partial(self) -> None:
        packet = NTPPacket()
        payload = b"short"
        
        packet.inject_timestamps(payload)
        extracted = packet.extract_timestamps(length=len(payload))
        
        assert extracted == payload

    def test_inject_too_large(self) -> None:
        packet = NTPPacket()
        payload = b"x" * 17
        
        with pytest.raises(PayloadCapacityError, match="limited to 16 bytes"):
            packet.inject_timestamps(payload)

    def test_timestamp_seconds_preserved(self) -> None:
        packet = NTPPacket()
        # Set dummy timestamps with high seconds and non-zero fractions
        packet.ref_timestamp = 0x1111111122222222
        packet.origin_timestamp = 0x3333333344444444
        
        packet.inject_timestamps(b"testdata12345678")
        
        # Verify upper 32 bits (seconds) are preserved
        assert (packet.ref_timestamp >> 32) == 0x11111111
        assert (packet.origin_timestamp >> 32) == 0x33333333
        
        # Verify extraction still works
        assert packet.extract_timestamps(length=16) == b"testdata12345678"

    def test_pack_unpack_with_timestamps(self) -> None:
        packet = NTPPacket()
        payload = b"crypto_key_12345"
        packet.inject_timestamps(payload)
        
        data = packet.pack()
        unpacked = NTPPacket.unpack(data)
        
        assert unpacked.extract_timestamps(length=16) == payload


# ═════════════════════════════════════════════════════════════════════
# End-to-End Integration Tests
# ═════════════════════════════════════════════════════════════════════

class TestProtocolIntegration:
    """Verify Crypto Engine + Protocol Packet pipeline."""

    def test_encrypt_pack_unpack_decrypt(self) -> None:
        # 1. Crypto Engine (Sender)
        engine_tx = CryptoEngine(password="research-password")
        plaintext = "This is a covert message hidden in an NTP packet."
        encrypted_payload = engine_tx.encrypt(plaintext)
        
        # 2. Protocol (Sender)
        packet_tx = NTPPacket()
        packet_tx.inject_extension(encrypted_payload)
        network_bytes = packet_tx.pack()
        
        # 3. Simulate Network Transmission
        assert len(network_bytes) > 48
        
        # 4. Protocol (Receiver)
        packet_rx = NTPPacket.unpack(network_bytes)
        extracted_payload = packet_rx.extract_extension()
        
        # 5. Crypto Engine (Receiver)
        engine_rx = CryptoEngine(password="research-password")
        recovered_plaintext = engine_rx.decrypt(extracted_payload)
        
        assert recovered_plaintext == plaintext
