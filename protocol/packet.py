"""
NTP-SCTAP Protocol Packet Module.

Handles generation and parsing of standard NTPv4 packets (RFC 5905),
along with covert payload injection and extraction capabilities.
"""

import struct

from utils.logger import get_logger
from protocol.exceptions import ProtocolError, PacketMalformedError, PayloadCapacityError

logger = get_logger("protocol.packet")


class NTPPacket:
    """NTPv4 Packet generator and parser.

    Standard NTP Header is exactly 48 bytes.
    Fields:
      LI, VN, Mode (1 byte)
      Stratum (1 byte)
      Poll (1 byte)
      Precision (1 byte)
      Root Delay (4 bytes)
      Root Dispersion (4 bytes)
      Reference ID (4 bytes)
      Reference Timestamp (8 bytes)
      Origin Timestamp (8 bytes)
      Receive Timestamp (8 bytes)
      Transmit Timestamp (8 bytes)

    Covert channels supported:
      1. Extension Field: Variable length payload appended after the 48-byte header.
         Used for full AES-256-GCM payloads.
      2. Timestamp Fractional Parts: Up to 16 bytes injected into the lower 32 bits
         of the four timestamps (Ref, Origin, Recv, Transmit).
    """

    # struct format: B B b b I I 4s Q Q Q Q
    HEADER_FORMAT = "!B B b b I I 4s Q Q Q Q"
    HEADER_SIZE = 48
    
    # Custom extension field type for our covert channel
    COVERT_EXT_TYPE = 0x7363  # "sc" (Secure Channel)

    def __init__(self) -> None:
        """Initialize a standard NTP Client packet with default values."""
        self.leap: int = 0
        self.version: int = 4
        self.mode: int = 3  # Client
        self.stratum: int = 0
        self.poll: int = 0
        self.precision: int = 0
        self.root_delay: int = 0
        self.root_dispersion: int = 0
        self.ref_id: bytes = b"\x00\x00\x00\x00"
        
        self.ref_timestamp: int = 0
        self.origin_timestamp: int = 0
        self.recv_timestamp: int = 0
        self.tx_timestamp: int = 0
        
        self.extension_data: bytes = b""

    @classmethod
    def unpack(cls, data: bytes) -> "NTPPacket":
        """Parse raw bytes into an NTPPacket instance.

        Args:
            data: Raw network bytes.

        Raises:
            PacketMalformedError: If data is less than 48 bytes or malformed.
        """
        if len(data) < cls.HEADER_SIZE:
            raise PacketMalformedError(f"Packet too short: {len(data)} bytes")

        packet = cls()
        header = data[:cls.HEADER_SIZE]
        
        try:
            unpacked = struct.unpack(cls.HEADER_FORMAT, header)
            
            # Unpack first byte (LI, VN, Mode)
            byte0 = unpacked[0]
            packet.leap = (byte0 >> 6) & 0x03
            packet.version = (byte0 >> 3) & 0x07
            packet.mode = byte0 & 0x07
            
            packet.stratum = unpacked[1]
            packet.poll = unpacked[2]
            packet.precision = unpacked[3]
            packet.root_delay = unpacked[4]
            packet.root_dispersion = unpacked[5]
            packet.ref_id = unpacked[6]
            
            packet.ref_timestamp = unpacked[7]
            packet.origin_timestamp = unpacked[8]
            packet.recv_timestamp = unpacked[9]
            packet.tx_timestamp = unpacked[10]
            
        except struct.error as e:
            raise PacketMalformedError(f"Failed to unpack header: {e}") from e

        # Extract remaining data as extension/payload
        if len(data) > cls.HEADER_SIZE:
            packet.extension_data = data[cls.HEADER_SIZE:]
            
        return packet

    def pack(self) -> bytes:
        """Serialize the packet into raw bytes for network transmission."""
        byte0 = (self.leap << 6) | (self.version << 3) | self.mode
        
        try:
            header = struct.pack(
                self.HEADER_FORMAT,
                byte0,
                self.stratum,
                self.poll,
                self.precision,
                self.root_delay,
                self.root_dispersion,
                self.ref_id,
                self.ref_timestamp,
                self.origin_timestamp,
                self.recv_timestamp,
                self.tx_timestamp,
            )
        except struct.error as e:
            raise ProtocolError(f"Failed to pack header: {e}") from e
            
        return header + self.extension_data

    # ── Covert Channel 1: Extension Field ────────────────────────────

    def inject_extension(self, payload: bytes) -> None:
        """Inject payload as a custom NTPv4 Extension Field.
        
        Suitable for large encrypted payloads (AES-256-GCM).
        
        Format (Custom 8-byte header):
          Field Type: 2 bytes (0x7363)
          Total Ext Length: 2 bytes
          Original Payload Length: 4 bytes
          Value: N bytes
          Padding: up to 3 bytes to maintain 4-byte alignment
        """
        if not payload:
            self.extension_data = b""
            return
            
        orig_len = len(payload)
        padding_len = (4 - (orig_len % 4)) % 4
        padded_payload = payload + (b"\x00" * padding_len)
        
        # 4 bytes (Type, Len) + 4 bytes (Orig Len) + padded payload
        ext_len = 8 + len(padded_payload)
        
        header = struct.pack("!H H I", self.COVERT_EXT_TYPE, ext_len, orig_len)
        self.extension_data = header + padded_payload
        
        logger.debug("Injected extension payload: orig_len=%d, ext_len=%d", orig_len, ext_len)

    def extract_extension(self) -> bytes:
        """Extract covert payload from the Extension Field.
        
        Returns:
            The exact original payload bytes, or b"" if not found or invalid.
        """
        if len(self.extension_data) < 8:
            return b""
            
        ext_type, ext_len, orig_len = struct.unpack("!H H I", self.extension_data[:8])
        
        # ✅ VALIDATION: Check extension length field matches actual data
        if ext_len != len(self.extension_data):
            logger.warning(
                "Invalid extension length: header=%d actual=%d",
                ext_len,
                len(self.extension_data),
            )
            return b""
        
        if ext_type != self.COVERT_EXT_TYPE:
            return b""
            
        if len(self.extension_data) < 8 + orig_len:
            logger.warning(
                "Extension field truncated: expected %d bytes, got %d",
                orig_len, len(self.extension_data) - 8
            )
            return b""
            
        # Extract exact length
        payload = self.extension_data[8:8 + orig_len]
        return payload

    # ── Covert Channel 2: Timestamp Fractional Parts ─────────────────

    def inject_timestamps(self, payload: bytes) -> None:
        """Inject up to 16 bytes into the fractional parts of the 4 timestamps.
        
        Replaces the lower 32 bits (fractional seconds) of Reference, Origin,
        Receive, and Transmit timestamps with the covert payload.
        
        Args:
            payload: Bytes to inject (max 16 bytes).

        Raises:
            PayloadCapacityError: If payload exceeds 16 bytes.
        """
        if len(payload) > 16:
            raise PayloadCapacityError(f"Timestamp injection limited to 16 bytes, got {len(payload)}")
            
        # Pad payload to exactly 16 bytes with nulls for deterministic spreading
        padded = payload + (b"\x00" * (16 - len(payload)))
        
        # Split into four 4-byte chunks
        c1, c2, c3, c4 = struct.unpack("!I I I I", padded)
        
        # Keep upper 32 bits (seconds), replace lower 32 bits (fractions)
        self.ref_timestamp = (self.ref_timestamp & 0xFFFFFFFF00000000) | c1
        self.origin_timestamp = (self.origin_timestamp & 0xFFFFFFFF00000000) | c2
        self.recv_timestamp = (self.recv_timestamp & 0xFFFFFFFF00000000) | c3
        self.tx_timestamp = (self.tx_timestamp & 0xFFFFFFFF00000000) | c4
        
        logger.debug("Injected %d bytes into timestamp fractional parts", len(payload))

    def extract_timestamps(self, length: int = 16) -> bytes:
        """Extract injected payload from the fractional parts of timestamps.
        
        Args:
            length: Exact original length to extract (clamped to 0-16).
            
        Returns:
            Extracted payload bytes (max 16 bytes).
        """
        # ✅ DEFENSIVE: Clamp length to valid range
        length = min(max(length, 0), 16)
        
        c1 = self.ref_timestamp & 0xFFFFFFFF
        c2 = self.origin_timestamp & 0xFFFFFFFF
        c3 = self.recv_timestamp & 0xFFFFFFFF
        c4 = self.tx_timestamp & 0xFFFFFFFF
        
        data = struct.pack("!I I I I", c1, c2, c3, c4)
        return data[:length]