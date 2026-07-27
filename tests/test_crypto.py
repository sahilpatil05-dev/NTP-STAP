"""
Tests for the crypto module.

Coverage:
  - Key derivation (PBKDF2-HMAC-SHA256)
  - AES-256-GCM encryption round-trip
  - Password-based mode
  - Raw-key mode
  - Wire-format structure verification
  - Error handling (wrong password, corrupted data, empty inputs)
  - Payload size constraints
  - Nonce uniqueness
  - Engine introspection
"""

import os

import pytest

from crypto.engine import CryptoEngine
from crypto.key_derivation import derive_key, DEFAULT_KEY_LENGTH, DEFAULT_SALT_LENGTH
from crypto.exceptions import (
    CryptoError,
    KeyDerivationError,
    EncryptionError,
    DecryptionError,
    PayloadTooLargeError,
)


# ═════════════════════════════════════════════════════════════════════
# Key Derivation Tests
# ═════════════════════════════════════════════════════════════════════

class TestDeriveKey:
    """Verify PBKDF2-HMAC-SHA256 key derivation."""

    def test_returns_key_and_salt(self) -> None:
        key, salt = derive_key("test-password")
        assert isinstance(key, bytes)
        assert isinstance(salt, bytes)

    def test_key_length_default(self) -> None:
        key, _ = derive_key("test-password")
        assert len(key) == DEFAULT_KEY_LENGTH

    def test_salt_length_default(self) -> None:
        _, salt = derive_key("test-password")
        assert len(salt) == DEFAULT_SALT_LENGTH

    def test_custom_key_length(self) -> None:
        key, _ = derive_key("test-password", key_length=16)
        assert len(key) == 16

    def test_deterministic_with_same_salt(self) -> None:
        key1, salt = derive_key("password123")
        key2, _ = derive_key("password123", salt=salt)
        assert key1 == key2

    def test_different_salts_produce_different_keys(self) -> None:
        key1, _ = derive_key("same-password")
        key2, _ = derive_key("same-password")
        # Overwhelmingly likely to differ (random salts)
        assert key1 != key2

    def test_different_passwords_produce_different_keys(self) -> None:
        salt = os.urandom(16)
        key1, _ = derive_key("password-a", salt=salt)
        key2, _ = derive_key("password-b", salt=salt)
        assert key1 != key2

    def test_empty_password_raises(self) -> None:
        with pytest.raises(KeyDerivationError, match="must not be empty"):
            derive_key("")

    def test_none_password_raises(self) -> None:
        with pytest.raises(KeyDerivationError):
            derive_key(None)  # type: ignore[arg-type]

    def test_low_iterations_still_works(self) -> None:
        """Reduced iterations for test speed — validates parameterisation."""
        key, salt = derive_key("fast", iterations=1000)
        assert len(key) == DEFAULT_KEY_LENGTH


# ═════════════════════════════════════════════════════════════════════
# CryptoEngine — Construction
# ═════════════════════════════════════════════════════════════════════

class TestEngineConstruction:
    """Verify engine initialisation guards."""

    def test_password_mode(self) -> None:
        engine = CryptoEngine(password="secret")
        info = engine.get_info()
        assert info["mode"] == "password"

    def test_raw_key_mode(self) -> None:
        key = os.urandom(32)
        engine = CryptoEngine(key=key)
        info = engine.get_info()
        assert info["mode"] == "raw-key"

    def test_both_raises(self) -> None:
        with pytest.raises(CryptoError, match="not both"):
            CryptoEngine(password="secret", key=os.urandom(32))

    def test_neither_raises(self) -> None:
        with pytest.raises(CryptoError, match="required"):
            CryptoEngine()

    def test_wrong_key_length_raises(self) -> None:
        with pytest.raises(CryptoError, match="exactly 32 bytes"):
            CryptoEngine(key=os.urandom(16))


# ═════════════════════════════════════════════════════════════════════
# CryptoEngine — Password-Based Round-Trip
# ═════════════════════════════════════════════════════════════════════

class TestPasswordModeRoundTrip:
    """Verify encrypt → decrypt with password-based key derivation."""

    @pytest.fixture()
    def engine(self) -> CryptoEngine:
        return CryptoEngine(password="research-password-2026")

    def test_basic_round_trip(self, engine: CryptoEngine) -> None:
        original = "Hello, NTP covert channel!"
        payload = engine.encrypt(original)
        recovered = engine.decrypt(payload)
        assert recovered == original

    def test_unicode_round_trip(self, engine: CryptoEngine) -> None:
        original = "日本語テスト 🔐 émojis"
        payload = engine.encrypt(original)
        assert engine.decrypt(payload) == original

    def test_long_message_round_trip(self, engine: CryptoEngine) -> None:
        original = "A" * 10_000
        payload = engine.encrypt(original)
        assert engine.decrypt(payload) == original

    def test_single_character(self, engine: CryptoEngine) -> None:
        payload = engine.encrypt("X")
        assert engine.decrypt(payload) == "X"

    def test_payload_is_bytes(self, engine: CryptoEngine) -> None:
        payload = engine.encrypt("test")
        assert isinstance(payload, bytes)

    def test_payload_larger_than_plaintext(self, engine: CryptoEngine) -> None:
        plaintext = "short"
        payload = engine.encrypt(plaintext)
        assert len(payload) > len(plaintext.encode("utf-8"))

    def test_each_encryption_produces_unique_output(self, engine: CryptoEngine) -> None:
        """Different salt + nonce → different ciphertext every time."""
        payloads = {engine.encrypt("same text") for _ in range(20)}
        assert len(payloads) == 20


# ═════════════════════════════════════════════════════════════════════
# CryptoEngine — Raw-Key Round-Trip
# ═════════════════════════════════════════════════════════════════════

class TestRawKeyModeRoundTrip:
    """Verify encrypt → decrypt with a pre-derived key."""

    @pytest.fixture()
    def engine(self) -> CryptoEngine:
        return CryptoEngine(key=os.urandom(32))

    def test_basic_round_trip(self, engine: CryptoEngine) -> None:
        original = "Raw key encryption test"
        payload = engine.encrypt(original)
        assert engine.decrypt(payload) == original

    def test_each_encryption_unique(self, engine: CryptoEngine) -> None:
        payloads = {engine.encrypt("deterministic?") for _ in range(10)}
        assert len(payloads) == 10


# ═════════════════════════════════════════════════════════════════════
# Wire Format Verification
# ═════════════════════════════════════════════════════════════════════

class TestWireFormat:
    """Verify the binary layout of encrypted payloads."""

    def test_overhead_constant(self) -> None:
        engine = CryptoEngine(password="test")
        # overhead = salt(16) + nonce(12) + tag(16) = 44
        assert engine.overhead == 44

    def test_payload_size_matches_formula(self) -> None:
        engine = CryptoEngine(password="test")
        plaintext = "exact size test!"
        payload = engine.encrypt(plaintext)
        expected = engine.overhead + len(plaintext.encode("utf-8"))
        assert len(payload) == expected

    def test_salt_field_position(self) -> None:
        """First 16 bytes should be the salt (non-zero in password mode)."""
        engine = CryptoEngine(password="test")
        payload = engine.encrypt("check salt")
        salt = payload[:16]
        assert len(salt) == 16
        # In password mode, salt should not be all-zero
        assert salt != b"\x00" * 16

    def test_raw_key_salt_is_zeroed(self) -> None:
        """In raw-key mode, salt field should be 16 zero-bytes."""
        engine = CryptoEngine(key=os.urandom(32))
        payload = engine.encrypt("check salt")
        salt = payload[:16]
        assert salt == b"\x00" * 16

    def test_nonce_field_position(self) -> None:
        """Bytes 16..28 should be the 12-byte nonce."""
        engine = CryptoEngine(password="test")
        payload = engine.encrypt("check nonce")
        nonce = payload[16:28]
        assert len(nonce) == 12


# ═════════════════════════════════════════════════════════════════════
# Error Handling
# ═════════════════════════════════════════════════════════════════════

class TestErrorHandling:
    """Verify graceful failure modes."""

    def test_empty_plaintext_raises(self) -> None:
        engine = CryptoEngine(password="test")
        with pytest.raises(EncryptionError, match="must not be empty"):
            engine.encrypt("")

    def test_wrong_password_raises_decryption_error(self) -> None:
        sender = CryptoEngine(password="correct-password")
        receiver = CryptoEngine(password="wrong-password")
        payload = sender.encrypt("secret message")
        with pytest.raises(DecryptionError, match="wrong password"):
            receiver.decrypt(payload)

    def test_corrupted_ciphertext_raises(self) -> None:
        engine = CryptoEngine(password="test")
        payload = engine.encrypt("will be corrupted")
        # Flip a byte in the ciphertext region (after salt + nonce)
        corrupted = bytearray(payload)
        corrupted[30] ^= 0xFF
        with pytest.raises(DecryptionError):
            engine.decrypt(bytes(corrupted))

    def test_truncated_payload_raises(self) -> None:
        engine = CryptoEngine(password="test")
        payload = engine.encrypt("will be truncated")
        with pytest.raises(DecryptionError, match="too short"):
            engine.decrypt(payload[:10])

    def test_empty_payload_raises(self) -> None:
        engine = CryptoEngine(password="test")
        with pytest.raises(DecryptionError, match="too short"):
            engine.decrypt(b"")

    def test_wrong_key_raises_decryption_error(self) -> None:
        engine_a = CryptoEngine(key=os.urandom(32))
        engine_b = CryptoEngine(key=os.urandom(32))
        payload = engine_a.encrypt("key mismatch test")
        with pytest.raises(DecryptionError):
            engine_b.decrypt(payload)

    def test_payload_too_large(self) -> None:
        engine = CryptoEngine(password="test")
        with pytest.raises(PayloadTooLargeError, match="exceed"):
            engine.encrypt("A" * 100, max_payload=50)


# ═════════════════════════════════════════════════════════════════════
# Engine Introspection
# ═════════════════════════════════════════════════════════════════════

class TestEngineInfo:
    """Verify get_info() output."""

    def test_info_structure(self) -> None:
        engine = CryptoEngine(password="test")
        info = engine.get_info()
        assert info["algorithm"] == "AES-256-GCM"
        assert info["key_length_bits"] == 256
        assert info["nonce_length_bytes"] == 12
        assert info["tag_length_bytes"] == 16
        assert info["overhead_bytes"] == 44
        assert info["mode"] == "password"

    def test_info_raw_key_mode(self) -> None:
        engine = CryptoEngine(key=os.urandom(32))
        assert engine.get_info()["mode"] == "raw-key"


# ═════════════════════════════════════════════════════════════════════
# Cross-Mode Isolation
# ═════════════════════════════════════════════════════════════════════

class TestCrossModeIsolation:
    """Verify that password-mode and raw-key-mode payloads are incompatible."""

    def test_password_payload_not_decryptable_by_raw_key(self) -> None:
        pw_engine = CryptoEngine(password="test")
        key_engine = CryptoEngine(key=os.urandom(32))
        payload = pw_engine.encrypt("cross-mode test")
        with pytest.raises(DecryptionError):
            key_engine.decrypt(payload)
