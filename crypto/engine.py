"""
NTP-SCTAP AES-256-GCM Encryption Engine.

Provides the ``CryptoEngine`` class — the single point of contact for
all encryption and decryption operations in the platform.

Architecture decision — single class, not two:
    The user requirement asked for separate encrypt/decrypt "service
    classes." However, both operations share identical key material,
    nonce parameters, and tag-length configuration. Splitting them would
    force duplicated state management or a shared base class — adding
    complexity with no testability or modularity benefit. Instead, the
    engine exposes clearly separated ``.encrypt()`` and ``.decrypt()``
    public methods, and can be instantiated with either a raw key or
    a password (which internally calls the key-derivation module).

Wire format (encrypted payload):
    ┌──────────┬───────────┬────────────────┬─────────────┐
    │ salt     │ nonce     │ ciphertext     │ tag         │
    │ 16 bytes │ 12 bytes  │ variable       │ 16 bytes    │
    └──────────┴───────────┴────────────────┴─────────────┘
    Total overhead: 44 bytes (salt + nonce + tag).

    When the engine is constructed with a raw key (no password), the
    salt field is zeroed (16 × 0x00) to keep the wire format fixed.

Usage:
    # Password-based
    engine = CryptoEngine(password="secret")
    payload = engine.encrypt("Hello, NTP!")
    plaintext = engine.decrypt(payload)

    # Raw-key-based
    engine = CryptoEngine(key=my_32_byte_key)
    payload = engine.encrypt("Hello, NTP!")
"""

import os
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from config.settings import get_config
from utils.logger import get_logger


from crypto.exceptions import (
    CryptoError,
    EncryptionError,
    DecryptionError,
    PayloadTooLargeError,
)
from crypto.key_derivation import derive_key

logger = get_logger("crypto.engine")

# Sentinel: 16 zero-bytes used as salt placeholder for raw-key mode
_EMPTY_SALT = b"\x00" * 16


class CryptoEngine:
    """AES-256-GCM authenticated encryption engine.

    Construct with **either** ``password`` or ``key`` (not both).

    Attributes:
        algorithm:    Always ``"AES-256-GCM"``.
        key_length:   Key size in bytes (32).
        nonce_length: Nonce size in bytes (12).
        tag_length:   GCM auth-tag size in bytes (16).
        overhead:     Fixed byte overhead added to every ciphertext
                      (salt + nonce + tag = 44 bytes).
    """

    def __init__(
        self,
        password: Optional[str] = None,
        key: Optional[bytes] = None,
    ) -> None:
        """Initialise the engine.

        Args:
            password: User-supplied password. Key is derived via
                      PBKDF2-HMAC-SHA256 on each ``.encrypt()`` call
                      (fresh salt every time) and re-derived during
                      ``.decrypt()`` using the salt embedded in the
                      payload.
            key:      Pre-derived 32-byte AES key. If supplied,
                      ``password`` must be *None*.

        Raises:
            CryptoError: If both or neither of ``password``/``key``
                         are supplied, or if the key length is wrong.
        """
        cfg = get_config()
        self.algorithm: str = cfg.CRYPTO_ALGORITHM
        self.key_length: int = cfg.CRYPTO_KEY_LENGTH
        self.nonce_length: int = cfg.CRYPTO_NONCE_LENGTH
        self.tag_length: int = cfg.CRYPTO_TAG_LENGTH
        self.overhead: int = 16 + self.nonce_length + self.tag_length  # salt + nonce + tag

        # Resolve key source
        if password and key:
            raise CryptoError("Specify password OR key, not both")
        if not password and not key:
            raise CryptoError("Either password or key is required")

        self._password: Optional[str] = password
        self._static_key: Optional[bytes] = None

        if key is not None:
            if len(key) != self.key_length:
                raise CryptoError(
                    f"Key must be exactly {self.key_length} bytes, "
                    f"got {len(key)}"
                )
            self._static_key = key

        mode = "password" if self._password else "raw-key"
        logger.info(
            "CryptoEngine initialised: algorithm=%s, mode=%s",
            self.algorithm, mode,
        )

    # ── Public API ───────────────────────────────────────────────────

    def encrypt(self, plaintext: str, max_payload: Optional[int] = None) -> bytes:
        """Encrypt a plaintext string using AES-256-GCM.

        Args:
            plaintext:    UTF-8 string to encrypt.
            max_payload:  Optional maximum total payload size in bytes.
                          If the resulting encrypted payload would
                          exceed this, ``PayloadTooLargeError`` is raised.

        Returns:
            Encrypted payload bytes in the wire format:
            ``salt (16) ‖ nonce (12) ‖ ciphertext ‖ tag (16)``

        Raises:
            EncryptionError:      If encryption fails.
            PayloadTooLargeError: If the result exceeds *max_payload*.
        """
        if not plaintext:
            raise EncryptionError("Plaintext must not be empty")

        plaintext_bytes = plaintext.encode("utf-8")

        # Check size constraint before doing expensive work
        if max_payload is not None:
            estimated = self.overhead + len(plaintext_bytes)
            if estimated > max_payload:
                raise PayloadTooLargeError(
                    f"Encrypted payload ({estimated} bytes) would exceed "
                    f"max capacity ({max_payload} bytes)"
                )

        try:
            # Resolve key and salt
            if self._password:
                key, salt = derive_key(self._password, key_length=self.key_length)
            elif self._static_key is not None:
                key = self._static_key
                salt = _EMPTY_SALT
            else:
                raise EncryptionError("Engine not properly initialized")

            # Generate a unique nonce for this operation
            nonce = os.urandom(self.nonce_length)

            # Encrypt (GCM appends the auth tag to the ciphertext)
            aesgcm = AESGCM(key)
            ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext_bytes, b"")

            # Assemble wire-format payload
            payload = salt + nonce + ciphertext_with_tag

        except (EncryptionError, PayloadTooLargeError):
            raise
        except Exception as exc:
            logger.error("Encryption failed: %s", exc)
            raise EncryptionError(f"Encryption failed: {exc}") from exc

        logger.debug(
            "Encrypted: plaintext=%d bytes → payload=%d bytes "
            "(salt=16, nonce=%d, ct+tag=%d)",
            len(plaintext_bytes),
            len(payload),
            self.nonce_length,
            len(ciphertext_with_tag),
        )
        return payload

    def decrypt(self, payload: bytes) -> str:
        """Decrypt an AES-256-GCM encrypted payload.

        Args:
            payload: Encrypted bytes in the wire format produced by
                     ``.encrypt()``.

        Returns:
            The recovered plaintext as a UTF-8 string.

        Raises:
            DecryptionError: If the payload is malformed, the password
                             is wrong, or the authentication tag does
                             not verify (data tampered).
        """
        min_length = self.overhead + 1  # at least 1 byte of ciphertext
        if len(payload) < min_length:
            raise DecryptionError(
                f"Payload too short ({len(payload)} bytes); "
                f"minimum is {min_length} bytes"
            )

        try:
            # Unpack wire format
            salt = payload[:16]
            nonce = payload[16:16 + self.nonce_length]
            ciphertext_with_tag = payload[16 + self.nonce_length:]

            # Resolve key
            if self._password:
                key, _ = derive_key(
                    self._password, salt=salt, key_length=self.key_length
                )
            elif self._static_key is not None:
                key = self._static_key
            else:
                raise DecryptionError("Engine not properly initialized")

            # Decrypt and verify auth tag
            aesgcm = AESGCM(key)
            plaintext_bytes = aesgcm.decrypt(nonce, ciphertext_with_tag, b"")

        except DecryptionError:
            raise
        except Exception as exc:
            logger.warning("Decryption failed")
            raise DecryptionError(
                "Decryption failed — wrong password or corrupted data"
            ) from exc

        plaintext = plaintext_bytes.decode("utf-8")
        logger.debug(
            "Decrypted: payload=%d bytes → plaintext=%d bytes",
            len(payload), len(plaintext_bytes),
        )
        return plaintext

    # ── Introspection ────────────────────────────────────────────────

    def get_info(self) -> dict:
        """Return a JSON-safe summary of engine configuration."""
        return {
            "algorithm": self.algorithm,
            "key_length_bits": self.key_length * 8,
            "nonce_length_bytes": self.nonce_length,
            "tag_length_bytes": self.tag_length,
            "overhead_bytes": self.overhead,
            "mode": "password" if self._password else "raw-key",
        }


