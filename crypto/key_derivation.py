"""
NTP-SCTAP Secure Key Derivation.

Derives a fixed-length AES-256 encryption key from a user-supplied
password using PBKDF2-HMAC-SHA256.

Design notes:
  - PBKDF2 is used over Scrypt/Argon2 because it is NIST-approved
    (SP 800-132), universally available, and the ``cryptography``
    library implements it in C (OpenSSL) — no extra dependencies.
  - The iteration count (600 000) follows OWASP 2024 guidance for
    PBKDF2-HMAC-SHA256.
  - Salt is 16 bytes of ``os.urandom()`` — CSPRNG on all platforms.
  - This module is intentionally isolated so that the KDF algorithm
    can be swapped (e.g. to Argon2id) without touching the engine.

Usage:
    from crypto.key_derivation import derive_key
    key, salt = derive_key("my-password")
    # To re-derive the same key later:
    key2, _ = derive_key("my-password", salt=salt)
    assert key == key2
"""

import os
from typing import Tuple

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

from utils.logger import get_logger
from crypto.exceptions import KeyDerivationError

logger = get_logger("crypto.key_derivation")

# ── Constants ────────────────────────────────────────────────────────
DEFAULT_KEY_LENGTH: int = 32        # 256 bits
DEFAULT_SALT_LENGTH: int = 16       # 128 bits
DEFAULT_ITERATIONS: int = 600_000   # OWASP 2024 recommendation


def derive_key(
    password: str,
    salt: bytes | None = None,
    key_length: int = DEFAULT_KEY_LENGTH,
    iterations: int = DEFAULT_ITERATIONS,
) -> Tuple[bytes, bytes]:
    """Derive a cryptographic key from a password using PBKDF2-HMAC-SHA256.

    Args:
        password:   User-supplied password string. Must not be empty.
        salt:       Optional salt bytes. If *None*, a fresh 16-byte
                    random salt is generated. Pass the original salt
                    to re-derive the same key for decryption.
        key_length: Desired key length in bytes (default 32 = AES-256).
        iterations: PBKDF2 iteration count.

    Returns:
        A ``(key, salt)`` tuple. The caller **must** store or transmit
        the salt alongside the ciphertext so the receiver can re-derive.

    Raises:
        KeyDerivationError: If the password is empty/None, if parameters
            are invalid, or if the underlying KDF raises an error.
    """
    # ✅ IMPROVEMENT 031: Validate all input parameters early
    
    # Password validation
    if not password:
        raise KeyDerivationError("Password must not be empty")

    # Key length validation
    if key_length <= 0:
        raise KeyDerivationError("Key length must be greater than zero")

    # Iteration count validation
    if iterations <= 0:
        raise KeyDerivationError("Iteration count must be greater than zero")

    # Salt type validation
    if salt is not None and not isinstance(salt, bytes):
        raise KeyDerivationError(f"Salt must be bytes, got {type(salt).__name__}")

    if salt is None:
        salt = os.urandom(DEFAULT_SALT_LENGTH)
        logger.debug("Generated fresh salt (%d bytes)", len(salt))

    try:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=key_length,
            salt=salt,
            iterations=iterations,
        )
        key = kdf.derive(password.encode("utf-8"))
    except Exception as exc:
        logger.error("Key derivation failed: %s", exc)
        raise KeyDerivationError(f"Key derivation failed: {exc}") from exc

    logger.debug(
        "Key derived: length=%d bytes, salt=%d bytes, iterations=%d",
        len(key), len(salt), iterations,
    )
    return key, salt