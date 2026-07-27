"""
NTP-SCTAP Cryptography Module.

Provides AES-256-GCM authenticated encryption with password-based key
derivation (PBKDF2-HMAC-SHA256).

Public API:
    CryptoEngine   — encrypt / decrypt operations
    derive_key     — standalone key derivation
    CryptoError    — base exception
    EncryptionError, DecryptionError, KeyDerivationError,
    PayloadTooLargeError — specific failure modes
"""

from crypto.engine import CryptoEngine
from crypto.key_derivation import derive_key
from crypto.exceptions import (
    CryptoError,
    KeyDerivationError,
    EncryptionError,
    DecryptionError,
    PayloadTooLargeError,
)

__all__ = [
    "CryptoEngine",
    "derive_key",
    "CryptoError",
    "KeyDerivationError",
    "EncryptionError",
    "DecryptionError",
    "PayloadTooLargeError",
]
