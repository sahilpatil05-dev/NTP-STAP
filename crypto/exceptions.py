"""
NTP-SCTAP Cryptographic Exception Hierarchy.

All crypto-related errors inherit from ``CryptoError`` so callers can
catch the entire family with a single except clause while still being
able to differentiate specific failure modes.

Exception tree::

    CryptoError
    ├── KeyDerivationError   — password/salt issues
    ├── EncryptionError      — encryption failures
    ├── DecryptionError      — decryption / auth-tag failures
    └── PayloadTooLargeError — message exceeds capacity
"""


class CryptoError(Exception):
    """Base exception for all cryptographic operations."""


class KeyDerivationError(CryptoError):
    """Raised when key derivation from a password fails.

    Typical causes:
    - Empty or None password
    - Salt generation failure
    - PBKDF2 parameter misconfiguration
    """


class EncryptionError(CryptoError):
    """Raised when AES-256-GCM encryption fails.

    Typical causes:
    - Invalid key length
    - Nonce generation failure
    - Internal library error
    """


class DecryptionError(CryptoError):
    """Raised when AES-256-GCM decryption fails.

    Typical causes:
    - Wrong password / derived key
    - Corrupted ciphertext
    - Authentication tag mismatch (data tampered)
    - Malformed encrypted payload
    """


class PayloadTooLargeError(CryptoError):
    """Raised when the plaintext exceeds the maximum payload capacity.

    NTP covert channel has limited steganographic bandwidth. This error
    prevents callers from attempting to encrypt messages that cannot fit
    inside the available packet space.
    """
