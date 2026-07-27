# NTP-SCTAP Security Model

Security architecture, threat model, and cryptographic design.  
Last updated: 2026-06-29 | Version: 0.5.0

---

## Disclaimer

This platform is designed strictly for **educational and research purposes**. It demonstrates covert channel techniques to enable defensive security research and detection engineering. It should never be used for unauthorized access, data exfiltration, or any malicious activity.

---

## Cryptographic Design

| Property | Value |
|---|---|
| Algorithm | AES-256-GCM |
| Key Length | 256 bits (32 bytes) |
| Nonce Length | 96 bits (12 bytes) |
| Tag Length | 128 bits (16 bytes) |
| Key Derivation | PBKDF2-HMAC-SHA256 (600,000 iterations) |
| Mode | Authenticated Encryption with Associated Data (AEAD) |

### Guarantees

- **Confidentiality:** AES-256 encryption
- **Integrity:** GCM authentication tag
- **Authenticity:** Only holders of the correct password can decrypt

### Rules

1. Plaintext is **never** transmitted over the network
2. The networking layer has **no access** to plaintext
3. Encryption happens **before** packet generation
4. Decryption happens **after** payload extraction
5. Each message uses a **unique nonce**

---

## Threat Detection Capabilities

The platform implements a dedicated `ThreatDetector` engine that monitors traffic for anomalies:
- **Covert Extension Analysis:** Identifies standard and non-standard NTP extension fields, particularly custom payloads (type `0x7363`).
- **Timing Burst Anomaly:** Computes packet inter-arrival latency to catch rapid transmission signatures.
- **Size Anomaly:** Flags NTP packets that deviate from standard 48-byte headers without formal extension flags.
- **Protocol Header Integrity:** Detects non-standard modes and versions.

---

## Network Security

- Default ports (9123/9124) are non-privileged — no root required
- Traffic is restricted to localhost (`127.0.0.1`) by default
- The Flask secret key is auto-generated per instance
- No authentication is implemented yet (research tool, single-user)

---

## Data Protection

- Database is stored locally (not exposed over network)
- Secret keys are excluded from API responses (`as_dict()`)
- No sensitive data is logged at INFO level
- Passwords are never stored — only used for key derivation

---

## Known Security Limitations

See [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md) for the current list.
