# NTP-SCTAP Changelog

> All notable changes to this project are documented here.  
> Format follows [Keep a Changelog](https://keepachangelog.com/).

## [1.0.0] — 2026-07-02

### Added
- **Dashboard State & System Resource Monitor:** Implemented thread-safe connection counters, dynamic UDP receiver controllers, and platform-agnostic hardware monitoring (CPU/RAM/db-size) inside `dashboard/manager.py`.
- **Zero-Dependency Data Exporter:** Added pure-Python JSON, CSV, and custom PDF document generators in `utils/exporter.py` with multi-page table formatting, layout spacers, text escaping, and binary xref compile table processing.
- **Chronological Packet Timelines:** Added millisecond-level lifecycle progression tracking (`created` -> `encrypted` -> `queued` -> `transmitted` -> `received` -> `parsed` -> `threat_checked` -> `stored`) in packet records for sender/receiver managers.
- **Real-Time WebSockets Integration:** Linked Flask-SocketIO connect/disconnect listeners in the application factory to dynamically propagate packet activity, recovered messages, threat alerts, and analytics changes.
- **Advanced Threat Forensics:** Expanded anomaly rules with category definitions, evidentiary logs, and target fields metadata inside `detector/engine.py`.
- **Advanced Analytics metrics:** Implemented throughput (PPS), bandwidth usage rates (B/s), mean packet transit latency (NTP timestamp deltas), session duration tracking, and protocol/crypto distribution counts.
- **WebSocket-Driven SPA UI:** Upgraded HTML/JS/CSS frontend to include live message/packet activity consoles, real-time Chart.js dashboards, interactive protocol learning mode, step-by-step session replays, and file export downloading.
- **Unit Test Coverage:** Added unit test suites under `tests/test_dashboard.py` and `tests/test_exporter.py`.

### Fixed
- **Test-Implementation Synchronization:** Fixed implementation consistency across all modules to align with Version 1.0.0.
- **Database Test Isolation:** Resolved test data leakage/dirty database states in the test suite by utilizing isolated temporary database paths per test.
- **Application Factory Test Safe-Mode:** Prevented background UDP receiver thread from binding real host ports when creating Flask app in testing mode.
- **Foreign Key Constraints in Tests:** Fixed metric calculations in test fixtures by correctly inserting sessions before packets/messages referencing them.
- **Version Mismatches:** Aligned the version string to `1.0.0` in both implementation configuration settings and testing assertion expectations.

## [0.5.0] — 2026-06-29

### Added

- **Threat Detection Engine:** Added `ThreatDetector` in `detector/engine.py` to run rule-based anomaly detection on logged packets (covert extension detection, timing bursts, size anomalies, and protocol header checks) and persist alerts to the `threats` table.
- **REST APIs:** Expanded backend HTTP routes to expose 12+ REST endpoints for packets, messages, threats, sessions, analytics, and system errors.
- **SPA Frontend Interface:** Built a fully interactive dashboard in `index.html`, `main.css`, and `main.js` with 7 sub-pages, automatic polling, data tables, and Chart.js analytics integration.
- **Detection tests:** Added `tests/test_detector.py` with 11 test cases validating all detection rules and anomaly conditions.

### Fixed

- **SenderManager Bug:** Refactored `send_message()` to ensure packet and message records are persisted to the database on both successful transmission and socket failure paths.

---

## [0.4.0] — 2026-06-28

### Added

- **Sender Orchestrator:** Added `SenderManager` in `sender/manager.py` to encrypt, pack, transmit, and write covert send attempts to the SQLite database.
- **Receiver Orchestrator:** Added `ReceiverManager` in `receiver/manager.py` to listen for packets, persist them, decrypt covert extensions, write incoming messages, and trigger user-defined callbacks.
- **Analytics Engine:** Added `AnalyticsEngine` in `analytics/engine.py` to calculate packet counts, payload sizes, decryption success rates, and log snapshots.
- **Milestone 4 tests:** 7 tests verifying message/packet persistence, decryption error handling, and metric computations under `tests/test_sender.py`, `tests/test_receiver.py`, and `tests/test_analytics.py`.

---

## [0.3.0] — 2026-06-28

### Added

- **Network exceptions:** Custom exception hierarchy — `NetworkError`, `TransmissionError`, `ListenerError` (`network/exceptions.py`)
- **UDP Sender:** `UDPSender` class to transmit NTP packets over non-blocking sockets (`network/sender.py`)
- **UDP Receiver:** `UDPReceiver` class running in a safe daemon thread to continuously listen for and parse incoming packets (`network/receiver.py`)
- **Network tests:** 6 tests covering UDP socket transmission, daemon thread lifecycle, startup/shutdown correctness, and end-to-end localhost transmission (`tests/test_network.py`)

---

## [0.2.0] — 2026-06-28

### Changed (Senior Code Review)

- **Robustness**: Added bounds checking to `NTPPacket.extract_extension` to prevent silent truncation.
- **Type Safety**: Refactored `CryptoEngine` key resolution for improved type safety (removed `type: ignore`) and explicit byte string usage for AES-GCM associated data.

### Added

- **Protocol exceptions:** Custom exception hierarchy — `ProtocolError`, `PacketMalformedError`, `PayloadCapacityError` (`protocol/exceptions.py`)
- **NTP Packet Engine:** `NTPPacket` class for RFC 5905 compliant 48-byte header parsing and generation (`protocol/packet.py`)
- **Covert Channel 1 (Extensions):** Support for injecting and extracting AES-256-GCM payloads via custom 8-byte NTPv4 extension headers
- **Covert Channel 2 (Timestamps):** Support for injecting deterministic payloads (up to 16 bytes) into the lower 32-bit fractional parts of NTP timestamps
- **Protocol tests:** 14 tests covering packet structure, extension injection, timestamp bounds, extraction integrity, and end-to-end crypto integration (`tests/test_protocol.py`)
- **Crypto exceptions:** Custom exception hierarchy — `CryptoError`, `KeyDerivationError`, `EncryptionError`, `DecryptionError`, `PayloadTooLargeError` (`crypto/exceptions.py`)
- **Key derivation:** PBKDF2-HMAC-SHA256 with 600k iterations, 16-byte random salt, OWASP 2024 compliant (`crypto/key_derivation.py`)
- **Encryption engine:** `CryptoEngine` class supporting password-based and raw-key AES-256-GCM encryption/decryption with fixed wire format (`crypto/engine.py`)
- **Crypto tests:** 35 tests covering key derivation, round-trips, wire format, error paths, nonce uniqueness, and cross-mode isolation (`tests/test_crypto.py`)

---

## [0.1.0] — 2026-06-28

### Added

- **Project scaffolding:** Complete modular folder structure with 14 Python packages
- **Configuration system:** Dataclass-based centralized config with environment variable support (`config/settings.py`)
- **Structured logging:** ANSI-coloured console output + rotating file handler (`utils/logger.py`)
- **Helper utilities:** ID generation, timestamp formatting, hex conversion, safe type coercion (`utils/helpers.py`)
- **Database layer:** SQLite schema with 9 tables and 12 indexes (`database/models.py`)
- **Database manager:** Thread-safe connection manager with generic CRUD operations (`database/manager.py`)
- **Flask application factory:** Production-ready app creation with SocketIO integration (`backend/app_factory.py`)
- **API endpoints:** `/api/health`, `/api/status`, `/api/config` (`backend/routes.py`)
- **Home page:** Dark-mode cybersecurity dashboard with stat cards, health grid, configuration summary, and activity console
- **Design system:** CSS custom properties, glassmorphism components, responsive layout (`frontend/static/css/main.css`)
- **Client-side JS:** Real-time clock, sidebar toggle, health polling (`frontend/static/js/main.js`)
- **Test suite:** 4 test modules with shared fixtures covering config, database, routes, and utilities
- **Documentation:** 15 documentation files including README, PROJECT_STRUCTURE, ARCHITECTURE, ROADMAP
- **Version control:** `.gitignore`, `requirements.txt`, `LICENSE` (MIT)
