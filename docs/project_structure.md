# NTP-SCTAP Project Structure

> Complete architectural reference for every folder and file in the project.  
> Last updated: 2026-06-29 | Version: 0.5.0 | Milestone: 5

---

## Root Files

### `app.py`
- **Purpose:** Top-level application entry point
- **Exports:** `app` (Flask instance), `socketio` (SocketIO instance)
- **Dependencies:** `backend.app_factory`
- **Used by:** `run.py`, WSGI servers

### `run.py`
- **Purpose:** Development server launcher
- **Functions:** `main()` — prints startup banner, starts Flask-SocketIO server
- **Dependencies:** `config.settings`, `utils.logger`, `app`

### `requirements.txt`
- **Purpose:** Python package dependencies
- **Packages:** Flask, Flask-SocketIO, python-socketio, python-engineio, cryptography, pytest, pytest-cov

### `.gitignore`
- **Purpose:** Git exclusion rules for caches, data, IDE files, virtual environments

### `LICENSE`
- **Purpose:** MIT License

---

## `config/` — Configuration

**Purpose:** Centralized, environment-aware application settings.  
**Dependencies:** None (zero internal imports to prevent circular dependencies).

### `config/__init__.py`
- **Exports:** `Config`, `get_config`

### `config/settings.py`
- **Purpose:** All application settings as a Python dataclass
- **Classes:** `Config` — dataclass with fields for app, server, database, logging, network, crypto, threat detection, and analytics settings
- **Functions:**
  - `get_config(**overrides) → Config` — Singleton accessor
  - `reset_config() → None` — Test-only teardown
- **Environment Variables:** `SCTAP_DEBUG`, `SCTAP_HOST`, `SCTAP_PORT`, `SCTAP_DB_PATH`, `SCTAP_LOG_LEVEL`, `SCTAP_LOG_FILE`, `SCTAP_NTP_SEND_PORT`, `SCTAP_NTP_LISTEN_PORT`, `SCTAP_NTP_TARGET`, `SCTAP_SECRET_KEY`

---

## `utils/` — Utilities

**Purpose:** Shared helpers with no internal-project dependencies.  
**Dependencies:** Python standard library only.

### `utils/__init__.py`
- **Exports:** `get_logger`, `generate_id`, `utc_now`, `format_timestamp`, `bytes_to_hex`

### `utils/logger.py`
- **Purpose:** Structured logging factory
- **Functions:**
  - `get_logger(name: str) → Logger` — Returns a child logger under `sctap.*`
  - `reset_logger() → None` — Test-only teardown
- **Classes:** `_ColouredFormatter`, `_FileFormatter`
- **Output:** Console (ANSI-coloured) + rotating file handler (5 MB × 5 backups)

### `utils/helpers.py`
- **Purpose:** Pure utility functions
- **Functions:**
  - `generate_id(prefix) → str` — UUID-based unique ID
  - `utc_now() → datetime` — Timezone-aware UTC timestamp
  - `format_timestamp(dt, fmt) → str` — Human-readable formatting
  - `iso_timestamp(dt) → str` — ISO-8601 formatting
  - `bytes_to_hex(data, separator) → str` — Hex dump
  - `hex_to_bytes(hex_string) → bytes` — Hex decode
  - `truncate(text, max_length) → str` — String truncation
  - `safe_int(value, default) → int` — Safe integer conversion

---

## `database/` — Database

**Purpose:** SQLite schema, connection management, and CRUD operations.  
**Dependencies:** `config.settings`, `utils.logger`, `utils.helpers`

### `database/__init__.py`
- **Exports:** `DatabaseManager`, `get_db`

### `database/models.py`
- **Purpose:** SQL DDL schema definitions
- **Tables (9):**
  - `sessions` — Communication session tracking
  - `packets` — NTP packet records
  - `messages` — Plaintext/ciphertext message pairs
  - `threats` — Threat detection events
  - `analytics` — Time-series metric snapshots
  - `events` — System event log
  - `errors` — Error records
  - `system_logs` — Persistent log entries
  - `configuration` — Runtime key-value config store
- **Indexes (12):** On foreign keys, timestamps, and commonly filtered columns
- **Exports:** `ALL_TABLES`, `CREATE_INDEXES`

### `database/manager.py`
- **Purpose:** Thread-safe SQLite connection manager
- **Classes:** `DatabaseManager`
  - `connect() → Connection` — Opens/returns persistent connection (WAL mode, foreign keys ON)
  - `close() → None` — Cleanly closes connection
  - `initialize() → None` — Creates all tables and indexes
  - `transaction() → Generator` — Context manager with commit/rollback
  - `execute(sql, params) → Cursor` — Single statement execution
  - `query(sql, params) → List[Dict]` — SELECT returning dicts
  - `query_one(sql, params) → Optional[Dict]` — Single-row SELECT
  - `insert(table, data) → str` — Insert with auto-ID and auto-timestamp
  - `update(table, row_id, data) → int` — Update by primary key
  - `delete(table, row_id) → int` — Delete by primary key
  - `count(table, where, params) → int` — Row count
  - `table_exists(name) → bool` — Introspection
  - `get_table_names() → List[str]` — All table names
  - `get_stats() → Dict` — Status summary for API endpoint
- **Functions:**
  - `get_db(db_path) → DatabaseManager` — Singleton accessor
  - `reset_db() → None` — Test-only teardown

---

## `backend/` — Web Backend

**Purpose:** Flask application factory, route handlers.  
**Dependencies:** `config.settings`, `database.manager`, `utils.logger`, `utils.helpers`

### `backend/__init__.py`
- **Exports:** `create_app`

### `backend/app_factory.py`
- **Purpose:** Flask application factory with SocketIO initialization
- **Functions:** `create_app(config) → tuple[Flask, SocketIO]`
- **Initializes:** Flask app, SocketIO, database, route registration

### `backend/routes.py`
- **Purpose:** HTTP route definitions
- **Functions:** `register_routes(app: Flask) → None`
- **Endpoints:**
  - `GET /` — Home page (HTML)
  - `GET /api/health` — Liveness probe (JSON)
  - `GET /api/status` — System status (JSON)
  - `GET /api/config` — Configuration (JSON, no secrets)
  - `404` — JSON for `/api/*`, HTML otherwise
  - `500` — JSON error response

---

## `frontend/` — Web Frontend

**Purpose:** HTML templates, CSS styles, JavaScript.

### `frontend/templates/base.html`
- **Purpose:** Base Jinja2 template
- **Layout:** Sidebar navigation + topbar + content area
- **Blocks:** `title`, `page_title`, `head`, `content`, `scripts`

### `frontend/templates/index.html`
- **Purpose:** Home page / system overview dashboard
- **Components:** Hero card, stat cards (4), health grid, config summary, activity console

### `frontend/static/css/main.css`
- **Purpose:** Complete design system
- **Design:** Dark mode, glassmorphism, cybersecurity-inspired theme
- **Tokens:** CSS custom properties for colors, typography, spacing, transitions
- **Components:** Sidebar, topbar, cards, stat cards, badges, health grid, config table, console panel
- **Responsive:** Breakpoints at 1024px and 768px

### `frontend/static/js/main.js`
- **Purpose:** Core client-side JavaScript
- **Features:** Real-time clock, sidebar toggle, health polling, `SCTAP.appendConsole()` utility

---

## `crypto/` — Cryptography

**Purpose:** AES-256-GCM authenticated encryption with password-based key derivation.  
**Dependencies:** `cryptography` library, `config.settings`, `utils.logger`

### `crypto/__init__.py`
- **Exports:** `CryptoEngine`, `derive_key`, `CryptoError`, `KeyDerivationError`, `EncryptionError`, `DecryptionError`, `PayloadTooLargeError`

### `crypto/exceptions.py`
- **Purpose:** Custom exception hierarchy for all crypto operations
- **Classes:**
  - `CryptoError` — Base exception
  - `KeyDerivationError(CryptoError)` — Password/salt issues
  - `EncryptionError(CryptoError)` — Encryption failures
  - `DecryptionError(CryptoError)` — Decryption / auth-tag failures
  - `PayloadTooLargeError(CryptoError)` — Message exceeds capacity

### `crypto/key_derivation.py`
- **Purpose:** PBKDF2-HMAC-SHA256 key derivation (isolated for KDF swappability)
- **Functions:**
  - `derive_key(password, salt, key_length, iterations) → Tuple[bytes, bytes]` — Returns `(key, salt)`
- **Constants:** `DEFAULT_KEY_LENGTH` (32), `DEFAULT_SALT_LENGTH` (16), `DEFAULT_ITERATIONS` (600,000)
- **Design:** OWASP 2024 iteration count; NIST SP 800-132 compliant

### `crypto/engine.py`
- **Purpose:** AES-256-GCM encryption/decryption engine
- **Classes:** `CryptoEngine`
  - `__init__(password, key)` — Construct with password (PBKDF2 mode) or raw key
  - `encrypt(plaintext, max_payload) → bytes` — Encrypt to wire format
  - `decrypt(payload) → str` — Decrypt wire-format payload
  - `get_info() → dict` — JSON-safe engine configuration summary
- **Wire format:** `salt(16) ‖ nonce(12) ‖ ciphertext ‖ tag(16)` — 44 bytes overhead
- **Attributes:** `algorithm`, `key_length`, `nonce_length`, `tag_length`, `overhead`

---

## `protocol/` — NTP Protocol

**Purpose:** NTPv4 packet generation, parsing, and covert payload injection.  
**Dependencies:** `utils.logger`

### `protocol/__init__.py`
- **Exports:** `NTPPacket`, `ProtocolError`, `PacketMalformedError`, `PayloadCapacityError`

### `protocol/exceptions.py`
- **Purpose:** Custom exception hierarchy for protocol operations
- **Classes:**
  - `ProtocolError` — Base exception
  - `PacketMalformedError(ProtocolError)` — Packet parsing failures
  - `PayloadCapacityError(ProtocolError)` — Injection exceeds field limits

### `protocol/packet.py`
- **Purpose:** Standard NTP packet formatting and covert injection
- **Classes:** `NTPPacket`
  - `__init__()` — Initializes standard 48-byte client header
  - `pack() → bytes` — Serializes header and extension data
  - `unpack(data) → NTPPacket` — Parses raw network bytes
  - `inject_extension(payload)` — Injects large payload via custom extension field
  - `extract_extension() → bytes` — Extracts payload from extension field
  - `inject_timestamps(payload)` — Injects up to 16 bytes into timestamp fractional parts
  - `extract_timestamps(length) → bytes` — Extracts payload from timestamps

## `network/` — UDP Networking

**Purpose:** UDP transmission and background reception for NTP packets.  
**Dependencies:** `socket`, `threading`, `config.settings`, `protocol.packet`, `utils.logger`

### `network/__init__.py`
- **Exports:** `UDPSender`, `UDPReceiver`, `NetworkError`, `TransmissionError`, `ListenerError`

### `network/exceptions.py`
- **Purpose:** Custom exception hierarchy for networking operations
- **Classes:**
  - `NetworkError` — Base exception
  - `TransmissionError(NetworkError)` — Send failures
  - `ListenerError(NetworkError)` — Bind or thread failures

### `network/sender.py`
- **Purpose:** UDP Socket Sender
- **Classes:** `UDPSender`
  - `__init__(target_host, target_port)` — Sets up non-blocking UDP socket
  - `transmit(packet) → int` — Serializes and sends `NTPPacket`
  - `close()` — Cleans up socket

### `network/receiver.py`
- **Purpose:** Background UDP Listener
- **Classes:** `UDPReceiver`
  - `__init__(bind_host, bind_port, callback)`
  - `start()` — Binds socket and spawns daemon listener thread
  - `stop()` — Signals thread termination and closes socket
  - `_listen_loop()` — Continuous receive loop
  - `_handle_packet()` — Parses packet and fires callback

## `sender/` — Sender Business Logic

**Purpose:** Coordinates outbound message encryption, packet building, network dispatch, and database persistence.
**Dependencies:** `crypto.engine`, `protocol.packet`, `network.sender`, `database.manager`, `utils.helpers`

### `sender/__init__.py`
- **Exports:** `SenderManager`

### `sender/manager.py`
- **Classes:** `SenderManager`
  - `__init__(crypto_engine, target_host, target_port, session_id)`
  - `send_message(plaintext) → str` — Encrypts message, building packet, transmitting it, and logging to the `messages` and `packets` tables (updating the session count). Handles error logging internally on network failure.

---

## `receiver/` — Receiver Business Logic

**Purpose:** Coordinates background listener execution, packet retrieval, decryption, message callbacks, and database logging.
**Dependencies:** `crypto.engine`, `crypto.exceptions`, `protocol.packet`, `network.receiver`, `database.manager`, `utils.helpers`

### `receiver/__init__.py`
- **Exports:** `ReceiverManager`

### `receiver/manager.py`
- **Classes:** `ReceiverManager`
  - `__init__(crypto_engine, bind_host, bind_port, message_callback)`
  - `start()`, `stop()` — Direct lifecycle commands
  - `_on_packet_received(packet, addr)` — Background thread callback that logs the packet, checks/updates sessions, decrypts any covert payload, logs messages, logs errors, and fires message event callbacks.

---

## `analytics/` — Analytics Engine

**Purpose:** Computes operational security and payload transmission statistics.
**Dependencies:** `database.manager`

### `analytics/__init__.py`
- **Exports:** `AnalyticsEngine`

### `analytics/engine.py`
- **Classes:** `AnalyticsEngine`
  - `calculate_metrics() → Dict[str, Any]` — Aggregates traffic counts, payload sizes, and decryption success rate; logs metrics as a new snapshot in the `analytics` table.
  - `get_latest_metrics() → Dict[str, Any]` — Retrieves the most recently recorded metrics from database history.

---

---

## `detector/` — Threat Detection Engine

**Purpose:** Performs anomaly detection, covert channel identification, and timing analysis.
**Dependencies:** `config.settings`, `database.manager`, `protocol.packet`, `utils.logger`, `utils.helpers`

### `detector/__init__.py`
- **Exports:** `ThreatDetector`, `DetectionError`, `AnalysisError`

### `detector/exceptions.py`
- **Purpose:** Custom exception hierarchy for the detection engine.

### `detector/engine.py`
- **Classes:** `ThreatDetector`
  - `analyze_packet(packet_id: str) → Optional[Dict[str, Any]]` — Main entry point: runs all rules on a logged packet, logs threats, and updates packet validation status.
  - `_check_timing_anomalies(pkt: Dict[str, Any]) → Optional[Dict[str, Any]]` — Analyzes inter-arrival times of recent packets from the same source host to detect timing bursts.
  - `_record_threat(...) → Dict[str, Any]` — Helper: inserts threat event into the database and updates packet validation.

---

## Stub Modules (Implementation in Future Milestones)

| Module | Purpose | Target Milestone |
|---|---|---|
| `dashboard/` | Dashboard state management | Milestone 6 |


---

## `tests/` — Test Suite

**Purpose:** Pytest-based automated testing.  
**Dependencies:** All source modules, pytest

### `tests/__init__.py`
- Package marker

### `tests/conftest.py`
- **Purpose:** Shared fixtures
- **Fixtures:** `config` (temp-dir Config), `db` (initialized DatabaseManager), `client` (Flask test client)
- **Auto-use:** `_clean_singletons` — resets Config, DB, Logger between tests

### `tests/test_config.py`
- **Coverage:** Defaults, directory creation, serialization, singleton, database URI

### `tests/test_database.py`
- **Coverage:** Schema initialization, insert, query, update, delete, count, introspection, stats

### `tests/test_app_factory.py`
- **Coverage:** Health endpoint, status endpoint, config endpoint, home page, error handlers

### `tests/test_utils.py`
- **Coverage:** ID generation, timestamps, hex conversion, truncation, safe_int

### `tests/test_crypto.py`
- **Coverage:** Key derivation (PBKDF2), password-mode round-trip, raw-key round-trip, wire format verification, error handling (wrong password, corruption, truncation, empty inputs, size limits), nonce uniqueness, engine introspection, cross-mode isolation

### `tests/test_protocol.py`
- **Coverage:** NTP header packing/unpacking, extension field injection/extraction, timestamp fractional injection/extraction, malformed packets, end-to-end crypto integration pipeline

### `tests/test_network.py`
- **Coverage:** UDP Sender initialization, Receiver lifecycle (start/stop daemon thread), callback firing, end-to-end localhost transmission

### `tests/test_detector.py`
- **Coverage:** Covert extension field detection, protocol header integrity checks, packet size anomaly detection, timing burst pattern analysis, clean packet validation, missing packet error handling

---

## `docs/` — Documentation

| File | Purpose |
|---|---|
| `project_structure.md` | This file — complete architectural reference |
| `progress_file.md` | Live engineering journal |
| `setup.md` | Installation guide |
| `run.md` | Execution guide |
| `ARCHITECTURE.md` | System architecture and design |
| `ROADMAP.md` | Development milestones and timeline |
| `CHANGELOG.md` | Version history |
| `API_REFERENCE.md` | REST API documentation |
| `CONTRIBUTING.md` | Contribution guidelines |
| `research_notes.md` | NTP protocol research notes |
| `engineering_log.md` | Engineering decisions journal |
| `TESTING.md` | Test strategy and coverage |
| `SECURITY.md` | Security model documentation |
| `KNOWN_LIMITATIONS.md` | Current limitations and constraints |
