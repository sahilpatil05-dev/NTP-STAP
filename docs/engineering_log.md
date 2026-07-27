# NTP-SCTAP Engineering Log

Architecture decisions and technical rationale.
Last updated: 2026-07-02

---

## 2026-07-02 — Test-Implementation Synchronization (Version 1.0.0 Release)

### Hermetic Test Database Isolation
To resolve database-level test leakage and integrity issues, we updated the shared `pytest` fixtures in `tests/conftest.py`. Rather than relying on simple config resets, we introduced a `tempfile.TemporaryDirectory` within the autouse `_clean_singletons` fixture. This guarantees that every single unit test gets an entirely separate, isolated database file located in a fresh path. Additionally, we bound the `db` fixture directly to the global `DatabaseManager` singleton (`get_db`), ensuring that the application models and test procedures reference the exact same active SQLite database instance.

### App Factory Testing Mode Guard
We decoupled application creation from active port binding in Flask testing scenarios. The application factory in `backend/app_factory.py` now queries `app.config.get("TESTING")` (which is auto-detected if running under `pytest` via `sys.modules`) and disables startup of the background UDP receiver. This avoids socket resource conflicts when running the test suite in parallel or on systems where port 9124 is occupied.

## 2026-06-29 — Version 1.0 Decisions

### Platform-Agnostic System Monitoring
Designed a resource monitor in `dashboard/manager.py` that checks the running platform (`platform.system()`). It utilizes `ctypes` on Windows to map `GlobalMemoryStatusEx` and `GetSystemTimes` (delta differences between user, kernel, and idle ticks) without external process overhead or third-party wheels like `psutil`. On Linux, it reads `/proc/stat` and `/proc/meminfo` to guarantee complete compatibility.

### Pure-Python Zero-Dependency PDF Engine
Constructed a lightweight PDF compiler (`MinimalPDFWriter` in `utils/exporter.py`) utilizing basic PDF specification structures (objects list, font mappings, page catalog, streams, and page size parameters). It calculates byte offsets manually during streaming to compile the cross-reference (`xref`) and trailer pointers, keeping the application's dependencies zero.

### Bidirectional Real-Time Updates (WebSocket-over-Threads)
Designed WebSockets emission hooks (`socketio.emit`) that are imported from `backend.app_factory` and invoked within background UDP sender/receiver/monitoring threads. Thread-safety is achieved using threading locks for WebSocket connections, and socket timeouts prevent deadlocks.

### Step-by-Step Chronological Session Replay
Created replay controller endpoints (`/api/sessions/<session_id>/replay`) that query packets chronologically and model lifecycle timings. The frontend decodes these timings to drive a step-by-step pipeline SVG diagram, giving analysts visibility into transmission delays, decryption states, and threat rules.

## 2026-06-28 — Milestone 1 Decisions
- Chose `@dataclass` for config type safety and initialization logic.
- Implemented lazy singletons with cleanup methods for isolated testing.
- Configured SQLite with WAL (Write-Ahead Logging) mode to support concurrent reading and writing.
- Used 12-character hex UUID fragments for primary keys to support distributed generation.
- Configured Flask-SocketIO in `threading` mode to ensure cross-platform compatibility.

---

## 2026-06-28 — Milestone 2a Decisions (Cryptography)
- Consolidated encrypt/decrypt operations into a single `CryptoEngine` class to manage shared key state cleanly.
- Selected PBKDF2-HMAC-SHA256 with 600,000 iterations for OWASP compliance and zero extra native dependencies.
- Defined a stable, fixed wire format: `salt(16) ‖ nonce(12) ‖ ciphertext ‖ tag(16)` to enable position-stable protocol parsing.

---

## 2026-06-28 — Milestone 2b Decisions (NTP Protocol)
- Implemented two distinct covert channels: NTPv4 Extension Fields for large payloads and Timestamp Fractional Parts for small payloads.
- Added a custom 8-byte extension field header to track original length and prevent ciphertext corruption during alignment padding.

---

## 2026-06-28 — Milestone 3 Decisions (Networking)
- Used standard `threading.Thread` for the background UDP listener to prevent event-loop conflicts.
- Applied a 1.0s socket timeout to ensure clean and immediate shutdown of background listener loops.

---

## 2026-06-28 — Milestone 4 Decisions (Database & Analytics)
- Implemented the Manager Orchestration Pattern to isolate low-level networking from database writes.
- Leveraged implicit session initiation to automatically track sender and receiver session lifetimes.
- Created `AnalyticsEngine` to calculate performance metrics directly from SQLite database logs.

---

## 2026-06-29 — Milestone 5 Decisions (Threat Detection & Frontend)

### Pipeline-Based Threat Analysis
Implemented `ThreatDetector` to sequentially analyze each packet for 4 anomaly rules: covert extension detection, timing bursts, size anomalies, and protocol header checks. Rationale: this provides comprehensive security monitoring and ensures that if a packet triggers multiple rules, only the highest-severity threat is prioritized and persisted.

### Temporal Burst Detection
Used a sliding window of historical packet logs (source-host filtered) to calculate inter-arrival deltas. If 60% or more packets arrive below the timing threshold, it is classified as a timing burst anomaly.

### Single Page Application (SPA) UI
Built a custom, responsive, vanilla JavaScript SPA router using navigation links with `data-page` attributes. This avoids the overhead, complexity, and compilation steps of modern framework bundlers (like React or Vue), keeping the research platform lightweight and zero-dependency.

### Unified Dashboard REST Endpoint
Aggregated all count metrics, recent packets, recent threats, and runtime configuration into a single REST endpoint `/api/dashboard` to optimize initial page loading and minimize network requests.
