# NTP-SCTAP Known Limitations

Current constraints and planned improvements.  
Last updated: 2026-06-29 | Version: 0.5.0

---

## Current Limitations

1. **No Authentication** — Single-user research tool, no login system or role-based access control.
2. **Localhost Bindings by Default** — Default configuration is restricted to loopback address (`127.0.0.1`) to ensure security during testing.
3. **Threading Mode** — SocketIO uses the standard library `threading` async mode instead of production-grade event loops (e.g. `eventlet` or `gevent`).
4. **SQLite Storage** — Single-file database. Suitable for research and development but not recommended for high-concurrency multi-server nodes.
5. **No HTTPS / TLS** — The built-in Flask development server runs on HTTP only. Reverse proxy (e.g. Nginx) is required for production TLS termination.
6. **Stateless Threat Detection** — The Threat Detection Engine executes sliding window calculations on local database records; it does not currently use active network tap streaming (e.g. eBPF or libpcap integration).
