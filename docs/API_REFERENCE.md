# NTP-SCTAP API Reference

> REST API documentation for all HTTP endpoints.  
> Last updated: 2026-07-02 | Version: 1.0.0

---

## Base URL

```
http://127.0.0.1:5000
```

---

## System & Diagnostics Endpoints

### Health Check

```
GET /api/health
```

Lightweight liveness probe. Returns immediately.

**Response (200):**
```json
{
    "status": "healthy",
    "timestamp": "2026-06-29T11:30:00+00:00"
}
```

---

### System Status

```
GET /api/status
```

Comprehensive system status including application info, system details, database stats, network config, and crypto settings.

**Response (200):**
```json
{
    "application": {
        "name": "NTP-SCTAP",
        "version": "1.0.0",
        "debug": false,
        "uptime_check": "2026-06-29T11:30:00+00:00"
    },
    "system": {
        "python_version": "3.12.0 ...",
        "platform": "Windows-10-...",
        "architecture": "AMD64"
    },
    "database": {
        "path": "d:\\NTP-SCTAP\\data\\ntp_sctap.db",
        "tables": 9,
        "table_counts": { "packets": 42, "messages": 12 },
        "size_bytes": 12288,
        "initialized": true
    },
    "network": {
        "send_port": 9123,
        "listen_port": 9124,
        "target_host": "127.0.0.1"
    },
    "crypto": {
        "algorithm": "AES-256-GCM",
        "key_length_bits": 256
    }
}
```

---

### Configuration

```
GET /api/config
```

Returns non-secret configuration values. Secret key is excluded.

**Response (200):**
```json
{
    "app_name": "NTP-SCTAP",
    "app_version": "1.0.0",
    "debug": false,
    "host": "127.0.0.1",
    "port": 5000,
    "database_path": "...",
    "log_level": "INFO",
    "ntp_send_port": 9123,
    "ntp_listen_port": 9124,
    "crypto_algorithm": "AES-256-GCM"
}
```

---

## Core Data Endpoints

### Packets Monitor

```
GET /api/packets
```

Returns recent packet logs.

**Query Parameters:**
- `limit`: Max rows (default 50, max 500)
- `direction`: Filter by `'sent'` or `'received'`

**Response (200):**
```json
{
  "count": 1,
  "packets": [
    {
      "id": "abc123xyz789",
      "session_id": "sess999",
      "direction": "received",
      "source_host": "192.168.1.100",
      "source_port": 123,
      "dest_host": "127.0.0.1",
      "dest_port": 9124,
      "packet_size": 104,
      "payload_status": "present",
      "encryption_status": "decrypted",
      "validation": "valid",
      "created_at": "2026-06-29T11:30:15+00:00"
    }
  ]
}
```

---

### Covert Messages

```
GET /api/messages
```

Returns recent plaintext/ciphertext covert message history.

**Query Parameters:**
- `limit`: Max rows (default 50, max 500)
- `direction`: Filter by `'sent'` or `'received'`

**Response (200):**
```json
{
  "count": 1,
  "messages": [
    {
      "id": "msg444555",
      "session_id": "sess999",
      "packet_id": "abc123xyz789",
      "direction": "received",
      "plaintext": "Secret covert payload text",
      "status": "decrypted",
      "created_at": "2026-06-29T11:30:15+00:00"
    }
  ]
}
```

---

### Threat Alerts

```
GET /api/threats
```

Returns threat detection alerts.

**Query Parameters:**
- `limit`: Max rows (default 50, max 500)
- `severity`: Filter by `'info'`, `'warning'`, `'critical'`

**Response (200):**
```json
{
  "count": 1,
  "threats": [
    {
      "id": "threat999",
      "packet_id": "abc123xyz789",
      "session_id": "sess999",
      "threat_level": "critical",
      "confidence": 0.99,
      "alert_reason": "Secure covert extension field (type 0x7363) detected in NTP packet.",
      "severity": "critical",
      "recommendation": "Inspect session; covert channel active.",
      "detected_at": "2026-06-29T11:30:16+00:00"
    }
  ]
}
```

---

### Threats Summary

```
GET /api/threats/summary
```

Returns count of threats grouped by level.

**Response (200):**
```json
{
  "total": 5,
  "critical": 1,
  "high": 1,
  "medium": 2,
  "low": 1
}
```

---

### Dashboard Aggregate

```
GET /api/dashboard
```

Aggregated view for front-end rendering. Contains total stat counters, 10 recent packets, and 5 recent threats.

---

### Analytics Metrics

```
GET /api/analytics
```

Calculates and returns recent transmission statistics, success rates, and active session counts.

---

### Analytics History

```
GET /api/analytics/history
```

Returns time-series history for a given metric.

**Query Parameters:**
- `metric`: Metric name (e.g. `'packets_sent'`, `'packets_received'`)
- `limit`: Max snapshots (default 50)

---

### System Errors

```
GET /api/errors
```

Returns recent error stack logs.

---

## Error Responses

### 404 Not Found

For API paths (`/api/*`):
```json
{
    "error": "Not found",
    "path": "/api/nonexistent"
}
```

### 500 Internal Server Error

```json
{
    "error": "Internal server error"
}
```
