# NTP-SCTAP Architecture

System architecture, design patterns, and data flow documentation.  
Last updated: 2026-06-29 | Version: 0.5.0

---

## System Overview

NTP-SCTAP is composed of five major subsystems:

```
┌─────────────────────────────────────────────────────────────────┐
│                     Web Browser (Client)                         │
│  ┌──────┐ ┌──────┐ ┌───────┐ ┌──────┐ ┌───────┐ ┌──────────┐  │
│  │ Home │ │Sender│ │Receiver│ │Monitor│ │Threats│ │ Analytics│  │
│  └───┬──┘ └───┬──┘ └───┬───┘ └───┬──┘ └───┬───┘ └────┬─────┘  │
└──────┼────────┼────────┼────────┼────────┼──────────┼──────────┘
       │  HTTP/WebSocket (REST API polling / events)
┌──────▼────────▼────────▼────────▼────────▼──────────▼──────────┐
│                     Flask + SocketIO Backend                     │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────────┐  │
│  │  Routes  │ │  Sender  │ │ Receiver │ │ Threat Detector  │  │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────────┬─────────┘  │
└───────┼────────────┼────────────┼─────────────────┼────────────┘
        │            │            │                 │
┌───────▼────────────▼────────────▼─────────────────▼────────────┐
│                        Core Services                            │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────────┐  │
│  │  Crypto  │ │ Protocol │ │ Network  │ │    Analytics     │  │
│  └──────────┘ └──────────┘ └──────────┘ └──────────────────┘  │
└────────────────────────┬───────────────────────────────────────┘
                          │
┌────────────────────────▼───────────────────────────────────────┐
│                    SQLite Database (WAL)                        │
│  packets │ messages │ sessions │ threats │ analytics │ events  │
└────────────────────────────────────────────────────────────────┘
```

## Data Flow

```
User Message → Crypto (AES-256-GCM encrypt)
            → Protocol (pack into NTP packet)
            → Network (transmit via UDP)
            → Network (receive via UDP listener)
            → Protocol (unpack NTP packet)
            → Crypto (AES-256-GCM decrypt)
            → Display recovered message
            → Database (persist all records)
            → Detector (analyze packet and timing history for threats)
            → Analytics (update metrics)
            → Dashboard (refresh frontend via REST/WebSockets)
```

## Design Patterns

| Pattern | Usage |
|---|---|
| Application Factory | `create_app()` in `backend/app_factory.py` |
| Singleton | Config, DatabaseManager, Logger |
| Repository | DatabaseManager CRUD methods |
| Observer | SocketIO event emission for real-time updates |
| Pipeline / Rules | ThreatDetector engine analysis pipeline |

## Module Dependency Graph

```
config ← utils ← database ← backend ← app
                           ← crypto
                           ← protocol ← network
                           ← sender (crypto + protocol + network)
                           ← receiver (protocol + network)
                           ← detector (database + protocol)
                           ← analytics (database)
```

Key rule: `config` and `utils` have **zero** internal dependencies. All other modules can import from them freely without circular import risk.
