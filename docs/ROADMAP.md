# NTP-SCTAP Roadmap

Development milestones and timeline.  
Last updated: 2026-06-29 | Version: 0.5.0

---

## Milestone Overview

| # | Milestone | Description | Status |
|---|---|---|---|
| 1 | Project Initialization | Folder structure, config, DB, Flask skeleton, docs | ✅ Complete |
| 2 | Cryptography & Protocol | AES-256-GCM engine, NTP packet generation/parsing | ✅ Complete |
| 3 | Networking & Services | UDP sender/receiver, background listener thread | ✅ Complete |
| 4 | Database & Analytics | Persist all data, real-time metrics collection | ✅ Complete |
| 5 | Threat Detection | Anomaly analysis, confidence scoring, alerting | ✅ Complete |
| 6 | REST API & Core UI | Complete REST APIs, SPA frontend integration | ✅ Complete |
| 7 | WebSockets & Streaming | WebSocket events for live packet stream and alerts | 🔲 Next |
| 8 | Polish & Final Review | Testing, documentation sync, release | 🔲 Pending |

---

## Milestone Details

### Milestone 5: Threat Detection Engine
- Anomaly detection pipeline (covert extension, timing burst, protocol header, size anomaly)
- Confidence scoring and severity classification
- Threat event persistence to SQLite database

### Milestone 6: REST API & Core UI
- Developed 12+ HTTP endpoints representing all data domains
- Full SPA frontend utilizing Vanilla HTML/CSS/JS
- Chart.js dashboards for analytics and traffic trends
- Live data tables with filtering and status tags

### Milestone 7: WebSockets & Streaming
- WebSocket events for live packet stream, threat alerts, metrics
- Real-time page push notifications

### Milestone 8: Polish, Review & Final Documentation
- Full test coverage review (117+ tests)
- Performance profiling
- Release preparation
