# NTP Secure Communication & Threat Analysis Platform (NTP-SCTAP)

> A professional real-time cybersecurity research platform for secure Network Time Protocol (NTP) communication, covert channel detection, packet inspection, cryptographic protection, and defensive network monitoring.

![Python](https://img.shields.io/badge/Python-3.12-3776AB?style=flat&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.1-000000?style=flat&logo=flask)
![Socket.IO](https://img.shields.io/badge/WebSocket-Socket.IO-black?style=flat)
![SQLite](https://img.shields.io/badge/Database-SQLite-blue?style=flat)
![AES-256-GCM](https://img.shields.io/badge/Crypto-AES--256--GCM-success?style=flat)
![License](https://img.shields.io/badge/License-MIT-green?style=flat)
![Version](https://img.shields.io/badge/Version-1.1.0-blue?style=flat)
![Status](https://img.shields.io/badge/Status-Stable-brightgreen?style=flat)

---

# Overview

NTP-SCTAP is a full-stack cybersecurity research platform that demonstrates how encrypted covert communication can be embedded inside Network Time Protocol (NTP) packets while simultaneously providing real-time monitoring, packet inspection, analytics, and threat detection.

The platform combines networking, cryptography, protocol engineering, packet analysis, defensive security techniques, and modern web technologies into a single interactive dashboard.

It is intended for:

- Cybersecurity Education
- Protocol Research
- Network Security Analysis
- Covert Channel Research
- Defensive Monitoring
- Secure Communication Demonstrations

---

# Key Features

## Secure Communication

- AES-256-GCM authenticated encryption
- Password-derived encryption keys
- Secure covert message transmission
- Automatic sender/receiver password synchronization
- Real-time encrypted message recovery

---

## NTP Protocol Engine

- Complete NTP packet generation
- NTP packet parser
- Extension Field support
- Secure covert payload embedding
- Packet serialization/deserialization
- Timestamp processing

---

## UDP Communication

- UDP Sender
- UDP Receiver
- Background receiver service
- Receiver lifecycle management
- Automatic receiver restart
- Multi-session communication

---

## Packet Inspection

Interactive packet inspection provides:

- NTP Header Fields
- Hex Dump
- Raw Packet View
- Extension Field Analysis
- Timeline Information
- Threat Association
- Message Association
- Packet Metadata
- Timestamp Breakdown

---

## Threat Detection Engine

Detects:

- Suspicious NTP Extension Fields
- Covert Channel Indicators
- Packet Validation Failures
- Security Anomalies
- Threat Severity Classification
- Confidence Scoring

---

## Analytics Dashboard

Real-time dashboard including:

- Live packet statistics
- Message statistics
- Active sessions
- Threat summaries
- Historical analytics
- Traffic monitoring
- System metrics
- Live Socket.IO updates

---

## Session Replay

Replay complete communication sessions including:

- Packet timeline
- Sender → Receiver flow
- Threat correlation
- Message recovery
- Communication history

---

## Export Center

Export data as:

- JSON
- CSV
- PDF

Supported domains:

- Packets
- Sessions
- Threats
- Analytics
- Configuration

---

## REST API

More than 20 REST endpoints including:

- Dashboard
- Health
- Status
- Configuration
- Messages
- Packets
- Packet Inspection
- Sessions
- Session Replay
- Threats
- Threat Summary
- Analytics
- Analytics History
- Receiver Control
- Receiver Status
- System Monitoring
- Export

---

# Technology Stack

## Backend

- Python 3.12
- Flask
- Flask-SocketIO
- Eventlet

## Frontend

- HTML5
- Vanilla JavaScript
- CSS3
- Chart.js
- Socket.IO Client

## Networking

- UDP Sockets
- Python socket
- struct

## Database

- SQLite
- WAL Mode
- Indexed Tables

## Cryptography

- cryptography
- AES-256-GCM
- Secure Random Nonces

## Testing

- pytest

---

# Architecture

```
                Web Dashboard
                     │
             Flask + SocketIO
                     │
      ┌──────────────┼──────────────┐
      │              │              │
 Dashboard      Analytics      Database
      │              │              │
      └──────────────┼──────────────┘
                     │
          Sender Manager
                     │
              Crypto Engine
                     │
             AES-256-GCM
                     │
             NTP Packet Builder
                     │
             UDP Transmission
                     │
═════════════════════════════════════
             Network
═════════════════════════════════════
                     │
              UDP Receiver
                     │
           NTP Packet Parser
                     │
          Threat Detection
                     │
          Crypto Decryption
                     │
          Dashboard Updates
```

---

# Project Structure

```
NTP-SCTAP/

backend/
frontend/
analytics/
config/
crypto/
dashboard/
database/
detector/
network/
protocol/
receiver/
sender/
tests/
utils/
docs/

run.py
app.py
requirements.txt
README.md
```

---

# Implemented Modules

| Module | Status |
|---------|--------|
| Configuration System | ✅ |
| Logging Framework | ✅ |
| Flask Application | ✅ |
| Socket.IO | ✅ |
| SQLite Database | ✅ |
| Analytics Engine | ✅ |
| Threat Detection | ✅ |
| Dashboard Manager | ✅ |
| Sender Manager | ✅ |
| Receiver Manager | ✅ |
| Crypto Engine | ✅ |
| UDP Sender | ✅ |
| UDP Receiver | ✅ |
| NTP Protocol Engine | ✅ |
| Packet Inspection | ✅ |
| Session Replay | ✅ |
| Export Engine | ✅ |
| REST API | ✅ |

---

# Current Capabilities

✔ Secure encrypted communication

✔ Real-time message recovery

✔ Live dashboard

✔ Packet monitoring

✔ Packet inspection

✔ Threat detection

✔ Session replay

✔ Analytics

✔ Historical metrics

✔ Receiver control

✔ System monitoring

✔ Export center

✔ WebSocket live updates

✔ Password synchronization

✔ JSON-safe packet inspection

✔ Defensive protocol analysis

---

# Installation

```bash
git clone https://github.com/yourusername/NTP-SCTAP.git

cd NTP-SCTAP

python -m venv venv

# Windows
venv\Scripts\activate

# Linux
source venv/bin/activate

pip install -r requirements.txt
```

---

# Run

```bash
python run.py
```

Open:

```
http://127.0.0.1:5000
```

---

# Testing

```bash
pytest -v
```

---

# Future Roadmap

- Interactive network topology visualization
- Animated packet flow
- Packet timeline playback
- Advanced anomaly detection
- Multi-user authentication
- PostgreSQL support
- Docker deployment
- Kubernetes deployment
- SIEM integration
- PCAP import/export
- Live Wireshark integration

---

# Educational Disclaimer

This project is intended solely for:

- Cybersecurity education
- Network protocol research
- Defensive security demonstrations
- Secure communication experiments
- Academic learning

It is **not intended** for unauthorized access, malicious activity, or offensive operations.

---

# License

MIT License