# NTP-SCTAP Setup Guide

Installation and environment setup instructions.  
Last updated: 2026-06-29 | Version: 0.5.0

---

## Prerequisites

- **Python 3.10+** — [Download](https://www.python.org/downloads/)
- **pip** — Included with Python
- **Git** — [Download](https://git-scm.com/downloads)

---

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/your-username/NTP-SCTAP.git
cd NTP-SCTAP
```

### 2. Create a Virtual Environment

```bash
python -m venv venv
```

### 3. Activate the Virtual Environment

**Windows (PowerShell):**
```powershell
.\venv\Scripts\Activate.ps1
```

**Windows (Command Prompt):**
```cmd
venv\Scripts\activate.bat
```

**Linux / macOS:**
```bash
source venv/bin/activate
```

### 4. Install Dependencies

```bash
pip install -r requirements.txt
```

---

## Environment Variables (Optional)

| Variable | Default | Description |
|---|---|---|
| `SCTAP_DEBUG` | `false` | Enable debug mode |
| `SCTAP_HOST` | `127.0.0.1` | Server bind address |
| `SCTAP_PORT` | `5000` | Server port |
| `SCTAP_DB_PATH` | `data/ntp_sctap.db` | Database file path |
| `SCTAP_LOG_LEVEL` | `INFO` | Log level (DEBUG, INFO, WARNING, ERROR) |
| `SCTAP_LOG_FILE` | `logs/sctap.log` | Log file path |
| `SCTAP_NTP_SEND_PORT` | `9123` | UDP send port |
| `SCTAP_NTP_LISTEN_PORT` | `9124` | UDP listen port |
| `SCTAP_NTP_TARGET` | `127.0.0.1` | Target host for NTP packets |
| `SCTAP_SECRET_KEY` | Auto-generated | Flask secret key |

---

## Verification

```bash
# Run the test suite
pytest -v

# Start the server
python run.py
```

Open `http://127.0.0.1:5000` in your browser.
