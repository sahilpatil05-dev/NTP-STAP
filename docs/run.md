# NTP-SCTAP Run Guide

How to start, stop, and manage the application.  
Last updated: 2026-06-29 | Version: 0.5.0

---

## Starting the Server

```bash
# Activate virtual environment first
python run.py
```

The server starts at `http://127.0.0.1:5000` by default.

### Debug Mode

```bash
# Windows PowerShell
$env:SCTAP_DEBUG = "true"
python run.py

# Linux / macOS
SCTAP_DEBUG=true python run.py
```

### Custom Port

```bash
$env:SCTAP_PORT = "8080"
python run.py
```

---

## Running Tests

```bash
# All tests
pytest -v

# Specific module
pytest tests/test_config.py -v

# With coverage
pytest --cov=. --cov-report=term-missing
```

---

## Stopping the Server

```
Press Ctrl+C in the terminal.
```

---

## Database

The SQLite database is created automatically on first run at `data/ntp_sctap.db`. To reset:

```bash
# Delete the database file
del data\ntp_sctap.db    # Windows
rm data/ntp_sctap.db     # Linux/macOS
```

The schema will be recreated on next startup.
