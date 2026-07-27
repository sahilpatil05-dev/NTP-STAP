# NTP-SCTAP Testing Strategy

Test architecture, conventions, and coverage goals.  
Last updated: 2026-07-02 | Version: 1.0.0

---

## Framework

- **pytest** 9.0+ with `conftest.py` shared fixtures
- **pytest-cov** for coverage reporting

---

## Test Organization

```
tests/
├── __init__.py
├── conftest.py          # Shared fixtures (config, db, client)
├── test_config.py       # config.settings tests (8 tests) ✅
├── test_database.py     # database.manager tests (12 tests) ✅
├── test_app_factory.py  # backend routes/factory tests (13 tests) ✅
├── test_utils.py        # utils.helpers tests (15 tests) ✅
├── test_crypto.py       # crypto module tests (35 tests) ✅
├── test_protocol.py     # protocol tests (14 tests) ✅
├── test_network.py      # network tests (6 tests) ✅
├── test_sender.py       # sender tests (2 tests) ✅
├── test_receiver.py     # receiver tests (3 tests) ✅
├── test_analytics.py    # analytics tests (2 tests) ✅
├── test_detector.py     # threat detection tests (11 tests) ✅
├── test_dashboard.py    # dashboard state tests (5 tests) ✅
├── test_exporter.py     # data exporter tests (4 tests) ✅
└── test_integration.py  # integration tests (2 tests) ✅
```

---

## Fixtures

| Fixture | Scope | Description |
|---|---|---|
| `_clean_singletons` | function (autouse) | Resets and isolates Config, DB, Logger singletons |
| `config` | function | Fresh Config with temp directories |
| `db` | function | Initialized DatabaseManager (temp file) |
| `client` | function | Flask test client |

---

## Running Tests

```bash
# All tests with verbose output
pytest -v

# Single module
pytest tests/test_database.py -v

# With coverage report
pytest --cov=. --cov-report=term-missing

# Stop on first failure
pytest -x
```

---

## Coverage Goals

| Module | Target |
|---|---|
| `config` | 95% |
| `utils` | 95% |
| `database` | 90% |
| `backend` | 85% |
| `crypto` | 95% |
| `protocol` | 95% |
| `network` | 80% |
| `detector` | 90% |

---

## Current Status (Version 1.0.0 Release)

| Test File | Tests | Status |
|---|---|---|
| `test_config.py` | 8 | ✅ |
| `test_database.py` | 12 | ✅ |
| `test_app_factory.py` | 13 | ✅ |
| `test_utils.py` | 15 | ✅ |
| `test_crypto.py` | 35 | ✅ |
| `test_protocol.py` | 14 | ✅ |
| `test_network.py` | 6 | ✅ |
| `test_sender.py` | 2 | ✅ |
| `test_receiver.py` | 3 | ✅ |
| `test_analytics.py` | 2 | ✅ |
| `test_detector.py` | 11 | ✅ |
| `test_dashboard.py` | 5 | ✅ |
| `test_exporter.py` | 4 | ✅ |
| `test_integration.py` | 2 | ✅ |
| **Total** | **145** | |
