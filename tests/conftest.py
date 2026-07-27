"""
Pytest fixtures shared across all NTP-SCTAP test modules.

Provides:
  - A fresh Config instance per test (no cross-test leakage).
  - An in-memory DatabaseManager for fast, isolated DB tests.
  - A Flask test client backed by the full app factory.
"""

import os
import tempfile
from pathlib import Path

import pytest

from config.settings import Config, reset_config
from database.manager import DatabaseManager, reset_db
from utils.logger import reset_logger


@pytest.fixture(autouse=True)
def _clean_singletons():
    """Reset module-level singletons before each test and isolate config/db."""
    import tempfile
    from pathlib import Path
    from config.settings import get_config
    
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        reset_config()
        # Initialize config singleton with isolated paths
        get_config(
            DEBUG=True,
            DATABASE_PATH=tmp_path / "test.db",
            LOG_FILE=tmp_path / "test.log"
        )
        reset_db()
        reset_logger()
        yield
        reset_config()
        reset_db()
        reset_logger()


@pytest.fixture()
def config(tmp_path: Path) -> Config:
    """Return a Config pointing at temp directories."""
    return Config(
        DEBUG=True,
        DATABASE_PATH=tmp_path / "test.db",
        LOG_FILE=tmp_path / "test.log",
    )


@pytest.fixture()
def db(config: Config) -> DatabaseManager:
    """Return an initialized DatabaseManager backed by a temp file."""
    from database.manager import get_db
    manager = get_db(config.DATABASE_PATH)
    manager.initialize()
    yield manager
    manager.close()
    reset_db()


@pytest.fixture()
def client(config: Config):
    """Return a Flask test client."""
    import os
    os.environ["SCTAP_DEBUG"] = "true"
    os.environ["SCTAP_TESTING"] = "true"

    from backend.app_factory import create_app

    app, _ = create_app(config)
    app.config["TESTING"] = True

    with app.test_client() as c:
        yield c

