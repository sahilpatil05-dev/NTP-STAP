"""
Tests for config.settings module.

Validates:
  - Default values are populated correctly
  - Environment variable overrides work
  - Directories are auto-created
  - Serialization to dict excludes secrets
  - Singleton behaviour (get_config / reset_config)
"""

import os
from pathlib import Path

import pytest

from config.settings import Config, get_config, reset_config


class TestConfigDefaults:
    """Verify default configuration values."""

    def test_app_name(self, config: Config) -> None:
        assert config.APP_NAME == "NTP-SCTAP"

    def test_app_version(self, config: Config) -> None:
        assert config.APP_VERSION == "1.0.0"

    def test_crypto_algorithm(self, config: Config) -> None:
        assert config.CRYPTO_ALGORITHM == "AES-256-GCM"

    def test_key_length(self, config: Config) -> None:
        assert config.CRYPTO_KEY_LENGTH == 32

    def test_nonce_length(self, config: Config) -> None:
        assert config.CRYPTO_NONCE_LENGTH == 12

    def test_debug_default_false(self, tmp_path: Path) -> None:
        os.environ.pop("SCTAP_DEBUG", None)
        cfg = Config(DATABASE_PATH=tmp_path / "t.db", LOG_FILE=tmp_path / "t.log")
        assert cfg.DEBUG is False


class TestConfigDirectories:
    """Verify directory auto-creation."""

    def test_database_dir_created(self, config: Config) -> None:
        assert config.DATABASE_PATH.parent.exists()

    def test_log_dir_created(self, config: Config) -> None:
        assert config.LOG_FILE.parent.exists()


class TestConfigSerialization:
    """Verify as_dict output."""

    def test_as_dict_has_required_keys(self, config: Config) -> None:
        d = config.as_dict()
        expected_keys = {
            "app_name", "app_version", "debug", "host", "port",
            "database_path", "log_level", "ntp_send_port",
            "ntp_listen_port", "crypto_algorithm",
        }
        assert expected_keys.issubset(d.keys())

    def test_as_dict_excludes_secret_key(self, config: Config) -> None:
        d = config.as_dict()
        assert "secret_key" not in d
        assert "SECRET_KEY" not in d


class TestConfigSingleton:
    """Verify singleton accessor."""

    def test_get_config_returns_same_instance(self) -> None:
        a = get_config()
        b = get_config()
        assert a is b

    def test_reset_config_creates_new_instance(self) -> None:
        a = get_config()
        reset_config()
        b = get_config()
        assert a is not b


class TestConfigDatabaseUri:
    """Verify the database_uri property."""

    def test_uri_format(self, config: Config) -> None:
        uri = config.database_uri
        assert uri.startswith("sqlite:///")
        assert "test.db" in uri
