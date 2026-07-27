"""
NTP-SCTAP Centralized Configuration.

All application settings are defined here. Settings are resolved in order:
  1. Environment variables (highest priority)
  2. Explicit overrides passed to Config()
  3. Default values defined below

This module is imported early, before any other module, so it must have
zero internal-project dependencies.
"""

import os
import secrets
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# Path constants (resolved once at import time)
# ---------------------------------------------------------------------------
BASE_DIR: Path = Path(__file__).resolve().parent.parent
DATABASE_DIR: Path = BASE_DIR / "data"
LOG_DIR: Path = BASE_DIR / "logs"
STATIC_DIR: Path = BASE_DIR / "frontend" / "static"
TEMPLATE_DIR: Path = BASE_DIR / "frontend" / "templates"


# ✅ IMPROVEMENT 2: Valid log levels
VALID_LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}


def _env(key: str, default: str) -> str:
    """Read an environment variable with a fallback default."""
    return os.environ.get(key, default)


def _env_bool(key: str, default: bool) -> bool:
    """Read a boolean environment variable."""
    return os.environ.get(key, str(default)).lower() in ("true", "1", "yes")


def _env_int(key: str, default: int) -> int:
    """Read an integer environment variable."""
    try:
        return int(os.environ.get(key, str(default)))
    except (ValueError, TypeError):
        return default


@dataclass(frozen=True)  # ✅ IMPROVEMENT 3: Freeze configuration to prevent accidental mutations
class Config:
    """Immutable application configuration container.

    After construction the object is fully populated with validated
    settings that every other module in the project can rely on.
    """

    # ── Application ──────────────────────────────────────────────────
    APP_NAME: str = "NTP-SCTAP"
    APP_VERSION: str = "1.0.0"
    APP_DESCRIPTION: str = (
        "NTP Secure Communication & Threat Analysis Platform"
    )
    DEBUG: bool = field(default_factory=lambda: _env_bool("SCTAP_DEBUG", False))
    SECRET_KEY: str = field(
        default_factory=lambda: _env("SCTAP_SECRET_KEY", secrets.token_hex(32))
    )

    # ── Server ───────────────────────────────────────────────────────
    HOST: str = field(default_factory=lambda: _env("SCTAP_HOST", "127.0.0.1"))
    PORT: int = field(default_factory=lambda: _env_int("SCTAP_PORT", 5000))
    # ✅ BUG-031 FIX: Socket.IO / CORS origin (configurable, defaults to wildcard for dev)
    CORS_ORIGIN: str = field(
        default_factory=lambda: _env("SCTAP_CORS_ORIGIN", "*")
    )

    # ── Database ─────────────────────────────────────────────────────
    DATABASE_PATH: Path = field(
        default_factory=lambda: Path(
            _env("SCTAP_DB_PATH", str(DATABASE_DIR / "ntp_sctap.db"))
        )
    )

    # ── Logging ──────────────────────────────────────────────────────
    LOG_LEVEL: str = field(
        default_factory=lambda: _env("SCTAP_LOG_LEVEL", "INFO")
    )
    LOG_FILE: Path = field(
        default_factory=lambda: Path(
            _env("SCTAP_LOG_FILE", str(LOG_DIR / "sctap.log"))
        )
    )
    LOG_MAX_BYTES: int = 5 * 1024 * 1024  # 5 MB
    LOG_BACKUP_COUNT: int = 5

    # ── Network ──────────────────────────────────────────────────────
    NTP_SEND_PORT: int = field(
        default_factory=lambda: _env_int("SCTAP_NTP_SEND_PORT", 9123)
    )
    NTP_LISTEN_PORT: int = field(
        default_factory=lambda: _env_int("SCTAP_NTP_LISTEN_PORT", 9124)
    )
    NTP_TARGET_HOST: str = field(
        default_factory=lambda: _env("SCTAP_NTP_TARGET", "127.0.0.1")
    )
    UDP_BUFFER_SIZE: int = 1024

    # ── Crypto ───────────────────────────────────────────────────────
    CRYPTO_ALGORITHM: str = "AES-256-GCM"
    CRYPTO_KEY_LENGTH: int = 32  # bytes
    CRYPTO_NONCE_LENGTH: int = 12  # bytes
    CRYPTO_TAG_LENGTH: int = 16  # bytes

    # ── Threat Detection ─────────────────────────────────────────────
    THREAT_TIMING_THRESHOLD_MS: float = 50.0
    THREAT_PATTERN_WINDOW: int = 20
    THREAT_MIN_CONFIDENCE: float = 0.4

    # ── Analytics ────────────────────────────────────────────────────
    ANALYTICS_FLUSH_INTERVAL: int = 10  # seconds
    METRICS_HISTORY_LIMIT: int = 1000

    # ── Paths (derived) ──────────────────────────────────────────────
    BASE_DIR: Path = field(default_factory=lambda: BASE_DIR)
    STATIC_DIR: Path = field(default_factory=lambda: STATIC_DIR)
    TEMPLATE_DIR: Path = field(default_factory=lambda: TEMPLATE_DIR)

    def __post_init__(self) -> None:
        """Ensure critical directories exist and validate configuration after construction."""
        # Create directories
        object.__setattr__(self, 'DATABASE_PATH', Path(self.DATABASE_PATH))
        object.__setattr__(self, 'LOG_FILE', Path(self.LOG_FILE))
        self.DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
        self.LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

        # ✅ IMPROVEMENT 1: Validate port ranges
        for port_name, port_value in [
            ("PORT", self.PORT),
            ("NTP_SEND_PORT", self.NTP_SEND_PORT),
            ("NTP_LISTEN_PORT", self.NTP_LISTEN_PORT),
        ]:
            if not (1 <= port_value <= 65535):
                raise ValueError(
                    f"{port_name} must be between 1 and 65535, got {port_value}"
                )

        # ✅ IMPROVEMENT 2: Validate log level
        if self.LOG_LEVEL.upper() not in VALID_LOG_LEVELS:
            raise ValueError(
                f"LOG_LEVEL must be one of {VALID_LOG_LEVELS}, got {self.LOG_LEVEL}"
            )

    # ── Convenience ──────────────────────────────────────────────────
    @property
    def database_uri(self) -> str:
        """Return the SQLite URI used by the DB manager."""
        return f"sqlite:///{self.DATABASE_PATH}"

    def as_dict(self) -> dict:
        """Serialize config to a JSON-safe dict (excludes secrets)."""
        return {
            "app_name": self.APP_NAME,
            "app_version": self.APP_VERSION,
            "debug": self.DEBUG,
            "host": self.HOST,
            "port": self.PORT,
            "cors_origin": self.CORS_ORIGIN,  # ✅ Include in dict
            "database_path": str(self.DATABASE_PATH),
            "log_level": self.LOG_LEVEL,
            "ntp_send_port": self.NTP_SEND_PORT,
            "ntp_listen_port": self.NTP_LISTEN_PORT,
            "crypto_algorithm": self.CRYPTO_ALGORITHM,
        }


# ---------------------------------------------------------------------------
# Module-level singleton accessor
# ---------------------------------------------------------------------------
_config_instance: Optional[Config] = None


def get_config(**overrides) -> Config:
    """Return the application-wide Config singleton.

    On first call the instance is created and cached. Subsequent calls
    return the same instance. Pass keyword arguments to override defaults
    only on the *first* call.
    """
    global _config_instance
    if _config_instance is None:
        _config_instance = Config(**overrides)
    return _config_instance


def reset_config() -> None:
    """Reset the singleton — used exclusively by tests."""
    global _config_instance
    _config_instance = None