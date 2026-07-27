"""
NTP-SCTAP Structured Logging.

Provides a pre-configured logger factory that writes structured output to
both the console (coloured, human-readable) and a rotating log file.

Usage:
    from utils.logger import get_logger
    logger = get_logger(__name__)
    logger.info("Packet transmitted", extra={"packet_id": "abc123"})
"""

import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional


# Colour codes for console output (ANSI)
_COLOURS = {
    "DEBUG": "\033[36m",     # Cyan
    "INFO": "\033[32m",      # Green
    "WARNING": "\033[33m",   # Yellow
    "ERROR": "\033[31m",     # Red
    "CRITICAL": "\033[35m",  # Magenta
    "RESET": "\033[0m",
}


class _ColouredFormatter(logging.Formatter):
    """Console formatter that applies ANSI colours based on log level."""

    FMT = "%(asctime)s │ %(levelname)-8s │ %(name)-28s │ %(message)s"
    DATE_FMT = "%Y-%m-%d %H:%M:%S"

    def __init__(self):
        super().__init__(self.FMT, datefmt=self.DATE_FMT)

    def format(self, record: logging.LogRecord) -> str:
        original = record.levelname
        try:
            colour = _COLOURS.get(original, "")
            record.levelname = f"{colour}{original}{_COLOURS['RESET']}"
            return super().format(record)
        finally:
            record.levelname = original


class _FileFormatter(logging.Formatter):
    """Plain-text formatter for the rotating log file."""

    FMT = "%(asctime)s | %(levelname)-8s | %(name)-28s | %(message)s"
    DATE_FMT = "%Y-%m-%d %H:%M:%S"

    def __init__(self):
        super().__init__(self.FMT, datefmt=self.DATE_FMT)


# Track whether the root NTP-SCTAP handler hierarchy is initialised.
_root_configured: bool = False


def _configure_root(
    log_level: str = "INFO",
    log_file: Optional[Path] = None,
    max_bytes: int = 5 * 1024 * 1024,
    backup_count: int = 5,
) -> None:
    """Attach console and file handlers to the top-level `sctap` logger.

    Called lazily on the first ``get_logger()`` invocation. Subsequent
    calls are no-ops.
    """
    global _root_configured
    if _root_configured:
        return

    root = logging.getLogger("sctap")
    root.setLevel(getattr(logging, log_level.upper(), logging.INFO))
    root.propagate = False

    # Console handler
    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(_ColouredFormatter())
    root.addHandler(console)

    # Rotating file handler (if a path is provided)
    if log_file is not None:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = RotatingFileHandler(
            str(log_file),
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8",
        )
        file_handler.setFormatter(_FileFormatter())
        root.addHandler(file_handler)

    _root_configured = True


def get_logger(name: str) -> logging.Logger:
    """Return a child logger under the ``sctap`` namespace.

    On first call, the root ``sctap`` logger is configured using
    application settings. If ``config.settings`` is not yet importable
    (e.g. during very early bootstrap), sensible defaults are used.
    """
    if not _root_configured:
        try:
            from config.settings import get_config
            cfg = get_config()
            _configure_root(
                log_level=cfg.LOG_LEVEL,
                log_file=cfg.LOG_FILE,
                max_bytes=cfg.LOG_MAX_BYTES,
                backup_count=cfg.LOG_BACKUP_COUNT,
            )
        except Exception:
            _configure_root()  # safe fallback

    return logging.getLogger(f"sctap.{name}")


def reset_logger() -> None:
    """Tear down the root handler — used exclusively by tests."""
    global _root_configured
    root = logging.getLogger("sctap")
    for handler in root.handlers[:]:
        handler.close()
        root.removeHandler(handler)
    _root_configured = False