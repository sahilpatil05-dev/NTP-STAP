"""
NTP-SCTAP Database Module.

Provides the SQLite schema, connection management, and high-level
database operations for persisting packets, sessions, threats,
analytics, and system events.
"""

from database.manager import DatabaseManager, get_db

__all__ = ["DatabaseManager", "get_db"]
