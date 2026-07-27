"""
NTP-SCTAP Database Manager.

Thread-safe SQLite connection manager with:
  - Schema initialization and migration support
  - Generic CRUD helpers (insert, query, update, delete)
  - Context-manager for transactions
  - Connection pooling via ``check_same_thread=False``

Usage:
    from database.manager import get_db
    db = get_db()
    db.initialize()
    rows = db.query("SELECT * FROM packets WHERE direction = ?", ("sent",))
"""

import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional, Tuple

from config.settings import get_config
from utils.logger import get_logger
from utils.helpers import generate_id, iso_timestamp

from database.models import ALL_TABLES, CREATE_INDEXES

logger = get_logger("database.manager")


class DatabaseManager:
    """Manages a single SQLite database file.

    The manager is thread-safe: it holds one persistent connection with
    ``check_same_thread=False`` and serialises write access with a
    ``threading.Lock``.
    """

    def __init__(self, db_path: Optional[Path] = None) -> None:
        cfg = get_config()
        self._db_path: Path = db_path or cfg.DATABASE_PATH
        self._conn: Optional[sqlite3.Connection] = None
        self._lock = threading.Lock()
        self._initialized = False

    # ── Connection lifecycle ─────────────────────────────────────────

    def connect(self) -> sqlite3.Connection:
        """Open (or return the existing) database connection."""
        if self._conn is None:
            self._db_path.parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(
                str(self._db_path),
                check_same_thread=False,
                detect_types=sqlite3.PARSE_DECLTYPES,
            )
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL;")
            self._conn.execute("PRAGMA foreign_keys=ON;")
            logger.info("Database connected: %s", self._db_path)
        return self._conn

    def close(self) -> None:
        """Close the database connection cleanly."""
        if self._conn is not None:
            self._conn.close()
            self._conn = None
            self._initialized = False
            logger.info("Database connection closed")

    # ── Schema management ────────────────────────────────────────────

    def initialize(self) -> None:
        """Create all tables and indexes if they don't exist."""
        if self._initialized:
            return

        conn = self.connect()
        with self._lock:
            cursor = conn.cursor()
            for ddl in ALL_TABLES:
                cursor.execute(ddl)
            for idx in CREATE_INDEXES:
                cursor.execute(idx)
            conn.commit()

        self._initialized = True
        table_count = len(ALL_TABLES)
        index_count = len(CREATE_INDEXES)
        logger.info(
            "Database initialized: %d tables, %d indexes",
            table_count,
            index_count,
        )

    # ── Transaction context manager ──────────────────────────────────

    @contextmanager
    def transaction(self) -> Generator[sqlite3.Cursor, None, None]:
        """Yield a cursor inside a locked transaction.

        Commits on success, rolls back on exception.
        """
        conn = self.connect()
        with self._lock:
            cursor = conn.cursor()
            try:
                yield cursor
                conn.commit()
            except Exception:
                conn.rollback()
                raise

    # ── Generic CRUD ─────────────────────────────────────────────────

    def execute(
        self, sql: str, params: Tuple = ()
    ) -> sqlite3.Cursor:
        """Execute a single SQL statement under a lock."""
        conn = self.connect()
        with self._lock:
            cursor = conn.cursor()
            cursor.execute(sql, params)
            conn.commit()
            return cursor

    def query(
        self, sql: str, params: Tuple = ()
    ) -> List[Dict[str, Any]]:
        """Run a SELECT and return results as a list of dicts."""
        conn = self.connect()
        cursor = conn.cursor()
        cursor.execute(sql, params)
        columns = [desc[0] for desc in cursor.description] if cursor.description else []
        return [dict(zip(columns, row)) for row in cursor.fetchall()]

    def query_one(
        self, sql: str, params: Tuple = ()
    ) -> Optional[Dict[str, Any]]:
        """Run a SELECT expecting at most one row."""
        rows = self.query(sql, params)
        return rows[0] if rows else None

    def insert(self, table: str, data: Dict[str, Any]) -> str:
        """Insert a row into *table* from a dict.

        Automatically adds ``id`` and timestamp fields if missing.

        Returns:
            The ``id`` of the inserted row.
        """
        if "id" not in data:
            data["id"] = generate_id()

        timestamp_field = self._timestamp_field(table)
        if timestamp_field and timestamp_field not in data:
            data[timestamp_field] = iso_timestamp()

        columns = ", ".join(data.keys())
        placeholders = ", ".join("?" for _ in data)
        sql = f"INSERT INTO {table} ({columns}) VALUES ({placeholders})"

        self.execute(sql, tuple(data.values()))
        logger.debug("Inserted into %s: id=%s", table, data["id"])
        return data["id"]

    def update(
        self,
        table: str,
        row_id: str,
        data: Dict[str, Any],
    ) -> int:
        """Update a row by its primary key.

        Returns:
            Number of rows affected (0 or 1).
        """
        set_clause = ", ".join(f"{k} = ?" for k in data)
        sql = f"UPDATE {table} SET {set_clause} WHERE id = ?"
        cursor = self.execute(sql, (*data.values(), row_id))
        return cursor.rowcount

    def delete(self, table: str, row_id: str) -> int:
        """Delete a row by its primary key.

        Returns:
            Number of rows affected (0 or 1).
        """
        sql = f"DELETE FROM {table} WHERE id = ?"
        cursor = self.execute(sql, (row_id,))
        return cursor.rowcount

    def count(self, table: str, where: str = "", params: Tuple = ()) -> int:
        """Return the row count for a table with an optional WHERE clause."""
        sql = f"SELECT COUNT(*) as cnt FROM {table}"
        if where:
            sql += f" WHERE {where}"
        row = self.query_one(sql, params)
        return row["cnt"] if row else 0

    # ── Introspection ────────────────────────────────────────────────

    def table_exists(self, table_name: str) -> bool:
        """Check whether a table exists in the database."""
        row = self.query_one(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
            (table_name,),
        )
        return row is not None

    def get_table_names(self) -> List[str]:
        """Return a list of all user-created table names."""
        rows = self.query(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name NOT LIKE 'sqlite_%' ORDER BY name"
        )
        return [r["name"] for r in rows]

    def get_stats(self) -> Dict[str, Any]:
        """Return a summary of database state for the status endpoint."""
        tables = self.get_table_names()
        counts = {t: self.count(t) for t in tables}
        return {
            "path": str(self._db_path),
            "tables": len(tables),
            "table_counts": counts,
            "size_bytes": self._db_path.stat().st_size if self._db_path.exists() else 0,
            "initialized": self._initialized,
        }

    # ── Internal helpers ─────────────────────────────────────────────

    @staticmethod
    def _timestamp_field(table: str) -> Optional[str]:
        """Return the name of the auto-populated timestamp column."""
        mapping = {
            "packets": "created_at",
            "messages": "created_at",
            "sessions": "started_at",
            "threats": "detected_at",
            "analytics": "recorded_at",
            "events": "created_at",
            "errors": "created_at",
            "system_logs": "created_at",
            "configuration": "updated_at",
        }
        return mapping.get(table)


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------
_db_instance: Optional[DatabaseManager] = None
_db_lock = threading.Lock()


def get_db(db_path: Optional[Path] = None) -> DatabaseManager:
    """Return the application-wide DatabaseManager singleton."""
    global _db_instance
    with _db_lock:
        if _db_instance is None:
            _db_instance = DatabaseManager(db_path)
        return _db_instance


def reset_db() -> None:
    """Close and discard the singleton — used exclusively by tests."""
    global _db_instance
    with _db_lock:
        if _db_instance is not None:
            _db_instance.close()
            _db_instance = None
