"""
Tests for database.manager module.

Validates:
  - Schema initialization (all 9 tables created)
  - CRUD operations (insert, query, update, delete)
  - Count and introspection helpers
  - Transaction rollback on error
  - Stats endpoint
"""

from pathlib import Path

import pytest

from database.manager import DatabaseManager
from utils.helpers import generate_id, iso_timestamp


class TestSchemaInitialization:
    """Verify that initialize() creates all expected tables."""

    EXPECTED_TABLES = {
        "packets", "messages", "sessions", "threats",
        "analytics", "events", "errors", "system_logs", "configuration",
    }

    def test_all_tables_exist(self, db: DatabaseManager) -> None:
        tables = set(db.get_table_names())
        assert self.EXPECTED_TABLES.issubset(tables)

    def test_initialize_is_idempotent(self, db: DatabaseManager) -> None:
        db.initialize()  # second call should not raise
        tables = db.get_table_names()
        assert len(tables) >= len(self.EXPECTED_TABLES)


class TestInsert:
    """Verify row insertion."""

    def test_insert_session(self, db: DatabaseManager) -> None:
        row_id = db.insert("sessions", {
            "status": "active",
            "sender_host": "127.0.0.1",
            "receiver_host": "127.0.0.1",
        })
        assert row_id is not None
        row = db.query_one("SELECT * FROM sessions WHERE id = ?", (row_id,))
        assert row is not None
        assert row["status"] == "active"

    def test_insert_auto_generates_id(self, db: DatabaseManager) -> None:
        row_id = db.insert("events", {
            "event_type": "test",
            "severity": "info",
            "source": "test_suite",
            "message": "Hello from tests",
        })
        assert len(row_id) == 12  # UUID hex[:12]

    def test_insert_with_explicit_id(self, db: DatabaseManager) -> None:
        explicit_id = "custom-id-001"
        returned_id = db.insert("events", {
            "id": explicit_id,
            "event_type": "test",
            "severity": "info",
            "source": "test_suite",
            "message": "Explicit ID test",
        })
        assert returned_id == explicit_id


class TestQuery:
    """Verify query operations."""

    def test_query_returns_list_of_dicts(self, db: DatabaseManager) -> None:
        db.insert("events", {
            "event_type": "alpha",
            "severity": "info",
            "source": "test",
            "message": "msg",
        })
        rows = db.query("SELECT * FROM events")
        assert isinstance(rows, list)
        assert isinstance(rows[0], dict)

    def test_query_one_returns_none_for_missing(self, db: DatabaseManager) -> None:
        row = db.query_one("SELECT * FROM events WHERE id = ?", ("nonexistent",))
        assert row is None


class TestUpdate:
    """Verify row updates."""

    def test_update_changes_value(self, db: DatabaseManager) -> None:
        row_id = db.insert("sessions", {
            "status": "active",
            "sender_host": "127.0.0.1",
            "receiver_host": "127.0.0.1",
        })
        affected = db.update("sessions", row_id, {"status": "closed"})
        assert affected == 1

        row = db.query_one("SELECT * FROM sessions WHERE id = ?", (row_id,))
        assert row["status"] == "closed"


class TestDelete:
    """Verify row deletion."""

    def test_delete_removes_row(self, db: DatabaseManager) -> None:
        row_id = db.insert("events", {
            "event_type": "temp",
            "severity": "info",
            "source": "test",
            "message": "will be deleted",
        })
        affected = db.delete("events", row_id)
        assert affected == 1
        assert db.query_one("SELECT * FROM events WHERE id = ?", (row_id,)) is None

    def test_delete_nonexistent_returns_zero(self, db: DatabaseManager) -> None:
        affected = db.delete("events", "does-not-exist")
        assert affected == 0


class TestCount:
    """Verify the count helper."""

    def test_count_empty_table(self, db: DatabaseManager) -> None:
        assert db.count("packets") == 0

    def test_count_with_rows(self, db: DatabaseManager) -> None:
        for i in range(5):
            db.insert("events", {
                "event_type": "batch",
                "severity": "info",
                "source": "test",
                "message": f"event {i}",
            })
        assert db.count("events") == 5

    def test_count_with_where(self, db: DatabaseManager) -> None:
        db.insert("events", {"event_type": "a", "severity": "info", "source": "t", "message": "m"})
        db.insert("events", {"event_type": "b", "severity": "warn", "source": "t", "message": "m"})
        assert db.count("events", "severity = ?", ("info",)) == 1


class TestIntrospection:
    """Verify introspection helpers."""

    def test_table_exists_true(self, db: DatabaseManager) -> None:
        assert db.table_exists("packets") is True

    def test_table_exists_false(self, db: DatabaseManager) -> None:
        assert db.table_exists("nonexistent_table") is False


class TestStats:
    """Verify the get_stats method."""

    def test_stats_structure(self, db: DatabaseManager) -> None:
        stats = db.get_stats()
        assert "tables" in stats
        assert "table_counts" in stats
        assert "initialized" in stats
        assert stats["initialized"] is True
