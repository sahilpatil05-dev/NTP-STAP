"""
Tests for the Flask application factory and routes.

Validates:
  - App creation succeeds
  - Health endpoint returns 200
  - Status endpoint returns system information
  - Config endpoint returns non-secret data
  - Home page renders HTML
  - 404 returns JSON for API paths, HTML otherwise
"""

import json

import pytest


class TestHealthEndpoint:
    """Verify /api/health."""

    def test_returns_200(self, client) -> None:
        resp = client.get("/api/health")
        assert resp.status_code == 200

    def test_returns_healthy(self, client) -> None:
        data = json.loads(resp := client.get("/api/health").data)
        assert data["status"] == "healthy"

    def test_contains_timestamp(self, client) -> None:
        data = json.loads(client.get("/api/health").data)
        assert "timestamp" in data


class TestStatusEndpoint:
    """Verify /api/status."""

    def test_returns_200(self, client) -> None:
        resp = client.get("/api/status")
        assert resp.status_code == 200

    def test_contains_application_info(self, client) -> None:
        data = json.loads(client.get("/api/status").data)
        assert data["application"]["name"] == "NTP-SCTAP"
        assert "version" in data["application"]

    def test_contains_database_info(self, client) -> None:
        data = json.loads(client.get("/api/status").data)
        assert "database" in data
        assert "tables" in data["database"]

    def test_contains_crypto_info(self, client) -> None:
        data = json.loads(client.get("/api/status").data)
        assert data["crypto"]["algorithm"] == "AES-256-GCM"


class TestConfigEndpoint:
    """Verify /api/config."""

    def test_returns_200(self, client) -> None:
        resp = client.get("/api/config")
        assert resp.status_code == 200

    def test_excludes_secret_key(self, client) -> None:
        data = json.loads(client.get("/api/config").data)
        assert "secret_key" not in data
        assert "SECRET_KEY" not in data


class TestHomePage:
    """Verify / (home page)."""

    def test_returns_200(self, client) -> None:
        resp = client.get("/")
        assert resp.status_code == 200

    def test_returns_html(self, client) -> None:
        resp = client.get("/")
        assert b"NTP-SCTAP" in resp.data


class TestErrorHandlers:
    """Verify custom error handling."""

    def test_404_api_returns_json(self, client) -> None:
        resp = client.get("/api/nonexistent")
        assert resp.status_code == 404
        data = json.loads(resp.data)
        assert "error" in data

    def test_404_page_returns_html(self, client) -> None:
        resp = client.get("/nonexistent-page")
        # Should still return 404 but render the index template
        assert resp.status_code == 404
