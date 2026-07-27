"""
NTP-SCTAP Backend Module.

Contains the Flask application factory, route definitions,
and WebSocket event handlers.
"""

from backend.app_factory import create_app

__all__ = ["create_app"]
