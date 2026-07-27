"""
NTP-SCTAP Application Entry Point.

This is the top-level module that creates the Flask application and
SocketIO instance. It is imported by ``run.py`` and can also be used
by WSGI servers (e.g. gunicorn) via ``app.app``.
"""

from backend.app_factory import create_app

app, socketio = create_app()
