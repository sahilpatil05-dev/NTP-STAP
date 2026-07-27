"""
NTP-SCTAP Flask Application Factory.

Creates and configures the Flask application instance using the
factory pattern. This ensures the app can be created multiple times
with different configurations (production, testing, etc.) without
global state leaking between instances.

Usage:
    from backend.app_factory import create_app
    app, socketio = create_app()
    socketio.run(app)
"""

from flask import Flask
from flask_socketio import SocketIO

from config.settings import get_config, Config
from database.manager import get_db
from utils.logger import get_logger
from analytics.engine import AnalyticsEngine

logger = get_logger("backend.app_factory")

# SocketIO instance — created once, attached to the app in create_app().
socketio = SocketIO()


def create_app(config: Config | None = None) -> tuple[Flask, SocketIO]:
    """Build and return a fully configured ``(Flask, SocketIO)`` pair.

    Args:
        config: Optional Config override. If *None*, the global
                singleton from ``get_config()`` is used.

    Returns:
        A tuple of ``(app, socketio)`` ready to serve.
    """
    cfg = config or get_config()

    app = Flask(
        __name__,
        static_folder=str(cfg.STATIC_DIR),
        template_folder=str(cfg.TEMPLATE_DIR),
    )

    # Flask config
    app.config["SECRET_KEY"] = cfg.SECRET_KEY
    app.config["DEBUG"] = cfg.DEBUG

    # Store our Config on the app for easy access in routes
    app.config["SCTAP"] = cfg

    # Initialize database
    db = get_db()
    db.initialize()

    # Register blueprints / routes
    from backend.routes import register_routes
    register_routes(app)

    # Initialize SocketIO
    socketio.init_app(app, cors_allowed_origins=cfg.CORS_ORIGIN, async_mode="threading")

    # Connect SocketIO events and start system monitoring
    from dashboard.manager import get_dashboard_manager
    import time

    mgr = get_dashboard_manager()

    @socketio.on("connect")
    def handle_connect() -> None:
        mgr.register_client()
        socketio.emit("system_monitoring", mgr.get_metrics())

    @socketio.on("disconnect")
    def handle_disconnect() -> None:
        mgr.unregister_client()

    # Start system monitoring thread and push updates via socketio
    if not mgr.is_monitoring_running():
        mgr.start_monitoring(emit_callback=lambda data: socketio.emit("system_monitoring", data))

    # Real-time decryption message recovery callback
    def on_message_recovered(plaintext: str, session_id: str) -> None:
        socketio.emit("message_activity", {
            "plaintext": plaintext,
            "session_id": session_id,
            "direction": "received",
            "status": "decrypted",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        })
        try:
            ae = AnalyticsEngine()
            metrics = ae.calculate_metrics()
            socketio.emit("analytics_activity", metrics)
        except Exception as ae_err:
            logger.error("Failed to run real-time analytics: %s", ae_err)

    # Automatically start background UDP receiver on boot (skip in TESTING mode)
    if not app.config.get("TESTING", False):
        if not mgr.is_receiver_running():
            mgr.start_receiver(password=mgr.current_password, message_callback=on_message_recovered)

    logger.info(
        "Application created: %s v%s [debug=%s]",
        cfg.APP_NAME,
        cfg.APP_VERSION,
        cfg.DEBUG,
    )

    return app, socketio