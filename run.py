"""
NTP-SCTAP Development Server Launcher.

Starts the Flask-SocketIO development server with settings from the
centralised configuration module.

Usage:
    python run.py
"""

from config.settings import get_config
from utils.logger import get_logger

logger = get_logger("run")


def main() -> None:
    """Start the development server."""
    cfg = get_config()

    logger.info("=" * 60)
    logger.info("  %s v%s", cfg.APP_NAME, cfg.APP_VERSION)
    logger.info("  %s", cfg.APP_DESCRIPTION)
    logger.info("  Server: http://%s:%d", cfg.HOST, cfg.PORT)
    logger.info("  Debug:  %s", cfg.DEBUG)
    logger.info("=" * 60)

    # Import app and socketio after config is ready
    from app import app, socketio

    try:
        socketio.run(
            app,
            host=cfg.HOST,
            port=cfg.PORT,
            debug=cfg.DEBUG,
            use_reloader=cfg.DEBUG,
            log_output=cfg.DEBUG,
        )
    except Exception:
        logger.exception("Failed to start development server.")
        raise


if __name__ == "__main__":
    main()