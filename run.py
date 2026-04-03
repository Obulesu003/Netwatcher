#!/usr/bin/env python3
"""Main entry point for Netwatcher"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.dashboard.app import create_app
from src.utils.config import get_config
from src.utils.logger import setup_logger

logger = setup_logger("netwatcher")


def main():
    """Run the Netwatcher application"""
    config = get_config("config.yaml")
    
    logger.info("Starting Netwatcher...")
    logger.info(f"Dashboard available at http://{config.dashboard.host}:{config.dashboard.port}")
    
    app, socketio = create_app("config.yaml")
    
    try:
        socketio.run(
            app,
            host=config.dashboard.host,
            port=config.dashboard.port,
            debug=False,
            use_reloader=False
        )
    except KeyboardInterrupt:
        logger.info("Shutting down Netwatcher...")
    except Exception as e:
        logger.error(f"Failed to start Netwatcher: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
