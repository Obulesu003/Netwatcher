#!/usr/bin/env python3
"""Run the Netwatcher dashboard"""

import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from src.dashboard.app import create_app

if __name__ == "__main__":
    app, socketio = create_app()
    print("\n" + "="*60)
    print("Netwatcher Dashboard")
    print("="*60)
    print("Dashboard running at: http://localhost:5000")
    print("Press Ctrl+C to stop\n")
    socketio.run(app, host='0.0.0.0', port=5000, debug=True, allow_unsafe_werkzeug=True)
