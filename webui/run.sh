#!/usr/bin/env bash
# Start the Find Evil! dashboard backend on the box (serves the React UI too).
cd "$(dirname "$0")/backend"
exec python3 -m uvicorn app:app --host 127.0.0.1 --port 8000
