#!/bin/sh
# Local deploy, no install step: Python stdlib only.
# Usage: ./run.sh [port]
#   PORT=9000 ./run.sh
set -e
cd "$(dirname "$0")"
PORT="${PORT:-${1:-8080}}"
echo "Starting Agent Guard on http://127.0.0.1:$PORT"
echo "Try: curl http://127.0.0.1:$PORT/health"
PORT="$PORT" python3 -m agent_guard.server
