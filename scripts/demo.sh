#!/usr/bin/env bash
# Quick demo: install deps, start the HTTP server, run a sample lookup, tear down.
#
# Requires: python >= 3.11, uv or pip, and a .env file with API keys
# (copy from .env.example first).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ ! -f .env ]]; then
  echo "error: .env not found. Copy .env.example to .env and fill in your API keys." >&2
  exit 1
fi

echo ">> installing package (editable, with dev extras)"
if command -v uv >/dev/null 2>&1; then
  uv pip install -e ".[dev]" --quiet
else
  python -m pip install -e ".[dev]" --quiet
fi

PORT="${HTTP_PORT:-8765}"
HOST="${HTTP_HOST:-127.0.0.1}"

echo ">> starting server on http://${HOST}:${PORT}"
python -m app --transport http --host "$HOST" --port "$PORT" &
SERVER_PID=$!
trap 'kill "$SERVER_PID" 2>/dev/null || true' EXIT

# Wait for the server to accept connections.
for _ in {1..30}; do
  if python -c "import socket,sys; s=socket.socket(); s.settimeout(0.5); \
       s.connect(('${HOST}', ${PORT})); s.close()" 2>/dev/null; then
    break
  fi
  sleep 0.2
done

echo ">> running sample lookup via client_example.py"
python scripts/client_example.py "${1:-8.8.8.8}"

echo ">> demo complete"
