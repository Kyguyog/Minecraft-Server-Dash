#!/usr/bin/env sh
# Start the Server-Finder web UI inside its virtualenv.
#
# If the default port is already in use, picks the next free port instead of
# exiting. Override the starting port with PORT=xxxx.
set -e
cd "$(dirname "$0")"

VENV="venv"

if [ ! -x "$VENV/bin/python" ]; then
    echo "Creating virtualenv ($VENV)…"
    python3 -m venv "$VENV"
fi

START_PORT="${PORT:-8081}"

PORT="$("$VENV/bin/python" - "$START_PORT" <<'PY'
import socket, sys

start = int(sys.argv[1])
for p in range(start, start + 20):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("0.0.0.0", p))
        except OSError:
            continue
        print(p)
        break
else:
    sys.exit(1)
PY
)"

if [ "$PORT" != "$START_PORT" ]; then
    echo "Port $START_PORT is in use (is the webui already running?). Using $PORT instead."
fi

echo "Starting webui on http://localhost:$PORT"
export PORT
exec "$VENV/bin/python" webui.py "$@"