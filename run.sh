#!/usr/bin/env sh
# Start the Minecraft Server Status dashboard.
#
# Uses a project-local virtualenv (.venv) so the optional `cryptography`
# dependency (needed to check online-mode servers) is always available, even
# when the system Python can't install packages (PEP 668).
set -e
cd "$(dirname "$0")"

VENV=".venv"

if [ ! -x "$VENV/bin/python" ]; then
    echo "Creating virtualenv ($VENV)…"
    python3 -m venv "$VENV"
fi

if ! "$VENV/bin/python" -c "import cryptography" >/dev/null 2>&1; then
    echo "Installing dependencies…"
    if ! "$VENV/bin/pip" install --disable-pip-version-check -r requirements.txt; then
        echo "warning: could not install requirements; online-mode whitelist checks will be unavailable" >&2
    fi
fi

exec "$VENV/bin/python" app.py "$@"
