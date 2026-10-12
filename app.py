#!/usr/bin/env python3
"""Minecraft Server Status - a small dashboard + notifier for MC Java servers.

Pure standard library. Run with:  python3 app.py
Then open:                         http://localhost:8080
"""

from __future__ import annotations

import json
import os
import posixpath
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse

from config import Config
from db import Database
from mcauth import AuthError, AuthManager
from notify import Notifier
from poller import Poller

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")
DB_PATH = os.path.join(BASE_DIR, "data", "servers.db")
AUTH_PATH = os.path.join(BASE_DIR, "data", "auth.json")
BACKUP_DIR = os.path.join(BASE_DIR, "data", "backups")

CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".ico": "image/x-icon",
    ".webmanifest": "application/manifest+json",
}

CONFIG = Config(CONFIG_PATH)
DB = Database(DB_PATH)
AUTH = AuthManager(AUTH_PATH)
NOTIFIER = Notifier(CONFIG.notifier_config())
POLLER = Poller(DB, CONFIG.get(), NOTIFIER)


# --------------------------------------------------------------------------- #
# Response helpers
# --------------------------------------------------------------------------- #
class ApiError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


def server_with_status(cfg: Config, server: dict, whitelist: dict | None = None) -> dict:
    latest = DB.latest_snapshot(server["id"])
    out = dict(server)
    out["status"] = latest
    out["whitelist"] = whitelist
    return out


def _split_host_port(value: str) -> tuple[str, str | None]:
    """Split an address into (host, port). Port is None when not supplied.

    Accepts "host", "host:port", "[::1]" and "[::1]:25565".
    """
    value = (value or "").strip()
    if value.startswith("["):
        end = value.find("]")
        if end == -1:
            return value, None
        host = value[1:end]
        rest = value[end + 1:]
        if rest.startswith(":") and len(rest) > 1:
            return host, rest[1:]
        return host, None
    if value.count(":") == 1:
        host, _, port = value.partition(":")
        return host, (port or None)
    return value, None


def validate_server_payload(payload: dict, require_all: bool = True) -> dict:
    name = (payload.get("name") or "").strip()
    host, embedded_port = _split_host_port(payload.get("host"))
    port_raw = embedded_port if embedded_port is not None else payload.get("port", 25565)

    if require_all and not host:
        raise ApiError(400, "host is required")
    if name and len(name) > 80:
        raise ApiError(400, "name is too long (max 80)")

    try:
        port = int(port_raw)
    except (TypeError, ValueError):
        raise ApiError(400, "port must be a number")
    if not (1 <= port <= 65535):
        raise ApiError(400, "port must be between 1 and 65535")

    if host and len(host) > 255:
        raise ApiError(400, "host is too long")

    return {"name": name or host, "host": host, "port": port}


def ensure_unique_server(host: str, port: int, exclude_id: int | None = None) -> None:
    if DB.server_exists(host, port, exclude_id=exclude_id):
        raise ApiError(409, "server already exists")


# --------------------------------------------------------------------------- #
# Route handlers
# --------------------------------------------------------------------------- #
def api_state(query: dict) -> dict:
    servers = DB.list_servers()
    notify_cfg = CONFIG.notifier_config()
    wl = DB.all_whitelist_checks()
    return {
        "servers": [server_with_status(CONFIG, s, wl.get(s["id"])) for s in servers],
        "events": DB.recent_events(30),
        "poller": {
            "interval": POLLER.interval,
            "last_run": POLLER.last_run,
            "last_duration": POLLER.last_duration,
            "now": time.time(),
        },
        "notify": {
            "enabled": notify_cfg.get("enabled", True),
            "provider": notify_cfg.get("provider", "ntfy"),
            "topic": (notify_cfg.get("ntfy") or {}).get("topic", ""),
            "server": (notify_cfg.get("ntfy") or {}).get("server", ""),
            "notify_on": notify_cfg.get("notify_on", {}),
        },
        "auth": auth_status(),
    }


def auth_status() -> dict:
    import mcping

    info = AUTH.status()
    info["crypto_available"] = mcping.crypto_available()
    info["crypto_error"] = mcping.crypto_error()
    return info


def api_auth_status(query: dict) -> dict:
    return auth_status()


def api_auth_device(payload: dict) -> dict:
    try:
        AUTH.start_device_flow()
    except AuthError as exc:
        raise ApiError(502, exc.message)
    return auth_status()


def api_auth_poll(payload: dict) -> dict:
    try:
        AUTH.poll_device_flow()
    except AuthError as exc:
        raise ApiError(502, exc.message)
    return auth_status()


def api_auth_logout(payload: dict) -> dict:
    AUTH.logout()
    return auth_status()


def api_list_servers(query: dict) -> dict:
    wl = DB.all_whitelist_checks()
    return {"servers": [server_with_status(CONFIG, s, wl.get(s["id"])) for s in DB.list_servers()]}


def api_add_server(payload: dict) -> dict:
    data = validate_server_payload(payload)
    ensure_unique_server(data["host"], data["port"])
    server = DB.add_server(data["name"], data["host"], data["port"], favorite=bool(payload.get("favorite")))
    POLLER.trigger()
    return {"server": server_with_status(CONFIG, server)}


def api_update_server(payload: dict, server_id: int) -> dict:
    if DB.get_server(server_id) is None:
        raise ApiError(404, "server not found")
    data = validate_server_payload(payload)
    ensure_unique_server(data["host"], data["port"], exclude_id=server_id)
    server = DB.update_server(server_id, data["name"], data["host"], data["port"])
    POLLER.trigger()
    return {"server": server_with_status(CONFIG, server)}


def api_favorite_server(payload: dict, server_id: int) -> dict:
    if DB.get_server(server_id) is None:
        raise ApiError(404, "server not found")
    server = DB.set_favorite(server_id, bool(payload.get("favorite")))
    return {"server": server_with_status(CONFIG, server)}


def api_delete_server(payload: dict, server_id: int) -> dict:
    if not DB.delete_server(server_id):
        raise ApiError(404, "server not found")
    return {"deleted": server_id}


def api_poll(payload: dict) -> dict:
    POLLER.trigger()
    threading.Thread(target=POLLER.poll_once, name="manual-poll", daemon=True).start()
    return {"ok": True, "message": "poll triggered"}


def api_history(query: dict) -> dict:
    try:
        server_id = int(query.get("id", ["0"])[0])
    except (TypeError, ValueError):
        raise ApiError(400, "invalid id")
    hours = float(query.get("hours", ["24"])[0])
    since = time.time() - hours * 3600
    return {"snapshots": DB.snapshots_since(server_id, since)}


def api_events(query: dict) -> dict:
    limit = int(query.get("limit", ["50"])[0])
    return {"events": DB.recent_events(limit)}


def api_get_config(query: dict) -> dict:
    return {"config": CONFIG.get(), "poller": {"interval": POLLER.interval}}


def api_update_config(payload: dict) -> dict:
    cfg = CONFIG.update(payload)
    global POLLER
    POLLER.config = CONFIG.get()
    POLLER.notifier.config = CONFIG.notifier_config()
    if "poll_interval_seconds" in payload:
        POLLER.trigger()
    return {"config": cfg}


def api_test_notify(payload: dict) -> dict:
    if "notify" in payload:
        CONFIG.update({"notify": payload["notify"]})
        POLLER.notifier.config = CONFIG.notifier_config()
    notifier = Notifier(CONFIG.notifier_config())
    ok, detail = notifier.test()
    if not ok:
        raise ApiError(502, detail)
    return {"ok": True, "detail": detail}


def api_ping_one(payload: dict) -> dict:
    data = validate_server_payload(payload)
    import mcping

    result = mcping.ping(data["host"], data["port"], timeout=POLLER.timeout)
    return {"result": result}


def api_preview_import(payload: dict) -> dict:
    text = payload.get("text") or ""
    if not isinstance(text, str):
        raise ApiError(400, "text must be a string")
    candidates = parse_server_addresses(text)
    out = []
    seen = set()
    for item in candidates:
        key = (DB.normalize_host(item["host"]), item["port"])
        if key in seen:
            continue
        seen.add(key)
        item["duplicate"] = DB.server_exists(item["host"], item["port"])
        out.append(item)
    return {"servers": out}


def parse_server_addresses(text: str) -> list[dict]:
    import re

    host_part = r"(?:[a-zA-Z0-9][a-zA-Z0-9-]{0,62}\.)+[a-zA-Z]{2,63}|(?:\d{1,3}\.){3}\d{1,3}|localhost"
    pattern = re.compile(rf"(?<![\w.-])({host_part})(?::(\d{{1,5}}))?(?![\w.-])")
    servers = []
    for match in pattern.finditer(text):
        host = match.group(1)
        port_raw = match.group(2)
        port = int(port_raw) if port_raw else 25565
        if not (1 <= port <= 65535):
            continue
        if all(part.isdigit() and 0 <= int(part) <= 255 for part in host.split(".")) or not host.replace(".", "").isdigit():
            servers.append({"name": host, "host": host, "port": port})
    return servers


def api_check_whitelist(payload: dict, server_id: int) -> dict:
    server = DB.get_server(server_id)
    if server is None:
        raise ApiError(404, "server not found")
    import mcping

    session = None
    if payload.get("use_account", True):
        session = AUTH.get_session()
    result = mcping.check_whitelist(
        server["host"], server["port"], timeout=POLLER.timeout, session=session
    )
    result["account"] = session.get("name") if session else None
    DB.set_whitelist_check(server_id, result)
    return {"whitelist": result}


def _backup_config() -> dict:
    cfg = CONFIG.get() or {}
    return cfg.get("backups") or {}


def run_backup() -> str | None:
    """Snapshot servers.db if backups are enabled. Returns the file path."""
    cfg = _backup_config()
    if not cfg.get("enabled", True):
        return None
    return DB.backup(BACKUP_DIR, int(cfg.get("keep", 30) or 30))


def api_backup(payload: dict) -> dict:
    path = run_backup()
    return {
        "ok": True,
        "file": os.path.basename(path) if path else None,
        "backups": DB.list_backups(BACKUP_DIR),
    }


def api_list_backups(query: dict) -> dict:
    return {"backups": DB.list_backups(BACKUP_DIR), "config": _backup_config()}


def api_export(query: dict) -> dict:
    return {"servers": DB.export_servers()}


def api_import(payload: dict) -> dict:
    servers = payload.get("servers")
    if not isinstance(servers, list):
        raise ApiError(400, "servers must be a list")
    result = DB.import_servers(servers, replace=bool(payload.get("replace")))
    POLLER.trigger()
    return result


def backup_loop() -> None:
    """Background daemon: take a snapshot every ``backups.interval_hours``."""
    while True:
        hours = float(_backup_config().get("interval_hours", 24) or 24)
        time.sleep(max(60.0, hours * 3600.0))
        try:
            run_backup()
        except Exception as exc:  # pragma: no cover - best effort
            print(f"[backup] failed: {exc!r}", flush=True)


ROUTES = [
    ("GET", "/api/state", lambda q, p: api_state(q)),
    ("GET", "/api/servers", lambda q, p: api_list_servers(q)),
    ("POST", "/api/servers", lambda q, p: api_add_server(p)),
    ("GET", "/api/history", lambda q, p: api_history(q)),
    ("GET", "/api/events", lambda q, p: api_events(q)),
    ("GET", "/api/config", lambda q, p: api_get_config(q)),
    ("PUT", "/api/config", lambda q, p: api_update_config(p)),
    ("POST", "/api/test-notify", lambda q, p: api_test_notify(p)),
    ("POST", "/api/ping", lambda q, p: api_ping_one(p)),
    ("POST", "/api/import/preview", lambda q, p: api_preview_import(p)),
    ("POST", "/api/poll", lambda q, p: api_poll(p)),
    ("POST", "/api/backup", lambda q, p: api_backup(p)),
    ("GET", "/api/backups", lambda q, p: api_list_backups(q)),
    ("GET", "/api/export", lambda q, p: api_export(q)),
    ("POST", "/api/import", lambda q, p: api_import(p)),
    ("GET", "/api/auth/status", lambda q, p: api_auth_status(q)),
    ("POST", "/api/auth/device", lambda q, p: api_auth_device(p)),
    ("GET", "/api/auth/poll", lambda q, p: api_auth_poll(p)),
    ("POST", "/api/auth/logout", lambda q, p: api_auth_logout(p)),
    ("PUT", "/api/servers/(\\d+)", lambda q, p, m: api_update_server(p, int(m.group(1)))),
    ("PUT", "/api/servers/(\\d+)/favorite", lambda q, p, m: api_favorite_server(p, int(m.group(1)))),
    ("DELETE", "/api/servers/(\\d+)", lambda q, p, m: api_delete_server(p, int(m.group(1)))),
    ("POST", "/api/servers/(\\d+)/whitelist", lambda q, p, m: api_check_whitelist(p, int(m.group(1)))),
]


# --------------------------------------------------------------------------- #
# HTTP handler
# --------------------------------------------------------------------------- #
class Handler(BaseHTTPRequestHandler):
    server_version = "MCServerStatus/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        if args and str(args[0]).startswith(("GET /api", "POST /api", "PUT /api", "DELETE /api")):
            sys.stderr.write("  %s\n" % (fmt % args))

    # ---------------------------- utilities --------------------------- #
    def _send(self, status: int, body: bytes, content_type: str, extra: dict | None = None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _send_json(self, status: int, payload) -> None:
        body = json.dumps(payload).encode("utf-8")
        self._send(status, body, "application/json; charset=utf-8")

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise ApiError(400, "invalid JSON body")
        if not isinstance(data, dict):
            raise ApiError(400, "JSON body must be an object")
        return data

    def _serve_static(self, path: str) -> None:
        rel = unquote(path)
        if rel in ("/", ""):
            rel = "/index.html"
        if rel.startswith("/static/"):
            rel = rel[len("/static"):]
        parts = [p for p in rel.split("/") if p not in ("", ".", "..")]
        full = os.path.join(STATIC_DIR, *parts)
        if not os.path.abspath(full).startswith(os.path.abspath(STATIC_DIR)):
            self._send(403, b"forbidden", "text/plain")
            return
        if not os.path.isfile(full):
            self._send(404, b"not found", "text/plain")
            return
        ext = os.path.splitext(full)[1].lower()
        ctype = CONTENT_TYPES.get(ext, "application/octet-stream")
        with open(full, "rb") as fh:
            body = fh.read()
        self._send(200, body, ctype)

    # ----------------------------- verbs ------------------------------ #
    def _dispatch(self, method: str):
        parsed = urlparse(self.path)
        path = posixpath.normpath(parsed.path)
        query = parse_qs(parsed.query)

        if path.startswith("/api/"):
            try:
                payload = self._read_json() if method in ("POST", "PUT", "PATCH") else {}
            except ApiError as exc:
                self._send_json(exc.status, {"error": exc.message})
                return

            for route_method, pattern, handler in ROUTES:
                if route_method != method:
                    continue
                import re

                match = re.fullmatch(pattern, path)
                if not match:
                    continue
                try:
                    if handler.__code__.co_argcount == 3:
                        result = handler(query, payload, match)
                    else:
                        result = handler(query, payload)
                    self._send_json(200, result)
                except ApiError as exc:
                    self._send_json(exc.status, {"error": exc.message})
                except Exception as exc:  # pragma: no cover - safety net
                    self._send_json(500, {"error": f"{type(exc).__name__}: {exc}"})
                return

            self._send_json(404, {"error": "unknown API route"})
            return

        if method in ("GET", "HEAD"):
            self._serve_static(parsed.path)
        else:
            self._send(405, b"method not allowed", "text/plain")

    def do_GET(self):
        self._dispatch("GET")

    def do_HEAD(self):
        self._dispatch("HEAD")

    def do_POST(self):
        self._dispatch("POST")

    def do_PUT(self):
        self._dispatch("PUT")

    def do_DELETE(self):
        self._dispatch("DELETE")


def main() -> None:
    cfg = CONFIG.get()
    host = os.environ.get("MCSTATUS_HOST", cfg["dashboard"]["host"])
    port = int(os.environ.get("MCSTATUS_PORT", cfg["dashboard"]["port"]))

    if _backup_config().get("enabled", True):
        try:
            saved = run_backup()
            if saved:
                print(f" Backed up DB:  {os.path.relpath(saved, BASE_DIR)}", flush=True)
        except Exception as exc:  # pragma: no cover - best effort
            print(f"[backup] startup backup failed: {exc!r}", flush=True)
    threading.Thread(target=backup_loop, name="backup-loop", daemon=True).start()

    POLLER.start()

    httpd = ThreadingHTTPServer((host, port), Handler)
    httpd.daemon_threads = True
    display_host = "localhost" if host in ("0.0.0.0", "::") else host
    print("=" * 56)
    print(" Minecraft Server Status")
    print(f" Dashboard:     http://{display_host}:{port}")
    print(f" Poll interval: {POLLER.interval}s")
    ntfy = CONFIG.notifier_config().get("ntfy", {})
    print(f" Notifications: {CONFIG.notifier_config().get('enabled')} "
          f"(ntfy {ntfy.get('server')}/{ntfy.get('topic')})")
    print(" Press Ctrl+C to stop")
    print("=" * 56, flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        POLLER.stop()
        httpd.server_close()


if __name__ == "__main__":
    main()
