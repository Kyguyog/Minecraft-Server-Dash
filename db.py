"""SQLite storage layer for Minecraft Server Status."""

from __future__ import annotations

import json
import os
import sqlite3
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS servers (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT    NOT NULL,
    host       TEXT    NOT NULL,
    port       INTEGER NOT NULL DEFAULT 25565,
    created_at REAL    NOT NULL
);

CREATE TABLE IF NOT EXISTS snapshots (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id      INTEGER NOT NULL,
    ts             REAL    NOT NULL,
    online         INTEGER NOT NULL,
    players_online INTEGER,
    players_max    INTEGER,
    version        TEXT,
    latency_ms     REAL,
    players        TEXT,
    motd           TEXT,
    error          TEXT,
    FOREIGN KEY (server_id) REFERENCES servers (id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_snapshots_server_ts ON snapshots (server_id, ts);

CREATE TABLE IF NOT EXISTS events (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id INTEGER NOT NULL,
    ts        REAL    NOT NULL,
    type      TEXT    NOT NULL,
    player    TEXT,
    detail    TEXT,
    FOREIGN KEY (server_id) REFERENCES servers (id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events (ts);

CREATE TABLE IF NOT EXISTS whitelist_checks (
    server_id   INTEGER PRIMARY KEY,
    checked_at  REAL,
    status      TEXT,
    online_mode INTEGER,
    reason      TEXT,
    protocol    INTEGER,
    FOREIGN KEY (server_id) REFERENCES servers (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS state (
    server_id      INTEGER PRIMARY KEY,
    last_online    INTEGER,
    last_players   TEXT,
    last_sample    INTEGER,
    last_count     INTEGER,
    last_seen_ts   REAL,
    FOREIGN KEY (server_id) REFERENCES servers (id) ON DELETE CASCADE
);
"""


class Database:
    def __init__(self, path: str):
        self.path = path
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with self._connect() as conn:
            conn.executescript(SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=15, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        return conn

    # ------------------------------------------------------------------ #
    # Servers
    # ------------------------------------------------------------------ #
    def list_servers(self) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM servers ORDER BY name COLLATE NOCASE, id"
            ).fetchall()
        return [dict(r) for r in rows]

    def get_server(self, server_id: int) -> dict | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM servers WHERE id = ?", (server_id,)).fetchone()
        return dict(row) if row else None

    def add_server(self, name: str, host: str, port: int = 25565) -> dict:
        with self._connect() as conn:
            cur = conn.execute(
                "INSERT INTO servers (name, host, port, created_at) VALUES (?, ?, ?, ?)",
                (name, host, int(port), time.time()),
            )
            server_id = cur.lastrowid
        return self.get_server(server_id)

    def update_server(self, server_id: int, name: str, host: str, port: int) -> dict | None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE servers SET name = ?, host = ?, port = ? WHERE id = ?",
                (name, host, int(port), server_id),
            )
        return self.get_server(server_id)

    def delete_server(self, server_id: int) -> bool:
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM servers WHERE id = ?", (server_id,))
        return cur.rowcount > 0

    def delete_all_servers(self) -> int:
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM servers")
        return cur.rowcount

    def export_servers(self) -> list[dict]:
        """Return the server list as a plain JSON-friendly structure."""
        return [
            {"name": s["name"], "host": s["host"], "port": s["port"]}
            for s in self.list_servers()
        ]

    def import_servers(self, servers: list[dict], replace: bool = False) -> dict:
        """Add servers, skipping blanks/invalid entries and duplicates."""
        added = skipped = 0
        if replace:
            self.delete_all_servers()
        existing = {(s["host"], s["port"]) for s in self.list_servers()}
        for item in servers or []:
            if not isinstance(item, dict):
                skipped += 1
                continue
            host = (item.get("host") or "").strip()
            if not host:
                skipped += 1
                continue
            try:
                port = int(item.get("port", 25565))
            except (TypeError, ValueError):
                skipped += 1
                continue
            if not (1 <= port <= 65535) or (host, port) in existing:
                skipped += 1
                continue
            name = (item.get("name") or host).strip()[:80] or host
            self.add_server(name, host, port)
            existing.add((host, port))
            added += 1
        return {"added": added, "skipped": skipped}

    # ------------------------------------------------------------------ #
    # Snapshots
    # ------------------------------------------------------------------ #
    def add_snapshot(self, server_id: int, result: dict) -> None:
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO snapshots
                   (server_id, ts, online, players_online, players_max, version,
                    latency_ms, players, motd, error)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    server_id,
                    time.time(),
                    1 if result.get("online") else 0,
                    result.get("players_online"),
                    result.get("players_max"),
                    result.get("version"),
                    result.get("latency_ms"),
                    json.dumps(result.get("players") or []),
                    result.get("motd"),
                    result.get("error"),
                ),
            )

    def latest_snapshot(self, server_id: int) -> dict | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM snapshots WHERE server_id = ? ORDER BY ts DESC LIMIT 1",
                (server_id,),
            ).fetchone()
        return self._decode_snapshot(row)

    def snapshots_since(self, server_id: int, since: float) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM snapshots WHERE server_id = ? AND ts >= ? ORDER BY ts ASC",
                (server_id, since),
            ).fetchall()
        return [self._decode_snapshot(r) for r in rows]

    def prune_snapshots(self, older_than_days: int = 14) -> int:
        cutoff = time.time() - older_than_days * 86400
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM snapshots WHERE ts < ?", (cutoff,))
        return cur.rowcount

    @staticmethod
    def _decode_snapshot(row) -> dict | None:
        if row is None:
            return None
        data = dict(row)
        try:
            data["players"] = json.loads(data.get("players") or "[]")
        except (TypeError, ValueError):
            data["players"] = []
        return data

    # ------------------------------------------------------------------ #
    # State (used for change detection between polls)
    # ------------------------------------------------------------------ #
    def get_state(self, server_id: int) -> dict | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM state WHERE server_id = ?", (server_id,)).fetchone()
        if not row:
            return None
        data = dict(row)
        try:
            data["last_players"] = json.loads(data.get("last_players") or "[]")
        except (TypeError, ValueError):
            data["last_players"] = []
        return data

    def set_state(
        self,
        server_id: int,
        online: bool,
        players: list[str],
        sample_available: bool = False,
        count: int | None = None,
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO state
                       (server_id, last_online, last_players, last_sample, last_count, last_seen_ts)
                   VALUES (?, ?, ?, ?, ?, ?)
                   ON CONFLICT (server_id) DO UPDATE SET
                       last_online  = excluded.last_online,
                       last_players = excluded.last_players,
                       last_sample  = excluded.last_sample,
                       last_count   = excluded.last_count,
                       last_seen_ts = excluded.last_seen_ts""",
                (
                    server_id,
                    1 if online else 0,
                    json.dumps(players or []),
                    1 if sample_available else 0,
                    count,
                    time.time(),
                ),
            )

    # ------------------------------------------------------------------ #
    # Whitelist checks
    # ------------------------------------------------------------------ #
    def set_whitelist_check(self, server_id: int, result: dict) -> None:
        online_mode = result.get("online_mode")
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO whitelist_checks
                       (server_id, checked_at, status, online_mode, reason, protocol)
                   VALUES (?, ?, ?, ?, ?, ?)
                   ON CONFLICT (server_id) DO UPDATE SET
                       checked_at  = excluded.checked_at,
                       status      = excluded.status,
                       online_mode = excluded.online_mode,
                       reason      = excluded.reason,
                       protocol    = excluded.protocol""",
                (
                    server_id,
                    time.time(),
                    result.get("status"),
                    None if online_mode is None else (1 if online_mode else 0),
                    result.get("reason"),
                    result.get("protocol"),
                ),
            )

    def all_whitelist_checks(self) -> dict[int, dict]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM whitelist_checks").fetchall()
        out = {}
        for row in rows:
            data = dict(row)
            if data.get("online_mode") is not None:
                data["online_mode"] = bool(data["online_mode"])
            out[data["server_id"]] = data
        return out

    # ------------------------------------------------------------------ #
    # Events
    # ------------------------------------------------------------------ #
    def add_event(self, server_id: int, event_type: str, player: str | None, detail: str | None) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO events (server_id, ts, type, player, detail) VALUES (?, ?, ?, ?, ?)",
                (server_id, time.time(), event_type, player, detail),
            )

    def recent_events(self, limit: int = 50) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                """SELECT e.*, s.name AS server_name
                   FROM events e JOIN servers s ON s.id = e.server_id
                   ORDER BY e.ts DESC LIMIT ?""",
                (int(limit),),
            ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------ #
    # Backups
    # ------------------------------------------------------------------ #
    def backup(self, backup_dir: str, keep: int = 30) -> str:
        """Write a consistent copy of the database into backup_dir.

        Uses SQLite's online backup API, so it is safe to call while the
        poller or web server is writing. Backups beyond ``keep`` are pruned.
        """
        os.makedirs(backup_dir, exist_ok=True)
        stamp = time.strftime("%Y%m%d-%H%M%S")
        dest = os.path.join(backup_dir, f"servers-{stamp}.db")
        source = self._connect()
        try:
            target = sqlite3.connect(dest)
            try:
                source.backup(target)
            finally:
                target.close()
        finally:
            source.close()
        self._prune_backups(backup_dir, keep)
        return dest

    @staticmethod
    def _prune_backups(backup_dir: str, keep: int) -> None:
        if not keep or keep <= 0:
            return
        try:
            files = sorted(
                f for f in os.listdir(backup_dir)
                if f.startswith("servers-") and f.endswith(".db")
            )
        except OSError:
            return
        for name in files[:-keep]:
            try:
                os.remove(os.path.join(backup_dir, name))
            except OSError:
                pass

    @staticmethod
    def list_backups(backup_dir: str) -> list[dict]:
        try:
            names = sorted(
                (f for f in os.listdir(backup_dir)
                 if f.startswith("servers-") and f.endswith(".db")),
                reverse=True,
            )
        except OSError:
            return []
        out = []
        for name in names:
            path = os.path.join(backup_dir, name)
            try:
                stat = os.stat(path)
            except OSError:
                continue
            out.append({"file": name, "size": stat.st_size, "mtime": stat.st_mtime})
        return out
