"""Background poller: pings every server on an interval, records snapshots,
detects players joining/leaving and fires notifications."""

from __future__ import annotations

import threading
import time

import mcping
from db import Database
from notify import Notifier


class Poller:
    def __init__(self, db: Database, config: dict, notifier: Notifier):
        self.db = db
        self.config = config
        self.notifier = notifier
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._poll_lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self.last_run: float | None = None
        self.last_duration: float | None = None

    # ------------------------------------------------------------------ #
    @property
    def interval(self) -> int:
        try:
            return max(10, int(self.config.get("poll_interval_seconds", 60)))
        except (TypeError, ValueError):
            return 60

    @property
    def timeout(self) -> float:
        try:
            return float(self.config.get("request_timeout_seconds", 5))
        except (TypeError, ValueError):
            return 5.0

    # ------------------------------------------------------------------ #
    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="poller", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()

    def trigger(self) -> None:
        """Ask the loop to poll again immediately."""
        self._wake.set()

    def _run(self) -> None:
        # Small initial delay so the web server is up before the first poll.
        self._wake.wait(2)
        while not self._stop.is_set():
            started = time.perf_counter()
            try:
                self.poll_once()
            except Exception as exc:  # never let the loop die
                print(f"[poller] poll cycle failed: {exc!r}", flush=True)
            self.last_run = time.time()
            self.last_duration = round(time.perf_counter() - started, 2)
            self._wake.wait(self.interval)
            self._wake.clear()

    # ------------------------------------------------------------------ #
    def poll_once(self) -> None:
        if not self._poll_lock.acquire(blocking=False):
            return
        try:
            servers = self.db.list_servers()
            for server in servers:
                try:
                    self._poll_server(server)
                except Exception as exc:
                    print(f"[poller] server {server.get('name')!r} failed: {exc!r}", flush=True)
            if self.config.get("prune_after_days"):
                try:
                    self.db.prune_snapshots(int(self.config["prune_after_days"]))
                except Exception:
                    pass
        finally:
            self._poll_lock.release()

    def _poll_server(self, server: dict) -> None:
        server_id = server["id"]
        # The server may have been removed while we were polling; skip writes
        # so a deleted server can't trigger a foreign-key error.
        if self.db.get_server(server_id) is None:
            return
        result = mcping.ping(server["host"], server["port"], timeout=self.timeout)
        if self.db.get_server(server_id) is None:
            return
        self.db.add_snapshot(server_id, result)

        prev = self.db.get_state(server_id)
        current_players = result.get("players") or []
        sample_available = bool(result.get("sample_available"))

        if prev is not None:
            self._detect_changes(server, prev, result, current_players, sample_available)

        self.db.set_state(
            server_id,
            bool(result.get("online")),
            current_players,
            sample_available=sample_available,
            count=result.get("players_online"),
        )

    def _detect_changes(self, server, prev, result, current_players, sample_available) -> None:
        server_id = server["id"]
        name = server["name"]
        was_online = bool(prev.get("last_online"))
        is_online = bool(result.get("online"))
        online = result.get("players_online")
        maximum = result.get("players_max")

        # Server came online after being down.
        if is_online and not was_online and self.notifier.notify_on("server_up"):
            self.db.add_event(server_id, "server_up", None, "server is back online")
            self._notify(self.notifier.server_up(name))

        # Server went down.
        if not is_online and was_online:
            detail = result.get("error") or "no response"
            self.db.add_event(server_id, "server_down", None, detail)
            if self.notifier.notify_on("server_down"):
                self._notify(self.notifier.server_down(name, detail))
            return

        if not is_online:
            return

        prev_players = prev.get("last_players") or []
        prev_count = prev.get("last_count")

        # Preferred: per-name diff when the server exposes a real player list.
        # Require names on both sides; otherwise fall back to counting so we
        # don't miss joins when a server hides (or empties) the sample list.
        if sample_available and current_players and prev_players:
            prev_set = set(prev_players)
            cur_set = set(current_players)
            joined = sorted(cur_set - prev_set)
            left = sorted(prev_set - cur_set)
            for player in joined:
                self.db.add_event(server_id, "join", player, None)
                if self.notifier.notify_on("join"):
                    self._notify(self.notifier.join(name, player, online, maximum))
            for player in left:
                self.db.add_event(server_id, "leave", player, None)
                if self.notifier.notify_on("leave"):
                    self._notify(self.notifier.leave(name, player, online, maximum))
            return

        # Fallback: count-based detection (many servers hide the sample list).
        if prev_count is not None and online is not None and online != prev_count:
            if online > prev_count:
                delta = online - prev_count
                detail = f"{prev_count} → {online}"
                self.db.add_event(server_id, "join", None, detail)
                if self.notifier.notify_on("join"):
                    self._notify(self.notifier.join(name, None, online, maximum))
                if delta > 1:
                    print(f"[poller] {name}: {delta} players joined at once", flush=True)
            elif online < prev_count:
                detail = f"{prev_count} → {online}"
                self.db.add_event(server_id, "leave", None, detail)
                if self.notifier.notify_on("leave"):
                    self._notify(self.notifier.leave(name, None, online, maximum))

    def _notify(self, result: tuple[bool, str]) -> None:
        ok, detail = result
        if not ok:
            print(f"[notify] failed: {detail}", flush=True)
