"""Push notifications via ntfy (https://ntfy.sh or a self-hosted instance).

ntfy is used as the delivery transport to your iPhone: install the free
"ntfy" app, subscribe to the topic, and iOS shows a normal push notification.
Titles, icons, tags and a tap-through link are all set here so the alert looks
like it comes from this dashboard. Self-host ntfy to keep everything on your
own server.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request

DEFAULT_SERVER = "https://ntfy.sh"
DEFAULT_TOPIC = "KyguyMCList"


class Notifier:
    def __init__(self, config: dict):
        self.config = config

    # ------------------------------------------------------------------ #
    @property
    def enabled(self) -> bool:
        return bool(self.config.get("enabled", True))

    @property
    def ntfy(self) -> dict:
        return self.config.get("ntfy", {}) or {}

    def notify_on(self, kind: str) -> bool:
        return bool((self.config.get("notify_on") or {}).get(kind, False))

    # ------------------------------------------------------------------ #
    def send(
        self,
        message: str,
        title: str | None = None,
        tags: list[str] | None = None,
        priority: str | None = None,
        click: str | None = None,
        icon: str | None = None,
    ) -> tuple[bool, str]:
        """Publish one notification. Returns (ok, detail)."""
        if not self.enabled:
            return False, "notifications disabled"

        cfg = self.ntfy
        base = (cfg.get("server") or DEFAULT_SERVER).rstrip("/")
        topic = (cfg.get("topic") or DEFAULT_TOPIC).strip()
        if not topic:
            return False, "no ntfy topic configured"

        payload: dict = {"topic": topic, "message": message}
        if title:
            payload["title"] = title
        if tags:
            payload["tags"] = tags
        if priority:
            payload["priority"] = priority if isinstance(priority, int) else priority
        if click:
            payload["click"] = click
        if icon:
            payload["icon"] = icon

        data = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            base,
            data=data,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        token = (cfg.get("token") or "").strip()
        if token:
            request.add_header("Authorization", f"Bearer {token}")

        try:
            with urllib.request.urlopen(request, timeout=10) as resp:
                resp.read()
            return True, f"sent to {base}/{topic}"
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:200]
            return False, f"HTTP {exc.code}: {detail}"
        except (urllib.error.URLError, OSError) as exc:
            return False, f"{type(exc).__name__}: {exc}"

    # ------------------------------------------------------------------ #
    def dashboard_url(self) -> str:
        return (self.config.get("click_url") or "").strip()

    def title_prefix(self) -> str:
        return (self.config.get("title_prefix") or "MC Status").strip()

    def join(self, server_name: str, player: str | None, online, maximum) -> tuple[bool, str]:
        count = f"{online}/{maximum}" if maximum else str(online)
        if player:
            message = f"{player} joined {server_name} — {count} online"
        else:
            message = f"A player joined {server_name} — {count} online"
        return self.send(
            message=message,
            title=f"{self.title_prefix()} · {server_name}",
            tags=["video_game", "bust_in_silhouette"],
            priority="default",
            click=self.dashboard_url() or None,
        )

    def leave(self, server_name: str, player: str | None, online, maximum) -> tuple[bool, str]:
        count = f"{online}/{maximum}" if maximum else str(online)
        who = player or "A player"
        message = f"{who} left {server_name} — {count} online"
        return self.send(
            message=message,
            title=f"{self.title_prefix()} · {server_name}",
            tags=["video_game"],
            click=self.dashboard_url() or None,
        )

    def server_down(self, server_name: str, detail: str | None = None) -> tuple[bool, str]:
        return self.send(
            message=f"{server_name} is unreachable{(' — ' + detail) if detail else ''}",
            title=f"{self.title_prefix()} · {server_name}",
            tags=["warning", "red_circle"],
            priority="high",
            click=self.dashboard_url() or None,
        )

    def server_up(self, server_name: str) -> tuple[bool, str]:
        return self.send(
            message=f"{server_name} is back online",
            title=f"{self.title_prefix()} · {server_name}",
            tags=["white_check_mark", "green_circle"],
            click=self.dashboard_url() or None,
        )

    def test(self) -> tuple[bool, str]:
        return self.send(
            message="Test notification — your Minecraft server alerts are working.",
            title=f"{self.title_prefix()} · Test",
            tags=["test_tube", "bell"],
            click=self.dashboard_url() or None,
        )
