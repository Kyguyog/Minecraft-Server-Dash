"""Load/save the JSON configuration, with defaults and thread safety."""

from __future__ import annotations

import copy
import json
import os
import threading

DEFAULTS = {
    "dashboard": {"host": "0.0.0.0", "port": 8080},
    "poll_interval_seconds": 60,
    "request_timeout_seconds": 5,
    "prune_after_days": 14,
    "click_url": "",
    "backups": {"enabled": True, "keep": 30, "interval_hours": 24},
    "notify": {
        "enabled": True,
        "provider": "ntfy",
        "title_prefix": "MC Status",
        "ntfy": {
            "server": "https://ntfy.sh",
            "topic": "KyguyMCList",
            "token": "",
        },
        "notify_on": {
            "join": True,
            "leave": True,
            "server_down": True,
            "server_up": True,
        },
    },
}

_ALLOWED_TOP_KEYS = {
    "dashboard",
    "poll_interval_seconds",
    "request_timeout_seconds",
    "prune_after_days",
    "click_url",
    "backups",
}


def _deep_merge(base: dict, override: dict) -> dict:
    out = copy.deepcopy(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out


class Config:
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.RLock()
        self._data = copy.deepcopy(DEFAULTS)
        self.load()

    def load(self) -> None:
        with self._lock:
            if os.path.exists(self.path):
                try:
                    with open(self.path, "r", encoding="utf-8") as fh:
                        stored = json.load(fh)
                    self._data = _deep_merge(DEFAULTS, stored)
                except (OSError, ValueError) as exc:
                    print(f"[config] could not read {self.path}: {exc}; using defaults")
                    self._data = copy.deepcopy(DEFAULTS)
            else:
                self._data = copy.deepcopy(DEFAULTS)
            self.save()

    def save(self) -> None:
        with self._lock:
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(self._data, fh, indent=2)
                fh.write("\n")
            os.replace(tmp, self.path)

    def get(self, key: str | None = None):
        with self._lock:
            if key is None:
                return copy.deepcopy(self._data)
            return copy.deepcopy(self._data.get(key))

    def update(self, patch: dict) -> dict:
        with self._lock:
            for key, value in (patch or {}).items():
                if key in ("notify", "backups") and isinstance(value, dict):
                    self._data[key] = _deep_merge(self._data[key], value)
                elif key in _ALLOWED_TOP_KEYS:
                    self._data[key] = value
            self.save()
            return copy.deepcopy(self._data)

    def notifier_config(self) -> dict:
        with self._lock:
            notify = copy.deepcopy(self._data["notify"])
            notify["title_prefix"] = notify.get("title_prefix", "MC Status")
            notify["click_url"] = self._data.get("click_url", "")
            return notify
