# Minecraft Server Status

A tiny self-hosted dashboard that monitors any number of Minecraft **Java**
servers. Every 60 seconds it pings each one, records **version** and
**player counts**, shows everything on a web dashboard, and pushes a
notification to your iPhone when a player logs on.

Pure Python standard library — **no `pip install` required**.

## Quick start

```sh
cd "Minecraft Server Status"
python3 app.py
```

Then open <http://localhost:8080>.

## Features

- Add/remove/edit servers from the web UI (host, port, name).
- Automatic `_minecraft._tcp` SRV resolution, so `play.example.com` works.
- Modern Server List Ping (1.7+) with a legacy fallback.
- Polls every 60s (configurable). Records a history of snapshots in SQLite.
- Detects joins/leaves two ways:
  - per-player list when the server exposes it, otherwise
  - player-count changes for servers that hide their list.
- Best-effort **whitelist detection** via a login probe (see below).
- Dashboard shows status, version, players (online/max), latency, MOTD,
  server icon, and a live activity feed.
- iPhone push notifications through [ntfy](https://ntfy.sh).
- Data lives in `data/servers.db`; settings in `config.json`.

## iPhone notifications

iOS does not allow a plain self-hosted website to push notifications while
it is closed, so this app uses **ntfy** as the delivery transport:

1. Install the free **ntfy** app from the App Store.
2. Subscribe to topic `KyguyMCList` (or whatever you set in Settings).
3. You'll get a push notification when someone joins.

To make notifications come *only* from your own infrastructure, run your own
ntfy server (`docker run -p 80:80 binwiederhier/ntfy serve`) and set the
**ntfy server** field in Settings to its address instead of `https://ntfy.sh`.

## Whitelist detection (best effort)

The status ping has **no** whitelist field, so the only way to tell is to
attempt a real login and read what the server replies. Each server card has a
**Whitelist check** button that does exactly that. It reports:

| Result | Meaning |
| ------ | ------- |
| **Whitelist-only** | Disconnected with a "not whitelisted" message. |
| **Open (no whitelist)** | The server admitted an unauthenticated login. |
| **Admitted (account allowed in)** | You are signed in and the server let your account through. |
| **Unknown (online-mode)** | The server asked for encryption and you are not signed in. |
| **Couldn't verify** | Blocked for another reason (full, banned, version). |

Why the limitation: in the vanilla login flow, online-mode servers send the
encryption request **before** checking the whitelist, while offline-mode
servers check it immediately. So offline-mode servers are detectable
anonymously; online-mode servers require a real account (see below).

The probe opens a login connection and disconnects immediately. It may briefly
appear in the target server's logs, so it runs on demand rather than on every
poll.

## Signing in with a Minecraft account

To probe **online-mode** servers you can sign in with your real Microsoft
account (the same one you use for Minecraft). Click **Sign in** on the
dashboard; the app shows a short code and a link
(<https://www.microsoft.com/link>). Enter the code there once.

- No password is ever seen or stored. The flow is Microsoft's standard
  device-code OAuth; only the resulting **refresh token** is kept on disk in
  `data/auth.json` (permissions `600`).
- The app uses the official Minecraft launcher client id
  (`00000000402b5328`) over the Windows Live (live.com) endpoint, then walks
  Microsoft → Xbox Live → XSTS → Minecraft Services to obtain a short-lived
  Minecraft access token.
- Tokens refresh automatically; sign out any time from the dashboard.
- **Caveat:** if the account you sign in with *is* whitelisted, a
  whitelist-only server will report **Admitted** — the authenticated probe can
  only answer "can *this* account join", not whether a whitelist exists in
  general.

## Configuration (`config.json`)

```jsonc
{
  "dashboard": { "host": "0.0.0.0", "port": 8080 },
  "poll_interval_seconds": 60,
  "request_timeout_seconds": 5,
  "prune_after_days": 14,
  "click_url": "",
  "backups": { "enabled": true, "keep": 30, "interval_hours": 24 },
  "notify": {
    "enabled": true,
    "provider": "ntfy",
    "title_prefix": "MC Status",
    "ntfy": { "server": "https://ntfy.sh", "topic": "KyguyMCList", "token": "" },
    "notify_on": { "join": true, "leave": false, "server_down": true, "server_up": false }
  }
}
```

Everything can also be edited from the **Settings** dialog in the dashboard.

## API

| Method | Path | Purpose |
| ------ | ---- | ------- |
| GET | `/api/state` | Servers + status + events + poller info |
| GET | `/api/servers` | List servers |
| POST | `/api/servers` | Add `{name, host}` — `host` may be `host` or `host:port` |
| PUT | `/api/servers/<id>` | Update a server (same body) |
| DELETE | `/api/servers/<id>` | Remove a server |
| POST | `/api/servers/<id>/whitelist` | Run a whitelist login probe |
| GET | `/api/history?id=&hours=` | Snapshot history |
| GET | `/api/events?limit=` | Activity feed |
| POST | `/api/poll` | Check all servers now |
| POST | `/api/ping` | Test-ping `{host, port}` without saving |
| GET/PUT | `/api/config` | Read/update settings |
| POST | `/api/test-notify` | Send a test notification |
| POST | `/api/backup` | Snapshot `servers.db` now |
| GET | `/api/backups` | List existing backups + backup settings |
| GET | `/api/export` | Download the server list as JSON |
| POST | `/api/import` | Bulk add `{servers:[{name,host,port}], replace?}` |
| GET | `/api/auth/status` | Sign-in status + in-progress device flow |
| POST | `/api/auth/device` | Start the Microsoft device-code flow |
| GET | `/api/auth/poll` | Poll the in-progress sign-in |
| POST | `/api/auth/logout` | Forget the stored refresh token |

## Backups

Your server list is snapshotted automatically on every startup and every
`backups.interval_hours` (default 24). Snapshots use SQLite's online backup API
so they are consistent even while a poll is running, and live in
`data/backups/servers-YYYYMMDD-HHMMSS.db`. Only the newest `backups.keep`
(default 30) are retained. Use **Back up now** in Settings to snapshot on
demand, **Export servers** to download the list as JSON, or `POST /api/import`
to restore it.

## Notes

- Port 25565 is the default; SRV is only consulted when the port is left at
  the default.
- The activity history is pruned after `prune_after_days` (default 14).
- Never delete `data/servers.db`; if it is lost, restore the newest file from
  `data/backups/`.
- Run behind a reverse proxy if you expose it to the internet; the API has no
  authentication.
