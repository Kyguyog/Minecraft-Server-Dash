"use strict";

const $ = (sel, root = document) => root.querySelector(sel);
const REFRESH_MS = 15000;
let refreshTimer = null;

/* ------------------------------------------------------------------ */
/* API helpers                                                         */
/* ------------------------------------------------------------------ */
async function api(method, path, body) {
  const opts = { method, headers: {} };
  if (body !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(path, opts);
  let data = null;
  try {
    data = await res.json();
  } catch (_) {
    /* ignore */
  }
  if (!res.ok) {
    throw new Error((data && data.error) || `HTTP ${res.status}`);
  }
  return data;
}

/* ------------------------------------------------------------------ */
/* Formatting                                                          */
/* ------------------------------------------------------------------ */
function relativeTime(ts) {
  if (!ts) return "never";
  const secs = Math.max(0, Math.round(Date.now() / 1000 - ts));
  if (secs < 5) return "just now";
  if (secs < 60) return `${secs}s ago`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m ago`;
  if (secs < 86400) return `${Math.floor(secs / 3600)}h ago`;
  return `${Math.floor(secs / 86400)}d ago`;
}

function clockTime(ts) {
  if (!ts) return "--:--";
  return new Date(ts * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function esc(text) {
  const div = document.createElement("div");
  div.textContent = text == null ? "" : String(text);
  return div.innerHTML;
}

/* ------------------------------------------------------------------ */
/* Rendering                                                           */
/* ------------------------------------------------------------------ */
function renderSummary(data) {
  const online = data.servers.filter((s) => s.status && s.status.online).length;
  const players = data.servers.reduce(
    (sum, s) => sum + ((s.status && s.status.online && s.status.players_online) || 0),
    0
  );
  $("#summary").textContent = `${online}/${data.servers.length} online · ${players} players · checks every ${data.poller.interval}s`;
  const pill = $("#poller-pill");
  pill.textContent = `checked ${relativeTime(data.poller.last_run)}`;
}

function renderServers(data) {
  const container = $("#servers");
  $("#server-count").textContent = data.servers.length ? `${data.servers.length} total` : "";
  $("#empty").classList.toggle("hidden", data.servers.length > 0);
  container.innerHTML = "";

  for (const server of data.servers) {
    container.appendChild(serverCard(server));
  }
}

const WHITELIST_INFO = {
  whitelist_only: { text: "Whitelist-only", cls: "wl-yes" },
  open: { text: "Open (no whitelist)", cls: "wl-no" },
  admitted: { text: "Account can join", cls: "wl-no" },
  online_mode_unknown: { text: "Unknown (online-mode)", cls: "wl-unknown" },
  blocked: { text: "Couldn't verify", cls: "wl-unknown" },
  error: { text: "Check failed", cls: "wl-unknown" },
};

function whitelistBadge(wl) {
  if (!wl || !wl.status) return "";
  const info = WHITELIST_INFO[wl.status] || WHITELIST_INFO.error;
  const when = wl.checked_at ? ` · ${relativeTime(wl.checked_at)}` : "";
  const who = wl.account ? ` (as ${wl.account})` : "";
  const tip = esc((wl.reason || "") + who);
  return `<span class="pill ${info.cls}" title="${tip}">${info.text}${when}</span>`;
}

function serverCard(server) {
  const st = server.status || {};
  const online = !!st.online;
  const card = document.createElement("div");
  card.className = `card ${online ? "online" : "offline"}`;

  const favicon = st.favicon
    ? `<img class="favicon" alt="" src="${esc(st.favicon)}" />`
    : `<div class="favicon" style="display:grid;place-items:center;font-size:16px">${online ? "⛏" : "⛔"}</div>`;

  const playersOnline = st.players_online;
  const playersMax = st.players_max;
  const pct = playersMax ? Math.min(100, Math.round((playersOnline / playersMax) * 100)) : 0;

  let playerTags = "";
  if (online && Array.isArray(st.players) && st.players.length) {
    playerTags = `<div class="players">${st.players.slice(0, 24).map((p) => `<span class="player-tag">${esc(p)}</span>`).join("")}</div>`;
  } else if (online && (playersOnline || 0) > 0 && st.sample_available === false) {
    playerTags = `<div class="players"><span class="player-tag">player list hidden by server</span></div>`;
  }

  const motd = online
    ? `<div class="motd">${esc(st.motd || "—")}</div>`
    : `<div class="motd offline-text">Offline${st.error ? " · " + esc(st.error) : ""}</div>`;

  card.innerHTML = `
    <div class="card-top">
      <div class="card-title">
        ${favicon}
        <div style="min-width:0">
          <div class="card-name">${esc(server.name)}</div>
          <div class="card-host">${esc(server.host)}:${esc(server.port)}</div>
        </div>
      </div>
      <span class="pill ${online ? "online" : "offline"}">
        <span class="dot"></span>${online ? "Online" : "Offline"}
      </span>
    </div>
    ${motd}
    <div class="metrics">
      <div class="metric">
        <span class="label">Players</span>
        <span class="value">${online ? `${playersOnline ?? "?"} / ${playersMax ?? "?"}` : "—"}</span>
      </div>
      <div class="metric">
        <span class="label">Version</span>
        <span class="value">${online ? esc(st.version || "unknown") : "—"}</span>
      </div>
      <div class="metric">
        <span class="label">Latency</span>
        <span class="value">${online && st.latency_ms != null ? `${Math.round(st.latency_ms)} ms` : "—"}</span>
      </div>
    </div>
    ${online && playersMax ? `<div class="bar"><span style="width:${pct}%"></span></div>` : ""}
    ${playerTags}
    <div class="wl-row">${whitelistBadge(server.whitelist)}</div>
    <div class="card-foot">
      <span class="when">checked ${relativeTime(st.ts)}</span>
      <div class="card-actions">
        <button class="btn ghost small" data-action="whitelist" title="Attempt a login probe to detect a whitelist">Whitelist check</button>
        <button class="btn ghost small" data-action="edit">Edit</button>
        <button class="btn ghost small" data-action="delete">Delete</button>
      </div>
    </div>
  `;

  card.querySelector('[data-action="delete"]').addEventListener("click", () => deleteServer(server));
  card.querySelector('[data-action="edit"]').addEventListener("click", () => editServer(server));
  card.querySelector('[data-action="whitelist"]').addEventListener("click", (event) => checkWhitelist(server, event.target));
  return card;
}

function renderEvents(data) {
  const list = $("#events");
  list.innerHTML = "";
  if (!data.events.length) {
    list.innerHTML = `<li class="muted">No activity recorded yet.</li>`;
    return;
  }
  const labels = {
    join: "joined",
    leave: "left",
    server_down: "went offline",
    server_up: "came online",
  };
  for (const ev of data.events) {
    const li = document.createElement("li");
    const who = ev.player ? esc(ev.player) : ev.type.startsWith("server") ? esc(ev.server_name) : "A player";
    const what = labels[ev.type] || ev.type;
    const detail = ev.detail && !ev.player ? ` (${esc(ev.detail)})` : "";
    li.innerHTML = `
      <span class="ev-time">${clockTime(ev.ts)}</span>
      <span><span class="ev-type ${ev.type}">${esc(who)}</span> ${esc(what)} <strong>${esc(ev.server_name)}</strong>${detail}</span>
    `;
    list.appendChild(li);
  }
}

/* ------------------------------------------------------------------ */
/* Actions                                                             */
/* ------------------------------------------------------------------ */
function flashError(message) {
  const el = $("#add-error");
  el.textContent = message || "";
  if (message) setTimeout(() => (el.textContent = ""), 6000);
}

async function loadState() {
  try {
    const data = await api("GET", "/api/state");
    renderSummary(data);
    renderServers(data);
    renderEvents(data);
    applyAuth(data.auth);
  } catch (err) {
    $("#summary").textContent = `Error: ${err.message}`;
  }
}

async function deleteServer(server) {
  if (!confirm(`Delete "${server.name}"?`)) return;
  try {
    await api("DELETE", `/api/servers/${server.id}`);
    loadState();
  } catch (err) {
    alert(`Delete failed: ${err.message}`);
  }
}

async function checkWhitelist(server, button) {
  const original = button.textContent;
  button.disabled = true;
  button.textContent = "Checking…";
  try {
    const { whitelist } = await api("POST", `/api/servers/${server.id}/whitelist`, {});
    const info = WHITELIST_INFO[whitelist.status] || WHITELIST_INFO.error;
    if (whitelist.status === "online_mode_unknown" || whitelist.status === "error") {
      alert(`${server.name}: ${info.text}\n${whitelist.reason || ""}`);
    }
    loadState();
  } catch (err) {
    alert(`Whitelist check failed: ${err.message}`);
  } finally {
    button.disabled = false;
    button.textContent = original;
  }
}

async function editServer(server) {
  const name = prompt("Server name:", server.name);
  if (name === null) return;
  const host = prompt("Host (optionally host:port):", `${server.host}:${server.port}`);
  if (host === null) return;
  try {
    await api("PUT", `/api/servers/${server.id}`, { name, host });
    loadState();
  } catch (err) {
    alert(`Update failed: ${err.message}`);
  }
}

/* ------------------------------------------------------------------ */
/* Settings modal                                                      */
/* ------------------------------------------------------------------ */
function openSettings() {
  api("GET", "/api/config")
    .then(({ config, poller }) => {
      const n = config.notify || {};
      const ntfy = n.ntfy || {};
      const form = $("#settings-form");
      form.enabled.checked = !!n.enabled;
      form.ntfy_server.value = ntfy.server || "";
      form.ntfy_topic.value = ntfy.topic || "";
      form.ntfy_token.value = ntfy.token || "";
      form.title_prefix.value = n.title_prefix || "";
      form.click_url.value = config.click_url || "";
      form.poll_interval_seconds.value = config.poll_interval_seconds || poller.interval;
      const on = n.notify_on || {};
      form.on_join.checked = !!on.join;
      form.on_leave.checked = !!on.leave;
      form.on_server_down.checked = !!on.server_down;
      form.on_server_up.checked = !!on.server_up;
      $("#test-result").textContent = "";
      $("#save-result").textContent = "";
      $("#backup-result").textContent = "";
      $("#settings-modal").classList.remove("hidden");
      api("GET", "/api/auth/status").then(applyAuth).catch(() => {});
      loadBackups();
    })
    .catch((err) => alert(`Could not load settings: ${err.message}`));
}

async function loadBackups() {
  try {
    const { backups, config } = await api("GET", "/api/backups");
    const interval = (config && config.interval_hours) || 24;
    $("#backup-interval").textContent = interval;
    renderBackups(backups);
  } catch (_) {
    /* non-fatal */
  }
}

function renderBackups(backups) {
  const list = $("#backup-list");
  list.innerHTML = "";
  if (!backups || !backups.length) {
    list.innerHTML = `<li>No backups yet.</li>`;
    return;
  }
  for (const b of backups.slice(0, 5)) {
    const li = document.createElement("li");
    const kb = Math.max(1, Math.round(b.size / 1024));
    li.textContent = `${b.file} · ${kb} KB · ${relativeTime(b.mtime)}`;
    list.appendChild(li);
  }
}

async function backupNow() {
  const btn = $("#btn-backup");
  const result = $("#backup-result");
  btn.disabled = true;
  result.textContent = "Backing up…";
  try {
    const res = await api("POST", "/api/backup", {});
    result.textContent = res.file ? `Saved ${res.file}` : "Backups are disabled.";
    renderBackups(res.backups);
  } catch (err) {
    result.textContent = `Failed: ${err.message}`;
  } finally {
    btn.disabled = false;
  }
}

function closeSettings() {
  $("#settings-modal").classList.add("hidden");
}

async function saveSettings(event) {
  event.preventDefault();
  const form = $("#settings-form");
  const payload = {
    click_url: form.click_url.value.trim(),
    poll_interval_seconds: Number(form.poll_interval_seconds.value) || 60,
    notify: {
      enabled: form.enabled.checked,
      title_prefix: form.title_prefix.value.trim() || "MC Status",
      ntfy: {
        server: form.ntfy_server.value.trim() || "https://ntfy.sh",
        topic: form.ntfy_topic.value.trim(),
        token: form.ntfy_token.value.trim(),
      },
      notify_on: {
        join: form.on_join.checked,
        leave: form.on_leave.checked,
        server_down: form.on_server_down.checked,
        server_up: form.on_server_up.checked,
      },
    },
  };
  const result = $("#save-result");
  try {
    await api("PUT", "/api/config", payload);
    result.textContent = "Saved.";
    loadState();
    setTimeout(closeSettings, 600);
  } catch (err) {
    result.textContent = `Error: ${err.message}`;
  }
}

async function sendTest() {
  const form = $("#settings-form");
  const result = $("#test-result");
  result.textContent = "Sending…";
  try {
    const pre = {
      click_url: form.click_url.value.trim(),
      notify: {
        enabled: true,
        title_prefix: form.title_prefix.value.trim() || "MC Status",
        ntfy: {
          server: form.ntfy_server.value.trim() || "https://ntfy.sh",
          topic: form.ntfy_topic.value.trim(),
          token: form.ntfy_token.value.trim(),
        },
      },
    };
    await api("PUT", "/api/config", pre);
    const res = await api("POST", "/api/test-notify", {});
    result.textContent = `Sent ✓ ${res.detail || ""}`;
  } catch (err) {
    result.textContent = `Failed: ${err.message}`;
  }
}

/* ------------------------------------------------------------------ */
/* Minecraft account sign-in (device-code flow)                        */
/* ------------------------------------------------------------------ */
let authTimer = null;

function stopAuthPolling() {
  if (authTimer) {
    clearInterval(authTimer);
    authTimer = null;
  }
}

function applyAuth(auth) {
  if (!auth) return;
  const statusEl = $("#account-status");
  const signIn = $("#btn-signin");
  const signOut = $("#btn-signout");
  const box = $("#device-box");
  const flow = auth.flow || {};

  if (auth.logged_in) {
    statusEl.textContent = `Signed in as ${auth.name || "?"}`;
    statusEl.className = "account-status signed-in";
    signIn.classList.add("hidden");
    signOut.classList.remove("hidden");
    box.classList.add("hidden");
    stopAuthPolling();
    return;
  }

  signOut.classList.add("hidden");

  if (flow.state === "pending") {
    signIn.classList.add("hidden");
    box.classList.remove("hidden");
    const uri = flow.verification_uri || "https://microsoft.com/link";
    const link = $("#device-uri");
    link.textContent = uri;
    link.href = uri;
    $("#device-code").textContent = flow.user_code || "";
    $("#device-status").textContent = "Waiting for authorization…";
    if (!authTimer) {
      authTimer = setInterval(pollAuth, Math.max(3, flow.interval || 5) * 1000);
    }
  } else if (flow.state === "error") {
    signIn.classList.remove("hidden");
    box.classList.remove("hidden");
    $("#device-status").textContent = flow.error || "Sign-in failed.";
    stopAuthPolling();
  } else {
    signIn.classList.remove("hidden");
    box.classList.add("hidden");
    if (auth.crypto_available === false) {
      statusEl.textContent =
        "Not signed in. Online-mode checks are unavailable: " +
        (auth.crypto_error || "the 'cryptography' package is missing") +
        " — start the app with ./run.sh.";
    } else {
      statusEl.textContent = "Not signed in.";
    }
    statusEl.className = "account-status";
    stopAuthPolling();
  }
}

async function pollAuth() {
  try {
    applyAuth(await api("GET", "/api/auth/poll"));
  } catch (err) {
    $("#device-status").textContent = `Error: ${err.message}`;
    stopAuthPolling();
  }
}

async function signIn() {
  $("#account-status").textContent = "Requesting a sign-in code…";
  try {
    applyAuth(await api("POST", "/api/auth/device", {}));
  } catch (err) {
    $("#account-status").textContent = `Sign-in failed: ${err.message}`;
  }
}

async function signOut() {
  try {
    applyAuth(await api("POST", "/api/auth/logout", {}));
  } catch (err) {
    alert(`Sign out failed: ${err.message}`);
  }
}

/* ------------------------------------------------------------------ */
/* Wiring                                                              */
/* ------------------------------------------------------------------ */
function wire() {
  $("#add-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.target;
    try {
      await api("POST", "/api/servers", {
        name: form.name.value.trim(),
        host: form.host.value.trim(),
      });
      form.reset();
      flashError("");
      loadState();
    } catch (err) {
      flashError(err.message);
    }
  });

  $("#btn-poll").addEventListener("click", async () => {
    try {
      await api("POST", "/api/poll", {});
      setTimeout(loadState, 1500);
    } catch (err) {
      alert(`Poll failed: ${err.message}`);
    }
  });

  $("#btn-settings").addEventListener("click", openSettings);
  $("#btn-close-settings").addEventListener("click", closeSettings);
  $("#btn-signin").addEventListener("click", signIn);
  $("#btn-signout").addEventListener("click", signOut);
  $("#btn-test").addEventListener("click", sendTest);
  $("#btn-backup").addEventListener("click", backupNow);
  $("#btn-clear-events").addEventListener("click", loadState);
  $("#settings-form").addEventListener("submit", saveSettings);
  $("#settings-modal").addEventListener("click", (event) => {
    if (event.target.id === "settings-modal") closeSettings();
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") closeSettings();
  });
}

function start() {
  wire();
  loadState();
  refreshTimer = setInterval(loadState, REFRESH_MS);
  document.addEventListener("visibilitychange", () => {
    if (document.hidden) {
      clearInterval(refreshTimer);
    } else {
      loadState();
      refreshTimer = setInterval(loadState, REFRESH_MS);
    }
  });
}

start();
