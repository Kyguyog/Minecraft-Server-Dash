#!/usr/bin/env python3
"""Web UI for Minecraft Server Scanner

Features:
1. Scan network ranges (e.g., 104.193.0.0/16)
2. View all found servers from found_servers.json with filters
   - Filter by servers with players online (online > 0)
   - Filter by minimum player count
   - Search by host/IP, MOTD, or version
"""

import json
import os
import ipaddress
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Any

from flask import Flask, request, jsonify, render_template_string, send_from_directory
from mcstatus import JavaServer
from tqdm import tqdm

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_FILE = os.path.join(BASE_DIR, "found_servers.json")
SCANNED_FILE = os.path.join(BASE_DIR, "scanned_ranges.json")
PROGRESS_FILE = os.path.join(BASE_DIR, "scan_progress.json")

MAX_WORKERS = 500
STATIC_DIR = os.path.join(BASE_DIR, "static")

# Guards read-modify-write of the JSON data files.
data_lock = threading.Lock()

# Scan queue state. Scans run one at a time; the rest wait in `scan_jobs`.
scan_lock = threading.Lock()
scan_jobs: List["ScanJob"] = []
running_scan: Optional["ScanJob"] = None
scan_manager_thread: Optional[threading.Thread] = None
scan_wakeup = threading.Event()

# Thread count shared by every scan (one setting for all).
scan_threads = 100

# Monotonic ordering keys. Normal scans get increasing positive keys (FIFO);
# prioritized scans get decreasing negative keys so they sort first.
_scan_seq = 0
_scan_priority_seq = 0

# Scans recovered from disk that the user has not decided to resume yet.
pending_scan_resume: List["ScanJob"] = []

# Metadata refresh state tracking
refresh_state = {
    "running": False,
    "progress": 0,
    "total": 0,
    "updated": 0,
    "failed": 0,
    "elapsed": 0,
    "message": "",
    "workers": 0,
    "error": None,
}
refresh_lock = threading.Lock()
refresh_thread: Optional[threading.Thread] = None

# Live-adjustable concurrency limiter (set while a refresh is running).
refresh_limiter: Optional["AdjustableSemaphore"] = None

# Limiter for the currently running scan (shared thread count).
running_limiter: Optional["AdjustableSemaphore"] = None


class AdjustableSemaphore:
    """A semaphore whose capacity can be changed while it is in use."""

    def __init__(self, capacity: int):
        self._cond = threading.Condition()
        self._capacity = max(1, int(capacity))
        self._available = self._capacity

    def acquire(self) -> None:
        with self._cond:
            while self._available <= 0:
                self._cond.wait()
            self._available -= 1

    def release(self) -> None:
        with self._cond:
            self._available += 1
            self._cond.notify()

    def set_capacity(self, capacity: int) -> None:
        capacity = max(1, int(capacity))
        with self._cond:
            self._available += capacity - self._capacity
            self._capacity = capacity
            if self._available > 0:
                self._cond.notify_all()


def load_servers() -> List[Dict[str, Any]]:
    if not os.path.exists(OUTPUT_FILE):
        return []
    try:
        with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, list):
                return data
            return []
    except Exception:
        return []


def _atomic_write_json(path: str, data: Any) -> None:
    try:
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        os.replace(tmp, path)
    except Exception:
        pass


def save_servers(servers: List[Dict[str, Any]]) -> None:
    _atomic_write_json(OUTPUT_FILE, servers)


def format_duration(seconds: float) -> str:
    try:
        seconds = float(seconds)
    except (TypeError, ValueError):
        return "--"
    if seconds < 0:
        seconds = 0
    if seconds < 1:
        return "<1s"
    total = int(round(seconds))
    if total < 60:
        return f"{total}s"
    m, s = divmod(total, 60)
    if m < 60:
        return f"{m}m {s}s"
    h, m = divmod(m, 60)
    if h < 24:
        return f"{h}h {m}m {s}s"
    d, h = divmod(h, 24)
    return f"{d}d {h}h {m}m"


def load_scanned_ranges() -> Dict[str, Any]:
    if not os.path.exists(SCANNED_FILE):
        return {}
    try:
        with open(SCANNED_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_scanned_ranges(ranges: Dict[str, Any]) -> None:
    _atomic_write_json(SCANNED_FILE, ranges)


def canonical_network(network: str) -> Optional[str]:
    try:
        return str(ipaddress.ip_network(network, strict=False))
    except ValueError:
        return None


def record_scanned_range(network: str, found: int) -> None:
    canonical = canonical_network(network)
    if canonical is None:
        return
    with data_lock:
        ranges = load_scanned_ranges()
        entry = ranges.get(canonical, {"network": canonical, "times": 0, "found": 0})
        entry["times"] = int(entry.get("times", 0)) + 1
        entry["found"] = found
        entry["last_scanned"] = time.time()
        ranges[canonical] = entry
        save_scanned_ranges(ranges)


def load_scan_progress() -> Optional[Dict[str, Any]]:
    if not os.path.exists(PROGRESS_FILE):
        return None
    try:
        with open(PROGRESS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, dict) else None
    except Exception:
        return None


def clear_scan_progress() -> None:
    """Forget any recoverable scans (in memory and on disk)."""
    pending_scan_resume.clear()
    try:
        if os.path.exists(PROGRESS_FILE):
            os.remove(PROGRESS_FILE)
    except Exception:
        pass


class ScanJob:
    """A single network scan that can be queued, paused and resumed."""

    def __init__(self, network: str, timeout: float = 0.4, priority_key: Optional[int] = None):
        global _scan_seq
        _scan_seq += 1
        self.id = _scan_seq
        self.network = network
        self.timeout = timeout
        self.priority_key = _scan_seq if priority_key is None else priority_key
        self.status = "queued"
        self.total = 0
        self.progress = 0
        self.found: List[Dict[str, Any]] = []
        self.remaining: Optional[List[str]] = None
        self.pause_requested = False
        self.elapsed = 0.0
        self.message = "Queued"
        self.error: Optional[str] = None
        self.finished_at: Optional[float] = None

    def public(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "network": self.network,
            "status": self.status,
            "total": self.total,
            "progress": self.progress,
            "found_in_batch": len(self.found),
            "elapsed": self.elapsed,
            "message": self.message,
            "error": self.error,
            "priority_key": self.priority_key,
        }

    def to_saved(self) -> Dict[str, Any]:
        data = self.public()
        data.update(
            {
                "timeout": self.timeout,
                "remaining": self.remaining,
                "found": self.found,
            }
        )
        return data

    @classmethod
    def from_saved(cls, data: Dict[str, Any]) -> "ScanJob":
        job = cls.__new__(cls)
        job.id = int(data.get("id", 0) or 0)
        job.network = data.get("network", "")
        job.timeout = float(data.get("timeout", 0.4) or 0.4)
        job.priority_key = int(data.get("priority_key", 0) or 0)
        job.status = data.get("status", "paused")
        job.total = int(data.get("total", 0) or 0)
        job.progress = int(data.get("progress", 0) or 0)
        job.found = list(data.get("found", []) or [])
        remaining = data.get("remaining")
        job.remaining = list(remaining) if remaining else None
        job.pause_requested = False
        job.elapsed = float(data.get("elapsed", 0) or 0)
        job.message = data.get("message", "")
        job.error = data.get("error")
        job.finished_at = None
        return job


def _persist_scan_queue() -> None:
    with scan_lock:
        saved = [j.to_saved() for j in scan_jobs if j.status in ("queued", "running", "paused")]
        threads = scan_threads
    with data_lock:
        _atomic_write_json(
            PROGRESS_FILE,
            {"jobs": saved, "threads": threads, "updated_at": time.time()},
        )


def _scan_queue_payload() -> Dict[str, Any]:
    with scan_lock:
        jobs = [j.public() for j in scan_jobs]
        threads = scan_threads
    return {"threads": threads, "jobs": jobs}


def _ensure_scan_manager() -> None:
    global scan_manager_thread
    with scan_lock:
        if scan_manager_thread is None or not scan_manager_thread.is_alive():
            scan_manager_thread = threading.Thread(
                target=_scan_manager_loop, daemon=True, name="scan-manager"
            )
            scan_manager_thread.start()


def _scan_manager_loop() -> None:
    global running_scan
    while True:
        now = time.time()
        with scan_lock:
            # Drop finished jobs after a short grace period so the UI can show them.
            scan_jobs[:] = [
                j
                for j in scan_jobs
                if not (
                    j.status in ("done", "failed")
                    and now - (j.finished_at or now) >= 10
                )
            ]
            candidates = [j for j in scan_jobs if j.status in ("queued", "paused")]
            job = min(candidates, key=lambda j: j.priority_key) if candidates else None
            if job is not None:
                running_scan = job
                job.status = "running"

        if job is None:
            scan_wakeup.wait(timeout=2.0)
            scan_wakeup.clear()
            continue

        try:
            _execute_scan_job(job)
        except Exception as e:  # pragma: no cover - defensive
            with scan_lock:
                job.status = "failed"
                job.error = str(e)
                job.message = f"Error: {e}"
                job.finished_at = time.time()

        with scan_lock:
            running_scan = None
        _persist_scan_queue()
        scan_wakeup.set()


def _execute_scan_job(job: ScanJob) -> None:
    global running_limiter

    if job.remaining is None:
        net = ipaddress.ip_network(job.network, strict=False)
        job.remaining = [str(ip) for ip in net.hosts()]
        job.total = len(job.remaining)

    remaining_set = set(job.remaining)
    found_batch = list(job.found)
    scanned_count = job.total - len(remaining_set)
    timeout = job.timeout

    with scan_lock:
        job.status = "running"
        job.progress = scanned_count
        job.message = f"Scanning {job.total:,} IPs..."
        job.error = None
        job.pause_requested = False

    # Persist immediately so the scan survives a crash even before the first
    # periodic snapshot.
    _persist_scan_queue()

    start_time = time.time()
    last_persist = start_time

    def check_ip_custom(ip):
        address = f"{ip}:25565"
        try:
            server = JavaServer.lookup(address, timeout=timeout)
            status = server.status()
            return {
                "ip": str(ip),
                "address": address,
                "version": status.version.name,
                "motd": str(status.description),
                "online": status.players.online,
                "max": status.players.max,
                "status": "online",
            }
        except Exception:
            return None

    limiter = AdjustableSemaphore(scan_threads)
    with scan_lock:
        running_limiter = limiter

    def handle_result(ip, future):
        nonlocal scanned_count, last_persist
        try:
            result = future.result()
        except Exception:
            result = None

        snapshot = False
        with scan_lock:
            remaining_set.discard(str(ip))
            scanned_count += 1
            if result:
                found_batch.append(result)
            job.progress = scanned_count
            job.elapsed = time.time() - start_time
            now = time.time()
            if now - last_persist >= 5:
                last_persist = now
                job.remaining = list(remaining_set)
                job.found = list(found_batch)
                snapshot = True

        if snapshot:
            _persist_scan_queue()

        limiter.release()

    try:
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            for ip in list(remaining_set):
                if job.pause_requested:
                    break
                limiter.acquire()
                future = executor.submit(check_ip_custom, ip)
                future.add_done_callback(lambda f, ip=ip: handle_result(ip, f))
            executor.shutdown(wait=True)
    finally:
        with scan_lock:
            running_limiter = None

    job.remaining = sorted(remaining_set)
    job.found = list(found_batch)
    job.progress = job.total - len(remaining_set)
    job.elapsed = time.time() - start_time

    if job.pause_requested:
        with scan_lock:
            job.status = "paused"
            job.message = "Paused"
        return

    if found_batch:
        with data_lock:
            existing_data = load_servers()
            existing_ips = {s["ip"] for s in existing_data}
            new_adds = [s for s in found_batch if s["ip"] not in existing_ips]
            if new_adds:
                save_servers(existing_data + new_adds)

    record_scanned_range(job.network, len(found_batch))

    with scan_lock:
        job.status = "done"
        job.progress = job.total
        job.remaining = []
        job.finished_at = time.time()
        job.message = (
            f"Completed in {format_duration(job.elapsed)}. "
            f"Found {len(found_batch)} servers in this batch."
        )


def _load_pending_scan_jobs() -> None:
    global _scan_seq
    data = load_scan_progress()
    if not data:
        return

    jobs_data = data.get("jobs")
    if jobs_data is None and data.get("remaining"):
        # Legacy single-scan progress file.
        jobs_data = [
            {
                "id": 1,
                "network": data.get("target_network", ""),
                "timeout": data.get("timeout", 0.4),
                "priority_key": 1,
                "status": "paused",
                "total": data.get("total", 0),
                "progress": data.get("scanned_count", 0),
                "found": data.get("found", []),
                "remaining": data.get("remaining", []),
                "message": "Interrupted by an unexpected shutdown",
            }
        ]

    recovered: List[ScanJob] = []
    for entry in jobs_data or []:
        try:
            job = ScanJob.from_saved(entry)
        except Exception:
            continue
        if job.status == "running":
            job.status = "paused"
        if job.status in ("queued", "paused") and (job.remaining or job.status == "queued"):
            if not job.message or job.status == "paused":
                job.message = "Interrupted by an unexpected shutdown"
            recovered.append(job)

    if recovered:
        pending_scan_resume.extend(recovered)
        _scan_seq = max(_scan_seq, max(j.id for j in recovered))


_load_pending_scan_jobs()


def check_ip(ip) -> Optional[Dict[str, Any]]:
    address = f"{ip}:25565"
    try:
        server = JavaServer.lookup(address, timeout=0.4)
        status = server.status()
        return {
            "ip": str(ip),
            "address": address,
            "version": status.version.name,
            "motd": str(status.description),
            "online": status.players.online,
            "max": status.players.max,
            "status": "online",
        }
    except Exception:
        return None



def run_refresh(addresses: List[str], timeout: float = 1.5, max_workers: int = 32) -> None:
    global refresh_state, refresh_limiter

    with refresh_lock:
        if refresh_state["running"]:
            return
        refresh_state.update(
            {
                "running": True,
                "progress": 0,
                "total": len(addresses),
                "updated": 0,
                "failed": 0,
                "elapsed": 0,
                "message": f"Refreshing {len(addresses):,} server(s)...",
                "workers": max_workers,
                "error": None,
            }
        )

    try:
        def refresh_one(address):
            try:
                server = JavaServer.lookup(address, timeout=timeout)
                status = server.status()
                return address, {
                    "version": status.version.name,
                    "motd": str(status.description),
                    "online": status.players.online,
                    "max": status.players.max,
                    "status": "online",
                }
            except Exception:
                return address, None

        results: Dict[str, Any] = {}
        start_time = time.time()
        updated = 0
        failed = 0
        done = 0

        refresh_limiter = AdjustableSemaphore(max_workers)

        def handle_result(address, future):
            nonlocal updated, failed, done
            try:
                _, result = future.result()
            except Exception:
                result = None

            with refresh_lock:
                results[address] = result
                if result is not None:
                    updated += 1
                else:
                    failed += 1
                done += 1
                refresh_state["progress"] = done
                refresh_state["updated"] = updated
                refresh_state["failed"] = failed
                refresh_state["elapsed"] = time.time() - start_time

            refresh_limiter.release()

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            try:
                for address in addresses:
                    refresh_limiter.acquire()
                    future = executor.submit(refresh_one, address)
                    future.add_done_callback(lambda f, a=address: handle_result(a, f))
                executor.shutdown(wait=True)
            finally:
                refresh_limiter = None

        with data_lock:
            servers = load_servers()
            for s in servers:
                key = s.get("address") or s.get("ip")
                if key in results:
                    result = results[key]
                    if result:
                        s.update(result)
                    else:
                        s["status"] = "offline"
            save_servers(servers)

        elapsed = time.time() - start_time
        with refresh_lock:
            refresh_state.update(
                {
                    "running": False,
                    "progress": len(addresses),
                    "updated": updated,
                    "failed": failed,
                    "elapsed": elapsed,
                    "message": f"Refreshed {updated:,} of {len(addresses):,} server(s) in {format_duration(elapsed)}.",
                }
            )
    except Exception as e:
        with refresh_lock:
            refresh_state.update({"running": False, "error": str(e), "message": f"Error: {e}"})
        refresh_limiter = None


@app.route("/")
def index():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Minecraft Server Scanner - Web UI</title>
        <style>
            * { box-sizing: border-box; margin: 0; padding: 0; font-family: system-ui, -apple-system, sans-serif; }
            body { background: #1a1a1a; color: #e0e0e0; line-height: 1.6; }
            .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
            header { background: #2d2d2d; padding: 20px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.3); }
            h1 { color: #4caf50; margin-bottom: 10px; }
            .section { background: #2d2d2d; padding: 20px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.3); }
            h2 { color: #4caf50; margin-bottom: 15px; }
            .form-group { margin-bottom: 15px; }
            label { display: block; margin-bottom: 5px; font-weight: 600; }
            input, select, button { padding: 10px 12px; border: 1px solid #444; border-radius: 4px; background: #1a1a1a; color: #e0e0e0; font-size: 14px; }
            input[type="text"], input[type="number"] { width: 100%; max-width: 400px; }
            button { background: #4caf50; color: #fff; cursor: pointer; border: none; font-weight: 600; transition: background 0.2s; }
            button:hover { background: #45a049; }
            button:disabled { background: #666; cursor: not-allowed; }
            .progress-container { display: none; margin-top: 15px; }
            .progress-bar { width: 100%; height: 20px; background: #1a1a1a; border-radius: 4px; overflow: hidden; border: 1px solid #444; }
            .progress-fill { height: 100%; background: #4caf50; transition: width 0.3s; }
            .progress-info { margin-top: 10px; font-size: 14px; color: #aaa; }
            .filters { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px; margin-bottom: 15px; }
            .filter-row { display: flex; align-items: center; gap: 10px; }
            .filter-row input[type="checkbox"] { width: auto; }
            table { width: 100%; border-collapse: collapse; margin-top: 15px; }
            th, td { padding: 12px; text-align: left; border-bottom: 1px solid #444; }
            th { background: #1a1a1a; color: #4caf50; font-weight: 600; position: sticky; top: 0; z-index: 10; }
            tr:hover { background: #333; }
            .online-yes { color: #4caf50; font-weight: 600; }
            .online-no { color: #999; }
            .badge { padding: 4px 8px; border-radius: 4px; font-size: 12px; background: #4caf50; color: #fff; }
            .stats { display: flex; gap: 20px; margin-bottom: 15px; flex-wrap: wrap; }
            .stat { background: #1a1a1a; padding: 10px 15px; border-radius: 4px; border: 1px solid #444; }
            .stat-value { font-size: 24px; font-weight: 700; color: #4caf50; }
            .stat-label { font-size: 12px; color: #aaa; }
            .search-box { width: 100%; max-width: 500px; }
            .actions { display: flex; gap: 10px; flex-wrap: wrap; margin-bottom: 15px; }
            .btn-secondary { background: #2196f3; }
            .btn-secondary:hover { background: #1976d2; }
            .btn-danger { background: #f44336; }
            .btn-danger:hover { background: #d32f2f; }
            .motd { max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
            .error { color: #f44336; margin-top: 10px; }
            .success { color: #4caf50; margin-top: 10px; }
            .status-offline { color: #f44336; font-weight: 600; }
            .modal-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.6); display: flex; align-items: center; justify-content: center; z-index: 100; }
            .modal { background: #2d2d2d; padding: 20px; border-radius: 8px; min-width: 320px; max-width: 90vw; box-shadow: 0 4px 12px rgba(0,0,0,0.5); }
            .modal h2 { margin-bottom: 15px; }
        </style>
    </head>
    <body>
        <div class="container">
            <header>
                <h1>Minecraft Server Scanner</h1>
                <p>Scan network ranges and browse discovered Minecraft servers</p>
            </header>

            <section class="section">
                <h2>Scan Network Range</h2>
                <form id="scanForm">
                    <div class="form-group">
                        <label for="network">Network Block (CIDR)</label>
                        <input type="text" id="network" name="network" placeholder="e.g., 104.193.0.0/16 or 45.63.0.0/16" value="104.193.0.0/16">
                    </div>
                    <div class="form-group">
                        <label for="timeout">Timeout (seconds)</label>
                        <input type="number" id="timeout" name="timeout" value="0.4" min="0.1" max="5" step="0.1">
                    </div>
                    <button type="submit" id="scanBtn">Add to Scan Queue</button>
                    <div id="scanError" class="error"></div>
                    <div id="scanSuccess" class="success"></div>
                    <div id="scanQueueSection" style="margin-top: 15px;">
                        <div class="filter-row" style="margin-bottom: 10px;">
                            <label for="scanThreadsInput">Threads (all scans):</label>
                            <input type="number" id="scanThreadsInput" min="1" max="500" value="100" style="max-width: 100px;">
                            <button type="button" id="scanThreadsApply" class="btn-secondary">Apply</button>
                        </div>
                        <div id="scanQueue"></div>
                    </div>
                </form>
            </section>

            <section class="section">
                <h2>Found Servers</h2>
                <div class="stats" id="stats"></div>
                <div class="filters">
                    <div class="form-group">
                        <label for="search">Search</label>
                        <div class="filter-row">
                            <select id="searchField">
                                <option value="all">All fields</option>
                                <option value="ip">IP</option>
                                <option value="motd">MOTD</option>
                                <option value="version">Version</option>
                            </select>
                            <input type="text" id="search" class="search-box" placeholder="Search...">
                        </div>
                        <div class="filter-row" style="margin-top: 8px;">
                            <input type="checkbox" id="exactMatch">
                            <label for="exactMatch">Exact match</label>
                        </div>
                    </div>
                    <div class="form-group">
                        <label for="minPlayers">Minimum Players Online</label>
                        <input type="number" id="minPlayers" value="0" min="0">
                    </div>
                    <div class="form-group">
                        <label for="maxPlayers">Maximum Players Online</label>
                        <input type="number" id="maxPlayers" placeholder="No limit" min="0">
                    </div>
                    <div class="form-group">
                        <label for="sortBy">Sort By</label>
                        <select id="sortBy">
                            <option value="default">Default (as found)</option>
                            <option value="online_desc">Players Online (High to Low)</option>
                            <option value="online_asc">Players Online (Low to High)</option>
                            <option value="players_full">Most Full</option>
                            <option value="ip">IP Address</option>
                            <option value="version">Version</option>
                        </select>
                    </div>
                </div>
                <div class="actions">
                    <button type="button" id="exportBtn" class="btn-secondary">Export JSON</button>
                    <button type="button" id="exportFilteredBtn" class="btn-secondary">Export Filtered JSON</button>
                    <button type="button" id="refreshMetaBtn" class="btn-secondary">Refresh Player Counts</button>
                </div>
                <div id="refreshError" class="error"></div>
                <div id="refreshSuccess" class="success"></div>
                <div id="refreshProgressContainer" class="progress-container">
                    <div class="progress-bar">
                        <div id="refreshProgressFill" class="progress-fill" style="width: 0%"></div>
                    </div>
                    <div id="refreshProgressInfo" class="progress-info"></div>
                    <div class="filter-row" id="refreshWorkersRow" style="margin-top: 8px; display: none;">
                        <label for="refreshWorkersLive">Threads:</label>
                        <input type="number" id="refreshWorkersLive" min="1" max="500" value="32" style="max-width: 100px;">
                        <button type="button" id="refreshWorkersApply" class="btn-secondary">Apply</button>
                    </div>
                </div>
                <div id="resultCount" class="progress-info"></div>
                <div style="overflow-x: auto;">
                    <table>
                        <thead>
                            <tr>
                                <th>IP Address</th>
                                <th>Version</th>
                                <th>MOTD</th>
                                <th>Players</th>
                                <th>Max</th>
                                <th>Status</th>
                            </tr>
                        </thead>
                        <tbody id="serversTable"></tbody>
                    </table>
                </div>
                <div id="noResults" style="text-align: center; padding: 40px; color: #999; display: none;">
                    No servers found matching your filters.
                </div>
            </section>
        </div>

        <div id="refreshModal" class="modal-overlay" style="display: none;">
            <div class="modal">
                <h2>Refresh Player Counts</h2>
                <div class="form-group">
                    <label>Scope</label>
                    <div class="filter-row">
                        <input type="radio" name="refreshScope" id="scopeFiltered" value="filtered" checked>
                        <label for="scopeFiltered">Filtered list (<span id="refreshFilteredCount">0</span> servers)</label>
                    </div>
                    <div class="filter-row">
                        <input type="radio" name="refreshScope" id="scopeAll" value="all">
                        <label for="scopeAll">Whole database (<span id="refreshAllCount">0</span> servers)</label>
                    </div>
                </div>
                <div class="form-group">
                    <label for="refreshWorkers">Threads</label>
                    <input type="number" id="refreshWorkers" value="32" min="1" max="500">
                </div>
                <div class="actions">
                    <button type="button" id="refreshCancelBtn" class="btn-secondary">Cancel</button>
                    <button type="button" id="refreshConfirmBtn">Start Refresh</button>
                </div>
            </div>
        </div>

        <div id="resumeModal" class="modal-overlay" style="display: none;">
            <div class="modal">
                <h2>Unfinished Scan</h2>
                <p id="resumeMessage" style="margin-bottom: 15px;"></p>
                <div class="actions">
                    <button type="button" id="resumeDiscardBtn" class="btn-danger">Discard</button>
                    <button type="button" id="resumeConfirmBtn">Resume Scan</button>
                </div>
            </div>
        </div>
        <script>
            let servers = [];
            let refreshInterval = null;
            let scanQueueInterval = null;
            let refreshProgressInterval = null;
            const serversRefreshedFor = new Set();

            async function fetchServers() {
                try {
                    const res = await fetch('/api/servers');
                    const data = await res.json();
                    servers = data.servers || [];
                    renderServers();
                    renderStats();
                } catch (e) {
                    console.error('Failed to fetch servers:', e);
                }
            }

            function renderStats() {
                const total = servers.length;
                const withPlayers = servers.filter(s => (s.online || 0) > 0).length;
                const totalPlayers = servers.reduce((sum, s) => sum + (s.online || 0), 0);
                document.getElementById('stats').innerHTML = `
                    <div class="stat"><div class="stat-value">${total.toLocaleString()}</div><div class="stat-label">Total Servers</div></div>
                    <div class="stat"><div class="stat-value">${withPlayers.toLocaleString()}</div><div class="stat-label">With Players Online</div></div>
                    <div class="stat"><div class="stat-value">${totalPlayers.toLocaleString()}</div><div class="stat-label">Total Players Online</div></div>
                `;
            }

            function getFilteredServers() {
                const search = document.getElementById('search').value.trim().toLowerCase();
                const searchField = document.getElementById('searchField').value;
                const exactMatch = document.getElementById('exactMatch').checked;
                const minPlayers = parseInt(document.getElementById('minPlayers').value) || 0;
                const maxRaw = document.getElementById('maxPlayers').value.trim();
                const maxPlayers = maxRaw === '' ? Infinity : (parseInt(maxRaw) || 0);
                const sortBy = document.getElementById('sortBy').value;

                function searchValues(s) {
                    const all = [s.ip, s.address, s.motd, s.version];
                    if (searchField === 'ip') return [s.ip, s.address];
                    if (searchField === 'motd') return [s.motd];
                    if (searchField === 'version') return [s.version];
                    return all;
                }

                let filtered = servers.filter(s => {
                    let matchesSearch = true;
                    if (search) {
                        const values = searchValues(s).map(v => (v || '').toLowerCase());
                        matchesSearch = values.some(v => exactMatch ? v === search : v.includes(search));
                    }
                    const matchesMin = (s.online || 0) >= minPlayers;
                    const matchesMax = (s.online || 0) <= maxPlayers;
                    return matchesSearch && matchesMin && matchesMax;
                });

                filtered.sort((a, b) => {
                    switch (sortBy) {
                        case 'online_desc': return (b.online||0) - (a.online||0);
                        case 'online_asc': return (a.online||0) - (b.online||0);
                        case 'players_full': {
                            const fa = (a.max||0) > 0 ? (a.online||0)/(a.max||0) : 0;
                            const fb = (b.max||0) > 0 ? (b.online||0)/(b.max||0) : 0;
                            return fb - fa;
                        }
                        case 'ip': return (a.ip||'').localeCompare(b.ip||'');
                        case 'version': return (a.version||'').localeCompare(b.version||'');
                        default: return 0;
                    }
                });

                return filtered;
            }

            function escapeHtml(str) {
                if (!str) return '';
                const div = document.createElement('div');
                div.textContent = str;
                return div.innerHTML;
            }

            function formatDuration(seconds) {
                if (!isFinite(seconds) || seconds < 0) return '--';
                if (seconds < 1) return '<1s';
                seconds = Math.round(seconds);
                if (seconds < 60) return seconds + 's';
                const m = Math.floor(seconds / 60);
                const s = seconds % 60;
                if (m < 60) return `${m}m ${s}s`;
                const h = Math.floor(m / 60);
                if (h < 24) return `${h}h ${m % 60}m ${s}s`;
                const d = Math.floor(h / 24);
                return `${d}d ${h % 24}h ${m % 60}m`;
            }

            function renderServers() {
                const filtered = getFilteredServers();
                const tbody = document.getElementById('serversTable');
                const noResults = document.getElementById('noResults');
                document.getElementById('resultCount').textContent =
                    `Showing ${filtered.length.toLocaleString()} of ${servers.length.toLocaleString()} servers`;

                if (filtered.length === 0) {
                    tbody.innerHTML = '';
                    noResults.style.display = 'block';
                    return;
                }
                noResults.style.display = 'none';

                tbody.innerHTML = filtered.map(s => {
                    const online = s.online || 0;
                    const max = s.max || 0;
                    const onlineClass = online > 0 ? 'online-yes' : 'online-no';
                    const offline = s.status === 'offline';
                    return `
                        <tr>
                            <td><a href="minecraft://${s.address || s.ip}" style="color:#4caf50;">${escapeHtml(s.address || s.ip)}</a></td>
                            <td>${escapeHtml(s.version)}</td>
                            <td class="motd" title="${escapeHtml(s.motd)}">${escapeHtml(s.motd)}</td>
                            <td class="${onlineClass}">${online}</td>
                            <td>${max}</td>
                            <td>${offline ? '<span class="status-offline">Offline</span>' : '<span class="badge">Online</span>'}</td>
                        </tr>
                    `;
                }).join('');
            }

            async function fetchScanQueue() {
                try {
                    const res = await fetch('/api/scan/queue');
                    const data = await res.json();
                    renderScanQueue(data);
                } catch (e) {
                    console.error('Failed to fetch scan queue:', e);
                }
            }

            function renderScanQueue(data) {
                const jobs = data.jobs || [];
                const threadsInput = document.getElementById('scanThreadsInput');
                if (document.activeElement !== threadsInput && data.threads) {
                    threadsInput.value = data.threads;
                }

                const queueEl = document.getElementById('scanQueue');
                const statusLabels = {
                    queued: 'Queued', running: 'Running', paused: 'Paused',
                    done: 'Done', failed: 'Failed'
                };

                queueEl.innerHTML = jobs.map(job => {
                    const pct = job.total > 0 ? (job.progress / job.total * 100) : 0;
                    let info = `${job.progress.toLocaleString()} / ${job.total.toLocaleString()} IPs (${pct.toFixed(1)}%) | Found: ${job.found_in_batch} | Elapsed: ${formatDuration(job.elapsed)}`;
                    if (job.status === 'running' && job.progress > 0 && job.total > job.progress) {
                        const eta = (job.elapsed / job.progress) * (job.total - job.progress);
                        info += ` | ETA: ${formatDuration(eta)}`;
                    }
                    const label = statusLabels[job.status] || job.status;
                    const statusClass = job.status === 'failed' ? 'status-offline' : 'badge';
                    let actions = '';
                    if (job.status === 'queued' || job.status === 'paused') {
                        actions = `<button type="button" class="btn-secondary scan-prioritize" data-id="${job.id}">Prioritize</button>
                                   <button type="button" class="btn-danger scan-cancel" data-id="${job.id}">Cancel</button>`;
                    }
                    return `
                        <div class="scan-job" style="border:1px solid #444; border-radius:6px; padding:10px; margin-bottom:10px;">
                            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
                                <strong>${escapeHtml(job.network)}</strong>
                                <span class="${statusClass}">${label}</span>
                            </div>
                            <div class="progress-bar"><div class="progress-fill" style="width:${pct}%"></div></div>
                            <div class="progress-info">${info}</div>
                            ${job.message ? `<div class="progress-info">${escapeHtml(job.message)}</div>` : ''}
                            ${actions ? `<div style="margin-top:8px;">${actions}</div>` : ''}
                        </div>
                    `;
                }).join('');

                jobs.forEach(job => {
                    if (job.status === 'done' && !serversRefreshedFor.has(job.id)) {
                        serversRefreshedFor.add(job.id);
                        fetchServers();
                    }
                });

                if (jobs.length > 0 && !scanQueueInterval) {
                    scanQueueInterval = setInterval(fetchScanQueue, 1000);
                } else if (jobs.length === 0 && scanQueueInterval) {
                    clearInterval(scanQueueInterval);
                    scanQueueInterval = null;
                }
            }

            async function fetchRefreshState() {
                try {
                    const res = await fetch('/api/refresh/status');
                    const state = await res.json();
                    updateRefreshProgress(state);
                } catch (e) {
                    console.error('Failed to fetch refresh state:', e);
                }
            }

            function updateRefreshProgress(state) {
                const container = document.getElementById('refreshProgressContainer');
                const fill = document.getElementById('refreshProgressFill');
                const info = document.getElementById('refreshProgressInfo');
                const btn = document.getElementById('refreshMetaBtn');
                const errEl = document.getElementById('refreshError');
                const okEl = document.getElementById('refreshSuccess');

                if (state.error) {
                    errEl.textContent = state.error;
                    okEl.textContent = '';
                } else if (state.message && !state.running) {
                    okEl.textContent = state.message;
                    errEl.textContent = '';
                }

                if (state.total > 0) {
                    container.style.display = 'block';
                    const pct = state.total > 0 ? (state.progress / state.total * 100) : 0;
                    fill.style.width = pct + '%';
                    let info = `${state.progress.toLocaleString()} / ${state.total.toLocaleString()} servers (${pct.toFixed(1)}%) | Updated: ${state.updated} | Failed: ${state.failed} | Elapsed: ${formatDuration(state.elapsed)}`;
                    if (state.running && state.progress > 0 && state.total > state.progress) {
                        const eta = (state.elapsed / state.progress) * (state.total - state.progress);
                        info += ` | ETA: ${formatDuration(eta)}`;
                    }
                    info.textContent = info;
                }

                const workersRow = document.getElementById('refreshWorkersRow');
                const workersInput = document.getElementById('refreshWorkersLive');
                if (state.running) {
                    workersRow.style.display = 'flex';
                    if (document.activeElement !== workersInput && state.workers) {
                        workersInput.value = state.workers;
                    }
                    btn.disabled = true;
                    if (!refreshProgressInterval) {
                        refreshProgressInterval = setInterval(fetchRefreshState, 1000);
                    }
                } else {
                    workersRow.style.display = 'none';
                    btn.disabled = false;
                    if (refreshProgressInterval) {
                        clearInterval(refreshProgressInterval);
                        refreshProgressInterval = null;
                    }
                    if (!state.error && state.message) {
                        setTimeout(fetchServers, 500);
                    }
                }
            }

            document.getElementById('scanForm').addEventListener('submit', async (e) => {
                e.preventDefault();
                const network = document.getElementById('network').value.trim();
                const timeout = parseFloat(document.getElementById('timeout').value) || 0.4;
                const scanError = document.getElementById('scanError');
                const scanSuccess = document.getElementById('scanSuccess');
                scanError.textContent = '';
                scanSuccess.textContent = '';

                // Warn if this range was already scanned before.
                try {
                    const chk = await fetch('/api/scan/check?network=' + encodeURIComponent(network));
                    const info = await chk.json();
                    if (info.scanned) {
                        const entry = info.entry || {};
                        const when = entry.last_scanned
                            ? new Date(entry.last_scanned * 1000).toLocaleString()
                            : 'previously';
                        const times = entry.times || 1;
                        const msg = `This range (${info.network}) has already been scanned ${times} time(s).\n` +
                            `Last scanned: ${when}\n\nScan it again?`;
                        if (!confirm(msg)) {
                            return;
                        }
                    }
                } catch (err) {
                    // If the check fails, just proceed with the scan.
                }

                try {
                    const res = await fetch('/api/scan/start', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({network, timeout})
                    });
                    const data = await res.json();
                    if (!res.ok) {
                        scanError.textContent = data.error || 'Failed to add scan';
                        return;
                    }
                    scanSuccess.textContent = 'Scan added to queue.';
                    renderScanQueue(data.queue);
                } catch (e) {
                    scanError.textContent = 'Failed to add scan: ' + e.message;
                }
            });

            document.getElementById('scanThreadsApply').addEventListener('click', async () => {
                const workers = parseInt(document.getElementById('scanThreadsInput').value) || 1;
                try {
                    const res = await fetch('/api/scan/workers', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({workers})
                    });
                    const data = await res.json();
                    if (!res.ok) {
                        document.getElementById('scanError').textContent = data.error || 'Failed to change threads';
                    }
                } catch (e) {
                    document.getElementById('scanError').textContent = 'Failed to change threads: ' + e.message;
                }
            });

            document.getElementById('scanQueue').addEventListener('click', async (e) => {
                const pri = e.target.closest('.scan-prioritize');
                const cancel = e.target.closest('.scan-cancel');
                try {
                    if (pri) {
                        const res = await fetch(`/api/scan/queue/${pri.dataset.id}/prioritize`, {method: 'POST'});
                        const data = await res.json();
                        if (!res.ok) {
                            document.getElementById('scanError').textContent = data.error || 'Failed to prioritize scan';
                        } else {
                            renderScanQueue(data.queue);
                        }
                    } else if (cancel) {
                        const res = await fetch(`/api/scan/queue/${cancel.dataset.id}/cancel`, {method: 'POST'});
                        const data = await res.json();
                        if (!res.ok) {
                            document.getElementById('scanError').textContent = data.error || 'Failed to cancel scan';
                        } else {
                            renderScanQueue(data.queue);
                        }
                    }
                } catch (err) {
                    document.getElementById('scanError').textContent = 'Request failed: ' + err.message;
                }
            });

            document.getElementById('refreshWorkersApply').addEventListener('click', async () => {
                const workers = parseInt(document.getElementById('refreshWorkersLive').value) || 1;
                try {
                    const res = await fetch('/api/refresh/workers', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({workers})
                    });
                    const data = await res.json();
                    if (!res.ok) {
                        document.getElementById('refreshError').textContent = data.error || 'Failed to change threads';
                    }
                } catch (e) {
                    document.getElementById('refreshError').textContent = 'Failed to change threads: ' + e.message;
                }
            });

            async function checkResume() {
                try {
                    const res = await fetch('/api/scan/resume/status');
                    const info = await res.json();
                    if (info.pending) {
                        const nets = (info.jobs || []).map(j => j.network).filter(Boolean);
                        document.getElementById('resumeMessage').innerHTML =
                            `<strong>${info.count}</strong> unfinished scan(s) can be resumed:<br>` +
                            escapeHtml(nets.join(', '));
                        document.getElementById('resumeModal').style.display = 'flex';
                    }
                } catch (e) {
                    console.error('Failed to check resumable scan:', e);
                }
            }

            document.getElementById('resumeConfirmBtn').addEventListener('click', async () => {
                document.getElementById('resumeModal').style.display = 'none';
                const scanError = document.getElementById('scanError');
                scanError.textContent = '';
                try {
                    const res = await fetch('/api/scan/resume', {method: 'POST'});
                    const data = await res.json();
                    if (!res.ok) {
                        scanError.textContent = data.error || 'Failed to resume scans';
                        return;
                    }
                    renderScanQueue(data.queue);
                } catch (e) {
                    scanError.textContent = 'Failed to resume scans: ' + e.message;
                }
            });

            document.getElementById('resumeDiscardBtn').addEventListener('click', async () => {
                document.getElementById('resumeModal').style.display = 'none';
                try {
                    await fetch('/api/scan/resume/dismiss', {method: 'POST'});
                } catch (e) {
                    console.error('Failed to dismiss resumable scan:', e);
                }
            });

            document.getElementById('search').addEventListener('input', renderServers);
            document.getElementById('searchField').addEventListener('change', renderServers);
            document.getElementById('exactMatch').addEventListener('change', renderServers);
            document.getElementById('minPlayers').addEventListener('input', renderServers);
            document.getElementById('maxPlayers').addEventListener('input', renderServers);
            document.getElementById('sortBy').addEventListener('change', renderServers);

            function downloadJson(data, filename) {
                const dataStr = JSON.stringify(data, null, 2);
                const blob = new Blob([dataStr], {type: 'application/json'});
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = filename;
                a.click();
                URL.revokeObjectURL(url);
            }

            document.getElementById('exportBtn').addEventListener('click', () => {
                downloadJson(servers, 'found_servers.json');
            });

            document.getElementById('exportFilteredBtn').addEventListener('click', () => {
                downloadJson(getFilteredServers(), 'found_servers_filtered.json');
            });

            document.getElementById('refreshMetaBtn').addEventListener('click', () => {
                document.getElementById('refreshFilteredCount').textContent = getFilteredServers().length.toLocaleString();
                document.getElementById('refreshAllCount').textContent = servers.length.toLocaleString();
                document.getElementById('refreshModal').style.display = 'flex';
            });

            document.getElementById('refreshCancelBtn').addEventListener('click', () => {
                document.getElementById('refreshModal').style.display = 'none';
            });

            document.getElementById('refreshModal').addEventListener('click', (e) => {
                if (e.target.id === 'refreshModal') {
                    e.target.style.display = 'none';
                }
            });

            document.getElementById('refreshConfirmBtn').addEventListener('click', async () => {
                const scope = document.querySelector('input[name="refreshScope"]:checked').value;
                const workers = parseInt(document.getElementById('refreshWorkers').value) || 32;
                const targets = (scope === 'all' ? servers : getFilteredServers())
                    .map(s => s.address || s.ip)
                    .filter(Boolean);
                const errEl = document.getElementById('refreshError');
                const okEl = document.getElementById('refreshSuccess');
                errEl.textContent = '';
                okEl.textContent = '';
                document.getElementById('refreshModal').style.display = 'none';

                if (targets.length === 0) {
                    errEl.textContent = 'No servers in the selected scope.';
                    return;
                }

                try {
                    const res = await fetch('/api/refresh/start', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({addresses: targets, workers})
                    });
                    const data = await res.json();
                    if (!res.ok) {
                        errEl.textContent = data.error || 'Failed to start refresh';
                        return;
                    }
                    updateRefreshProgress(data.state);
                } catch (e) {
                    errEl.textContent = 'Failed to start refresh: ' + e.message;
                }
            });

            fetchServers();
            setInterval(fetchServers, 5000); // Auto-refresh every 5s
            fetchScanQueue();
            fetchRefreshState();
            checkResume();
        </script>
    </body>
    </html>
    """
    return render_template_string(html)


@app.route("/api/servers")
def api_list_servers():
    servers = load_servers()

    # Apply filters via query params
    search = request.args.get("search", "").lower()
    online_only = request.args.get("online_only", "false").lower() == "true"
    min_players = request.args.get("min_players", "0")
    try:
        min_players_int = int(min_players)
    except ValueError:
        min_players_int = 0

    max_players = request.args.get("max_players")
    if max_players is None or max_players == "":
        max_players_int = None
    else:
        try:
            max_players_int = int(max_players)
        except ValueError:
            max_players_int = None

    filtered = []
    for s in servers:
        online = s.get("online", 0) or 0
        if online_only and online == 0:
            continue
        if online < min_players_int:
            continue
        if max_players_int is not None and online > max_players_int:
            continue
        if search:
            haystack = " ".join(
                str(x)
                for x in [
                    s.get("ip", ""),
                    s.get("address", ""),
                    s.get("motd", ""),
                    s.get("version", ""),
                ]
            ).lower()
            if search not in haystack:
                continue
        filtered.append(s)

    # Sort
    sort_by = request.args.get("sort_by", "default")
    if sort_by == "online_desc":
        filtered.sort(key=lambda x: x.get("online", 0) or 0, reverse=True)
    elif sort_by == "online_asc":
        filtered.sort(key=lambda x: x.get("online", 0) or 0)
    elif sort_by == "players_full":
        filtered.sort(
            key=lambda x: (x.get("online", 0) or 0) / max(1, x.get("max", 1) or 1),
            reverse=True,
        )
    elif sort_by == "ip":
        filtered.sort(key=lambda x: x.get("ip", ""))

    return jsonify({"servers": filtered, "total": len(servers)})


@app.route("/api/servers", methods=["DELETE"])
def api_clear_servers():
    save_servers([])
    return jsonify({"success": True})


@app.route("/api/scan/start", methods=["POST"])
def api_scan_start():
    global scan_threads
    data = request.get_json(silent=True) or {}
    network = data.get("network", "").strip()
    canonical = canonical_network(network) if network else None
    if canonical is None:
        return jsonify({"error": "A valid CIDR range (e.g. 104.193.0.0/16) is required"}), 400

    try:
        timeout = float(data.get("timeout", 0.4))
    except (ValueError, TypeError):
        timeout = 0.4
    timeout = max(0.1, min(timeout, 5))

    if data.get("workers") is not None:
        try:
            scan_threads = max(1, min(int(data.get("workers")), MAX_WORKERS))
        except (ValueError, TypeError):
            pass

    with scan_lock:
        # Roll any recoverable scans into the queue before adding the new one.
        if pending_scan_resume:
            scan_jobs.extend(pending_scan_resume)
            pending_scan_resume.clear()
        scan_jobs.append(ScanJob(canonical, timeout))

    _ensure_scan_manager()
    scan_wakeup.set()
    _persist_scan_queue()
    return jsonify({"success": True, "queue": _scan_queue_payload()})


@app.route("/api/scan/queue")
def api_scan_queue():
    return jsonify(_scan_queue_payload())


@app.route("/api/scan/status")
def api_scan_status():
    with scan_lock:
        if running_scan is None:
            return jsonify({"running": False})
        return jsonify(running_scan.public())


@app.route("/api/scan/workers", methods=["POST"])
def api_scan_workers():
    global scan_threads
    data = request.get_json(silent=True) or {}
    try:
        workers = int(data.get("workers"))
    except (TypeError, ValueError):
        return jsonify({"error": "workers must be an integer"}), 400
    scan_threads = max(1, min(workers, MAX_WORKERS))

    with scan_lock:
        limiter = running_limiter
    if limiter is not None:
        limiter.set_capacity(scan_threads)
    return jsonify({"success": True, "workers": scan_threads})


@app.route("/api/refresh/workers", methods=["POST"])
def api_refresh_workers():
    data = request.get_json(silent=True) or {}
    try:
        workers = int(data.get("workers"))
    except (TypeError, ValueError):
        return jsonify({"error": "workers must be an integer"}), 400
    workers = max(1, min(workers, MAX_WORKERS))

    with refresh_lock:
        if not refresh_state["running"] or refresh_limiter is None:
            return jsonify({"error": "No refresh is running"}), 409
        refresh_state["workers"] = workers
        limiter = refresh_limiter
    limiter.set_capacity(workers)
    return jsonify({"success": True, "workers": workers})


@app.route("/api/scan/check")
def api_scan_check():
    network = request.args.get("network", "").strip()
    canonical = canonical_network(network) if network else None
    if canonical is None:
        return jsonify({"valid": False, "scanned": False})
    with data_lock:
        entry = load_scanned_ranges().get(canonical)
    return jsonify(
        {
            "valid": True,
            "network": canonical,
            "scanned": entry is not None,
            "entry": entry,
        }
    )


@app.route("/api/scan/queue/<int:job_id>/prioritize", methods=["POST"])
def api_scan_prioritize(job_id):
    global _scan_priority_seq
    with scan_lock:
        job = next((j for j in scan_jobs if j.id == job_id), None)
        if job is None:
            return jsonify({"error": "Scan not found"}), 404
        if job.status not in ("queued", "paused"):
            return jsonify({"error": "Only queued or paused scans can be prioritized"}), 409
        _scan_priority_seq -= 1
        job.priority_key = _scan_priority_seq
        if running_scan is not None and running_scan.id != job.id:
            running_scan.pause_requested = True

    _ensure_scan_manager()
    scan_wakeup.set()
    return jsonify({"success": True, "queue": _scan_queue_payload()})


@app.route("/api/scan/queue/<int:job_id>/cancel", methods=["POST"])
def api_scan_cancel(job_id):
    with scan_lock:
        job = next((j for j in scan_jobs if j.id == job_id), None)
        if job is None:
            return jsonify({"error": "Scan not found"}), 404
        if job.status == "running":
            return jsonify(
                {"error": "Cannot cancel the running scan; prioritize another scan first"}
            ), 409
        scan_jobs.remove(job)
    _persist_scan_queue()
    return jsonify({"success": True, "queue": _scan_queue_payload()})


@app.route("/api/scan/resume/status")
def api_scan_resume_status():
    with scan_lock:
        count = len(pending_scan_resume)
        jobs = [j.public() for j in pending_scan_resume]
    if count == 0:
        return jsonify({"pending": False})
    return jsonify({"pending": True, "count": count, "jobs": jobs})


@app.route("/api/scan/resume", methods=["POST"])
def api_scan_resume():
    with scan_lock:
        if not pending_scan_resume:
            return jsonify({"error": "No scan progress to resume"}), 400
        scan_jobs.extend(pending_scan_resume)
        pending_scan_resume.clear()
    _ensure_scan_manager()
    scan_wakeup.set()
    return jsonify({"success": True, "queue": _scan_queue_payload()})


@app.route("/api/scan/resume/dismiss", methods=["POST"])
def api_scan_resume_dismiss():
    clear_scan_progress()
    return jsonify({"success": True})


@app.route("/api/refresh/start", methods=["POST"])
def api_refresh_start():
    data = request.get_json(silent=True) or {}
    addresses = data.get("addresses") or []
    if not isinstance(addresses, list):
        return jsonify({"error": "addresses must be a list"}), 400

    seen = set()
    clean: List[str] = []
    for a in addresses:
        a = str(a).strip()
        if a and a not in seen:
            seen.add(a)
            clean.append(a)
    if not clean:
        return jsonify({"error": "No addresses to refresh"}), 400

    try:
        timeout = float(data.get("timeout", 1.5))
    except (ValueError, TypeError):
        timeout = 1.5
    if timeout < 0.1:
        timeout = 0.1
    if timeout > 10:
        timeout = 10

    try:
        workers = int(data.get("workers", 32))
    except (ValueError, TypeError):
        workers = 32
    if workers < 1:
        workers = 1
    if workers > 500:
        workers = 500

    with refresh_lock:
        if refresh_state["running"]:
            return jsonify({"error": "Refresh already in progress", "state": refresh_state}), 409

    global refresh_thread
    refresh_thread = threading.Thread(
        target=run_refresh, args=(clean, timeout, workers), daemon=True
    )
    refresh_thread.start()

    time.sleep(0.1)  # Give thread time to update state
    with refresh_lock:
        return jsonify({"success": True, "state": dict(refresh_state)})


@app.route("/api/refresh/status")
def api_refresh_status():
    with refresh_lock:
        return jsonify(dict(refresh_state))


if __name__ == "__main__":
    app.run(
        host=os.environ.get("HOST", "0.0.0.0"),
        port=int(os.environ.get("PORT", "8081")),
        debug=True,
    )
