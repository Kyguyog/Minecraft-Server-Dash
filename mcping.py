"""Minecraft Java Edition Server List Ping client.

Pure standard-library implementation of the modern (1.7+) Server List Ping
protocol, with a best-effort legacy (pre-1.7) fallback and minimal DNS SRV
resolution (_minecraft._tcp) so `play.example.com` style addresses work.
"""

from __future__ import annotations

import hashlib
import json
import os
import random
import re
import socket
import struct
import time
import urllib.error
import urllib.request

DEFAULT_PORT = 25565
STATUS_PROTOCOL = 47  # 1.8; servers return their real version regardless

_USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{1,16}$")

_SRV_CACHE: dict[str, tuple[float, str, int]] = {}
_SRV_TTL = 300.0


class MCPingError(Exception):
    pass


# --------------------------------------------------------------------------- #
# VarInt helpers
# --------------------------------------------------------------------------- #
def _write_varint(value: int) -> bytes:
    value &= 0xFFFFFFFF
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _read_varint(sock: socket.socket) -> int:
    num = 0
    for i in range(5):
        data = sock.recv(1)
        if not data:
            raise MCPingError("connection closed while reading VarInt")
        byte = data[0]
        num |= (byte & 0x7F) << (7 * i)
        if not (byte & 0x80):
            return num
    raise MCPingError("VarInt is too big")


def _varint_from_bytes(data: bytes, offset: int = 0) -> tuple[int, int]:
    num = 0
    for i in range(5):
        if offset >= len(data):
            raise MCPingError("truncated VarInt")
        byte = data[offset]
        offset += 1
        num |= (byte & 0x7F) << (7 * i)
        if not (byte & 0x80):
            return num, offset
    raise MCPingError("VarInt is too big")


def _write_string(text: str) -> bytes:
    data = text.encode("utf-8")
    return _write_varint(len(data)) + data


def _read_exact(sock: socket.socket, count: int) -> bytes:
    chunks = []
    remaining = count
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise MCPingError("connection closed unexpectedly")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


# --------------------------------------------------------------------------- #
# DNS SRV resolution (minimal, stdlib only)
# --------------------------------------------------------------------------- #
def _system_nameservers() -> list[str]:
    servers: list[str] = []
    try:
        with open("/etc/resolv.conf", "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if line.startswith("nameserver"):
                    parts = line.split()
                    if len(parts) >= 2:
                        servers.append(parts[1])
    except OSError:
        pass
    return servers or ["8.8.8.8"]


def _encode_dns_name(name: str) -> bytes:
    out = bytearray()
    for label in name.rstrip(".").split("."):
        data = label.encode("idna") if any(ord(c) > 127 for c in label) else label.encode("ascii")
        out.append(len(data))
        out.extend(data)
    out.append(0)
    return bytes(out)


def _decode_dns_name(data: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    jumped = False
    end = offset
    while True:
        if offset >= len(data):
            raise MCPingError("malformed DNS name")
        length = data[offset]
        if length == 0:
            offset += 1
            if not jumped:
                end = offset
            break
        if length & 0xC0 == 0xC0:
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                end = offset + 2
                jumped = True
            offset = pointer
            continue
        labels.append(data[offset + 1:offset + 1 + length].decode("latin-1"))
        offset += 1 + length
        if not jumped:
            end = offset
    return ".".join(labels), end


def resolve_srv(host: str, timeout: float = 2.0) -> tuple[str, int] | None:
    """Resolve _minecraft._tcp.<host> SRV record. Returns (target, port) or None."""
    if not host or _is_ip(host):
        return None
    key = host.lower()
    cached = _SRV_CACHE.get(key)
    now = time.time()
    if cached and cached[0] > now:
        return (cached[1], cached[2]) if cached[1] else None

    query_name = f"_minecraft._tcp.{host}"
    transaction_id = random.randint(0, 0xFFFF)
    header = struct.pack(">HHHHHH", transaction_id, 0x0100, 1, 0, 0, 0)
    question = _encode_dns_name(query_name) + struct.pack(">HH", 33, 1)
    packet = header + question

    result: tuple[str, int] | None = None
    for nameserver in _system_nameservers()[:2]:
        try:
            family = socket.AF_INET6 if ":" in nameserver else socket.AF_INET
            with socket.socket(family, socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout)
                sock.sendto(packet, (nameserver, 53))
                data, _ = sock.recvfrom(2048)
        except OSError:
            continue
        try:
            if len(data) < 12 or struct.unpack(">H", data[:2])[0] != transaction_id:
                continue
            qdcount, ancount = struct.unpack(">HH", data[4:8])
            offset = 12
            for _ in range(qdcount):
                _, offset = _decode_dns_name(data, offset)
                offset += 4
            best = None
            for _ in range(ancount):
                _, offset = _decode_dns_name(data, offset)
                rtype, _rclass, _ttl, rdlength = struct.unpack(">HHIH", data[offset:offset + 10])
                offset += 10
                rdata_end = offset + rdlength
                if rtype == 33 and rdlength >= 7:
                    _prio, _weight, port = struct.unpack(">HHH", data[offset:offset + 6])
                    target, _ = _decode_dns_name(data, offset + 6)
                    target = target.rstrip(".")
                    if target:
                        if best is None or _prio < best[0]:
                            best = (_prio, target, port)
                offset = rdata_end
            if best is not None:
                result = (best[1], best[2])
                break
        except (MCPingError, struct.error, IndexError):
            continue

    if result:
        _SRV_CACHE[key] = (now + _SRV_TTL, result[0], result[1])
    else:
        _SRV_CACHE[key] = (now + _SRV_TTL, "", 0)
    return result


def _is_ip(host: str) -> bool:
    try:
        socket.inet_aton(host)
        return True
    except OSError:
        return ":" in host


# --------------------------------------------------------------------------- #
# Chat / MOTD helpers
# --------------------------------------------------------------------------- #
def _flatten_chat(component) -> str:
    if component is None:
        return ""
    if isinstance(component, str):
        return component
    if isinstance(component, (int, float, bool)):
        return str(component)
    if isinstance(component, list):
        return "".join(_flatten_chat(item) for item in component)
    if isinstance(component, dict):
        text = component.get("text", "")
        if not isinstance(text, str):
            text = str(text)
        text += "".join(_flatten_chat(item) for item in component.get("extra", []) or [])
        return text
    return ""


def _clean_text(text: str) -> str:
    return re.sub(r"\u00a7.", "", text).strip()


# --------------------------------------------------------------------------- #
# Ping implementations
# --------------------------------------------------------------------------- #
def _ping_modern(host: str, port: int, timeout: float) -> dict:
    started = time.perf_counter()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        payload = (
            _write_varint(0x00)
            + _write_varint(STATUS_PROTOCOL)
            + _write_string(host)
            + struct.pack(">H", port)
            + _write_varint(1)
        )
        sock.sendall(_write_varint(len(payload)) + payload)
        sock.sendall(_write_varint(1) + _write_varint(0x00))

        length = _read_varint(sock)
        data = _read_exact(sock, length)

    latency_ms = round((time.perf_counter() - started) * 1000, 1)

    packet_id, offset = _varint_from_bytes(data, 0)
    if packet_id != 0x00:
        raise MCPingError(f"unexpected packet id {packet_id}")
    str_len, offset = _varint_from_bytes(data, offset)
    raw = data[offset:offset + str_len].decode("utf-8", "replace")
    info = json.loads(raw)

    version = info.get("version") or {}
    players = info.get("players") or {}
    description = info.get("description")

    sample = players.get("sample")
    sample_available = isinstance(sample, list)
    names = []
    if sample_available:
        for entry in sample:
            if not isinstance(entry, dict):
                continue
            raw_name = _clean_text(str(entry.get("name", "")))
            # Some servers inject fake/MOTD entries into the sample list.
            if _USERNAME_RE.match(raw_name):
                names.append(raw_name)

    return {
        "online": True,
        "version": _clean_text(str(version.get("name", "unknown"))),
        "protocol": version.get("protocol"),
        "players_online": players.get("online"),
        "players_max": players.get("max"),
        "players": names,
        "sample_available": sample_available,
        "motd": _clean_text(_flatten_chat(description)),
        "favicon": info.get("favicon"),
        "latency_ms": latency_ms,
        "error": None,
    }


def _ping_legacy(host: str, port: int, timeout: float) -> dict:
    started = time.perf_counter()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(b"\xfe\x01")
        data = b""
        while True:
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            data += chunk
            if len(data) >= 3:
                length = struct.unpack(">H", data[1:3])[0]
                if len(data) >= 3 + length * 2:
                    break
            if len(data) > 65536:
                break

    latency_ms = round((time.perf_counter() - started) * 1000, 1)

    if not data or data[0] != 0xFF:
        raise MCPingError("legacy ping: no response")
    length = struct.unpack(">H", data[1:3])[0]
    raw = data[3:3 + length * 2].decode("utf-16-be", "replace")
    parts = raw.split("\x00")
    if len(parts) < 6:
        raise MCPingError("legacy ping: malformed response")

    return {
        "online": True,
        "version": parts[2],
        "protocol": _safe_int(parts[1]),
        "players_online": _safe_int(parts[4]),
        "players_max": _safe_int(parts[5]),
        "players": [],
        "sample_available": False,
        "motd": _clean_text(parts[3]),
        "favicon": None,
        "latency_ms": latency_ms,
        "error": None,
    }


def _safe_int(value: str):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #
def _resolve_target(host: str, port: int | None, timeout: float) -> tuple[str, int]:
    """Apply _minecraft._tcp SRV resolution unless an explicit port was given."""
    host = (host or "").strip()
    explicit_port = port is not None and int(port) != DEFAULT_PORT
    port = int(port) if port else DEFAULT_PORT

    if not explicit_port and not _is_ip(host):
        try:
            srv = resolve_srv(host, timeout=min(timeout, 2.0))
        except Exception:
            srv = None
        if srv:
            host, port = srv
    return host, port


def ping(host: str, port: int | None = None, timeout: float = 5.0) -> dict:
    """Ping a Minecraft Java server and return a normalized status dict.

    Never raises for network/protocol problems: failures come back as
    {"online": False, "error": "..."}.
    """
    host, port = _resolve_target(host, port, timeout)

    errors = []
    try:
        return _ping_modern(host, port, timeout)
    except (MCPingError, OSError, json.JSONDecodeError, ValueError) as exc:
        errors.append(f"{type(exc).__name__}: {exc}")

    try:
        return _ping_legacy(host, port, timeout)
    except (MCPingError, OSError, ValueError) as exc:
        errors.append(f"{type(exc).__name__}: {exc}")

    return {
        "online": False,
        "version": None,
        "protocol": None,
        "players_online": None,
        "players_max": None,
        "players": [],
        "sample_available": False,
        "motd": None,
        "favicon": None,
        "latency_ms": None,
        "error": "; ".join(errors),
    }


# --------------------------------------------------------------------------- #
# Login probe / whitelist detection
# --------------------------------------------------------------------------- #
# Login-state clientbound packet ids shared by all modern versions
_LOGIN_DISCONNECT = 0x00
_LOGIN_ENCRYPTION_REQUEST = 0x01
_LOGIN_SUCCESS_IDS = (0x02, 0x03, 0x04, 0x05)  # success / compression / plugin / cookie
SESSION_JOIN_URL = "https://sessionserver.mojang.com/session/minecraft/join"

_CRYPTO: dict | None = None
_CRYPTO_TRIED = False
_CRYPTO_ERROR: str | None = None


def _load_crypto() -> dict | None:
    """Lazily import `cryptography`; returns None when unavailable."""
    global _CRYPTO, _CRYPTO_TRIED, _CRYPTO_ERROR
    if _CRYPTO_TRIED:
        return _CRYPTO
    _CRYPTO_TRIED = True
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
        try:
            from cryptography.hazmat.decrepit.ciphers.modes import CFB8
        except ImportError:
            from cryptography.hazmat.primitives.ciphers.modes import CFB8
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives.serialization import load_der_public_key

        _CRYPTO = {
            "Cipher": Cipher,
            "algorithms": algorithms,
            "CFB8": CFB8,
            "padding": padding,
            "load_der_public_key": load_der_public_key,
        }
        _CRYPTO_ERROR = None
    except Exception as exc:
        _CRYPTO = None
        _CRYPTO_ERROR = f"{type(exc).__name__}: {exc}"
    return _CRYPTO


def crypto_available() -> bool:
    return _load_crypto() is not None


def crypto_error() -> str | None:
    """Why `cryptography` could not be imported, or None if it is available."""
    _load_crypto()
    return _CRYPTO_ERROR


def crypto_install_hint() -> str:
    return (
        "the 'cryptography' package is required for online-mode checks -- "
        "start the app with ./run.sh, or run: python3 -m pip install -r requirements.txt"
    )


class _EncryptedConn:
    """AES/CFB8 stream wrapper for the connection after the encryption response."""

    def __init__(self, sock: socket.socket, secret: bytes, crypto: dict):
        self.sock = sock
        self._enc = crypto["Cipher"](crypto["algorithms"].AES(secret), crypto["CFB8"](secret)).encryptor()
        self._dec = crypto["Cipher"](crypto["algorithms"].AES(secret), crypto["CFB8"](secret)).decryptor()
        self._buf = b""

    def sendall(self, data: bytes) -> None:
        self.sock.sendall(self._enc.update(data))

    def _fill(self, n: int) -> None:
        while len(self._buf) < n:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise MCPingError("connection closed")
            self._buf += self._dec.update(chunk)

    def read_exact(self, n: int) -> bytes:
        self._fill(n)
        out, self._buf = self._buf[:n], self._buf[n:]
        return out

    def read_varint(self) -> int:
        num = 0
        for i in range(5):
            byte = self.read_exact(1)[0]
            num |= (byte & 0x7F) << (7 * i)
            if not (byte & 0x80):
                return num
        raise MCPingError("VarInt is too big")

    def read_packet(self) -> bytes:
        return self.read_exact(self.read_varint())


def _login_start_payload(name: str, protocol: int) -> bytes:
    """Build a Login Start packet in the layout used by `protocol`."""
    payload = _write_varint(0x00) + _write_string(name)
    if protocol >= 764:        # 1.20.2+ : required UUID
        payload += b"\x00" * 16
    elif protocol >= 761:      # 1.19.3 - 1.20.1 : Optional<UUID> (absent)
        payload += b"\x00"
    elif protocol >= 759:      # 1.19 - 1.19.2 : Optional<PlayerPublicKey> (absent)
        payload += b"\x00"
    # protocol <= 758 (1.7 - 1.18.2): name only
    return payload


def _read_byte_array(data: bytes, offset: int) -> tuple[bytes, int]:
    length, offset = _varint_from_bytes(data, offset)
    return data[offset:offset + length], offset + length


def _server_hash(server_id: str, shared_secret: bytes, public_key: bytes) -> str:
    """Minecraft's signed-hex SHA-1 digest of the login details."""
    digest = hashlib.sha1(server_id.encode("ascii") + shared_secret + public_key).digest()
    if digest[0] & 0x80:
        value = int.from_bytes(bytes(b ^ 0xFF for b in digest), "big") + 1
        return "-" + format(value, "x")
    return format(int.from_bytes(digest, "big"), "x")


def _join_session(access_token: str, uuid: str, server_hash: str, timeout: float) -> None:
    body = json.dumps(
        {
            "accessToken": access_token,
            "selectedProfile": uuid.replace("-", ""),
            "serverId": server_hash,
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        SESSION_JOIN_URL, data=body, method="POST", headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as resp:
            if not (200 <= resp.status < 300):
                raise MCPingError(f"session join returned HTTP {resp.status}")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:200]
        raise MCPingError(f"session join failed (HTTP {exc.code}): {detail}")
    except (urllib.error.URLError, OSError) as exc:
        raise MCPingError(f"session join error: {exc}")


def _read_disconnect_reason(data: bytes, offset: int) -> str:
    try:
        raw_len, offset = _varint_from_bytes(data, offset)
        raw = data[offset:offset + raw_len].decode("utf-8", "replace")
        return _clean_text(_flatten_chat(json.loads(raw)))
    except (MCPingError, ValueError, json.JSONDecodeError):
        return "disconnected by server"


def _classify_disconnect(reason: str) -> str:
    if "whitelist" in reason.lower():
        return "whitelist_only"
    return "blocked"


def check_whitelist(
    host: str,
    port: int | None = None,
    timeout: float = 5.0,
    session: dict | None = None,
) -> dict:
    """Probe a server's whitelist/admission behaviour by opening a login.

    Without a `session` this is anonymous and can only resolve offline-mode
    servers. With a `session` ({"access_token","uuid","name"}) it completes the
    encrypted online-mode handshake, so online-mode servers are covered too.

    Returned `status`:
      * "whitelist_only"      - disconnected with a "not whitelisted" message
      * "open"                - offline-mode server that admits anyone
      * "admitted"            - the signed-in account was allowed in
      * "online_mode_unknown" - online-mode and no account available
      * "blocked"             - refused for another reason (full/banned/version)
      * "error"               - network or protocol failure

    Never raises.
    """
    result = {
        "status": "error",
        "online_mode": None,
        "reason": "",
        "protocol": None,
        "reachable": False,
        "authenticated": False,
    }

    status = ping(host, port, timeout=timeout)
    if not status.get("online"):
        result["reason"] = status.get("error") or "server unreachable"
        return result

    result["reachable"] = True
    protocol = status.get("protocol") or STATUS_PROTOCOL
    result["protocol"] = protocol

    target_host, target_port = _resolve_target(host, port, timeout)
    name = (session or {}).get("name") or f"Probe{random.randint(0, 99999):05d}"

    try:
        sock = socket.create_connection((target_host, target_port), timeout=timeout)
        sock.settimeout(timeout)
        handshake = (
            _write_varint(0x00)
            + _write_varint(protocol)
            + _write_string(target_host)
            + struct.pack(">H", target_port)
            + _write_varint(2)  # next state: login
        )
        sock.sendall(_write_varint(len(handshake)) + handshake)
        login_start = _login_start_payload(name, protocol)
        sock.sendall(_write_varint(len(login_start)) + login_start)

        data = _read_exact(sock, _read_varint(sock))
        packet_id, offset = _varint_from_bytes(data, 0)

        if packet_id == _LOGIN_DISCONNECT:
            result["reason"] = _read_disconnect_reason(data, offset)
            result["status"] = _classify_disconnect(result["reason"])
            result["online_mode"] = False
            return result

        if packet_id in _LOGIN_SUCCESS_IDS:
            result["status"] = "open"
            result["online_mode"] = False
            result["reason"] = "server admitted an unauthenticated login (no whitelist)"
            return result

        if packet_id != _LOGIN_ENCRYPTION_REQUEST:
            result["status"] = "blocked"
            result["reason"] = f"unexpected login response 0x{packet_id:02x}"
            return result

        # --- Encryption requested: online-mode server ---
        result["online_mode"] = True
        if not session:
            result["status"] = "online_mode_unknown"
            result["reason"] = "online-mode server: sign in with a Minecraft account to check"
            return result

        crypto = _load_crypto()
        if crypto is None:
            err = _CRYPTO_ERROR
            result["reason"] = crypto_install_hint() + (f"  ({err})" if err else "")
            return result

        server_id_bytes, offset = _read_byte_array(data, offset)
        public_key, offset = _read_byte_array(data, offset)
        verify_token, offset = _read_byte_array(data, offset)
        server_id = server_id_bytes.decode("utf-8", "replace")

        shared_secret = os.urandom(16)
        digest = _server_hash(server_id, shared_secret, public_key)
        _join_session(session["access_token"], session["uuid"], digest, timeout)

        public_key_obj = crypto["load_der_public_key"](public_key)
        enc_secret = public_key_obj.encrypt(shared_secret, crypto["padding"].PKCS1v15())
        enc_token = public_key_obj.encrypt(verify_token, crypto["padding"].PKCS1v15())
        response = (
            _write_varint(0x01)
            + _write_varint(len(enc_secret)) + enc_secret
            + _write_varint(len(enc_token)) + enc_token
        )
        sock.sendall(_write_varint(len(response)) + response)  # still plaintext
        result["authenticated"] = True

        conn = _EncryptedConn(sock, shared_secret, crypto)
        packet = conn.read_packet()
        pid, poffset = _varint_from_bytes(packet, 0)

        if pid == _LOGIN_DISCONNECT:
            result["reason"] = _read_disconnect_reason(packet, poffset)
            result["status"] = _classify_disconnect(result["reason"])
            return result
        if pid in _LOGIN_SUCCESS_IDS:
            result["status"] = "admitted"
            result["reason"] = f"account '{name}' was allowed in (online-mode)"
            return result

        result["status"] = "blocked"
        result["reason"] = f"unexpected encrypted response 0x{pid:02x}"
        return result

    except (MCPingError, OSError, ValueError) as exc:
        result["reason"] = f"{type(exc).__name__}: {exc}"
        return result
    finally:
        try:
            sock.close()
        except (NameError, OSError):
            pass
