"""Microsoft / Xbox Live / Minecraft account authentication (device-code flow).

No password is ever stored: you authorize once through Microsoft's device-code
page, and the resulting refresh token is kept (chmod 600) so the app can mint
short-lived Minecraft access tokens later and fully log in to online-mode
servers.

Chain: MS OAuth -> Xbox Live (user.auth.xboxlive.com) -> XSTS -> Minecraft
Services. Standard library only.
"""

from __future__ import annotations

import json
import os
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

CLIENT_ID = "00000000402b5328"  # Minecraft launcher public client (Windows Live)
SCOPE = "service::user.auth.xboxlive.com::MBI_SSL"
DEVICE_CODE_URL = "https://login.live.com/oauth20_connect.srf"
TOKEN_URL = "https://login.live.com/oauth20_token.srf"
XBL_URL = "https://user.auth.xboxlive.com/user/authenticate"
XSTS_URL = "https://xsts.auth.xboxlive.com/xsts/authorize"
MC_LOGIN_URL = "https://api.minecraftservices.com/authentication/login_with_xbox"
MC_PROFILE_URL = "https://api.minecraftservices.com/minecraft/profile"

XSTS_ERRORS = {
    2148916227: "This account has been banned by Xbox Live.",
    2148916233: "This Microsoft account has no Xbox Live profile. Sign in at xbox.com once, then retry.",
    2148916235: "Xbox Live is not available in this account's country/region.",
    2148916236: "This account needs adult verification.",
    2148916237: "This account needs adult verification.",
    2148916238: "This is a child account and must be added to a Microsoft family by an adult.",
}


class AuthError(Exception):
    def __init__(self, message: str, code: str | None = None):
        super().__init__(message)
        self.message = message
        self.code = code


def _http(method: str, url: str, body: bytes | None, headers: dict, timeout: float = 20.0):
    request = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        code = str(exc.code)
        message = raw.decode("utf-8", "replace")[:400]
        try:
            parsed = json.loads(raw.decode("utf-8", "replace"))
            code = parsed.get("error") or code
            message = parsed.get("error_description") or parsed.get("Message") or message
        except (ValueError, AttributeError):
            parsed = None
        raise AuthError(message, code)
    except (urllib.error.URLError, OSError) as exc:
        raise AuthError(f"network error: {exc}")
    if not raw:
        return None
    try:
        return json.loads(raw.decode("utf-8", "replace"))
    except ValueError:
        return None


def _post_form(url: str, fields: dict) -> dict:
    body = urllib.parse.urlencode(fields).encode("ascii")
    return _http("POST", url, body, {"Content-Type": "application/x-www-form-urlencoded"}) or {}


def _post_json(url: str, obj: dict, extra_headers: dict | None = None) -> dict:
    body = json.dumps(obj).encode("utf-8")
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    headers.update(extra_headers or {})
    return _http("POST", url, body, headers) or {}


def _get_json(url: str, headers: dict) -> dict:
    return _http("GET", url, None, headers) or {}


class AuthManager:
    """Owns the token store and the interactive device-code flow."""

    def __init__(self, store_path: str):
        self.store_path = store_path
        self._lock = threading.RLock()
        self._flow: dict | None = None
        self._data: dict = self._load()

    # ------------------------------------------------------------------ #
    # persistence
    # ------------------------------------------------------------------ #
    def _load(self) -> dict:
        try:
            with open(self.store_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def _save(self) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(self.store_path)), exist_ok=True)
        tmp = self.store_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(self._data, fh, indent=2)
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.store_path)
        try:
            os.chmod(self.store_path, 0o600)
        except OSError:
            pass

    # ------------------------------------------------------------------ #
    # status
    # ------------------------------------------------------------------ #
    def status(self) -> dict:
        with self._lock:
            data = dict(self._data)
            flow = dict(self._flow) if self._flow else None
        return {
            "logged_in": bool(data.get("refresh_token") and data.get("uuid")),
            "name": data.get("name"),
            "uuid": data.get("uuid"),
            "expires_at": data.get("expires_at"),
            "flow": flow,
        }

    def logout(self) -> None:
        with self._lock:
            self._data = {}
            self._flow = None
            self._save()

    # ------------------------------------------------------------------ #
    # device-code flow
    # ------------------------------------------------------------------ #
    def start_device_flow(self) -> dict:
        response = _post_form(
            DEVICE_CODE_URL,
            {"client_id": CLIENT_ID, "scope": SCOPE, "response_type": "device_code"},
        )
        if "device_code" not in response:
            raise AuthError("Microsoft did not return a device code", "device_code_failed")
        with self._lock:
            self._flow = {
                "state": "pending",
                "user_code": response.get("user_code"),
                "verification_uri": response.get("verification_uri")
                or response.get("verification_uri_complete"),
                "message": response.get("message", ""),
                "interval": int(response.get("interval", 5)),
                "device_code": response["device_code"],
                "expires_at": time.time() + int(response.get("expires_in", 900)),
            }
            return dict(self._flow)

    def poll_device_flow(self) -> dict:
        with self._lock:
            if not self._flow or self._flow.get("state") != "pending":
                return self.status()
            if time.time() > self._flow["expires_at"]:
                self._flow["state"] = "error"
                self._flow["error"] = "The code expired. Start again."
                return self.status()
            device_code = self._flow["device_code"]

        try:
            token = _post_form(
                f"{TOKEN_URL}?client_id={CLIENT_ID}",
                {
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                    "client_id": CLIENT_ID,
                    "device_code": device_code,
                },
            )
        except AuthError as exc:
            with self._lock:
                if self._flow:
                    if exc.code == "authorization_pending":
                        return self.status()
                    if exc.code == "slow_down":
                        self._flow["interval"] = self._flow.get("interval", 5) + 5
                        return self.status()
                    self._flow["state"] = "error"
                    self._flow["error"] = exc.message
            return self.status()

        self._complete_ms_login(token.get("access_token"), token.get("refresh_token"))
        return self.status()

    def _complete_ms_login(self, ms_access_token: str | None, refresh_token: str | None) -> None:
        if not ms_access_token:
            raise AuthError("Microsoft returned no access token", "no_access_token")
        mc = self._microsoft_to_minecraft(ms_access_token)
        with self._lock:
            self._data = {
                "refresh_token": refresh_token,
                "ms_access_token": ms_access_token,
                "mc_access_token": mc["access_token"],
                "expires_at": mc["expires_at"],
                "uuid": mc["uuid"],
                "name": mc["name"],
            }
            self._flow = {
                "state": "success",
                "user_code": None,
                "verification_uri": None,
                "message": f"Signed in as {mc['name']}",
            }
            self._save()

    @staticmethod
    def _microsoft_to_minecraft(ms_access_token: str) -> dict:
        xbl = _post_json(
            XBL_URL,
            {
                "Properties": {
                    "AuthMethod": "RPS",
                    "SiteName": "user.auth.xboxlive.com",
                    "RpsTicket": "t=" + ms_access_token,
                },
                "RelyingParty": "http://auth.xboxlive.com",
                "TokenType": "JWT",
            },
        )
        xbl_token = xbl.get("Token")
        if not xbl_token:
            raise AuthError("Xbox Live authentication failed", "xbl_failed")
        uhs = xbl["DisplayClaims"]["xui"][0]["uhs"]

        try:
            xsts = _post_json(
                XSTS_URL,
                {
                    "Properties": {"SandboxId": "RETAIL", "UserTokens": [xbl_token]},
                    "RelyingParty": "rp://api.minecraftservices.com/",
                    "TokenType": "JWT",
                },
            )
        except AuthError as exc:
            # 401 bodies carry an XErr code in "XErr"
            raise AuthError(exc.message, exc.code)
        xsts_token = xsts.get("Token")
        if not xsts_token:
            raise AuthError("XSTS authorization failed", "xsts_failed")
        uhs = xsts["DisplayClaims"]["xui"][0]["uhs"]

        mc = _post_json(
            MC_LOGIN_URL,
            {"identityToken": f"XBL3.0 x={uhs};{xsts_token}"},
        )
        mc_token = mc.get("access_token")
        if not mc_token:
            raise AuthError("Minecraft Services login failed (does this account own Minecraft?)", "mc_failed")
        expires_at = time.time() + int(mc.get("expires_in", 86400))

        profile = _get_json(MC_PROFILE_URL, {"Authorization": "Bearer " + mc_token})
        if not profile.get("id"):
            raise AuthError("This account does not own Minecraft: Java Edition.", "no_profile")

        return {
            "access_token": mc_token,
            "expires_at": expires_at,
            "uuid": profile["id"],
            "name": profile.get("name", ""),
        }

    # ------------------------------------------------------------------ #
    # session access (for the login probe)
    # ------------------------------------------------------------------ #
    def refresh(self) -> bool:
        with self._lock:
            refresh_token = self._data.get("refresh_token")
        if not refresh_token:
            return False
        token = _post_form(
            TOKEN_URL,
            {
                "grant_type": "refresh_token",
                "client_id": CLIENT_ID,
                "refresh_token": refresh_token,
                "scope": SCOPE,
            },
        )
        self._complete_ms_login(token.get("access_token"), token.get("refresh_token", refresh_token))
        return True

    def get_session(self) -> dict | None:
        """Return a valid Minecraft session or None."""
        with self._lock:
            token = self._data.get("mc_access_token")
            expires_at = self._data.get("expires_at", 0)
            uuid = self._data.get("uuid")
            name = self._data.get("name")
        if token and uuid and expires_at > time.time() + 120:
            return {"access_token": token, "uuid": uuid, "name": name}
        try:
            if self.refresh():
                return self.get_session()
        except AuthError:
            return None
        return None
