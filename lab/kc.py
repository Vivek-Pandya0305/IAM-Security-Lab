import base64, json, time
import pyotp, requests
from . import config as C

TOKEN_URL = f"{C.KC_URL}/realms/{C.REALM}/protocol/openid-connect/token"
LOGOUT_URL = f"{C.KC_URL}/realms/{C.REALM}/protocol/openid-connect/logout"


class _KC:
    def __init__(self):
        self._tok, self._exp = None, 0

    def _admin_token(self):
        if self._tok and time.time() < self._exp - 10:
            return self._tok
        r = requests.post(f"{C.KC_URL}/realms/master/protocol/openid-connect/token", timeout=15,
                          data=dict(grant_type="password", client_id="admin-cli",
                                    username=C.ADMIN_USER, password=C.ADMIN_PASS))
        r.raise_for_status()
        j = r.json()
        self._tok, self._exp = j["access_token"], time.time() + j["expires_in"]
        return self._tok

    def _call(self, method, url, **kw):
        h = {"Authorization": f"Bearer {self._admin_token()}"}
        return requests.request(method, url, headers=h, timeout=20, **kw)

    def r(self, method, path, **kw):  # inside the lab realm
        return self._call(method, f"{C.KC_URL}/admin/realms/{C.REALM}{path}", **kw)

    def m(self, method, path, **kw):  # realm-level (create/read realms)
        return self._call(method, f"{C.KC_URL}/admin/realms{path}", **kw)


kc = _KC()


def ok(r):
    if r.status_code >= 400:
        raise RuntimeError(f"{r.request.method} {r.url} -> {r.status_code}: {r.text[:300]}")
    return r


def wait_ready(timeout=240):
    end = time.time() + timeout
    while time.time() < end:
        try:
            if requests.get(f"{C.KC_URL}/realms/master", timeout=3).status_code == 200:
                return True
        except requests.RequestException:
            pass
        time.sleep(3)
    raise RuntimeError("Keycloak did not become ready. Is `docker compose up -d` running?")


def totp_code(username):
    raw = C.USERS.get(username, {}).get("mfa_secret")
    return pyotp.TOTP(base64.b32encode(raw.encode()).decode()).now() if raw else None


def login(username, password=C.PASSWORD, client=C.CLIENT_ID, totp="auto"):
    """Password grant. totp='auto' -> generate code if user has MFA; None -> send none; str -> send that."""
    data = dict(grant_type="password", client_id=client, username=username,
                password=password, scope="openid")
    auto = totp == "auto"
    code = totp_code(username) if auto else totp
    if code:
        data["totp"] = code
    r = requests.post(TOKEN_URL, data=data, timeout=20)
    if r.status_code != 200 and auto and code and password == C.PASSWORD:
        time.sleep(30 - (time.time() % 30) + 1)  # code may be replay-rejected; wait for next window
        data["totp"] = totp_code(username)
        r = requests.post(TOKEN_URL, data=data, timeout=20)
    return r


def refresh(refresh_token, client=C.CLIENT_ID):
    return requests.post(TOKEN_URL, timeout=20, data=dict(
        grant_type="refresh_token", client_id=client, refresh_token=refresh_token))


def logout(refresh_token, client=C.CLIENT_ID):
    return requests.post(LOGOUT_URL, timeout=20, data=dict(client_id=client, refresh_token=refresh_token))


def decode(token):
    p = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))


def app_get(path, token=None):
    h = {"Authorization": f"Bearer {token}"} if token else {}
    r = requests.get(C.APP_URL + path, headers=h, timeout=15)
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, r.text


def realm():
    return ok(kc.r("GET", "")).json()


def user_id(username):
    users = ok(kc.r("GET", "/users", params={"username": username, "exact": "true"})).json()
    return users[0]["id"] if users else None


def set_enabled(uid, enabled):
    u = ok(kc.r("GET", f"/users/{uid}")).json()
    u["enabled"] = enabled
    ok(kc.r("PUT", f"/users/{uid}", json=u))


def reset_password(uid, pw):
    return kc.r("PUT", f"/users/{uid}/reset-password", json={"type": "password", "value": pw, "temporary": False})
