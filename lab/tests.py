"""Security test engine. Each test returns (actual, passed, evidence) and is compared to its expectation."""
import base64, json, time
from dataclasses import dataclass
from typing import Callable
import requests
from . import config as C, kc as K, provision as P, audit as A

GROUPS = ["Authorization", "Sessions", "Privilege Changes", "MFA & Lifecycle", "Auditability"]


@dataclass
class T:
    group: str
    name: str
    expected: str
    fn: Callable


REGISTRY = []


def reg(group, name, expected):
    def deco(fn):
        REGISTRY.append(T(group, name, expected, fn))
        return fn
    return deco


class Ctx:
    """Caches one login per user, re-logging in when the token is about to expire."""
    def __init__(self):
        self._c = {}

    def token(self, user):
        tok = self._c.get(user)
        if not tok or K.decode(tok)["exp"] - time.time() < 20:
            r = K.login(user)
            if r.status_code != 200:
                raise RuntimeError(f"login failed for {user}: HTTP {r.status_code} {r.text[:150]}")
            tok = self._c[user] = r.json()["access_token"]
        return tok


def b64(d):
    return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()


# ---------------------------------------------------------------- Authorization
ROLE_USER = {"employee": "emp_user", "manager": "mgr_user", "hr": "hr_user",
             "admin": "admin_user", "auditor": "audit_user"}


def _matrix(role, user, path, exp):
    def fn(ctx):
        t0 = time.time()
        code, _ = K.app_get(path, ctx.token(user))
        e = A.find_app_log("access_granted" if exp == 200 else "access_denied", user, path, t0)
        return f"HTTP {code}", code == exp, A.fmt_app(e)
    reg("Authorization", f"{role} -> {path}", f"HTTP {exp}")(fn)


for _role, _user in ROLE_USER.items():
    for _path, _allowed in C.ACCESS.items():
        _matrix(_role, _user, _path, 200 if _role in _allowed else 403)


@reg("Authorization", "No token -> protected page", "HTTP 401")
def _(ctx):
    t0 = time.time()
    code, _ = K.app_get("/payroll")
    return f"HTTP {code}", code == 401, A.fmt_app(A.find_app_log("unauthenticated", None, "/payroll", t0, "missing_token"))


@reg("Authorization", "Garbage token", "HTTP 401")
def _(ctx):
    code, _ = K.app_get("/payroll", "not.a.token")
    return f"HTTP {code}", code == 401, "-"


@reg("Authorization", "Tampered token (payload edited to admin)", "HTTP 401")
def _(ctx):
    tok = ctx.token("emp_user")
    h, p, s = tok.split(".")
    pl = K.decode(tok)
    pl["realm_access"] = {"roles": ["admin"]}
    code, _ = K.app_get("/admin/users", f"{h}.{b64(pl)}.{s}")
    return f"HTTP {code}", code == 401, "signature check rejects forged payload"


@reg("Authorization", "Unsigned token (alg=none)", "HTTP 401")
def _(ctx):
    pl = K.decode(ctx.token("emp_user"))
    pl["realm_access"] = {"roles": ["admin"]}
    code, _ = K.app_get("/admin/users", f"{b64({'alg': 'none', 'typ': 'JWT'})}.{b64(pl)}.")
    return f"HTTP {code}", code == 401, "alg=none attack rejected"


# ---------------------------------------------------------------- Sessions
@reg("Sessions", "Realm access-token lifetime within policy", f"<= {C.MAX_TOKEN_LIFETIME} s")
def _(ctx):
    v = K.realm()["accessTokenLifespan"]
    return f"{v} s", v <= C.MAX_TOKEN_LIFETIME, "realm configuration"


@reg("Sessions", "Observed token lifetime (exp - iat)", f"<= {C.MAX_TOKEN_LIFETIME} s")
def _(ctx):
    c = K.decode(ctx.token("emp_user"))
    v = c["exp"] - c["iat"]
    return f"{v} s", v <= C.MAX_TOKEN_LIFETIME, "decoded from a real token"


@reg("Sessions", "SSO session idle/max timeouts within policy", "idle <= 1800 s, max <= 36000 s")
def _(ctx):
    r = K.realm()
    i, m = r["ssoSessionIdleTimeout"], r["ssoSessionMaxLifespan"]
    return f"idle={i} s, max={m} s", i <= 1800 and m <= 36000, "realm configuration"


@reg("Sessions", "Expired access token is rejected", "HTTP 200 before expiry, 401 after")
def _(ctx):
    tok = K.login("emp_user", client=C.SHORT_CLIENT_ID).json()["access_token"]  # 5 s lifetime client
    c1, _ = K.app_get("/profile", tok)
    time.sleep(7)
    t0 = time.time()
    c2, _ = K.app_get("/profile", tok)
    e = A.find_app_log("unauthenticated", None, "/profile", t0, "token_expired")
    return f"before: {c1}, after: {c2}", c1 == 200 and c2 == 401, A.fmt_app(e)


@reg("Sessions", "Logout kills the refresh token", "Refresh after logout fails")
def _(ctx):
    j = K.login("emp_user").json()
    lo = K.logout(j["refresh_token"]).status_code
    rc = K.refresh(j["refresh_token"]).status_code
    return f"logout HTTP {lo}, refresh HTTP {rc}", rc != 200, "Keycloak invalidated the session"


@reg("Sessions", "Access token rejected after logout", "HTTP 200 before logout, 401 after")
def _(ctx):
    j = K.login("emp_user").json()
    c1, _ = K.app_get("/profile", j["access_token"])
    K.logout(j["refresh_token"])
    t0 = time.time()
    c2, _ = K.app_get("/profile", j["access_token"])
    e = A.find_app_log("unauthenticated", None, "/profile", t0, "session_revoked")
    return f"before: {c1}, after: {c2}", c1 == 200 and c2 == 401, A.fmt_app(e)


# ---------------------------------------------------------------- Privilege changes
@reg("Privilege Changes", "Promotion employee -> manager", "/team-report: 403 before, 200 after token refresh")
def _(ctx):
    t0 = time.time()
    uid = P.create_user("mover_user", ["employee"])
    j = K.login("mover_user").json()
    before, _ = K.app_get("/team-report", j["access_token"])
    P.assign_roles(uid, ["manager"])
    j2 = K.refresh(j["refresh_token"]).json()
    after, _ = K.app_get("/team-report", j2["access_token"])
    e = A.find_admin_event(uid, "CREATE", "REALM_ROLE_MAPPING", t0)
    return f"before: {before}, after: {after}", before == 403 and after == 200, A.fmt_kc(e, "admin event")


@reg("Privilege Changes", "Demotion manager -> employee", "/team-report: 200 before, 403 after token refresh")
def _(ctx):
    t0 = time.time()
    uid = P.create_user("mover_user", ["employee", "manager"])
    j = K.login("mover_user").json()
    before, _ = K.app_get("/team-report", j["access_token"])
    P.remove_roles(uid, ["manager"])
    j2 = K.refresh(j["refresh_token"]).json()
    after, _ = K.app_get("/team-report", j2["access_token"])
    e = A.find_admin_event(uid, "DELETE", "REALM_ROLE_MAPPING", t0)
    return f"before: {before}, after: {after}", before == 200 and after == 403, A.fmt_kc(e, "admin event")


@reg("Privilege Changes", "Employee token cannot use Keycloak admin API", "HTTP 401 or 403")
def _(ctx):
    r = requests.get(f"{C.KC_URL}/admin/realms/{C.REALM}/users", timeout=15,
                     headers={"Authorization": f"Bearer {ctx.token('emp_user')}"})
    return f"HTTP {r.status_code}", r.status_code in (401, 403), "self-escalation blocked"


# ---------------------------------------------------------------- MFA & lifecycle
for _u in ("admin_user", "hr_user"):
    def _mk(u):
        @reg("MFA & Lifecycle", f"{u}: password only (no TOTP)", "Login denied")
        def _a(ctx):
            r = K.login(u, totp=None)
            return f"HTTP {r.status_code}", r.status_code != 200, "second factor is mandatory"

        @reg("MFA & Lifecycle", f"{u}: password + wrong TOTP", "Login denied")
        def _b(ctx):
            r = K.login(u, totp="000000")
            return f"HTTP {r.status_code}", r.status_code != 200, "bad code rejected"

        @reg("MFA & Lifecycle", f"{u}: password + valid TOTP", "Token issued")
        def _c(ctx):
            tok = ctx.token(u)
            return "token issued", bool(tok), "MFA succeeds with correct code"
    _mk(_u)


@reg("MFA & Lifecycle", "Brute-force lockout", "Correct password refused after repeated failures")
def _(ctx):
    P.create_user("lockout_user", ["employee"])
    base = K.login("lockout_user").status_code
    for _ in range(6):
        K.login("lockout_user", password="Wrong#Pass1")
    r = K.login("lockout_user")
    desc = r.json().get("error_description", "") if r.status_code != 200 else "login still works"
    return f"baseline {base}; after 6 bad attempts: HTTP {r.status_code}", base == 200 and r.status_code != 200, desc


@reg("MFA & Lifecycle", "Weak password rejected by policy", "HTTP 400")
def _(ctx):
    uid = P.create_user("policy_user", ["employee"])
    try:
        r = K.reset_password(uid, "abc")
        return f"HTTP {r.status_code}", r.status_code == 400, "password policy: length(8) and notUsername"
    finally:
        P.delete_user("policy_user")


@reg("MFA & Lifecycle", "Joiner gets least privilege", "/profile 200, /payroll 403")
def _(ctx):
    P.create_user("joiner_user", ["employee"])
    try:
        j = K.login("joiner_user").json()
        a, _ = K.app_get("/profile", j["access_token"])
        b, _ = K.app_get("/payroll", j["access_token"])
        return f"/profile {a}, /payroll {b}", a == 200 and b == 403, "new hire has only the employee role"
    finally:
        P.delete_user("joiner_user")


@reg("MFA & Lifecycle", "Leaver: disabled account loses all access", "Login, refresh and old token all rejected")
def _(ctx):
    t0 = time.time()
    uid = P.create_user("leaver_user", ["employee"])
    j = K.login("leaver_user").json()
    pre, _ = K.app_get("/profile", j["access_token"])
    K.set_enabled(uid, False)
    lc = K.login("leaver_user").status_code
    rc = K.refresh(j["refresh_token"]).status_code
    tc, _ = K.app_get("/profile", j["access_token"])
    e = A.find_admin_event(uid, "UPDATE", "USER", t0)
    return (f"before: {pre}; after disable -> login {lc}, refresh {rc}, old token {tc}",
            pre == 200 and lc != 200 and rc != 200 and tc == 401, A.fmt_kc(e, "admin event"))


# ---------------------------------------------------------------- Auditability
@reg("Auditability", "Failed login is recorded", "LOGIN_ERROR event in Keycloak")
def _(ctx):
    t0 = time.time()
    K.login("audit_user", password="Wrong#Pass1")
    e = A.find_kc_event("audit_user", "LOGIN_ERROR", t0, K.user_id("audit_user"))
    return ("recorded" if e else "missing"), bool(e), A.fmt_kc(e)


@reg("Auditability", "Successful login is recorded", "LOGIN event in Keycloak")
def _(ctx):
    t0 = time.time()
    K.login("audit_user")
    e = A.find_kc_event("audit_user", "LOGIN", t0, K.user_id("audit_user"))
    return ("recorded" if e else "missing"), bool(e), A.fmt_kc(e)


@reg("Auditability", "Access denial is recorded by the app", "access_denied entry in app log")
def _(ctx):
    t0 = time.time()
    K.app_get("/payroll", ctx.token("emp_user"))
    e = A.find_app_log("access_denied", "emp_user", "/payroll", t0)
    return ("recorded" if e else "missing"), bool(e), A.fmt_app(e)


@reg("Auditability", "Unauthenticated attempt is recorded", "unauthenticated entry in app log")
def _(ctx):
    t0 = time.time()
    K.app_get("/admin/users", "bad.token.value")
    e = A.find_app_log("unauthenticated", None, "/admin/users", t0, "invalid_token")
    return ("recorded" if e else "missing"), bool(e), A.fmt_app(e)


@reg("Auditability", "Role change is recorded (who/what/when)", "Admin events for role grant and revoke")
def _(ctx):
    t0 = time.time()
    uid = P.create_user("mover_user", ["employee"])
    P.assign_roles(uid, ["auditor"])
    P.remove_roles(uid, ["auditor"])
    g = A.find_admin_event(uid, "CREATE", "REALM_ROLE_MAPPING", t0)
    r = A.find_admin_event(uid, "DELETE", "REALM_ROLE_MAPPING", t0)
    return f"grant: {bool(g)}, revoke: {bool(r)}", bool(g and r), A.fmt_kc(g, "admin event (grant)")


# ---------------------------------------------------------------- runner
def run(groups=None, progress=None):
    items = [t for t in REGISTRY if not groups or t.group in groups]
    ctx, out = Ctx(), []
    for i, t in enumerate(items):
        if progress:
            progress(i, len(items), t.name)
        s = time.time()
        try:
            actual, passed, ev = t.fn(ctx)
        except Exception as e:  # a crashed test is a failed test
            actual, passed, ev = f"ERROR: {e}"[:300], False, "-"
        out.append(dict(group=t.group, test=t.name, expected=t.expected, actual=actual,
                        result="PASS" if passed else "FAIL", evidence=ev, seconds=round(time.time() - s, 1)))
    if progress:
        progress(len(items), len(items), "done")
    C.REPORT_DIR.mkdir(exist_ok=True)
    (C.REPORT_DIR / "latest.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
    return out
