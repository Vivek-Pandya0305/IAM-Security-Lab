"""Creates / restores the secure identity environment (idempotent)."""
import json
from . import config as C
from .kc import kc, ok, wait_ready, user_id

WEAKENINGS = {
    "token_lifetime": "Access tokens last 24 hours (instead of 2 minutes)",
    "no_bruteforce": "Brute-force lockout turned OFF",
    "no_admin_mfa": "MFA removed from admin_user",
    "employee_is_admin": "Privilege creep: emp_user silently given the admin role",
}


def ensure_realm():
    if kc.m("GET", f"/{C.REALM}").status_code == 404:
        ok(kc.m("POST", "", json={"realm": C.REALM, "enabled": True, **C.SECURE_REALM}))
    ok(kc.r("PUT", "", json=C.SECURE_REALM))


def ensure_roles():
    for name in C.ROLES:
        if kc.r("GET", f"/roles/{name}").status_code == 404:
            ok(kc.r("POST", "/roles", json={"name": name}))


def ensure_clients():
    specs = [(C.CLIENT_ID, {}), (C.SHORT_CLIENT_ID, {"access.token.lifespan": "5"})]
    for cid, attrs in specs:
        for c in ok(kc.r("GET", "/clients", params={"clientId": cid})).json():
            ok(kc.r("DELETE", f"/clients/{c['id']}"))
        ok(kc.r("POST", "/clients", json={
            "clientId": cid, "protocol": "openid-connect", "publicClient": True,
            "directAccessGrantsEnabled": True, "standardFlowEnabled": True,
            "redirectUris": ["http://localhost:8000/*"], "attributes": attrs}))


def assign_roles(uid, roles):
    reps = [ok(kc.r("GET", f"/roles/{r}")).json() for r in roles]
    ok(kc.r("POST", f"/users/{uid}/role-mappings/realm", json=reps))


def remove_roles(uid, roles):
    reps = [ok(kc.r("GET", f"/roles/{r}")).json() for r in roles]
    ok(kc.r("DELETE", f"/users/{uid}/role-mappings/realm", json=reps))


def delete_user(username):
    uid = user_id(username)
    if uid:
        ok(kc.r("DELETE", f"/users/{uid}"))


def create_user(username, roles, mfa_secret=None, password=C.PASSWORD):
    delete_user(username)
    creds = [{"type": "password", "value": password, "temporary": False}]
    if mfa_secret:
        creds.append({
            "type": "otp",
            "secretData": json.dumps({"value": mfa_secret}),
            "credentialData": json.dumps({"subType": "totp", "digits": 6, "counter": 0,
                                          "period": 30, "algorithm": "HmacSHA1"})})
    r = ok(kc.r("POST", "/users", json={
        "username": username, "enabled": True, "emailVerified": True,
        "email": f"{username}@lab.local", "firstName": username, "lastName": "Lab",
        "credentials": creds}))
    uid = r.headers["Location"].rsplit("/", 1)[1]
    if roles:
        assign_roles(uid, roles)
    return uid


def ensure_users():
    for name, spec in C.USERS.items():
        create_user(name, spec["roles"], spec.get("mfa_secret"))


def provision(log=print):
    log("Waiting for Keycloak..."); wait_ready()
    log("Realm + security settings..."); ensure_realm()
    log("Roles..."); ensure_roles()
    log("Clients..."); ensure_clients()
    log("Users (with MFA for hr_user and admin_user)..."); ensure_users()


def weaken(key):
    if key == "token_lifetime":
        ok(kc.r("PUT", "", json={"accessTokenLifespan": 86400}))
    elif key == "no_bruteforce":
        ok(kc.r("PUT", "", json={"bruteForceProtected": False}))
    elif key == "no_admin_mfa":
        create_user("admin_user", ["admin"], None)
    elif key == "employee_is_admin":
        assign_roles(user_id("emp_user"), ["admin"])
    else:
        raise ValueError(key)


def restore_all():
    ensure_realm()
    ensure_users()
