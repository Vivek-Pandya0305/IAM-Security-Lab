"""Protected demo API. Validates Keycloak tokens, enforces RBAC, writes JSON audit logs."""
import json, os, threading, time
import jwt, requests
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

KC_INTERNAL = os.getenv("KC_INTERNAL_URL", "http://keycloak:8080")
REALM = os.getenv("REALM", "iam-lab")
ISSUER = os.getenv("ISSUER", f"http://localhost:8080/realms/{REALM}")
ALLOWED_CLIENTS = {"lab-app", "lab-app-short"}
LOG_FILE = os.getenv("LOG_FILE", "/logs/app_audit.jsonl")
CERTS = f"{KC_INTERNAL}/realms/{REALM}/protocol/openid-connect/certs"
USERINFO = f"{KC_INTERNAL}/realms/{REALM}/protocol/openid-connect/userinfo"

# resource -> roles allowed (None = any authenticated user)
ACCESS = {
    "/profile": None,
    "/team-report": {"manager", "admin"},
    "/payroll": {"hr"},
    "/admin/users": {"admin"},
    "/audit/logs": {"auditor", "admin"},
}

app = FastAPI(title="IAM Lab Demo App")
_lock = threading.Lock()
_jwks = jwt.PyJWKClient(CERTS)


def audit(event, request, path, user=None, roles=None, reason=None):
    entry = {
        "ts": time.time(),
        "time": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()),
        "event": event, "user": user, "roles": sorted(roles or []),
        "path": path, "method": request.method,
        "ip": request.client.host if request.client else None, "reason": reason,
    }
    try:
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        with _lock, open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except OSError:
        pass


def signing_key(token):
    global _jwks
    try:
        return _jwks.get_signing_key_from_jwt(token)
    except jwt.PyJWKClientError:
        _jwks = jwt.PyJWKClient(CERTS)  # keys may have rotated; refetch once
        return _jwks.get_signing_key_from_jwt(token)


def authenticate(request):
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        return None, "missing_token"
    token = auth[7:].strip()
    try:
        key = signing_key(token)
        claims = jwt.decode(token, key.key, algorithms=["RS256"], issuer=ISSUER,
                            options={"verify_aud": False})
    except jwt.ExpiredSignatureError:
        return None, "token_expired"
    except Exception:
        return None, "invalid_token"
    if claims.get("azp") not in ALLOWED_CLIENTS:
        return None, "wrong_client"
    try:  # session liveness: fails after logout, session end, or user disabled
        r = requests.get(USERINFO, headers={"Authorization": f"Bearer {token}"}, timeout=5)
    except requests.RequestException:
        return None, "idp_unreachable"
    if r.status_code != 200:
        return None, "session_revoked"
    return claims, None


def make_handler(path, allowed):
    def handler(request: Request):
        claims, err = authenticate(request)
        if err:
            audit("unauthenticated", request, path, reason=err)
            return JSONResponse({"error": err}, status_code=401)
        user = claims.get("preferred_username")
        roles = set(claims.get("realm_access", {}).get("roles", []))
        if allowed is not None and not (roles & allowed):
            audit("access_denied", request, path, user, roles, "missing_role")
            return JSONResponse({"error": "forbidden", "required_any_of": sorted(allowed)}, status_code=403)
        audit("access_granted", request, path, user, roles)
        return body(path, user, roles, claims)
    return handler


def body(path, user, roles, claims):
    if path == "/profile":
        return {"user": user, "roles": sorted(roles), "token_expires_in": int(claims["exp"] - time.time())}
    if path == "/team-report":
        return {"report": "Team performance Q3", "members": 8}
    if path == "/payroll":
        return {"payroll": [{"employee": "A. Rao", "salary": "confidential"}]}
    if path == "/admin/users":
        return {"users": ["emp_user", "mgr_user", "hr_user", "admin_user"]}
    if path == "/audit/logs":
        try:
            with open(LOG_FILE, encoding="utf-8") as f:
                return {"entries": [json.loads(l) for l in f.readlines()[-100:]]}
        except OSError:
            return {"entries": []}


for _p, _a in ACCESS.items():
    app.add_api_route(_p, make_handler(_p, _a), methods=["GET"])


@app.get("/health")
def health():
    return {"status": "ok"}
