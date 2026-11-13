import json, time
from . import config as C
from .kc import kc, ok

LOG_FILE = C.LOG_DIR / "app_audit.jsonl"


def app_log(limit=500):
    if not LOG_FILE.exists():
        return []
    out = []
    for line in LOG_FILE.read_text(encoding="utf-8").splitlines()[-limit:]:
        try:
            out.append(json.loads(line))
        except ValueError:
            pass
    return out


def kc_events(max=300):
    return ok(kc.r("GET", "/events", params={"max": max})).json()


def admin_events(max=300):
    return ok(kc.r("GET", "/admin-events", params={"max": max})).json()


def _poll(fn, timeout):
    end = time.time() + timeout
    while True:
        found = fn()
        if found or time.time() > end:
            return found
        time.sleep(0.5)


def find_app_log(event, user, path, since, reason=None, timeout=4):
    def look():
        for e in reversed(app_log()):
            if (e.get("event") == event and e.get("path") == path and e["ts"] >= since - 60
                    and (user is None or e.get("user") == user)
                    and (reason is None or e.get("reason") == reason)):
                return e
    return _poll(look, timeout)


def find_kc_event(username, etype, since, uid=None, timeout=5):
    def look():
        for e in kc_events():
            if e.get("type") == etype and e["time"] >= (since - 60) * 1000 and (
                    e.get("userId") == uid or e.get("details", {}).get("username") == username):
                return e
    return _poll(look, timeout)


def find_admin_event(uid, op, rtype, since, timeout=5):
    def look():
        for e in admin_events():
            if (e.get("operationType") == op and e.get("resourceType") == rtype
                    and e["time"] >= (since - 60) * 1000 and uid in e.get("resourcePath", "")):
                return e
    return _poll(look, timeout)


def fmt_app(e):
    if not e:
        return "NO audit entry found in app log"
    return f"app log: {e['event']} user={e.get('user')} path={e['path']} reason={e.get('reason')} @ {e['time']}Z"


def fmt_kc(e, label="keycloak event"):
    if not e:
        return f"NO {label} found"
    return f"{label}: {e.get('type') or e.get('operationType')} {e.get('resourcePath', '')} @ {time.strftime('%H:%M:%S', time.gmtime(e['time']/1000))}Z"
