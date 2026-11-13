import json
import pandas as pd
import requests
import streamlit as st
from lab import config as C, kc as K, provision as P, tests as T, audit as A

st.set_page_config(page_title="IAM Security Lab", page_icon="🔐", layout="wide")
st.title("🔐 IAM Security Test Lab")
st.caption("Keycloak · OAuth2/OIDC · RBAC · MFA · Audit logs")


def up(url):
    try:
        return requests.get(url, timeout=3).status_code == 200
    except requests.RequestException:
        return False


def load_results():
    if "results" in st.session_state:
        return st.session_state["results"]
    f = C.REPORT_DIR / "latest.json"
    return json.loads(f.read_text(encoding="utf-8")) if f.exists() else None


def run_and_store(groups):
    bar, label = st.progress(0.0), st.empty()

    def cb(i, n, name):
        bar.progress(i / n if n else 1.0)
        label.write(f"Running {i + 1}/{n}: {name}" if i < n else "Finished")
    st.session_state["results"] = T.run(groups, cb)


def summary(res):
    p = sum(r["result"] == "PASS" for r in res)
    a, b, c = st.columns(3)
    a.metric("Tests", len(res)); b.metric("Passed", p); c.metric("Pass rate", f"{100 * p // len(res)}%")


def table(res):
    df = pd.DataFrame(res)
    color = lambda r: [("background-color:#d4edda;color:#111" if r["result"] == "PASS"
                        else "background-color:#f8d7da;color:#111")] * len(r)
    st.dataframe(df.style.apply(color, axis=1), use_container_width=True, hide_index=True)
    return df


tabs = st.tabs(["1 Lab Status", "2 Try It Yourself", "3 Run Security Tests",
                "4 Results Report", "5 Audit Logs", "6 Misconfiguration Demo"])

# ---- 1 status
with tabs[0]:
    kc_up = up(f"{C.KC_URL}/realms/master")
    realm_up = up(f"{C.KC_URL}/realms/{C.REALM}")
    app_up = up(f"{C.APP_URL}/health")
    db_up = False
    if kc_up:
        try:
            K.kc._admin_token(); db_up = True
        except Exception:
            pass
    for label, state in [("Keycloak (identity provider)", kc_up), ("Database (Postgres via Keycloak)", db_up),
                         (f"Realm '{C.REALM}' provisioned", realm_up), ("Demo app (FastAPI)", app_up)]:
        st.write(f"{'🟢' if state else '🔴'}  {label}")
    if not (kc_up and realm_up and app_up):
        st.warning("Something is down. Run `docker compose up -d`, wait a minute, then `python setup_lab.py`.")
    st.button("Refresh status")

# ---- 2 try it
with tabs[1]:
    user = st.selectbox("Test user", list(C.USERS))
    spec = C.USERS[user]
    st.caption(f"Roles: {', '.join(spec['roles'])}  |  MFA: {'required (code is generated automatically)' if spec.get('mfa_secret') else 'not required'}")
    if st.button("Log in"):
        r = K.login(user)
        if r.status_code == 200:
            st.session_state["tok"], st.session_state["tok_user"] = r.json(), user
            st.session_state.pop("last", None)
        else:
            st.session_state.pop("tok", None)
            st.error(f"Login failed: HTTP {r.status_code} {r.text[:200]}")
    tok = st.session_state.get("tok")
    if tok:
        c = K.decode(tok["access_token"])
        st.success(f"Logged in as **{st.session_state['tok_user']}** | roles in token: {c.get('realm_access', {}).get('roles')} | token lifetime: {c['exp'] - c['iat']} s")
        cols = st.columns(len(C.ACCESS) + 1)
        for col, path in zip(cols, C.ACCESS):
            if col.button(path):
                code, body = K.app_get(path, tok["access_token"])
                st.session_state["last"] = (path, code, body)
        if cols[-1].button("Log out"):
            K.logout(tok["refresh_token"])
            st.session_state["last"] = ("(logout)", 0, "Session ended. Click a page again to see the old token rejected.")
        if "last" in st.session_state:
            path, code, body = st.session_state["last"]
            icon = {200: "✅ Allowed", 403: "⛔ Denied (403)", 401: "🔒 Rejected (401)"}.get(code, f"HTTP {code}")
            st.subheader(f"{path}: {icon}")
            st.json(body)

# ---- 3 run
with tabs[2]:
    groups = st.multiselect("Test groups", T.GROUPS, default=T.GROUPS)
    st.caption(f"{len([t for t in T.REGISTRY if t.group in groups])} tests selected. A full run takes about 1-2 minutes.")
    if st.button("▶ Run tests", type="primary"):
        run_and_store(groups)
        st.success("Done. Open the **Results Report** tab.")

# ---- 4 report
with tabs[3]:
    res = load_results()
    if not res:
        st.info("No results yet. Run tests first.")
    else:
        summary(res)
        gsel = st.multiselect("Filter by group", T.GROUPS, default=T.GROUPS, key="rg")
        only_fail = st.checkbox("Show failures only")
        view = [r for r in res if r["group"] in gsel and (not only_fail or r["result"] == "FAIL")]
        if view:
            df = table(view)
            d1, d2, d3 = st.columns(3)
            d1.download_button("Download CSV", df.to_csv(index=False), "iam_report.csv")
            d2.download_button("Download JSON", json.dumps(res, indent=2), "iam_report.json")
            d3.download_button("Download HTML", df.to_html(index=False), "iam_report.html")

# ---- 5 audit
with tabs[4]:
    src = st.radio("Source", ["App audit log", "Keycloak login events", "Keycloak admin events"], horizontal=True)
    q = st.text_input("Filter (e.g. access_denied, LOGIN_ERROR, REALM_ROLE_MAPPING, a username)")
    st.button("Refresh logs")
    try:
        if src == "App audit log":
            rows = [{k: e.get(k) for k in ("time", "event", "user", "roles", "path", "reason", "ip")} for e in reversed(A.app_log())]
        elif src == "Keycloak login events":
            rows = [{"time": pd.to_datetime(e["time"], unit="ms"), "type": e.get("type"), "user": e.get("details", {}).get("username", e.get("userId")),
                     "error": e.get("error"), "ip": e.get("ipAddress")} for e in A.kc_events()]
        else:
            rows = [{"time": pd.to_datetime(e["time"], unit="ms"), "operation": e.get("operationType"), "resource": e.get("resourceType"),
                     "path": e.get("resourcePath"), "by": e.get("authDetails", {}).get("userId")} for e in A.admin_events()]
        df = pd.DataFrame(rows)
        if q and not df.empty:
            df = df[df.astype(str).apply(lambda r: q.lower() in " ".join(r).lower(), axis=1)]
        st.dataframe(df, use_container_width=True, hide_index=True)
    except Exception as e:
        st.error(f"Could not load logs: {e}")

# ---- 6 misconfig
with tabs[5]:
    st.write("Break one security setting, re-run the tests, and watch them turn red. Then restore.")
    key = st.selectbox("Weakness to introduce", list(P.WEAKENINGS), format_func=P.WEAKENINGS.get)
    a, b, c = st.columns(3)
    if a.button("1) Weaken setting"):
        P.weaken(key); st.warning(f"Weakened: {P.WEAKENINGS[key]}")
    if b.button("2) Run all tests"):
        run_and_store(T.GROUPS)
        res = st.session_state["results"]
        summary(res)
        fails = [r for r in res if r["result"] == "FAIL"]
        st.error(f"{len(fails)} test(s) detected the problem:") if fails else st.success("No failures")
        if fails:
            table(fails)
    if c.button("3) Restore secure settings"):
        with st.spinner("Restoring..."):
            P.restore_all()
        st.success("Secure configuration restored. Run all tests again to see green.")
