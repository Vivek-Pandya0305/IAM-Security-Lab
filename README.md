# IAM Security Test Lab

A small, repeatable lab that sets up a test identity environment (Keycloak), attacks it with automated tests, and reports **Expected vs Actual** with audit-log evidence.

## Scope

**In scope**
- Role-based access (employee, manager, hr, admin, auditor) and least privilege
- OAuth 2.0 / OIDC tokens (JWT) validated by a protected demo app
- MFA (TOTP) for admin and hr
- Session expiry, logout, and token lifetime
- Account lifecycle: joiner, mover (promotion/demotion), leaver
- Brute-force lockout and password policy
- Auditability: app audit log, Keycloak login events, admin events
- 53 automated tests, an interactive Streamlit dashboard, and a "weaken a setting and retest" demo

**Out of scope**
- Production deployment, HTTPS, high availability
- Browser login flow (Authorization Code + PKCE), SSO between apps
- Performance, load, or penetration testing beyond the listed cases
- External directories (LDAP/AD) and social login

## Architecture

```
Browser -> Streamlit Dashboard -> Python Test Engine
                                     |-- requests with token --> Demo App (FastAPI :8000)
                                     |-- login / admin API ----> Keycloak (:8080) -> PostgreSQL
Demo App --verifies token + session--> Keycloak
Demo App + Keycloak --> Audit logs (logs/app_audit.jsonl, Keycloak events) --> read by Test Engine
```

- **Keycloak**: users, roles, MFA, sessions, security events
- **Demo App**: 5 pages (`/profile`, `/team-report`, `/payroll`, `/admin/users`, `/audit/logs`); checks token signature, issuer, client, live session, then role
- **Test Engine** (`lab/tests.py`): runs tests, compares expected vs actual, collects log evidence
- **Dashboard** (`dashboard.py`): 6 tabs (status, try it, run tests, report, audit logs, misconfiguration demo)

## Assumptions

- Lab runs on one machine; all services are on `localhost`
- Ports 8080, 8000, and 8501 are free
- Host and Docker clocks are in sync (needed for MFA codes)
- All data is fake; test users share the password `Lab#Pass123`
- Tests may create, change, and delete the test users, so the lab must not hold real data
- The test engine logs in with the password grant for automation (not how real users would log in)

## Test Environment

| Item | Version / Setting |
|---|---|
| OS | Windows 10/11 with WSL 2 |
| Docker | Docker Desktop (Engine running) |
| Keycloak | 24.0.5 (dev mode, HTTP) |
| Database | PostgreSQL 16 |
| Demo app | Python 3.12 container, FastAPI |
| Host tools | Python 3.10+, pip, Git |
| Libraries | requests, pyotp, streamlit, pandas, pytest |
| Realm | `iam-lab`; access token 2 min, idle session 30 min, max session 10 h, lockout after 5 failures |

**Quick start (PowerShell)**
```
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
docker compose up -d --build
python setup_lab.py
streamlit run dashboard.py
```
Keycloak console: http://localhost:8080 (admin / admin). Stop with `docker compose down`.

## Limitations

- Development setup only: HTTP, Keycloak dev mode, default admin credentials. Do not expose to a network.
- Role changes appear in a user's token only after refresh or re-login (up to the 2-minute token life).
- The app calls Keycloak on every request to confirm the session; this is accurate but adds delay.
- Test secrets (passwords, TOTP seeds) are stored in plain code for repeatability.
- Audit logs are local files and Keycloak events; they are not tamper-proof or centrally shipped.
- Only one realm and one demo app are covered; results do not prove security of other systems.
- Expiry tests rely on a short-lived (5 s) test client, so they check behaviour, not the exact production client setup.
- A full test run takes 1-2 minutes and changes test-user state; the "Restore" button resets it.
