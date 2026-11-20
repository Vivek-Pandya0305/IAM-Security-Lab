# IAM Security Test Lab

A small practice lab that sets up a login system (Keycloak), tries to break it with automatic tests, and shows what was **expected** vs what **actually happened**, with log evidence.

## Scope

**What it covers**
- Role-based access: employee, manager, hr, admin, auditor
- Least privilege: each role sees only its own pages
- MFA (6-digit code) for admin and hr
- Session expiry and logout
- Joiner, mover and leaver (new hire, role change, resignation)
- Account lockout after repeated wrong passwords
- Audit logs: proof of who did what
- 53 automatic tests and a dashboard to run them

**What it does not cover**
- Real production use, HTTPS, or many servers
- Browser login redirect flow (Authorization Code + PKCE)
- Load, speed, or hacking-style testing beyond the listed tests

## Architecture

- **Main flow:** User -> Dashboard -> Test Engine -> Demo App -> Keycloak -> Database
- **Login flow:** Test Engine -> Keycloak -> Access badge (token) -> Demo App -> Allowed or Denied
- **Evidence flow:** Demo App and Keycloak -> Audit Logs -> Test Engine -> Report

| Part | Job |
|---|---|
| Keycloak | Handles users, roles, MFA, sessions |
| Demo App | Five pages that check the user's badge (token) and role |
| Test Engine | Runs the tests and compares expected vs actual |
| Dashboard | Click to try users, run tests, read reports and logs |
| Audit Logs | Record of logins, denials and role changes |

## Assumptions

- Everything runs on one Windows laptop (`localhost`)
- Ports 8080, 8000 and 8501 are free
- All data is fake; every test user has the password `Lab#Pass123`
- The laptop clock is correct (MFA codes depend on time)
- Tests may change or delete test users, so no real data is used

## Test Environment

| Item | Used |
|---|---|
| Computer | Windows 10/11 with Docker Desktop (WSL 2) |
| Keycloak | 24.0.5 (dev mode) |
| Database | PostgreSQL 16 |
| Demo app | Python 3.12, FastAPI |
| Your tools | Python 3.10+, Git |

**Start it (PowerShell)**
```
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
docker compose up -d --build
python setup_lab.py
streamlit run dashboard.py
```
Dashboard: http://localhost:8501. Stop: `docker compose down`.

## Limitations

- For learning only: plain HTTP and default admin password. Do not put it on a public network.
- A role change shows in a user's badge only after refresh (up to 2 minutes).
- Passwords and MFA secrets are kept in plain code to keep the lab repeatable.
- Audit logs are simple local files, not tamper-proof.
- It tests one demo app and one realm, so it does not prove other systems are secure.
