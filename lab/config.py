import os
from pathlib import Path

KC_URL = os.getenv("KC_URL", "http://localhost:8080")
APP_URL = os.getenv("APP_URL", "http://localhost:8000")
REALM = "iam-lab"
ADMIN_USER, ADMIN_PASS = "admin", "admin"
CLIENT_ID, SHORT_CLIENT_ID = "lab-app", "lab-app-short"
PASSWORD = "Lab#Pass123"
ROOT = Path(__file__).resolve().parent.parent
LOG_DIR = ROOT / "logs"
REPORT_DIR = ROOT / "reports"
MAX_TOKEN_LIFETIME = 300  # policy: access tokens must live <= 5 min

ROLES = ["employee", "manager", "hr", "admin", "auditor"]

# Raw TOTP secrets (Keycloak stores the raw string; authenticator apps use its base32 form)
USERS = {
    "emp_user": {"roles": ["employee"]},
    "mgr_user": {"roles": ["manager"]},
    "hr_user": {"roles": ["hr"], "mfa_secret": "HRsecretLabSeed12345"},
    "admin_user": {"roles": ["admin"], "mfa_secret": "AdminSecretLabSeed12"},
    "audit_user": {"roles": ["auditor"]},
    "mover_user": {"roles": ["employee"]},
    "leaver_user": {"roles": ["employee"]},
    "lockout_user": {"roles": ["employee"]},
}

# EXPECTED least-privilege matrix (independent of the app's code)
ALL = set(ROLES)
ACCESS = {
    "/profile": ALL,
    "/team-report": {"manager", "admin"},
    "/payroll": {"hr"},
    "/admin/users": {"admin"},
    "/audit/logs": {"auditor", "admin"},
}

SECURE_REALM = {
    "sslRequired": "none",
    "accessTokenLifespan": 120,
    "ssoSessionIdleTimeout": 1800,
    "ssoSessionMaxLifespan": 36000,
    "bruteForceProtected": True,
    "permanentLockout": False,
    "failureFactor": 5,
    "waitIncrementSeconds": 60,
    "maxFailureWaitSeconds": 900,
    "minimumQuickLoginWaitSeconds": 60,
    "quickLoginCheckMilliSeconds": 1,
    "maxDeltaTimeSeconds": 43200,
    "passwordPolicy": "length(8) and notUsername",
    "eventsEnabled": True,
    "eventsExpiration": 604800,
    "adminEventsEnabled": True,
    "adminEventsDetailsEnabled": True,
}
