"""Creates the identity environment and smoke-tests every user login."""
import sys
from lab import config as C, kc as K, provision as P

sys.stdout.reconfigure(encoding="utf-8")
P.provision()
print("\nSmoke test (logging in as every user, TOTP generated automatically):")
bad = 0
for u in C.USERS:
    r = K.login(u)
    print(f"  {'OK  ' if r.status_code == 200 else 'FAIL'} {u}" + ("" if r.status_code == 200 else f"  -> {r.text[:150]}"))
    bad += r.status_code != 200
print("\nLab ready." if not bad else f"\n{bad} user(s) failed to log in - see messages above.")
print("Next: streamlit run dashboard.py")
sys.exit(1 if bad else 0)
