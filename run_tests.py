"""CLI runner: python run_tests.py"""
import sys
from lab import tests as T

sys.stdout.reconfigure(encoding="utf-8")
res = T.run(progress=lambda i, n, name: print(f"[{i}/{n}] {name}", flush=True) if i < n else None)
print(f"\n{'RESULT':6} {'GROUP':18} TEST | EXPECTED | ACTUAL")
for r in res:
    print(f"{r['result']:6} {r['group']:18} {r['test']} | {r['expected']} | {r['actual']}")
p = sum(r["result"] == "PASS" for r in res)
print(f"\n{p}/{len(res)} passed. Report saved to reports/latest.json")
sys.exit(0 if p == len(res) else 1)
