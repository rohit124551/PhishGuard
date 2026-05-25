"""Smoke test — run while the server is live on localhost:8000."""
import requests

BASE = "http://localhost:8000"
SEP  = "─" * 70


def show(label, url):
    print(f"\n{SEP}")
    print(f"  {label}")
    print(f"  URL: {url}")
    print(SEP)
    r = requests.post(f"{BASE}/analyze", json={"url": url}, timeout=35)
    d = r.json()
    verdict = d.get("verdict", "N/A")
    score   = d.get("total_score", "N/A")
    print(f"  VERDICT: {verdict.upper():<12}  total_score: {score}/150")
    print()
    for c in d.get("checks", []):
        status = c["status"].upper()
        name   = c["name"]
        sc     = c["score"]
        reason = c["reason"][:85]
        print(f"  [{status:7}]  {name:<28}  score={sc:<3}  {reason}")


# 1. Health
print(SEP)
print("  GET /health")
print(SEP)
r = requests.get(f"{BASE}/health", timeout=5)
print(" ", r.status_code, r.json())

# 2. Known-safe HTTPS site
show("SAFE — google.com", "https://www.google.com")

# 3. Phishing-like URL (HTTP + keyword-stuffed + lookalike domain)
show(
    "PHISHING-LIKE — paypa1 login/verify over HTTP",
    "http://paypa1-login-verify-account.com/webscr?cmd=confirm-password",
)

# 4. Microsoft lookalike over HTTPS
show(
    "SUSPICIOUS — microsoft lookalike",
    "https://micros0ft-account-update-signin.com/verify",
)

# 5. Validation error (bad scheme)
print(f"\n{SEP}")
print("  POST /analyze  (invalid URL — expect HTTP 422)")
print(SEP)
r = requests.post(f"{BASE}/analyze", json={"url": "not-a-url"}, timeout=5)
print(f"  HTTP {r.status_code}")
detail = r.json().get("detail", [])
if isinstance(detail, list) and detail:
    print(f"  {detail[0]['msg']}")
else:
    print(f"  {detail}")

print(f"\n{SEP}")
print("  Smoke tests complete.")
print(SEP)
