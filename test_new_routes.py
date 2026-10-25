"""
test_new_routes.py - Tests all new unit routes and AJAX checkers.
Run from: C:/VOICESHEILD AI with:  py test_new_routes.py
"""
import json
import sys

# ----------------------------------------------------------------
# 1. Build the test app with an isolated temporary database
# ----------------------------------------------------------------
import os
import shutil
import tempfile
from app import create_app
from config import Config

temp_db_fd, temp_db_path = tempfile.mkstemp(suffix=".db")
os.close(temp_db_fd)
prod_db_file = os.path.join(os.path.dirname(__file__), "voiceshield.db")
if os.path.exists(prod_db_file):
    shutil.copy2(prod_db_file, temp_db_path)


class IsolatedRouteTestConfig(Config):
    SQLALCHEMY_DATABASE_URI = f"sqlite:///{temp_db_path}"


app = create_app(IsolatedRouteTestConfig)
c = app.test_client()

results = []
PASS = "PASS"
FAIL = "FAIL"


def check(label, expr, extra=""):
    status = PASS if expr else FAIL
    results.append((status, label, extra))
    icon = "OK" if expr else "XX"
    print(f"  [{icon}]  {label}  {extra}")


print("\n=== VoiceShield AI – New Route Tests ===\n")

# ----------------------------------------------------------------
# 2. Unauthenticated redirect check
# ----------------------------------------------------------------
r = c.get("/")
check("/ redirects to login when unauthenticated", r.status_code == 302)

# ----------------------------------------------------------------
# 3. Register + login a test user
# ----------------------------------------------------------------
c.post("/register", data={
    "username": "routetester",
    "email": "routetester@vs.test",
    "password": "Secure@1234",
    "confirm_password": "Secure@1234",
})
login_r = c.post("/login", data={
    "identifier": "routetester",
    "password": "Secure@1234",
}, follow_redirects=True)
check("Login succeeds (200)", login_r.status_code == 200)

# ----------------------------------------------------------------
# 4. Check all pages return 200
# ----------------------------------------------------------------
pages = [
    ("/",          "Dashboard"),
    ("/analyse",   "Analyse"),
    ("/history",   "History"),
    ("/education", "Education Hub"),
    ("/privacy",   "Privacy"),
    ("/unit1",     "Unit I – Cyber Intro"),
    ("/unit2",     "Unit II – Cyber Law"),
    ("/unit3",     "Unit III – Social Media"),
    ("/unit4",     "Unit IV – Payments"),
    ("/unit5",     "Unit V – Device Security"),
]
for path, name in pages:
    r = c.get(path)
    check(f"GET {path} ({name})", r.status_code == 200)

# ----------------------------------------------------------------
# 5. AJAX – Unit III suspicious message checker
# ----------------------------------------------------------------
# High-risk text should return score > 0
r3a = c.post("/unit3/check",
             data=json.dumps({"text": "Congratulations you won! Share your OTP and click this link now urgently."}),
             content_type="application/json")
d3a = json.loads(r3a.data)
check("Unit III checker – high risk text returns score > 0",
      r3a.status_code == 200 and d3a.get("score", 0) > 0,
      f"score={d3a.get('score')} level={d3a.get('level')}")

# Empty text should return 400
r3b = c.post("/unit3/check",
             data=json.dumps({"text": ""}),
             content_type="application/json")
check("Unit III checker – empty text returns 400", r3b.status_code == 400)

# Normal text should return low score
r3c = c.post("/unit3/check",
             data=json.dumps({"text": "Let's meet for coffee tomorrow."}),
             content_type="application/json")
d3c = json.loads(r3c.data)
check("Unit III checker – benign text returns low/zero score",
      r3c.status_code == 200 and d3c.get("score", 999) <= 30,
      f"score={d3c.get('score')}")

# ----------------------------------------------------------------
# 6. AJAX – Unit IV payment fraud checker
# ----------------------------------------------------------------
r4a = c.post("/unit4/check",
             data=json.dumps({"text": "Bank officer called. Share your OTP and CVV to update KYC. Scan this QR code now."}),
             content_type="application/json")
d4a = json.loads(r4a.data)
check("Unit IV checker – fraud text returns score > 0 and flags",
      r4a.status_code == 200 and d4a.get("score", 0) > 0 and len(d4a.get("flags", [])) > 0,
      f"score={d4a.get('score')} flags={len(d4a.get('flags', []))}")

r4b = c.post("/unit4/check",
             data=json.dumps({"text": ""}),
             content_type="application/json")
check("Unit IV checker – empty text returns 400", r4b.status_code == 400)

# ----------------------------------------------------------------
# 7. CSV export still works
# ----------------------------------------------------------------
r_csv = c.get("/export/csv")
check("CSV export returns 200", r_csv.status_code == 200)

# ----------------------------------------------------------------
# 8. Privacy isolation – second user cannot access first user's incidents
# ----------------------------------------------------------------
# Register user2 and login
c.get("/logout")
c.post("/register", data={
    "username": "isolationtest2",
    "email": "isolation2@vs.test",
    "password": "Secure@1234",
    "confirm_password": "Secure@1234",
})
c.post("/login", data={
    "identifier": "isolationtest2",
    "password": "Secure@1234",
}, follow_redirects=True)

# Try to access incident #1 (which, if it exists, belongs to another user)
r_iso = c.get("/incident/1")
check("Privacy isolation – user2 cannot access user1 incident (404 or 200 only if owns it)",
      r_iso.status_code in (404, 302),
      f"status={r_iso.status_code}")

# ----------------------------------------------------------------
# 9. Summary
# ----------------------------------------------------------------
passed = sum(1 for s, _, _ in results if s == PASS)
failed = sum(1 for s, _, _ in results if s == FAIL)
print(f"\n{'='*50}")
print(f"  Results: {passed} PASSED  |  {failed} FAILED")
print(f"{'='*50}\n")

# Clean up isolated test database
try:
    if os.path.exists(temp_db_path):
        os.remove(temp_db_path)
except OSError:
    pass

if failed > 0:
    print("Failed tests:")
    for s, label, extra in results:
        if s == FAIL:
            print(f"  [XX]  {label}  {extra}")
    sys.exit(1)
else:
    print("All tests passed!")
    sys.exit(0)
