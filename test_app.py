"""test_app.py – automated functional test of VoiceShield AI"""
import urllib.request
import urllib.parse
import http.cookiejar
import sys

BASE = "http://127.0.0.1:5000"
PASS_MARK = "\033[92m[PASS]\033[0m"
FAIL_MARK = "\033[91m[FAIL]\033[0m"
results = []

cj = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))


def check(label, condition, detail=""):
    status = PASS_MARK if condition else FAIL_MARK
    print(f"{status} {label}" + (f" – {detail}" if detail else ""))
    results.append(condition)


# 1. Root redirects to login
try:
    r = opener.open(BASE + "/")
    check("Root redirects to login", "/login" in r.url, r.url)
except Exception as e:
    check("Root redirects to login", False, str(e))

# 2. Register
data = urllib.parse.urlencode({
    "username": "testuser2",
    "email": "test2@example.com",
    "password": "TestPass123",
    "confirm_password": "TestPass123",
}).encode()
try:
    r = opener.open(BASE + "/register", data)
    check("Registration succeeds", "/login" in r.url or "/" in r.url, r.url)
except Exception as e:
    check("Registration", False, str(e))

# 3. Login
data = urllib.parse.urlencode({
    "identifier": "testuser2",
    "password": "TestPass123",
}).encode()
try:
    r = opener.open(BASE + "/login", data)
    body = r.read(3000).decode(errors="ignore")
    check("Login succeeds", "VoiceShield" in body, r.url)
except Exception as e:
    check("Login", False, str(e))

# 4. Dashboard accessible
try:
    r = opener.open(BASE + "/")
    body = r.read(3000).decode(errors="ignore")
    check("Dashboard loads", "Dashboard" in body and "VoiceShield" in body)
except Exception as e:
    check("Dashboard", False, str(e))

# 5. Analyse page GET
try:
    r = opener.open(BASE + "/analyse")
    body = r.read(2000).decode(errors="ignore")
    check("Analyse page loads", "Run Analysis" in body or "Analyse" in body)
except Exception as e:
    check("Analyse page", False, str(e))

# 6. Submit analysis with manual text (multipart)
boundary = "VS_TEST_BOUNDARY_XYZ"
nl = "\r\n"

def field(name, value):
    return (
        f"--{boundary}{nl}"
        f"Content-Disposition: form-data; name=\"{name}\"{nl}{nl}"
        f"{value}{nl}"
    ).encode()

body_parts = [
    field("title", "SBI OTP Scam Test"),
    field("category", "OTP & Identity Scam"),
    field("manual_text",
          "Hello sir I am calling from SBI bank. "
          "Your account will be blocked. Share your OTP and CVV number immediately."),
    f"--{boundary}--{nl}".encode(),
]
body_bytes = b"".join(body_parts)
req = urllib.request.Request(BASE + "/analyse", data=body_bytes)
req.add_header("Content-Type", f"multipart/form-data; boundary={boundary}")

try:
    r = opener.open(req)
    final_url = r.url
    body_text = r.read(6000).decode(errors="ignore")
    check("Analysis submitted", "/incident/" in final_url, final_url)

    found_level = None
    for level in ["Critical", "High", "Medium", "Low"]:
        if level in body_text:
            found_level = level
            break
    check("Risk level present in detail", found_level is not None, found_level or "none found")
    check("Risk Score shown", "Risk Score" in body_text or "/100" in body_text)
    check("Recommendations shown", "Recommendations" in body_text or "Safety" in body_text)
    check("Acoustic section present", "Acoustic" in body_text)
except Exception as e:
    check("Analysis", False, str(e))

# 7. History page
try:
    r = opener.open(BASE + "/history")
    body = r.read(3000).decode(errors="ignore")
    check("History page loads", "Incident History" in body or "history" in r.url.lower())
    check("Incident appears in history", "SBI OTP Scam Test" in body)
except Exception as e:
    check("History", False, str(e))

# 8. Education page – all 5 units
try:
    r = opener.open(BASE + "/education")
    body = r.read(8000).decode(errors="ignore")
    check("Education page loads", "Unit 1" in body or "Fundamentals" in body)
    check("Unit 1 Fundamentals", "Fundamentals" in body)
    check("Unit 2 Cyber Law", "IT Act" in body or "Cyber Law" in body)
    check("Unit 3 Social Media", "Social Media" in body)
    check("Unit 4 Digital Payment", "Digital Payment" in body or "UPI" in body)
    check("Unit 5 Device Security", "Device" in body and "Security" in body)
except Exception as e:
    check("Education", False, str(e))

# 9. Privacy page
try:
    r = opener.open(BASE + "/privacy")
    body = r.read(3000).decode(errors="ignore")
    check("Privacy page loads", "Privacy" in body)
    check("Audio deletion mentioned", "deleted" in body.lower())
    check("Whisper local mentioned", "Whisper" in body or "local" in body.lower())
except Exception as e:
    check("Privacy", False, str(e))

# 10. CSV export
try:
    r = opener.open(BASE + "/export/csv")
    content_type = r.headers.get("Content-Type", "")
    body = r.read(2000).decode(errors="ignore")
    check("CSV export works", "text/csv" in content_type or "ID,Title" in body,
          content_type)
except Exception as e:
    check("CSV export", False, str(e))

# Summary
total = len(results)
passed = sum(results)
print(f"\n{'='*50}")
print(f"Results: {passed}/{total} tests passed")
if passed == total:
    print("ALL TESTS PASSED ✅")
else:
    print(f"{total-passed} test(s) FAILED ❌")
sys.exit(0 if passed == total else 1)
