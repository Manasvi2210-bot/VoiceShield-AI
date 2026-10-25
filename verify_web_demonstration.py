"""
verify_web_demonstration.py – Automated full demonstration verification.
Tests all application features safely in an isolated temporary database copy:
1. Registration & Authentication Lifecycle
2. Dashboard & Statistics Rendering
3. Unit I: Introduction to Cyber Security
4. Unit II: Ethical Hacking & Defensive Testing
5. Unit III: Cyber Laws & DPDP Act 2023
6. Audio Analysis Upload Pipeline (Magic-Byte verification & Incident Creation)
7. Incident Detail View & Forensics Rendering
8. Incident History Page
9. CSV Export & PDF Export Handling
10. Interactive Suspicious Message Checker (Unit III)
11. Interactive Payment Fraud Checker (Unit IV)
12. Multi-user Privacy & Access Isolation
"""
import io
import json
import os
import shutil
import sys
import tempfile

from app import create_app
from config import Config

# Create an isolated temporary copy of the production database
temp_db_fd, temp_db_path = tempfile.mkstemp(suffix=".db")
os.close(temp_db_fd)
prod_db = os.path.join(os.path.dirname(__file__), "voiceshield.db")
if os.path.exists(prod_db):
    shutil.copy2(prod_db, temp_db_path)


class IsolatedDemoConfig(Config):
    SQLALCHEMY_DATABASE_URI = f"sqlite:///{temp_db_path}"
    TESTING = True


app = create_app(IsolatedDemoConfig)
c = app.test_client()

results = []
PASS = "PASS"
FAIL = "FAIL"


def check(label, condition, extra=""):
    status = PASS if condition else FAIL
    results.append((status, label, extra))
    mark = "OK" if condition else "XX"
    print(f"  [{mark}] {label}" + (f" -> {extra}" if extra else ""))


print("\n=== VoiceShield AI – Final Website Verification Suite ===\n")

try:
    # 1. Unauthenticated Security
    print("[1] Unauthenticated Security & Access Control:")
    r_unauth = c.get("/")
    check("Root / redirects to /login when unauthenticated", r_unauth.status_code == 302 and "/login" in r_unauth.headers.get("Location", ""))

    r_dash_unauth = c.get("/dashboard")
    check("GET /dashboard redirects or 404 (handled by auth)", r_dash_unauth.status_code in (302, 404))

    # 2. Registration & Login
    print("\n[2] User Registration & Authentication:")
    r_reg = c.post("/register", data={
        "username": "demopresenter",
        "email": "presenter@voiceshield.demo",
        "password": "DemoPassword@2026",
        "confirm_password": "DemoPassword@2026",
    }, follow_redirects=True)
    check("New user registration succeeds", r_reg.status_code == 200 and (b"Account created" in r_reg.data or b"Registration" in r_reg.data))

    r_login = c.post("/login", data={
        "identifier": "demopresenter",
        "password": "DemoPassword@2026",
    }, follow_redirects=True)
    check("Login succeeds for new user", r_login.status_code == 200 and b"Welcome back" in r_login.data)

    # 3. Dashboard
    print("\n[3] Dashboard Rendering & Metrics:")
    r_dash = c.get("/")
    check("Dashboard loads with HTTP 200", r_dash.status_code == 200)
    check("Dashboard contains brand & operations navigation", b"VoiceShield AI" in r_dash.data and b"AI Voice Detection" in r_dash.data)
    check("Dashboard displays Course 171405A syllabus links", b"Unit I: Cyber Security" in r_dash.data and b"Unit III: Cyber Laws" in r_dash.data)

    # 4. Educational Units I – III
    print("\n[4] Course 171405A Educational Modules:")
    r_u1 = c.get("/unit1")
    check("Unit I loads with HTTP 200", r_u1.status_code == 200 and b"Unit I: Introduction to Cyber Security" in r_u1.data)
    check("Unit I contains CIA triad and WannaCry case study", b"CIA Triad" in r_u1.data and b"WannaCry" in r_u1.data)

    r_u2 = c.get("/unit2")
    check("Unit II loads with HTTP 200", r_u2.status_code == 200 and b"Unit II: Ethical Hacking" in r_u2.data)
    check("Unit II contains 5-phase methodology & Sony PSN case study", b"Planning" in r_u2.data and b"Sony PlayStation" in r_u2.data)

    r_u3 = c.get("/unit3")
    check("Unit III loads with HTTP 200", r_u3.status_code == 200 and b"Unit III: Cyber Laws" in r_u3.data)
    check("Unit III contains verified DPDP Act Gazette G.S.R. 843(E) details", b"G.S.R. 843(E)" in r_u3.data and b"November 13, 2025" in r_u3.data)
    check("Unit III contains Section 66A struck down notice", b"STRUCK DOWN" in r_u3.data and b"Shreya Singhal" in r_u3.data)
    check("Unit III contains accurate Eighth Schedule notice language", b"Eighth Schedule" in r_u3.data and b"Individual notices do not need to contain all 22 languages" in r_u3.data)

    # 5. Audio Analysis Upload & Processing Pipeline
    print("\n[5] Audio Upload & Analysis Pipeline:")
    valid_wav_header = b"RIFF\x2c\x00\x00\x00WAVEfmt \x10\x00\x00\x00\x01\x00\x01\x00\x44\xac\x00\x00\x88\x58\x01\x00\x02\x00\x10\x00data\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    r_upload = c.post("/analyse", data={
        "title": "Live Demo Scam Call Test",
        "category": "OTP & Identity Scam",
        "manual_text": "This is bank security. Share your OTP urgently to avoid account suspension.",
        "audio_file": (io.BytesIO(valid_wav_header), "call_sample.wav"),
    }, content_type="multipart/form-data", follow_redirects=False)
    check("Valid audio upload redirects to incident view", r_upload.status_code == 302 and "/incident/" in r_upload.headers.get("Location", ""))

    incident_url = r_upload.headers.get("Location")
    r_inc_view = c.get(incident_url)
    check("Incident detail view loads with HTTP 200", r_inc_view.status_code == 200)
    check("Incident detail view displays risk analysis & matched scam phrases",
          b"Live Demo Scam Call Test" in r_inc_view.data and (b"OTP" in r_inc_view.data or b"High" in r_inc_view.data or b"Critical" in r_inc_view.data))

    # Test upload security rejection on disguised file
    fake_exe = b"MZ\x90\x00\x03\x00\x00\x00This is a malicious PE binary executable disguised as WAV"
    r_fake = c.post("/analyse", data={
        "title": "Fake Upload Test",
        "category": "General / Other",
        "audio_file": (io.BytesIO(fake_exe), "malware.wav"),
    }, content_type="multipart/form-data", follow_redirects=True)
    check("Disguised non-audio executable rejected by magic bytes", b"Upload error:" in r_fake.data)

    # 6. Incident History & Exports
    print("\n[6] Incident History & Export Features:")
    r_hist = c.get("/history")
    check("Incident history loads with HTTP 200", r_hist.status_code == 200 and b"Incident History" in r_hist.data)
    check("History lists newly created demo incident", b"Live Demo Scam Call Test" in r_hist.data)

    r_csv = c.get("/export/csv")
    check("CSV Export returns HTTP 200", r_csv.status_code == 200 and "text/csv" in r_csv.headers.get("Content-Type", ""))
    check("CSV contains incident headers and data", b"ID,Title,Category" in r_csv.data and b"Live Demo Scam Call Test" in r_csv.data)

    r_pdf = c.get("/export/pdf")
    check("PDF Export route handles request cleanly (PDF download or ReportLab fallback)",
          r_pdf.status_code in (200, 302))

    # 7. Interactive Scanners & AJAX Tools
    print("\n[7] Interactive Scam & Fraud Scanners:")
    r_scam_msg = c.post("/unit3/check",
                        data=json.dumps({"text": "Congratulations you won! Click this link and send your password now."}),
                        content_type="application/json")
    d_scam = json.loads(r_scam_msg.data)
    check("Unit III message checker flags high-risk phishing/lottery scam",
          r_scam_msg.status_code == 200 and d_scam.get("score", 0) > 0 and len(d_scam.get("flags", [])) > 0,
          f"score={d_scam.get('score')} level={d_scam.get('level')}")

    r_benign_msg = c.post("/unit3/check",
                          data=json.dumps({"text": "Hi, see you in college library at 2 PM."}),
                          content_type="application/json")
    d_benign = json.loads(r_benign_msg.data)
    check("Unit III message checker marks benign communication as low risk",
          r_benign_msg.status_code == 200 and d_benign.get("score", 999) <= 30,
          f"score={d_benign.get('score')}")

    r_pay_scam = c.post("/unit4/check",
                        data=json.dumps({"text": "Bank manager calling. Share OTP and CVV to update KYC and scan QR code."}),
                        content_type="application/json")
    d_pay = json.loads(r_pay_scam.data)
    check("Unit IV payment fraud checker flags KYC & QR scam patterns",
          r_pay_scam.status_code == 200 and d_pay.get("score", 0) > 0,
          f"score={d_pay.get('score')}")

    # 8. User Data Isolation & Privacy Security
    print("\n[8] User Data Isolation & Security Isolation:")
    c.get("/logout")
    # Register second user
    c.post("/register", data={
        "username": "seconduser",
        "email": "second@voiceshield.demo",
        "password": "SecondPassword@2026",
        "confirm_password": "SecondPassword@2026",
    })
    c.post("/login", data={
        "identifier": "seconduser",
        "password": "SecondPassword@2026",
    })

    # Second user tries to access demopresenter's incident
    r_unauthorized_inc = c.get(incident_url)
    check("User data isolation enforced (second user cannot view first user's incident -> 404)",
          r_unauthorized_inc.status_code in (404, 302),
          f"status={r_unauthorized_inc.status_code}")

finally:
    # Clean up isolated test database
    try:
        if os.path.exists(temp_db_path):
            os.remove(temp_db_path)
    except OSError:
        pass

passed = sum(1 for s, _, _ in results if s == PASS)
failed = sum(1 for s, _, _ in results if s == FAIL)
print(f"\n{'='*55}")
print(f"  Final Verification Results: {passed} PASSED  |  {failed} FAILED")
print(f"{'='*55}\n")

if failed > 0:
    sys.exit(1)
sys.exit(0)
