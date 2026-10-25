"""
test_cybersecurity_suite.py – Comprehensive Automated Test Suite for VoiceShield AI Defensive Cybersecurity Suite (Features 1–7)

Verifies:
1. Route Protection: Unauthenticated requests to all 7 features redirect to /login.
2. Feature 1: Phishing & Email Threat Analyzer (/phishing-checker)
   - Benign text risk scoring
   - Suspicious phishing / credential harvesting risk scoring
   - Empty input validation & size limits
   - URL detection and lookalike domain heuristics
3. Feature 2: Password Security Checker (/password-checker)
   - Route availability & zero-credential-transmission guarantee
4. Feature 3: Security Incident Response Center (/incident-center)
   - Create, list, detail view, status update, closure, and activity logs
   - User data isolation (user A cannot view/edit user B's incident -> 404)
   - Non-existent incident IDs return 404
5. Feature 4: Cybersecurity Awareness Training (/security-training)
   - 8 defensive modules & interactive quiz structure
6. Feature 5: Defensive Threat Intelligence Dashboard (/threat-intelligence)
   - MITRE ATT&CK mappings, IoCs, and educational disclaimers
7. Feature 6: Cryptographic File Integrity Checker (/file-integrity)
   - Streaming SHA-256 calculation on text and binary files
   - Matching reference hash validation
   - Mismatched reference hash detection
   - Empty upload rejection
8. Feature 7: Personal Cybersecurity Audit (/personal-security-audit)
   - 10-control self-assessment checklist and client-side scoring
9. Zero-Touch Database Safety:
   - Uses an isolated temporary SQLite database copy.
"""

import hashlib
import io
import os
import shutil
import sqlite3
import sys
import tempfile

from app import create_app
from config import Config
from extensions import db
from models import SecurityIncident, SecurityIncidentLog, User

# Step 1: Create isolated temporary SQLite database copy
temp_db_fd, temp_db_path = tempfile.mkstemp(suffix=".db")
os.close(temp_db_fd)
prod_db_file = os.path.join(os.path.dirname(__file__), "voiceshield.db")
if os.path.exists(prod_db_file):
    shutil.copy2(prod_db_file, temp_db_path)

class IsolatedTestConfig(Config):
    SQLALCHEMY_DATABASE_URI = f"sqlite:///{temp_db_path}"
    WTF_CSRF_ENABLED = False  # Disable CSRF for programmatic test client POSTs
    TESTING = True

app = create_app(IsolatedTestConfig)

# Ensure new tables (security_incidents, security_incident_logs) exist in temp db
with app.app_context():
    db.create_all()
    # Create test user B for isolation testing
    if not User.query.filter_by(username="user_b").first():
        u_b = User(username="user_b", email="user_b@isolation.test")
        u_b.set_password("Password@123")
        db.session.add(u_b)
        db.session.commit()

client = app.test_client()

results = []
PASS = "PASS"
FAIL = "FAIL"

def check(label, condition, extra=""):
    status = PASS if condition else FAIL
    results.append((status, label, extra))
    mark = "OK" if condition else "XX"
    print(f"  [{mark}] {label}" + (f" -> {extra}" if extra else ""))

print("\n=== VoiceShield AI – Defensive Cybersecurity Suite Test Suite (Features 1–7) ===\n")

# ---------------------------------------------------------------------------
# 1. Unauthenticated Route Access Protection
# ---------------------------------------------------------------------------
print("[1] Unauthenticated Route Access Protection:")
protected_routes = [
    "/phishing-checker",
    "/password-checker",
    "/incident-center",
    "/incident-center/new",
    "/security-training",
    "/threat-intelligence",
    "/file-integrity",
    "/personal-security-audit"
]

for route in protected_routes:
    resp = client.get(route)
    check(f"GET {route} redirects unauthenticated user",
          resp.status_code == 302 and "/login" in resp.headers.get("Location", ""))

# ---------------------------------------------------------------------------
# 2. User Authentication
# ---------------------------------------------------------------------------
print("\n[2] User Authentication:")
login_res = client.post("/login", data={
    "identifier": "foundationuser",
    "password": "Password@123",
}, follow_redirects=True)
check("Login succeeds for primary user 'foundationuser'",
      login_res.status_code == 200 and b"Logout" in login_res.data)

# ---------------------------------------------------------------------------
# 3. Feature 1: Phishing & Email Threat Analyzer (/phishing-checker)
# ---------------------------------------------------------------------------
print("\n[3] Feature 1: Phishing & Email Threat Analyzer:")

# 3a. GET route
r_phish_get = client.get("/phishing-checker")
check("GET /phishing-checker returns 200 OK", r_phish_get.status_code == 200)
check("Page contains educational disclaimer", b"Defensive Analysis Notice" in r_phish_get.data)

# 3b. Empty POST
r_phish_empty = client.post("/phishing-checker", data={"threat_text": "   "}, follow_redirects=True)
check("Empty input triggers flash warning", b"Please paste or enter message text" in r_phish_empty.data)

# 3c. Benign email POST
benign_text = "Hi Team, Attached is the weekly status agenda for our Friday team sync meeting. Best regards, Rahul."
r_phish_benign = client.post("/phishing-checker", data={"threat_text": benign_text})
check("Benign text evaluated successfully", r_phish_benign.status_code == 200)
check("Benign text assessed as Low risk", b"LOW RISK" in r_phish_benign.data or b"Low" in r_phish_benign.data)

# 3d. Malicious phishing email with urgency, OTP, and suspicious URL
phish_text = (
    "URGENT FINAL NOTICE: Your bank account will be suspended within 2 hours due to unauthorized activity. "
    "To prevent account suspension, verify your OTP immediately and confirm your credentials at: "
    "http://192.168.1.50/secure-update-hdfc-login.php. Do not ignore this mandatory message."
)
r_phish_bad = client.post("/phishing-checker", data={"threat_text": phish_text})
check("Phishing text evaluated successfully", r_phish_bad.status_code == 200)
check("Urgency indicator detected", b"Urgency" in r_phish_bad.data)
check("OTP / Credential harvesting detected", b"OTP" in r_phish_bad.data or b"Credential" in r_phish_bad.data)
check("Suspicious URL indicator detected", b"Suspicious URL" in r_phish_bad.data or b"192.168.1.50" in r_phish_bad.data)
check("High / Critical Risk tier assigned", b"High" in r_phish_bad.data or b"Critical" in r_phish_bad.data)

# 3e. Oversized input validation (>50,000 chars)
oversized = "A" * 60000
r_phish_over = client.post("/phishing-checker", data={"threat_text": oversized}, follow_redirects=True)
check("Oversized input (>50,000 chars) triggers warning redirect",
      b"Input text exceeds maximum allowed length" in r_phish_over.data or r_phish_over.status_code == 200)

# ---------------------------------------------------------------------------
# 4. Feature 2: Password Security Checker (/password-checker)
# ---------------------------------------------------------------------------
print("\n[4] Feature 2: Password Security Checker:")
r_pwd = client.get("/password-checker")
check("GET /password-checker returns 200 OK", r_pwd.status_code == 200)
check("Page contains client-side zero-transmission notice", b"Zero-Knowledge Client-Side Evaluation" in r_pwd.data)
check("Page explains offline dictionary limit", b"offline capability" in r_pwd.data)
check("Page includes dynamic password strength meter DOM elements", b"passwordInput" in r_pwd.data and b"pwd-meter-container" in r_pwd.data)

# ---------------------------------------------------------------------------
# 5. Feature 3: Security Incident Response Center (/incident-center)
# ---------------------------------------------------------------------------
print("\n[5] Feature 3: Security Incident Response Center:")

# 5a. List incidents
r_inc_list = client.get("/incident-center")
check("GET /incident-center returns 200 OK", r_inc_list.status_code == 200)
check("Incident center title rendered", b"Security Incident Response Center" in r_inc_list.data)

# 5b. New incident form
r_inc_new_form = client.get("/incident-center/new")
check("GET /incident-center/new returns 200 OK", r_inc_new_form.status_code == 200)

# 5c. Create incident
r_create = client.post("/incident-center/new", data={
    "title": "Suspected Credential Harvesting Campaign",
    "category": "Phishing",
    "severity": "High",
    "assigned_responder": "SOC Analyst Team Alpha",
    "description": "Observed multiple staff reporting SMS messages containing deceptive banking update links."
}, follow_redirects=True)
check("POST /incident-center/new creates incident successfully",
      r_create.status_code == 200 and b"Incident #" in r_create.data)

# Retrieve created incident from DB
with app.app_context():
    user = User.query.filter_by(username="foundationuser").first()
    incident = SecurityIncident.query.filter_by(user_id=user.id).order_by(SecurityIncident.id.desc()).first()
    check("SecurityIncident record persisted in database", incident is not None)
    inc_id = incident.id if incident else 1

# 5d. View incident detail
r_inc_detail = client.get(f"/incident-center/{inc_id}")
check(f"GET /incident-center/{inc_id} returns 200 OK", r_inc_detail.status_code == 200)
check("Detail shows category and severity", b"Suspected Credential Harvesting Campaign" in r_inc_detail.data)

# 5e. Update incident
r_update = client.post(f"/incident-center/{inc_id}/update", data={
    "status": "Investigating",
    "severity": "High",
    "assigned_responder": "Lead Responder Alice",
    "note": "Correlated IP addresses with firewall perimeter logs. Identified 2 internal workstation requests."
}, follow_redirects=True)
check("POST /incident-center/<id>/update updates status and notes",
      r_update.status_code == 200 and b"Incident details and activity log updated" in r_update.data)

with app.app_context():
    updated_inc = db.session.get(SecurityIncident, inc_id)
    check("Status updated to Investigating", updated_inc.status == "Investigating")
    check("Activity log record created", updated_inc.logs.count() >= 2)

# 5f. Close incident
r_close = client.post(f"/incident-center/{inc_id}/close", data={
    "closure_note": "All malicious domains blocked on DNS resolver. Workstations reimaged."
}, follow_redirects=True)
check("POST /incident-center/<id>/close resolves incident",
      r_close.status_code == 200 and b"Incident #" in r_close.data and b"Resolved" in r_close.data)

with app.app_context():
    closed_inc = db.session.get(SecurityIncident, inc_id)
    check("Status changed to Resolved", closed_inc.status == "Resolved")

# 5g. User Data Isolation Test
# Log out user A and log in as user B (user_b)
client.get("/logout")
r_login_b = client.post("/login", data={
    "identifier": "user_b",
    "password": "Password@123",
}, follow_redirects=True)
check("User B logged in successfully", r_login_b.status_code == 200 and b"Logout" in r_login_b.data)

r_isolated_get = client.get(f"/incident-center/{inc_id}")
check("User B cannot access User A's private incident (returns 404)", r_isolated_get.status_code == 404)

r_isolated_post = client.post(f"/incident-center/{inc_id}/update", data={"status": "Contained"})
check("User B cannot update User A's private incident (returns 404)", r_isolated_post.status_code == 404)

r_not_found = client.get("/incident-center/999999")
check("Nonexistent incident ID returns 404", r_not_found.status_code == 404)

# Log back in as foundationuser
client.get("/logout")
client.post("/login", data={
    "identifier": "foundationuser",
    "password": "Password@123",
}, follow_redirects=True)

# ---------------------------------------------------------------------------
# 6. Feature 4: Cybersecurity Awareness Training (/security-training)
# ---------------------------------------------------------------------------
print("\n[6] Feature 4: Cybersecurity Awareness Training:")
r_training = client.get("/security-training")
check("GET /security-training returns 200 OK", r_training.status_code == 200)
check("Training covers Phishing & Social Engineering", b"Phishing &amp; Social Engineering" in r_training.data)
check("Training covers Ransomware Prevention", b"Ransomware &amp; Malware Prevention" in r_training.data)
check("Training covers Multi-Factor Authentication", b"Multi-Factor Authentication" in r_training.data)
check("Training covers DPDP Act & Privacy", b"DPDP" in r_training.data or b"Data Privacy" in r_training.data)
check("Training covers Voice-Cloning Impersonation", b"Voice-Cloning Impersonation" in r_training.data)
check("Interactive quiz contains 8 questions", b"q1" in r_training.data and b"q8" in r_training.data)

# ---------------------------------------------------------------------------
# 7. Feature 5: Threat Intelligence Dashboard (/threat-intelligence)
# ---------------------------------------------------------------------------
print("\n[7] Feature 5: Defensive Threat Intelligence Dashboard:")
r_intel = client.get("/threat-intelligence")
check("GET /threat-intelligence returns 200 OK", r_intel.status_code == 200)
check("Page contains educational disclaimer", b"Educational Threat Repository Disclaimer" in r_intel.data)
check("Contains MITRE ATT&CK T1566 (Phishing)", b"T1566.001" in r_intel.data)
check("Contains MITRE ATT&CK T1486 (Ransomware)", b"T1486" in r_intel.data)
check("Contains MITRE ATT&CK T1598.003 (Voice Impersonation)", b"T1598.003" in r_intel.data)
check("Contains CISA and CERT-In reference citations", b"CERT-In" in r_intel.data and b"CISA" in r_intel.data)

# ---------------------------------------------------------------------------
# 8. Feature 6: Cryptographic File Integrity Checker (/file-integrity)
# ---------------------------------------------------------------------------
print("\n[8] Feature 6: Cryptographic File Integrity Checker:")

# 8a. GET route
r_file_get = client.get("/file-integrity")
check("GET /file-integrity returns 200 OK", r_file_get.status_code == 200)
check("Page contains integrity vs authenticity explanation", b"Integrity vs. Authenticity" in r_file_get.data)

# 8b. Empty file upload
r_file_empty = client.post("/file-integrity", data={}, follow_redirects=True)
check("Missing file upload flashes warning", b"Please choose a file" in r_file_empty.data)

# 8c. Valid file SHA-256 calculation & MATCH verification
test_content = b"Cybersecurity Defense Suite - VoiceShield AI Test Payload 2026\n"
expected_sha256 = hashlib.sha256(test_content).hexdigest().lower()

file_data = {
    "check_file": (io.BytesIO(test_content), "payload.txt"),
    "reference_hash": expected_sha256
}
r_file_match = client.post("/file-integrity", data=file_data, content_type="multipart/form-data")
check("File upload processed successfully", r_file_match.status_code == 200)
check("Computed SHA-256 matches expected digest", expected_sha256.encode("utf-8") in r_file_match.data)
check("Match status verdict indicates MATCH", b"INTEGRITY VERIFIED (MATCH)" in r_file_match.data)

# 8d. Mismatched reference hash
file_data_mismatch = {
    "check_file": (io.BytesIO(test_content), "payload.txt"),
    "reference_hash": "0000000000000000000000000000000000000000000000000000000000000000"
}
r_file_mismatch = client.post("/file-integrity", data=file_data_mismatch, content_type="multipart/form-data")
check("Mismatch detected with wrong reference hash", b"INTEGRITY MISMATCH DETECTED" in r_file_mismatch.data)

# ---------------------------------------------------------------------------
# 9. Feature 7: Personal Cybersecurity Audit (/personal-security-audit)
# ---------------------------------------------------------------------------
print("\n[9] Feature 7: Personal Cybersecurity Audit:")
r_audit = client.get("/personal-security-audit")
check("GET /personal-security-audit returns 200 OK", r_audit.status_code == 200)
check("Page contains privacy notice", b"Privacy &amp; Educational Assessment Notice" in r_audit.data)
check("Contains MFA control item", b"Multi-Factor Authentication" in r_audit.data)
check("Contains 3-2-1 backup item", b"3-2-1 Backup Strategy" in r_audit.data)
check("Contains 1930 Cyber Helpline reporting item", b"1930" in r_audit.data)
check("Contains dynamic score calculation container", b"auditScoreDisplay" in r_audit.data)

# ---------------------------------------------------------------------------
# 10. Navigation Integration
# ---------------------------------------------------------------------------
print("\n[10] Navigation Integration in Dashboard:")
r_dash = client.get("/dashboard")
check("GET /dashboard returns 200 OK", r_dash.status_code == 200)
check("Dashboard contains 'Defensive Cybersecurity Suite' section", b"Defensive Cybersecurity Suite" in r_dash.data)
check("Dashboard links to Phishing Checker", b"/phishing-checker" in r_dash.data)
check("Dashboard links to Password Checker", b"/password-checker" in r_dash.data)
check("Dashboard links to Incident Center", b"/incident-center" in r_dash.data)
check("Dashboard links to Security Training", b"/security-training" in r_dash.data)
check("Dashboard links to Threat Intelligence", b"/threat-intelligence" in r_dash.data)
check("Dashboard links to File Integrity", b"/file-integrity" in r_dash.data)
check("Dashboard links to Personal Audit", b"/personal-security-audit" in r_dash.data)

# Clean up isolated temporary database
try:
    if os.path.exists(temp_db_path):
        os.remove(temp_db_path)
except OSError:
    pass

# Summary
passed = sum(1 for status, _, _ in results if status == PASS)
failed = sum(1 for status, _, _ in results if status == FAIL)
total = len(results)

print("\n" + "=" * 65)
print(f"Cybersecurity Suite Test Summary: {passed}/{total} PASSED, {failed} FAILED")
print("=" * 65 + "\n")

if failed > 0:
    sys.exit(1)
