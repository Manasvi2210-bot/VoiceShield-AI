"""
test_attack_lab.py – Automated Test Suite for Cybersecurity Attack & Defense Lab.

Verifies:
1. Route protection: unauthenticated requests to /attack-lab and API endpoints redirect to /login.
2. Authenticated GET /attack-lab returns 200 OK and renders all components:
   - Scenario 1: Phishing & Social Engineering (BEC)
   - Scenario 2: AI Voice-Cloning Impersonation (Deepfake Vishing)
   - Scenario 3: SQL Injection (SQLi) Awareness (CWE-89)
   - Scenario 4: Cross-Site Scripting (XSS) Awareness (CWE-79)
   - Scenario 5: Password Security & Storage Defenses (Salt & Argon2id/bcrypt)
   - Threat Risk Analyzer with interactive 5x5 matrix
   - Digital Forensics Timeline with events E-101 through E-106
   - Cybersecurity Challenge Zone with Unit I-III links and synthesis quiz.
3. Threat Risk Analyzer endpoint (POST /attack-lab/analyze-risk):
   - Computes deterministic NIST SP 800-30 / ISO 27005 risk scores.
   - Evaluates defense-in-depth controls (MFA, segmentation, backups, training).
   - Handles custom scenarios with transparent rule-based attribution.
4. Digital Forensics Timeline endpoint (POST /attack-lab/forensics-event):
   - Returns valid triage data and cryptographic artifacts for E-101 through E-106.
   - Returns 404 for nonexistent event IDs.
5. Navigation integration:
   - Verifies the Attack Lab link is present in the main navigation.
6. Database safety:
   - Tests execute against an isolated temporary SQLite database copy.
"""

import json
import os
import shutil
import sqlite3
import sys
import tempfile

from app import create_app
from config import Config

# Create isolated temporary database copy
temp_db_fd, temp_db_path = tempfile.mkstemp(suffix=".db")
os.close(temp_db_fd)
prod_db_file = os.path.join(os.path.dirname(__file__), "voiceshield.db")
if os.path.exists(prod_db_file):
    shutil.copy2(prod_db_file, temp_db_path)


class IsolatedTestConfig(Config):
    SQLALCHEMY_DATABASE_URI = f"sqlite:///{temp_db_path}"


app = create_app(IsolatedTestConfig)
client = app.test_client()

results = []
PASS = "PASS"
FAIL = "FAIL"


def check(label, condition, extra=""):
    status = PASS if condition else FAIL
    results.append((status, label, extra))
    mark = "OK" if condition else "XX"
    print(f"  [{mark}] {label}" + (f" -> {extra}" if extra else ""))


print("\n=== VoiceShield AI – Attack & Defense Lab Test Suite ===\n")

# ---------------------------------------------------------------------------
# 1. Unauthenticated Route Access Protection
# ---------------------------------------------------------------------------
print("[1] Unauthenticated Route Protection:")
r_unauth_page = client.get("/attack-lab")
check("GET /attack-lab redirects unauthenticated user", r_unauth_page.status_code == 302 and "/login" in r_unauth_page.headers.get("Location", ""))

r_unauth_risk = client.post("/attack-lab/analyze-risk", json={"likelihood": 3, "impact": 3})
check("POST /attack-lab/analyze-risk redirects unauthenticated user", r_unauth_risk.status_code == 302 and "/login" in r_unauth_risk.headers.get("Location", ""))

r_unauth_forensic = client.post("/attack-lab/forensics-event", json={"event_id": "E-101"})
check("POST /attack-lab/forensics-event redirects unauthenticated user", r_unauth_forensic.status_code == 302 and "/login" in r_unauth_forensic.headers.get("Location", ""))

# ---------------------------------------------------------------------------
# 2. Authentication
# ---------------------------------------------------------------------------
print("\n[2] User Authentication:")
login_res = client.post("/login", data={
    "identifier": "foundationuser",
    "password": "Password@123",
}, follow_redirects=True)
check("Login succeeds for foundationuser", login_res.status_code == 200 and b"Logout" in login_res.data)

# ---------------------------------------------------------------------------
# 3. Authenticated Page & Component Rendering
# ---------------------------------------------------------------------------
print("\n[3] Lab Page Content & Component Rendering:")
lab_res = client.get("/attack-lab")
check("Authenticated GET /attack-lab returns 200 OK", lab_res.status_code == 200)

content = lab_res.data.decode("utf-8")
check("Page contains Course Code 171405A badge", "Course Code: 171405A" in content)
check("Page contains Lab Overview & Ethical Guardrails", "Lab Overview &amp; Ethical Guardrails" in content or "Lab Overview" in content)
check("Section 1: Attack Simulator present", "1. Interactive Attack Simulator" in content)
check("Scenario 1 (Phishing / BEC) present", "Urgent Executive Wire Request" in content)
check("Scenario 2 (AI Voice-Cloning Vishing) present", "AI Voice-Cloning CFO Impersonation" in content)
check("Scenario 3 (SQLi CWE-89) present", "SQL Injection (SQLi) Vulnerability Awareness" in content)
check("Scenario 4 (XSS CWE-79) present", "Cross-Site Scripting (Reflected &amp; Stored XSS) Awareness" in content or "Cross-Site Scripting" in content)
check("Scenario 5 (Password Security) present", "Credential Stuffing &amp; Password Storage Defenses" in content)

check("Section 2: Threat Risk Analyzer present", "2. Threat Risk Analyzer" in content)
check("5x5 Quantitative Risk Matrix container present", "5×5 Quantitative Risk Matrix" in content)
check("Deterministic calculation formula disclosed", "Effective Likelihood × Effective Impact" in content)

check("Section 3: Forensics Timeline present", "3. Digital Forensics Timeline: Operation SpoofedCaller" in content)
check("All timeline nodes E-101 to E-106 rendered", all(f"E-10{i}" in content for i in range(1, 7)))

check("Section 4: Challenge Zone present", "4. Cybersecurity Challenge Zone" in content)
check("Direct links to Units I, II, and III present", all(unit in content for unit in ["/unit1", "/unit2", "/unit3"]))
check("Synthesis Challenge quiz present with 5 questions", "Attack Lab Synthesis Challenge" in content and "cq5" in content)

# ---------------------------------------------------------------------------
# 4. Threat Risk Analyzer API Tests
# ---------------------------------------------------------------------------
print("\n[4] Threat Risk Analyzer API Endpoint:")
# Base Voice Cloning scenario without controls
res_risk1 = client.post("/attack-lab/analyze-risk", json={
    "scenario_key": "voice_cloning_wire_fraud",
    "likelihood": 4,
    "impact": 5,
    "controls": []
})
check("POST /attack-lab/analyze-risk returns 200 OK", res_risk1.status_code == 200)
data_risk1 = res_risk1.get_json()
check("Voice cloning unmitigated score is 20", data_risk1.get("score") == 20)
check("Risk tier is 'Critical'", data_risk1.get("tier") == "Critical")
check("Method clearly states rule-based NIST alignment", "NIST SP 800-30" in data_risk1.get("method", ""))

# Mitigated scenario with defensive controls
res_risk2 = client.post("/attack-lab/analyze-risk", json={
    "scenario_key": "voice_cloning_wire_fraud",
    "likelihood": 4,
    "impact": 5,
    "controls": ["mfa", "segmentation", "training"]
})
check("POST with defensive controls returns 200 OK", res_risk2.status_code == 200)
data_risk2 = res_risk2.get_json()
check("Effective likelihood reduced by controls", data_risk2.get("effective_likelihood") < 4)
check("Mitigated risk score is lower than 20", data_risk2.get("score") < 20)
check("Mitigations list provided in response", len(data_risk2.get("mitigations", [])) > 0)

# Custom scenario evaluation
res_risk_custom = client.post("/attack-lab/analyze-risk", json={
    "scenario_key": "custom",
    "custom_desc": "Misconfigured Cloud Object Storage with Customer PII",
    "likelihood": 3,
    "impact": 4,
    "controls": []
})
check("Custom scenario returns 200 OK", res_risk_custom.status_code == 200)
data_custom = res_risk_custom.get_json()
check("Custom scenario title reflects input description", "Misconfigured Cloud Object Storage" in data_custom.get("scenario_title", ""))
check("Custom score calculated accurately (12)", data_custom.get("score") == 12)

# ---------------------------------------------------------------------------
# 5. Digital Forensics Timeline API Tests
# ---------------------------------------------------------------------------
print("\n[5] Digital Forensics Timeline API Endpoint:")
# Test Benign Event E-101
res_e101 = client.post("/attack-lab/forensics-event", json={"event_id": "E-101"})
check("E-101 returns 200 OK", res_e101.status_code == 200)
d_e101 = res_e101.get_json()
check("E-101 is Benign", d_e101.get("severity") == "Benign" and not d_e101.get("is_anomaly"))
check("E-101 mentions CERT-In log retention", "CERT-In" in d_e101.get("recommended_action", ""))

# Test Suspicious Voice-Clone Event E-102
res_e102 = client.post("/attack-lab/forensics-event", json={"event_id": "E-102"})
check("E-102 returns 200 OK", res_e102.status_code == 200)
d_e102 = res_e102.get_json()
check("E-102 includes SHA-256 evidence artifact", "SHA-256:" in d_e102.get("evidence_artifact", ""))
check("E-102 verdict identifies synthetic vocoder artifacts", "synthetic vocoder" in d_e102.get("forensic_verdict", ""))
check("E-102 IR phase is NIST Detection & Analysis", "Detection & Analysis" in d_e102.get("ir_phase", ""))

# Test Fraud Staging Event E-104
res_e104 = client.post("/attack-lab/forensics-event", json={"event_id": "E-104"})
check("E-104 returns 200 OK", res_e104.status_code == 200)
d_e104 = res_e104.get_json()
check("E-104 cites IT Act Section 66D and Section 43", "Section 66D" in d_e104.get("forensic_verdict", "") and "Section 43" in d_e104.get("forensic_verdict", ""))
check("E-104 response cites Helpline 1930 and 6-hour CERT-In reporting", "1930" in d_e104.get("recommended_action", "") and "6 hours" in d_e104.get("recommended_action", ""))

# Test Forensic Vault Custody Event E-106
res_e106 = client.post("/attack-lab/forensics-event", json={"event_id": "E-106"})
check("E-106 returns 200 OK", res_e106.status_code == 200)
d_e106 = res_e106.get_json()
check("E-106 references Section 65B Indian Evidence Act / BSA Section 63", "Section 65B" in d_e106.get("forensic_verdict", ""))

# Test Unknown Event 404
res_e999 = client.post("/attack-lab/forensics-event", json={"event_id": "E-999"})
check("Unknown event E-999 returns 404 Not Found", res_e999.status_code == 404)

# ---------------------------------------------------------------------------
# 6. Navigation Link Integration
# ---------------------------------------------------------------------------
print("\n[6] Navigation Link Integration:")
dash_res = client.get("/dashboard")
check("Dashboard navigation contains /attack-lab link", b"/attack-lab" in dash_res.data)

# Clean up isolated temporary database
try:
    if os.path.exists(temp_db_path):
        os.remove(temp_db_path)
except Exception:
    pass

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
total = len(results)
passed = sum(1 for s, _, _ in results if s == PASS)
failed = sum(1 for s, _, _ in results if s == FAIL)

print(f"\nResults: {passed}/{total} passed, {failed} failed.\n")

if failed > 0:
    print(f"FAILED tests ({failed}):")
    for s, label, extra in results:
        if s == FAIL:
            print(f"  - {label} ({extra})")
    sys.exit(1)
else:
    print("ALL ATTACK LAB TESTS PASSED.")
    sys.exit(0)
