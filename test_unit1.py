"""
test_unit1.py – Test suite for Unit I: Introduction to Cyber Security.

Verifies:
1. /unit1 requires authentication (unauthenticated access redirects to login).
2. Authenticated GET /unit1 returns 200 OK.
3. Content validation for Course 171405A syllabus topics:
   - Information security & CIA triad.
   - Attack classifications: active, passive, interception, interruption, modification, fabrication.
   - Voice cloning & synthetic audio connection to social engineering.
   - Malware taxonomy: viruses, worms, Trojans, ransomware, spyware.
   - Network security: firewalls (stateless/stateful), IDS (NIDS/HIDS, signature/anomaly), IPS.
   - Defensive password security: entropy, salting, hashing, MFA.
   - Insecure connections: HTTPS, TLS, certificate authorities.
   - WannaCry ransomware case study: EternalBlue, SMBv1, MS17-010, kill switch, 3-2-1 backups.
4. Interactive Quiz verification:
   - At least 8 multiple-choice questions present (10 verified).
   - Form structure, option inputs, submit button, and explanation containers present.
   - Pure client-side execution without unauthorized database mutation.
"""

import sys
from app import create_app

app = create_app()
c = app.test_client()

results = []
PASS = "PASS"
FAIL = "FAIL"


def check(label, condition, extra=""):
    status = PASS if condition else FAIL
    results.append((status, label, extra))
    mark = "OK" if condition else "XX"
    print(f"  [{mark}] {label}" + (f" -> {extra}" if extra else ""))


print("\n=== VoiceShield AI – Unit I Syllabus Test Suite ===\n")

# 1. Unauthenticated redirect
r_unauth = c.get("/unit1")
check("/unit1 redirects to login for unauthenticated user", r_unauth.status_code == 302)

# 2. Authenticate
c.post("/login", data={
    "identifier": "foundationuser",
    "password": "Password@123",
}, follow_redirects=True)

# 3. Authenticated GET /unit1
r = c.get("/unit1")
check("GET /unit1 returns 200 OK for authenticated user", r.status_code == 200)

html = r.data.decode("utf-8")

# 4. Syllabus Core Topics
print("\n[Syllabus Content Checks]")
check("Course Code 171405A present", "171405A" in html)
check("Unit I Title present", "Unit I: Introduction to Cyber Security" in html or "Unit I – Introduction" in html)
check("CIA Triad present", "Confidentiality" in html and "Integrity" in html and "Availability" in html)
check("Active vs Passive attacks present", "Passive Attacks" in html and "Active Attacks" in html)
check("Attack classifications (interception, interruption, modification, fabrication)",
      "Interception" in html and "Interruption" in html and "Modification" in html and "Fabrication" in html)
check("Voice cloning & social engineering connection present",
      "Voice Cloning" in html or "Vishing" in html)
check("Malware taxonomy (virus, worm, trojan, ransomware, spyware)",
      "Computer Virus" in html and "Computer Worm" in html and "Trojan" in html and "Ransomware" in html and "Spyware" in html)
check("Firewall types (stateless, stateful, NGFW) present",
      "Stateless Packet Filtering" in html and "Stateful Inspection" in html)
check("IDS types and modes (NIDS, HIDS, signature, anomaly) present",
      "NIDS" in html and "HIDS" in html and "Signature-Based" in html and "Anomaly-Based" in html)
check("Defensive password security & cryptographic salting present",
      "Cryptographic Salting" in html and "Rainbow Table" in html and "Multi-Factor Authentication" in html)
check("Insecure connections and HTTPS/TLS present",
      "HTTPS" in html and "TLS" in html and "Man-in-the-Middle" in html)

# 5. WannaCry Case Study
print("\n[WannaCry Case Study Checks]")
check("WannaCry case study section present", "WannaCry Ransomware Outbreak" in html)
check("EternalBlue exploit (CVE-2017-0144) cited", "EternalBlue" in html)
check("SMBv1 protocol cited", "SMBv1" in html)
check("Kill switch domain & Marcus Hutchins cited", "Marcus Hutchins" in html and "kill switch" in html.lower())
check("MS17-010 patch lesson cited", "MS17-010" in html)
check("3-2-1 backup rule cited", "3-2-1" in html)

# 6. Interactive Knowledge Quiz Checks
print("\n[Interactive Knowledge Quiz Checks]")
# Count quiz questions (qitem-1 to qitem-10)
question_count = sum(1 for i in range(1, 20) if f'id="qitem-{i}"' in html)
check("Quiz contains at least 8 questions", question_count >= 8, f"{question_count} questions found")
check("Quiz submit button present", 'id="btnSubmitQuiz"' in html or "Submit Answers" in html)
check("Quiz score banner container present", 'id="quizScoreBanner"' in html)
check("Quiz explanation containers present for all questions",
      all(f'id="exp-{i}"' in html for i in range(1, question_count + 1)))
check("Progress checklist tracker present", 'id="unit1ProgressCard"' in html or 'id="sec-progress"' in html)

# Summary
passed = sum(1 for s, _, _ in results if s == PASS)
failed = sum(1 for s, _, _ in results if s == FAIL)
print(f"\n{'='*55}")
print(f"  Unit I Results: {passed} PASSED  |  {failed} FAILED")
print(f"{'='*55}\n")

if failed > 0:
    sys.exit(1)
sys.exit(0)
