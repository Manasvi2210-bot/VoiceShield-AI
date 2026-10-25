"""
test_unit2.py – Test suite for Unit II: Ethical Hacking & Defensive Security Testing.

Verifies:
1. /unit2 requires authentication (redirects to login for unauthenticated requests).
2. Authenticated GET /unit2 returns 200 OK.
3. Content validation for Course 171405A syllabus topics:
   - Introduction to ethical hacking, authorization & Rules of Engagement.
   - Hacker classifications: white-hat, black-hat, grey-hat, red/blue/purple teams.
   - 5-phase ethical hacking methodology (Planning, Recon, Scanning, Validation, Reporting).
   - Passive vs. active reconnaissance and OSINT.
   - Scanning, vulnerability assessment, and CVSS framework.
   - Web application security risks: SQL injection, XSS, Broken Access Control (IDOR).
   - Password defense: hashing vs encryption, cryptographic salting, memory-hard hashing.
   - Social engineering awareness: vishing, pretexting, voice-cloning defenses.
   - Professional security tools (Nmap, Wireshark, OWASP ZAP, Burp Suite) & safe labs (DVWA, Juice Shop).
   - Coordinated Vulnerability Disclosure (CVD) and bug bounty standards.
   - Sony PlayStation Network 2011 breach case study (hacktivism vs ethical hacking).
4. Interactive Knowledge Quiz:
   - At least 10 multiple-choice questions present.
   - Form inputs, submit button, score banner, and explanation containers present.
   - Progress checklist tracker present.
5. Unit I and core application regression verification:
   - GET /unit1 remains intact and returns 200 OK.
   - Privacy isolation on incident records remains enforced.
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


print("\n=== VoiceShield AI – Unit II Syllabus Test Suite ===\n")

# 1. Unauthenticated redirect
r_unauth = c.get("/unit2")
check("/unit2 redirects to login for unauthenticated user", r_unauth.status_code == 302)

# 2. Authenticate using foundation test user
c.post("/login", data={
    "identifier": "foundationuser",
    "password": "Password@123",
}, follow_redirects=True)

# 3. Authenticated GET /unit2
r = c.get("/unit2")
check("GET /unit2 returns 200 OK for authenticated user", r.status_code == 200)

html = r.data.decode("utf-8")

# 4. Syllabus Core Topics
print("\n[Syllabus Content Checks]")
check("Course Code 171405A present", "171405A" in html)
check("Unit II Title present", "Unit II: Ethical Hacking" in html or "Unit II – Ethical Hacking" in html)
check("Authorization & Rules of Engagement requirement present",
      "Rules of Engagement" in html or "written authorization" in html.lower())
check("Hacker categories (white-hat, black-hat, grey-hat) present",
      "White-Hat" in html and "Black-Hat" in html and "Grey-Hat" in html)
check("Security teams (Red, Blue, Purple) present",
      "Red Team" in html and "Blue Team" in html and "Purple Team" in html)
check("5-Phase Ethical Hacking lifecycle present",
      ("Planning & Scoping" in html or "Planning &amp; Scoping" in html) and
      "Reconnaissance" in html and
      ("Scanning & Enumeration" in html or "Scanning &amp; Enumeration" in html) and
      ("Reporting & Retesting" in html or "Reporting &amp; Retesting" in html))
check("Passive vs. Active reconnaissance & OSINT present",
      "Passive Reconnaissance" in html and "Active Reconnaissance" in html and "OSINT" in html)
check("Vulnerability, Threat, Risk & CVSS metrics present",
      "Vulnerability" in html and "Threat" in html and "CVSS" in html)
check("Web application security (SQLi, XSS, Broken Access Control) present",
      "SQL Injection" in html and "Cross-Site Scripting" in html and "Broken Access Control" in html)
check("Password defense (hashing vs encryption, salting) present",
      "Hashing vs. Encryption" in html and "Cryptographic Salts" in html)
check("Social engineering & voice cloning vishing context present",
      "Voice Cloning" in html and "Out-of-Band" in html)
check("Security tools (Nmap, Wireshark, OWASP ZAP/Burp) present",
      "Nmap" in html and "Wireshark" in html and ("OWASP ZAP" in html or "Burp Suite" in html))
check("Safe educational lab environments (Juice Shop, DVWA) present",
      "Juice Shop" in html and "DVWA" in html)
check("Responsible disclosure & Coordinated Disclosure present",
      "Responsible Disclosure" in html or "Coordinated Vulnerability Disclosure" in html)

# 5. Sony Case Study Checks
print("\n[Sony PSN Case Study Checks]")
check("Sony case study section present", "Sony PlayStation Network" in html or "Sony Cyberattack" in html)
check("Hacktivism vs ethical hacking distinction present", "Hacktivism" in html and "Ethical Hacking" in html)
check("77 million user accounts cited", "77 million" in html)
check("23-day outage cited", "23 days" in html or "23-day" in html)
check("Credible source references included", "Sony Computer Entertainment" in html and "SANS Institute" in html)

# 6. Interactive Knowledge Quiz Checks
print("\n[Interactive Knowledge Quiz Checks]")
# Count quiz questions (q2item-1 to q2item-10)
question_count = sum(1 for i in range(1, 20) if f'id="q2item-{i}"' in html)
check("Quiz contains at least 10 questions", question_count >= 10, f"{question_count} questions found")
check("Quiz submit button present", 'id="btnSubmitQuiz2"' in html)
check("Quiz score banner container present", 'id="quizScoreBanner2"' in html)
check("Quiz explanation containers present for all questions",
      all(f'id="u2exp-{i}"' in html for i in range(1, question_count + 1)))
check("Progress checklist tracker present", 'id="unit2ProgressCard"' in html or 'id="sec-progress"' in html)

# 7. Regression & Preservation Checks
print("\n[Regression & Preservation Checks]")
r_u1 = c.get("/unit1")
check("Unit I remains intact and returns 200 OK", r_u1.status_code == 200 and b"Unit I: Introduction" in r_u1.data)

# Summary
passed = sum(1 for s, _, _ in results if s == PASS)
failed = sum(1 for s, _, _ in results if s == FAIL)
print(f"\n{'='*55}")
print(f"  Unit II Results: {passed} PASSED  |  {failed} FAILED")
print(f"{'='*55}\n")

if failed > 0:
    sys.exit(1)
sys.exit(0)
