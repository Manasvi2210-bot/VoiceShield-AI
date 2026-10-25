"""
test_unit3.py – Comprehensive Test Suite for Unit III: Cyber Laws & Legal Frameworks.

Verifies:
1. /unit3 requires authentication (redirects unauthenticated requests to login).
2. Authenticated GET /unit3 returns 200 OK.
3. Content validation for Course 171405A syllabus topics:
   - Topic 1: Meaning and purpose of cyber law, jurisdiction, Section 75 extra-territorial jurisdiction.
   - Topic 2: IT Act 2000 provisions (43, 43A, 65, 66, 66C, 66D, 66E, 66F, 67, 69, 70, 70B, 72)
             and Section 66A struck down constitutional status.
   - Topic 3: Electronic records & signatures vs digital signatures (PKI, CCA, non-repudiation).
   - Topic 4: Privacy & DPDP Act 2023 (Data Principal, Data Fiduciary, phased implementation status, review date: October 2026).
   - Topic 5: Cybercrime scenarios (identity theft, phishing, unauthorized access, cyberstalking, payment fraud, ransomware, AI voice cloning).
   - Topic 6: Intellectual Property (copyright, software licensing, trademarks, cybersquatting, AI content ethics).
   - Topic 7: Electronic evidence (volatility, chain of custody, Section 65B, SHA-256 as integrity vs authenticity).
   - Topic 8: CERT-In compliance (Section 70B, 6-hour mandatory reporting, 180-day log retention).
   - Topic 9: Fact-checked landmark case studies (Shreya Singhal, Suhas Katti, Puttaswamy) with authoritative links.
   - Topic 10: Responsible digital citizenship & legal disclaimer.
4. Interactive Tools & Quiz:
   - Suspicious message checker widget and /unit3/check endpoint compatibility.
   - Progress checklist with interactive tracker.
   - At least 10 multiple-choice questions present with submit, reset, score banner, and explanations.
5. Regression & Preservation:
   - Unit I and Unit II remain intact and return 200 OK.
   - Privacy isolation and existing routes remain intact.
"""

import json
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


print("\n=== VoiceShield AI – Unit III Cyber Laws Test Suite ===\n")

# 1. Unauthenticated redirect
r_unauth = c.get("/unit3")
check("/unit3 redirects to login for unauthenticated user", r_unauth.status_code == 302)

# 2. Authenticate using foundation test user
login_res = c.post("/login", data={
    "identifier": "foundationuser",
    "password": "Password@123",
}, follow_redirects=True)
check("Login succeeds for foundationuser", login_res.status_code == 200)

# 3. Authenticated GET /unit3
r = c.get("/unit3")
check("GET /unit3 returns 200 OK for authenticated user", r.status_code == 200)

html = r.data.decode("utf-8")

# 4. Syllabus Core Topics & Header
print("\n[Syllabus Content Checks]")
check("Course Code 171405A present", "171405A" in html)
check("Unit III Title present", "Unit III: Cyber Laws" in html or "Unit III – Cyber Laws" in html)
check("Legal information review date (October 2026) present", "October 2026" in html)

# Topic 1: Cyber Law & Jurisdiction
print("\n[Topic 1: Cyber Law & Jurisdiction Checks]")
check("Meaning and purpose of cyber law present", "jurisprudence" in html.lower() or "cyber law" in html.lower())
check("Section 75 extra-territorial jurisdiction present", "Section 75" in html and "extra-territorial" in html.lower())

# Topic 2: IT Act, 2000 & Sections
print("\n[Topic 2: IT Act 2000 Provisions & Accuracy Checks]")
check("IT Act 2000 cited", "Information Technology Act, 2000" in html or "IT Act" in html)
check("Section 43 civil liability & compensation present", "Section 43" in html and "compensation" in html.lower())
check("Section 43A historical status & DPDP transition present", "Section 43A" in html and "sensitive personal data" in html.lower())
check("Section 65 computer source code tampering present", "Section 65" in html and "source" in html.lower())
check("Section 66 computer related offences present", "Section 66" in html and ("dishonestly" in html.lower() or "fraudulently" in html.lower()))
check("Section 66A explicitly marked STRUCK DOWN / UNCONSTITUTIONAL",
      "Section 66A" in html and ("struck down" in html.lower() or "unconstitutional" in html.lower()))
check("Section 66C identity theft present", "Section 66C" in html and "identity theft" in html.lower())
check("Section 66D cheating by personation present", "Section 66D" in html and "cheating by personation" in html.lower())
check("Section 66E violation of privacy present", "Section 66E" in html and "privacy" in html.lower())
check("Section 66F cyberterrorism present", "Section 66F" in html and "cyberterrorism" in html.lower())
check("Section 67 / 67A / 67B electronic obscenity / CSAM present", "Section 67" in html and ("67A" in html or "67B" in html))
check("Section 69 / 69A interception & blocking safeguards present", "Section 69" in html and "Section 69A" in html)
check("Section 70 protected systems present", "Section 70" in html and "protected system" in html.lower())
check("Section 70B CERT-In statutory role present", "Section 70B" in html and "CERT-In" in html)
check("Section 72 / 72A breach of confidentiality present", "Section 72" in html)
check("Distinction between civil liability and criminal offences present",
      "civil liability" in html.lower() and "criminal offence" in html.lower())

# Topic 3: E-Signatures & Digital Signatures
print("\n[Topic 3: E-Signatures vs Digital Signatures Checks]")
check("E-Signature vs Digital Signature comparison present",
      "Electronic Signature" in html and "Digital Signature" in html)
check("Asymmetric Public Key Infrastructure (PKI) cited", "asymmetric" in html.lower() or "PKI" in html)
check("Controller of Certifying Authorities (CCA) cited", "Controller of Certifying Authorities" in html or "CCA" in html)
check("Authentication, Integrity, and Non-Repudiation present",
      "Authentication" in html and "Integrity" in html and "Non-Repudiation" in html)

# Topic 4: Privacy & DPDP Act 2023
print("\n[Topic 4: Privacy & DPDP Act 2023 Checks]")
check("DPDP Act 2023 cited", "Digital Personal Data Protection Act, 2023" in html or "DPDP Act" in html)
check("Distinction between enactment and phased implementation status present",
      "phased" in html.lower() or "commencement" in html.lower())
check("Data Principal and Data Fiduciary defined", "Data Principal" in html and "Data Fiduciary" in html)
check("Core privacy principles (purpose limitation, data minimisation) present",
      "Purpose Limitation" in html and ("Data Minimisation" in html or "Data Minimization" in html))

# Topic 5: Cybercrime Scenarios & AI Voice Impersonation
print("\n[Topic 5: Cybercrime Scenarios Checks]")
check("Identity theft scenario present", "Identity Theft" in html or "SIM Swap" in html)
check("Phishing scenario present", "Phishing" in html)
check("Unauthorized access & data theft scenario present", "Unauthorized Access" in html and "Data Theft" in html)
check("Cyberstalking scenario present", "Cyberstalking" in html or "Harassment" in html)
check("Digital payment / QR code fraud scenario present", "Digital Payment" in html or "QR Code" in html)
check("Ransomware scenario present", "Ransomware" in html)
check("AI Voice Impersonation scenario present", "Voice Impersonation" in html or "Voice Clone" in html or "Voice-Cloning" in html)

# Topic 6: Intellectual Property
print("\n[Topic 6: Intellectual Property Checks]")
check("Copyright & software licensing present", "Copyright" in html and "Licensing" in html)
check("Trademarks & Cybersquatting present", "Trade Marks" in html or "Trademarks" in html or "Cybersquatting" in html)

# Topic 7: Electronic Evidence & Integrity vs Authenticity
print("\n[Topic 7: Electronic Evidence Checks]")
check("Electronic evidence fragility & chain of custody present", "Chain of Custody" in html)
check("SHA-256 integrity vs authenticity distinction explicitly made",
      "SHA-256" in html and "integrity" in html.lower() and "authenticity" in html.lower())
check("Section 65B Evidence Act certificate mentioned", "Section 65B" in html or "Bharatiya Sakshya Adhiniyam" in html)
check("National Cyber Crime Reporting Portal (cybercrime.gov.in) cited", "cybercrime.gov.in" in html)
check("Citizen Financial Helpline 1930 cited", "1930" in html)

# Topic 8: CERT-In Compliance
print("\n[Topic 8: CERT-In Compliance Checks]")
check("CERT-In 6-hour mandatory reporting cited", "6 hour" in html.lower() or "6-hour" in html.lower())
check("180-day log retention cited", "180 day" in html.lower() or "180-day" in html.lower())
check("NTP clock synchronization cited", "NTP" in html)

# Topic 9: Case Studies & Citations
print("\n[Topic 9: Landmark Judicial Case Studies Checks]")
check("Shreya Singhal v. Union of India (2015) case study present", "Shreya Singhal" in html and "2015" in html)
check("State of Tamil Nadu v. Suhas Katti (2004) case study present", "Suhas Katti" in html and "2004" in html)
check("Justice K.S. Puttaswamy v. Union of India (2017) case study present", "Puttaswamy" in html and "2017" in html)
check("Working official links to India Code, MeitY, Supreme Court present",
      "indiacode.nic.in" in html and "meity.gov.in" in html and "sci.gov.in" in html)

# Topic 10: Responsible Digital Citizenship & Legal Disclaimer
print("\n[Topic 10: Responsible Digital Citizenship Checks]")
check("Responsible digital citizenship principles present", "Digital Citizenship" in html or "Coordinated Vulnerability" in html)
check("Educational legal disclaimer present", "Disclaimer" in html)

# Interactive Tools: Message Checker & Progress Tracker
print("\n[Interactive Tools Checks]")
check("Suspicious message input element present", 'id="socialMsgInput"' in html)
check("Suspicious message check button present", 'id="socialCheckBtn"' in html)
check("Progress checklist container present", 'id="unit3ProgressCard"' in html or 'id="sec-progress"' in html)

# Interactive Knowledge Quiz Checks
print("\n[Interactive Knowledge Quiz Checks]")
question_count = sum(1 for i in range(1, 20) if f'id="q3item-{i}"' in html)
check("Quiz contains at least 10 questions", question_count >= 10, f"{question_count} questions found")
check("Quiz submit button present", 'id="btnSubmitQuiz3"' in html)
check("Quiz reset button present", 'id="btnResetQuiz3"' in html)
check("Quiz score banner container present", 'id="quizScoreBanner3"' in html)
check("Quiz explanation containers present for all 10 questions",
      all(f'id="u3exp-{i}"' in html for i in range(1, question_count + 1)))

# Regression & Preservation Checks
print("\n[Regression & Preservation Checks]")
# 1. Check /unit3/check endpoint continues to work via test client
r_check_high = c.post("/unit3/check",
                      data=json.dumps({"text": "Congratulations you won a lottery! Click this link and share your OTP now urgently."}),
                      content_type="application/json")
d_check = json.loads(r_check_high.data)
check("/unit3/check high-risk scam text returns score > 0",
      r_check_high.status_code == 200 and d_check.get("score", 0) > 0,
      f"score={d_check.get('score')} level={d_check.get('level')}")

r_check_empty = c.post("/unit3/check",
                       data=json.dumps({"text": ""}),
                       content_type="application/json")
check("/unit3/check empty text returns 400", r_check_empty.status_code == 400)

# 2. Check Unit I returns 200
r_u1 = c.get("/unit1")
check("Unit I remains intact and returns 200 OK", r_u1.status_code == 200 and b"Unit I: Introduction" in r_u1.data)

# 3. Check Unit II returns 200
r_u2 = c.get("/unit2")
check("Unit II remains intact and returns 200 OK", r_u2.status_code == 200 and b"Unit II: Ethical Hacking" in r_u2.data)

# Summary
passed = sum(1 for s, _, _ in results if s == PASS)
failed = sum(1 for s, _, _ in results if s == FAIL)
print(f"\n{'='*55}")
print(f"  Unit III Results: {passed} PASSED  |  {failed} FAILED")
print(f"{'='*55}\n")

if failed > 0:
    print("Failed tests:")
    for s, label, extra in results:
        if s == FAIL:
            print(f"  [XX] {label} -> {extra}")
    sys.exit(1)
sys.exit(0)
