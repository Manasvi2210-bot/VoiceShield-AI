# VoiceShield AI — Cybersecurity & Cyber Laws Defense Suite

**Course Code:** 171405A — Cyber Security and Laws  
**Application Architecture:** Python Flask with SQLite (SQLAlchemy), Jinja2, Vanilla CSS, and Client-Side Hardened Security Utilities.

---

## Overview

VoiceShield AI is an integrated cybersecurity platform built to detect social-engineering audio scams, provide hands-on attack-and-defense simulations, map syllabus concepts (Units I–V), and deliver a comprehensive **Defensive Cybersecurity Suite** for classroom demonstrations and personal cyber defense.

---

## Defensive Cybersecurity Suite Modules (Features 1–7)

### 1. Phishing & Email Threat Analyzer
* **Route:** `/phishing-checker`
* **Capabilities:** Evaluates pasted emails, SMS messages, and URLs against rule-based indicators including artificial urgency, executive impersonation, OTP/credential demands, and lookalike/typosquatting URL patterns.
* **Limitations:** Uses transparent regex heuristics, not deep-learning linguistic models. Does *not* fetch external websites, execute active scripts, or connect to third-party reputation APIs from the server. Heuristic scores are risk indicators, not definitive proof of phishing.

### 2. Client-Side Password Security Checker
* **Route:** `/password-checker`
* **Capabilities:** Evaluates password length, character diversity, repeated sequences, common patterns, and dictionary resilience entirely inside the client browser. Provides actionable strength recommendations.
* **Limitations:** Strictly client-side. Entered passwords are never transmitted, logged, or saved to server disks or databases. No password can be guaranteed 100% unbreakable against quantum or unlimited offline brute force; offline checking cannot verify real-time dark-web credential dumps.

### 3. Security Incident Response Center
* **Routes:** `/incident-center`, `/incident-center/new`, `/incident-center/<id>`, `/incident-center/<id>/update`, `/incident-center/<id>/close`, `/incident-center/<id>/delete`
* **Capabilities:** Structured incident lifecycle management (Open &rarr; Investigating &rarr; Contained &rarr; Resolved). Tracks category, severity, responder assignment, notes, and an immutable timestamped activity audit log.
* **Limitations:** Enforces strict user isolation via session authentication; users cannot access, modify, or close other analysts' incidents. Built on a dedicated relational model (`SecurityIncident`) without modifying existing audio incident tables.

### 4. Cybersecurity Awareness Training & Quizzes
* **Route:** `/security-training`
* **Capabilities:** 8 structured defensive modules covering Phishing/Social Engineering, Ransomware, MFA/Password Hygiene, Safe Browsing, Data Privacy (DPDP Act), Wi-Fi/Device Security, Incident Reporting (1930 / cybercrime.gov.in), and Synthetic Voice Impersonation. Includes an interactive graded 8-question quiz with dynamic answer reveals and feedback.
* **Limitations:** Educational scenarios are strictly simulations and do not represent active or real live incidents.

### 5. Defensive Threat Intelligence Dashboard
* **Route:** `/threat-intelligence`
* **Capabilities:** Curated defensive threat repository mapping modern threat actors, typical Indicators of Compromise (IoCs), business impact, and defensive mitigations aligned with MITRE ATT&CK&reg; techniques and CISA/CERT-In advisories. Includes real-time category filtering and text search.
* **Limitations:** Curated educational static repository. Does not connect to paid commercial feeds or claim live zero-day surveillance. Sample indicators are illustrative.

### 6. Cryptographic File Integrity Checker
* **Route:** `/file-integrity`
* **Capabilities:** Computes streaming SHA-256 (plus legacy SHA-1 and MD5 for backward compatibility) cryptographic digests using Python's standard-library `hashlib` in fixed 64 KB memory chunks. Automatically compares output against user-supplied reference hashes.
* **Limitations:** Verifies bit-for-bit integrity (that the file was not altered or corrupted in transit), but does *not* prove that a file is benign or trustworthy unless the reference hash was obtained from an authenticated, trusted publisher. Files are immediately deleted from temporary storage upon computation.

### 7. Personal Cybersecurity Hygiene Audit
* **Route:** `/personal-security-audit`
* **Capabilities:** Privacy-friendly 10-control self-assessment evaluating personal defense readiness (MFA, password managers, patch management, 3-2-1 backups, recovery hygiene, safe browsing, app permissions, disk encryption, vishing protocols, and CERT-In reporting). Computes transparent score percentages, readiness tier badges, and dynamic recommendations.
* **Limitations:** Evaluated entirely client-side. VoiceShield AI never asks for or stores private credentials, recovery keys, or bank details. The readiness score is an educational baseline and does not represent an ISO 27001 compliance audit.

---

## Audio Analysis Transparency Notice

The core audio analysis module (`/analyse`) provides defensive evaluation of voice recordings using:
1. **Scam-Phrase Heuristics:** Keyword and regex pattern matching across transcriptions for typical scam tropes (digital arrest, Aadhaar verification, electricity bill cutoffs, urgent bank transfers).
2. **Acoustic Measurements:** Baseline signal measurements (silence ratio, clipping distortion, frequency distribution).
3. **Important Note:** The application does *not* claim trained AI deepfake/voice-cloning classification models. Scores reflect rule-based heuristic risk indicators.

---

## How to Run the Application Locally

### Prerequisites
- Python 3.10+ installed
- Virtual environment with Flask, Flask-Login, Flask-SQLAlchemy, Flask-WTF, Werkzeug

### Starting the Server
From the root workspace directory (`C:\CS Mini Project`):

```bash
# Using Python virtual environment:
python app.py
```

The application runs locally on:
`http://127.0.0.1:5000`

### Default Test Analyst Credentials
- **Username:** `analyst`
- **Password:** `Analyst@123`

---

## Running the Automated Test Suites

All tests use isolated in-memory or temporary databases to ensure the production database (`voiceshield.db`) is never modified or reset:

```bash
# Run new Cybersecurity Suite test suite:
python test_cybersecurity_suite.py

# Run existing test suites:
python test_attack_lab.py
python verify_web_demonstration.py
python test_foundation.py
python test_new_routes.py
python test_unit1.py
python test_unit2.py
python test_unit3.py
```
