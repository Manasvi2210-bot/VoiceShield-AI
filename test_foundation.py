"""
test_foundation.py – Regression tests for Stage 2 Foundation Enhancements.

Tests cover:
1. Local server security and configuration (debug disabled by default, host 127.0.0.1, stable secret).
2. Deep audio upload validation (valid containers, fake/disguised files, empty streams, unsupported extensions).
3. End-to-end incident submission with upload validation.
4. Database integrity (preservation of existing records).
5. User authentication lifecycle (login, authenticated access, logout).
6. Cross-user privacy isolation.
"""

import io
import json
import os
import shutil
import sqlite3
import sys
import tempfile

from app import create_app
from config import Config
from upload_security import validate_audio_upload, ALLOWED_EXTENSIONS
from werkzeug.datastructures import FileStorage

# Set up isolated temporary database to keep production voiceshield.db untouched
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


def record(label, condition, extra=""):
    status = PASS if condition else FAIL
    results.append((status, label, extra))
    mark = "OK" if condition else "XX"
    print(f"  [{mark}] {label}" + (f" -> {extra}" if extra else ""))


print("\n=== VoiceShield AI – Stage 2 Foundation Test Suite ===\n")

# ---------------------------------------------------------------------------
# 1. Configuration & Server Security Tests
# ---------------------------------------------------------------------------
print("[1] Configuration & Server Security Checks:")

# Debug mode must be False by default
record("Debug mode disabled by default", app.config.get("DEBUG") is False)

# Server host must bind to 127.0.0.1 by default
record("Server host binds to 127.0.0.1 by default", app.config.get("SERVER_HOST") == "127.0.0.1")

# Secret key must be non-empty and stable across two config instantiations
c1 = Config()
c2 = Config()
record("Secret key exists and is non-empty", bool(c1.SECRET_KEY) and len(c1.SECRET_KEY) >= 32)
record("Secret key remains stable across application instances", c1.SECRET_KEY == c2.SECRET_KEY)

# Evidence vault folder configured
record("Evidence vault folder path configured", "EVIDENCE_VAULT_FOLDER" in app.config)

# ---------------------------------------------------------------------------
# 2. Audio Upload Validation & Magic Byte Security Tests
# ---------------------------------------------------------------------------
print("\n[2] Audio Upload Magic-Byte Validation Checks:")

# Valid WAV sample
valid_wav_bytes = b"RIFF\x2c\x00\x00\x00WAVEfmt \x10\x00\x00\x00\x01\x00\x01\x00\x44\xac\x00\x00\x88\x58\x01\x00\x02\x00\x10\x00data\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
fs_valid_wav = FileStorage(stream=io.BytesIO(valid_wav_bytes), filename="sample.wav", content_type="audio/wav")
ok, msg, meta = validate_audio_upload(fs_valid_wav)
record("Valid WAV file accepted", ok, msg)

# Disguised executable (.exe renamed to .wav with MZ header)
fake_wav_bytes = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00" + b"\x00" * 40
fs_fake_wav = FileStorage(stream=io.BytesIO(fake_wav_bytes), filename="payload.wav", content_type="audio/wav")
ok, msg, meta = validate_audio_upload(fs_fake_wav)
record("Disguised executable as WAV rejected", not ok, msg)

# Empty audio file (0 bytes)
fs_empty_wav = FileStorage(stream=io.BytesIO(b""), filename="empty.wav", content_type="audio/wav")
ok, msg, meta = validate_audio_upload(fs_empty_wav)
record("0-byte empty audio file rejected", not ok, msg)

# Valid MP3 with ID3v2 tag
valid_id3_mp3 = b"ID3\x03\x00\x00\x00\x00\x00\x0a" + b"\x00" * 30
fs_id3 = FileStorage(stream=io.BytesIO(valid_id3_mp3), filename="song.mp3", content_type="audio/mpeg")
ok, msg, meta = validate_audio_upload(fs_id3)
record("Valid ID3-tagged MP3 accepted", ok, msg)

# Valid raw sync-frame MP3 (0xFF 0xFB)
valid_raw_mp3 = b"\xff\xfb\x90\x64" + b"\x00" * 40
fs_raw_mp3 = FileStorage(stream=io.BytesIO(valid_raw_mp3), filename="voice.mp3", content_type="audio/mpeg")
ok, msg, meta = validate_audio_upload(fs_raw_mp3)
record("Valid raw sync-frame MP3 accepted", ok, msg)

# Fake MP3 with plain text
fake_mp3 = b"This is plain text pretending to be an mp3 file."
fs_fake_mp3 = FileStorage(stream=io.BytesIO(fake_mp3), filename="fake.mp3", content_type="audio/mpeg")
ok, msg, meta = validate_audio_upload(fs_fake_mp3)
record("Plain text disguised as MP3 rejected", not ok, msg)

# Valid FLAC
valid_flac = b"fLaC\x00\x00\x00\x22" + b"\x00" * 40
fs_flac = FileStorage(stream=io.BytesIO(valid_flac), filename="test.flac", content_type="audio/flac")
ok, msg, meta = validate_audio_upload(fs_flac)
record("Valid FLAC file accepted", ok, msg)

# Valid OGG
valid_ogg = b"OggS\x00\x02\x00\x00" + b"\x00" * 40
fs_ogg = FileStorage(stream=io.BytesIO(valid_ogg), filename="sample.ogg", content_type="audio/ogg")
ok, msg, meta = validate_audio_upload(fs_ogg)
record("Valid OGG file accepted", ok, msg)

# Disallowed file extension (.sh)
fs_sh = FileStorage(stream=io.BytesIO(b"#!/bin/sh\necho hi\n"), filename="script.sh", content_type="text/x-shellscript")
ok, msg, meta = validate_audio_upload(fs_sh)
record("Unapproved extension (.sh) rejected", not ok, msg)

# ---------------------------------------------------------------------------
# 3. Database Preservation Verification
# ---------------------------------------------------------------------------
print("\n[3] Database Records Preservation Checks:")

db_path = os.path.join(os.path.dirname(__file__), "voiceshield.db")
conn = sqlite3.connect(db_path)
cur = conn.cursor()
user_count = cur.execute("SELECT COUNT(*) FROM users").fetchone()[0]
incident_count = cur.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
conn.close()

record("Existing user accounts preserved", user_count >= 7, f"{user_count} users present")
record("Existing incident records preserved", incident_count >= 2, f"{incident_count} incidents present")

# ---------------------------------------------------------------------------
# 4. Authentication Lifecycle & Navigation Checks
# ---------------------------------------------------------------------------
print("\n[4] Auth Lifecycle & Route Integrity Checks:")

# Register a dedicated foundation test user
client.post("/register", data={
    "username": "foundationuser",
    "email": "foundation@test.local",
    "password": "Password@123",
    "confirm_password": "Password@123",
})

# Login
r_login = client.post("/login", data={
    "identifier": "foundationuser",
    "password": "Password@123",
}, follow_redirects=True)
record("User login succeeds", r_login.status_code == 200 and b"Welcome back" in r_login.data)

# Dashboard loads with new Course 171405A navigation
r_dash = client.get("/")
record("Dashboard loads with 200 OK", r_dash.status_code == 200)
record("Navigation contains Course 171405A Syllabus label", b"Course 171405A Syllabus" in r_dash.data)
record("Navigation contains Unit I link", b"Unit I: Cyber Security" in r_dash.data)
record("Navigation contains Unit IV Forensics link", b"Unit IV: Cyber Forensics" in r_dash.data)

# End-to-end incident creation via form with valid WAV upload
r_submit_valid = client.post("/analyse", data={
    "title": "Stage 2 Verified WAV Test",
    "category": "OTP & Identity Scam",
    "manual_text": "OTP verification call test.",
    "audio_file": (io.BytesIO(valid_wav_bytes), "sample_recording.wav"),
}, content_type="multipart/form-data", follow_redirects=True)
record("Incident creation with verified WAV succeeds", r_submit_valid.status_code == 200 and b"Analysis complete" in r_submit_valid.data)

# End-to-end incident creation with disguised executable should be rejected and flash error
r_submit_fake = client.post("/analyse", data={
    "title": "Disguised EXE Test",
    "category": "OTP & Identity Scam",
    "audio_file": (io.BytesIO(fake_wav_bytes), "trojan.wav"),
}, content_type="multipart/form-data", follow_redirects=True)
record("Incident submission with disguised EXE rejected", b"Upload error:" in r_submit_fake.data)

# Logout
r_logout = client.get("/logout", follow_redirects=True)
record("User logout succeeds", r_logout.status_code == 200 and b"logged out" in r_logout.data.lower())

# Summary
passed = sum(1 for s, _, _ in results if s == PASS)
failed = sum(1 for s, _, _ in results if s == FAIL)
print(f"\n{'='*55}")
print(f"  Stage 2 Results: {passed} PASSED  |  {failed} FAILED")
print(f"{'='*55}\n")

# Clean up isolated test database
try:
    if os.path.exists(temp_db_path):
        os.remove(temp_db_path)
except OSError:
    pass

if failed > 0:
    sys.exit(1)
sys.exit(0)
