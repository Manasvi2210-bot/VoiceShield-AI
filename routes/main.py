"""
routes/main.py – Dashboard, incident upload, history, export
"""
import csv
import hashlib
import io
import json
import os
import re
import uuid
from datetime import datetime

from flask import (Blueprint, render_template, redirect, url_for, flash,
                   request, current_app, jsonify, send_file, abort)
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename

from extensions import db
from models import Incident, SecurityIncident, SecurityIncidentLog
from analysis import analyse_text, measure_audio
from transcription import transcribe
from upload_security import (validate_audio_upload,
                             generate_secure_storage_name,
                             ALLOWED_EXTENSIONS)

main_bp = Blueprint("main", __name__)

CATEGORIES = [
    "Banking & Financial Fraud",
    "OTP & Identity Scam",
    "KYC Verification Scam",
    "Lottery & Prize Scam",
    "Job & Investment Scam",
    "Social Media Scam",
    "Digital Payment Fraud",
    "Fear-based / Impersonation",
    "Remote Access Scam",
    "Utility Scam",
    "General / Other",
]


def allowed_file(filename: str) -> bool:
    if not filename or "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[-1].lower()
    allowed = current_app.config.get("ALLOWED_EXTENSIONS", ALLOWED_EXTENSIONS)
    return ext in allowed


def delete_file_safely(path: str):
    try:
        if path and os.path.exists(path):
            os.remove(path)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------
@main_bp.route("/")
@main_bp.route("/dashboard")
@login_required
def dashboard():
    recent = (Incident.query
              .filter_by(user_id=current_user.id)
              .order_by(Incident.created_at.desc())
              .limit(5).all())
    total = Incident.query.filter_by(user_id=current_user.id).count()
    high_risk = (Incident.query
                 .filter_by(user_id=current_user.id)
                 .filter(Incident.risk_level.in_(["High", "Critical"])).count())
    return render_template("main/dashboard.html",
                           recent=recent, total=total,
                           high_risk=high_risk, categories=CATEGORIES)


# ---------------------------------------------------------------------------
# Upload & Analyse
# ---------------------------------------------------------------------------
@main_bp.route("/analyse", methods=["GET", "POST"])
@login_required
def analyse():
    if request.method == "GET":
        return render_template("main/analyse.html", categories=CATEGORIES)

    # ---- POST ----
    title = request.form.get("title", "").strip()
    category = request.form.get("category", "General / Other")

    if not title:
        flash("Please provide a title for this incident.", "warning")
        return redirect(url_for("main.analyse"))

    if category not in CATEGORIES:
        category = "General / Other"

    file = request.files.get("audio_file")
    manual_text = request.form.get("manual_text", "").strip()

    saved_path = None
    safe_name = None
    transcript_result = {"status": "unavailable", "text": None,
                         "message": "No audio uploaded."}

    orig_display_name = None
    if file and file.filename:
        is_valid, validation_msg, meta = validate_audio_upload(
            file, max_size_bytes=current_app.config.get("MAX_CONTENT_LENGTH", 50 * 1024 * 1024)
        )
        if not is_valid:
            flash(f"Upload error: {validation_msg}", "danger")
            return redirect(url_for("main.analyse"))

        safe_name, orig_display_name = generate_secure_storage_name(file.filename)
        saved_path = os.path.join(current_app.config["UPLOAD_FOLDER"], safe_name)
        try:
            file.save(saved_path)
        except Exception as exc:
            flash(f"File save error: {exc}", "danger")
            return redirect(url_for("main.analyse"))

        # --- Acoustic measurements BEFORE transcription (file still present) ---
        acoustic = measure_audio(saved_path)

        # --- Transcribe ---
        whisper_model = current_app.config.get("WHISPER_MODEL", "tiny")
        transcript_result = transcribe(saved_path, model_name=whisper_model)

        # Always delete upload after analysis (success or failure)
        delete_file_safely(saved_path)
        audio_deleted = True
    else:
        acoustic = {
            "clipping_ratio": None, "spectral_flatness": None,
            "snr_db": None, "duration_seconds": None, "sample_rate": None,
            "acoustic_note": "No audio file uploaded; measurements not available.",
        }
        audio_deleted = True

    # Use manual text if no transcript or transcription failed
    final_text = transcript_result.get("text") or manual_text or None

    # Scam analysis
    scam = analyse_text(final_text or "")

    incident = Incident(
        user_id=current_user.id,
        title=title,
        category=category,
        transcript=final_text,
        transcription_status=transcript_result["status"],
        risk_score=scam["risk_score"],
        risk_level=scam["risk_level"],
        matched_phrases=json.dumps(scam["matched_phrases"]),
        recommendations=json.dumps(scam["recommendations"]),
        clipping_ratio=acoustic.get("clipping_ratio"),
        spectral_flatness=acoustic.get("spectral_flatness"),
        snr_db=acoustic.get("snr_db"),
        duration_seconds=acoustic.get("duration_seconds"),
        sample_rate=acoustic.get("sample_rate"),
        acoustic_note=acoustic.get("acoustic_note"),
        original_filename=orig_display_name,
        audio_deleted=audio_deleted,
    )
    db.session.add(incident)
    db.session.commit()

    flash(f"Analysis complete – Risk Level: {scam['risk_level']}", "success")
    return redirect(url_for("main.incident_detail", incident_id=incident.id))


# ---------------------------------------------------------------------------
# Incident detail
# ---------------------------------------------------------------------------
@main_bp.route("/incident/<int:incident_id>")
@login_required
def incident_detail(incident_id: int):
    incident = Incident.query.filter_by(
        id=incident_id, user_id=current_user.id).first_or_404()
    return render_template("main/incident_detail.html", incident=incident)


# ---------------------------------------------------------------------------
# History with filters
# ---------------------------------------------------------------------------
@main_bp.route("/history")
@login_required
def history():
    q = Incident.query.filter_by(user_id=current_user.id)

    cat_filter = request.args.get("category", "")
    risk_filter = request.args.get("risk_level", "")
    date_from = request.args.get("date_from", "")
    date_to = request.args.get("date_to", "")
    search = request.args.get("search", "").strip()

    if cat_filter:
        q = q.filter(Incident.category == cat_filter)
    if risk_filter:
        q = q.filter(Incident.risk_level == risk_filter)
    if date_from:
        try:
            q = q.filter(Incident.created_at >= datetime.strptime(date_from, "%Y-%m-%d"))
        except ValueError:
            pass
    if date_to:
        try:
            q = q.filter(Incident.created_at <= datetime.strptime(date_to + " 23:59:59",
                                                                    "%Y-%m-%d %H:%M:%S"))
        except ValueError:
            pass
    if search:
        q = q.filter(Incident.title.ilike(f"%{search}%"))

    incidents = q.order_by(Incident.created_at.desc()).all()
    return render_template("main/history.html",
                           incidents=incidents, categories=CATEGORIES,
                           cat_filter=cat_filter, risk_filter=risk_filter,
                           date_from=date_from, date_to=date_to, search=search)


# ---------------------------------------------------------------------------
# Delete incident
# ---------------------------------------------------------------------------
@main_bp.route("/incident/<int:incident_id>/delete", methods=["POST"])
@login_required
def delete_incident(incident_id: int):
    incident = Incident.query.filter_by(
        id=incident_id, user_id=current_user.id).first_or_404()
    db.session.delete(incident)
    db.session.commit()
    flash("Incident deleted.", "info")
    return redirect(url_for("main.history"))


# ---------------------------------------------------------------------------
# CSV Export
# ---------------------------------------------------------------------------
@main_bp.route("/export/csv")
@login_required
def export_csv():
    incidents = (Incident.query.filter_by(user_id=current_user.id)
                 .order_by(Incident.created_at.desc()).all())

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Title", "Category", "Date", "Risk Level", "Risk Score",
                     "Transcript", "Clipping %", "Spectral Flatness", "SNR (dB)",
                     "Duration (s)", "Sample Rate"])
    for inc in incidents:
        writer.writerow([
            inc.id, inc.title, inc.category,
            inc.created_at.strftime("%Y-%m-%d %H:%M"),
            inc.risk_level, inc.risk_score,
            (inc.transcript or "").replace("\n", " "),
            inc.clipping_ratio, inc.spectral_flatness,
            inc.snr_db, inc.duration_seconds, inc.sample_rate,
        ])

    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode("utf-8")),
        mimetype="text/csv",
        as_attachment=True,
        download_name=f"voiceshield_incidents_{datetime.utcnow().strftime('%Y%m%d')}.csv",
    )


# ---------------------------------------------------------------------------
# PDF Export
# ---------------------------------------------------------------------------
@main_bp.route("/export/pdf")
@login_required
def export_pdf():
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                        Table, TableStyle)
        from reportlab.lib.units import cm
    except ImportError:
        flash("PDF export unavailable. Run: py -m pip install reportlab", "warning")
        return redirect(url_for("main.history"))

    incidents = (Incident.query.filter_by(user_id=current_user.id)
                 .order_by(Incident.created_at.desc()).all())

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4,
                             rightMargin=2*cm, leftMargin=2*cm,
                             topMargin=2*cm, bottomMargin=2*cm)
    styles = getSampleStyleSheet()
    story = []

    story.append(Paragraph("VoiceShield AI – Incident Report", styles["Title"]))
    story.append(Paragraph(
        f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M')} UTC  |  "
        f"User: {current_user.username}",
        styles["Normal"]))
    story.append(Spacer(1, 0.5*cm))

    RISK_COLORS = {
        "Low": colors.HexColor("#22c55e"),
        "Medium": colors.HexColor("#f59e0b"),
        "High": colors.HexColor("#ef4444"),
        "Critical": colors.HexColor("#7c3aed"),
    }

    for inc in incidents:
        story.append(Paragraph(f"#{inc.id} – {inc.title}", styles["Heading2"]))
        data = [
            ["Category", inc.category],
            ["Date", inc.created_at.strftime("%Y-%m-%d %H:%M")],
            ["Risk Level", inc.risk_level],
            ["Risk Score", f"{inc.risk_score}/100"],
            ["Transcription", inc.transcription_status],
        ]
        if inc.duration_seconds:
            data.append(["Duration", f"{inc.duration_seconds}s"])
        t = Table(data, colWidths=[4*cm, 13*cm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#1e293b")),
            ("TEXTCOLOR", (0, 0), (0, -1), colors.white),
            ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#334155")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ROWBACKGROUNDS", (1, 0), (1, -1),
             [colors.HexColor("#f8fafc"), colors.HexColor("#f1f5f9")]),
        ]))
        story.append(t)
        if inc.transcript:
            story.append(Spacer(1, 0.3*cm))
            story.append(Paragraph("Transcript:", styles["Heading3"]))
            story.append(Paragraph(
                inc.transcript[:800] + ("…" if len(inc.transcript) > 800 else ""),
                styles["Normal"]))
        story.append(Spacer(1, 0.6*cm))

    doc.build(story)
    buf.seek(0)
    return send_file(
        buf,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"voiceshield_report_{datetime.utcnow().strftime('%Y%m%d')}.pdf",
    )


# ---------------------------------------------------------------------------
# Education pages
# ---------------------------------------------------------------------------
@main_bp.route("/education")
@login_required
def education():
    return render_template("main/education.html")


# ---------------------------------------------------------------------------
# Unit I – Introduction to Cyber Security
# ---------------------------------------------------------------------------
@main_bp.route("/unit1")
@login_required
def unit1():
    return render_template("main/unit1_intro.html")


# ---------------------------------------------------------------------------
# Unit II – Cyber Crimes & Cyber Law
# ---------------------------------------------------------------------------
@main_bp.route("/unit2")
@login_required
def unit2():
    return render_template("main/unit2_cybercrime.html")


# ---------------------------------------------------------------------------
# Unit III – Social Media Security
# ---------------------------------------------------------------------------
@main_bp.route("/unit3")
@login_required
def unit3():
    return render_template("main/unit3_social.html")


# ---------------------------------------------------------------------------
# Unit III – Social message checker (AJAX / POST)
# ---------------------------------------------------------------------------
@main_bp.route("/unit3/check", methods=["POST"])
@login_required
def unit3_check():
    """Rule-based suspicious-message checker. Returns JSON."""
    import html
    text = request.json.get("text", "").strip() if request.is_json else ""
    if not text:
        return jsonify({"error": "No text provided."}), 400
    if len(text) > 2000:
        return jsonify({"error": "Text too long (max 2000 characters)."}), 400

    SOCIAL_FLAGS = [
        {"pattern": r"click\s+(this|here|the)\s+link", "label": "Suspicious link prompt",
         "weight": 20, "tip": "Legitimate contacts don't pressure you to click unverified links."},
        {"pattern": r"(your\s+account|account\s+(has\s+been)?\s*)(suspended|blocked|hacked|compromised)",
         "label": "Account-threat claim", "weight": 25,
         "tip": "Platforms send official emails, not DMs, for account issues."},
        {"pattern": r"(send|transfer|pay)\s+(money|cash|₹|rs\.?|upi)",
         "label": "Money request", "weight": 30,
         "tip": "Never send money to someone you haven't verified through a second channel."},
        {"pattern": r"(otp|one.time.password|verification\s+code)",
         "label": "OTP / verification code request", "weight": 35,
         "tip": "No one should ever ask for your OTP over a message or call."},
        {"pattern": r"(you\s+(have\s+)?won|congratulations|selected\s+(as\s+)?winner|prize|lottery)",
         "label": "Lottery / prize scam signal", "weight": 20,
         "tip": "You cannot win a prize in a contest you never entered."},
        {"pattern": r"(act|respond|reply)\s+(now|immediately|urgently|fast|quickly)",
         "label": "Artificial urgency", "weight": 15,
         "tip": "Urgency is a key psychological pressure tactic used by scammers."},
        {"pattern": r"(share|send|give)\s+(your\s+)?(password|pin|cvv|card.number|aadhaar)",
         "label": "Credential request", "weight": 40,
         "tip": "Never share passwords, PINs or card details via any message."},
        {"pattern": r"(i\s+am|i'm)\s+(your\s+)?(friend|relative|colleague|boss|ceo|officer)",
         "label": "Possible impersonation", "weight": 18,
         "tip": "Verify the sender's identity through a known contact number or in-person."},
        {"pattern": r"(gift\s+card|amazon\s+voucher|google\s+play|itunes)",
         "label": "Gift-card payment demand", "weight": 25,
         "tip": "No legitimate authority asks for payment via gift cards."},
        {"pattern": r"install.*(app|apk|software|teamviewer|anydesk)",
         "label": "App / remote-access install request", "weight": 30,
         "tip": "Never install apps sent via messages from unknown people."},
    ]

    score = 0
    flags = []
    text_lower = text.lower()
    for item in SOCIAL_FLAGS:
        if re.search(item["pattern"], text_lower, re.IGNORECASE):
            score += item["weight"]
            flags.append({"label": item["label"], "tip": item["tip"]})

    score = min(score, 100)
    if score == 0:
        level = "Low"
    elif score < 30:
        level = "Low"
    elif score < 55:
        level = "Medium"
    elif score < 75:
        level = "High"
    else:
        level = "Critical"

    return jsonify({
        "score": score,
        "level": level,
        "flags": flags,
        "safe_text": html.escape(text[:300]),
    })


# ---------------------------------------------------------------------------
# Unit IV – E-Commerce & Digital Payments
# ---------------------------------------------------------------------------
@main_bp.route("/unit4")
@login_required
def unit4():
    return render_template("main/unit4_payment.html")


# ---------------------------------------------------------------------------
# Unit IV – Payment fraud checker (AJAX / POST)
# ---------------------------------------------------------------------------
@main_bp.route("/unit4/check", methods=["POST"])
@login_required
def unit4_check():
    """Rule-based digital payment fraud checker. Returns JSON.
    IMPORTANT: This tool does NOT store, transmit or verify any financial data.
    Users should NEVER enter real OTPs, PINs, CVVs or passwords.
    """
    import html
    data = request.json if request.is_json else {}
    text = data.get("text", "").strip()
    if not text:
        return jsonify({"error": "No text provided."}), 400
    if len(text) > 2000:
        return jsonify({"error": "Text too long (max 2000 characters)."}), 400

    PAYMENT_FLAGS = [
        {"pattern": r"(share|send|give|tell)\s+(your\s+)?(otp|one.time.password)",
         "category": "OTP Request", "weight": 40,
         "tip": "Banks and UPI apps never ask for your OTP over call or message."},
        {"pattern": r"(share|send|give|tell)\s+(your\s+)?(cvv|card.verification)",
         "category": "CVV Request", "weight": 40,
         "tip": "Your CVV must never be shared — not even with bank staff."},
        {"pattern": r"(enter|input|provide)\s+(your\s+)?(upi\s+pin|mpin|atm\s+pin)",
         "category": "PIN Request", "weight": 40,
         "tip": "You enter your PIN only inside your own banking app — never elsewhere."},
        {"pattern": r"(scan|open)\s+(this\s+)?qr\s*(code)?",
         "category": "QR Code Scam", "weight": 25,
         "tip": "Scanning a QR code can DEBIT money from your account, not credit it."},
        {"pattern": r"(bank|rbi|income.tax|police)\s+(officer|official|helpline|customer.care)",
         "category": "Suspicious bank/authority call", "weight": 30,
         "tip": "Real bank officials never call asking for credentials or OTPs."},
        {"pattern": r"(payment\s+(received|successful|credited)|money\s+(received|credited))",
         "category": "Fake payment confirmation", "weight": 25,
         "tip": "Always verify credits in your official bank app — never trust screenshots."},
        {"pattern": r"(click|tap|visit|open)\s+(this\s+)?(payment\s+)?link",
         "category": "Suspicious payment link", "weight": 30,
         "tip": "Only use links from the official bank website or app."},
        {"pattern": r"(kyc|know\s+your\s+customer)\s+(update|verify|expire|pending|block)",
         "category": "KYC Scam", "weight": 35,
         "tip": "KYC updates are done only through official bank branches or apps."},
        {"pattern": r"(refund|cashback|reversal)\s+(of\s+)?₹?\d+",
         "category": "Refund Scam", "weight": 25,
         "tip": "Legitimate refunds do not require your PIN or OTP."},
        {"pattern": r"(sim\s+swap|number\s+(change|port|transfer))",
         "category": "SIM Swap Warning", "weight": 30,
         "tip": "Call your telecom provider immediately if you suspect SIM swap fraud."},
        {"pattern": r"(install|download)\s+(anydesk|teamviewer|remote|screen\s*share)",
         "category": "Remote Access Request", "weight": 40,
         "tip": "Never give remote access to your phone or computer to an unknown person."},
    ]

    score = 0
    flags = []
    text_lower = text.lower()
    for item in PAYMENT_FLAGS:
        if re.search(item["pattern"], text_lower, re.IGNORECASE):
            score += item["weight"]
            flags.append({"category": item["category"], "tip": item["tip"]})

    score = min(score, 100)
    if score == 0:
        level = "Low"
    elif score < 30:
        level = "Low"
    elif score < 55:
        level = "Medium"
    elif score < 75:
        level = "High"
    else:
        level = "Critical"

    return jsonify({
        "score": score,
        "level": level,
        "flags": flags,
        "safe_text": html.escape(text[:300]),
    })


# ---------------------------------------------------------------------------
# Unit V – Digital Device Security
# ---------------------------------------------------------------------------
@main_bp.route("/unit5")
@login_required
def unit5():
    return render_template("main/unit5_device.html")


# ---------------------------------------------------------------------------
# Privacy notice
# ---------------------------------------------------------------------------
@main_bp.route("/privacy")
def privacy():
    return render_template("main/privacy.html")


# ---------------------------------------------------------------------------
# Cybersecurity Attack & Defense Lab
# ---------------------------------------------------------------------------
@main_bp.route("/attack-lab")
@login_required
def attack_lab():
    return render_template("main/attack_lab.html")


@main_bp.route("/attack-lab/analyze-risk", methods=["POST"])
@login_required
def attack_lab_analyze_risk():
    """Deterministic, transparent rule-based risk analyzer aligning with
    ISO/IEC 27005 and NIST SP 800-30 frameworks.
    Returns calculated likelihood, impact, composite risk score, tier, and mitigations.
    """
    data = request.json if request.is_json else request.form
    scenario_key = data.get("scenario_key", "custom")
    custom_desc = data.get("custom_desc", "").strip()

    try:
        likelihood = int(data.get("likelihood", 3))
    except (ValueError, TypeError):
        likelihood = 3
    try:
        impact = int(data.get("impact", 3))
    except (ValueError, TypeError):
        impact = 3

    likelihood = max(1, min(5, likelihood))
    impact = max(1, min(5, impact))

    controls = data.get("controls", [])
    if isinstance(controls, str):
        controls = [c.strip() for c in controls.split(",") if c.strip()]

    mitigation_discount = len(controls) * 0.4
    effective_likelihood = max(1.0, round(likelihood - (mitigation_discount * 0.6), 2))
    effective_impact = max(1.0, round(impact - (mitigation_discount * 0.4), 2))

    composite_score = round(effective_likelihood * effective_impact, 1)
    composite_score = min(25.0, max(1.0, composite_score))

    if composite_score <= 4.0:
        tier = "Low"
        tier_color = "#22c55e"
    elif composite_score <= 9.0:
        tier = "Medium"
        tier_color = "#f59e0b"
    elif composite_score <= 15.0:
        tier = "High"
        tier_color = "#ef4444"
    else:
        tier = "Critical"
        tier_color = "#a855f7"

    SCENARIO_PROFILES = {
        "voice_clone_fraud": {
            "title": "Synthetic AI Voice Cloning wire fraud targeting Accounts Payable",
            "threat_agent": "Organized cybercrime group using generative audio synthesis",
            "vulnerability": "Lack of verbal passphrase or out-of-band verification",
            "key_factors": [
                "High emotional urgency engineered over inbound call",
                "Audio training sample harvested from public executive conference talk",
                "Absence of dual-authorization policy for urgent wires"
            ],
            "mitigations": [
                "Enforce out-of-band callback to verified secondary phone number.",
                "Require dual-person cryptographic authorization for transfers above threshold.",
                "Deploy VoiceShield AI acoustic frequency and phase consistency analysis."
            ]
        },
        "voice_cloning_wire_fraud": {
            "title": "Synthetic AI Voice Cloning wire fraud targeting Accounts Payable",
            "threat_agent": "Organized cybercrime group using generative audio synthesis",
            "vulnerability": "Lack of verbal passphrase or out-of-band verification",
            "key_factors": [
                "High emotional urgency engineered over inbound call",
                "Audio training sample harvested from public executive conference talk",
                "Absence of dual-authorization policy for urgent wires"
            ],
            "mitigations": [
                "Enforce out-of-band callback to verified secondary phone number.",
                "Require dual-person cryptographic authorization for transfers above threshold.",
                "Deploy VoiceShield AI acoustic frequency and phase consistency analysis."
            ]
        },
        "sqli_portal": {
            "title": "SQL Injection in public-facing customer portal search field",
            "threat_agent": "External untrusted user sending crafted SQL payloads",
            "vulnerability": "Direct string concatenation into backend SQL queries without parameters",
            "key_factors": [
                "Public internet exposure without request filtering",
                "Database contains sensitive student/user records",
                "Database account runs with excessive SELECT and UPDATE permissions"
            ],
            "mitigations": [
                "Replace raw string concatenation with Parameterized Queries / Prepared Statements.",
                "Enforce least-privilege database user account permissions.",
                "Deploy Web Application Firewall (WAF) to inspect incoming request bodies."
            ]
        },
        "sql_injection_exfiltration": {
            "title": "SQL Injection in public-facing customer portal search field",
            "threat_agent": "External untrusted user sending crafted SQL payloads",
            "vulnerability": "Direct string concatenation into backend SQL queries without parameters",
            "key_factors": [
                "Public internet exposure without request filtering",
                "Database contains sensitive student/user records",
                "Database account runs with excessive SELECT and UPDATE permissions"
            ],
            "mitigations": [
                "Replace raw string concatenation with Parameterized Queries / Prepared Statements.",
                "Enforce least-privilege database user account permissions.",
                "Deploy Web Application Firewall (WAF) to inspect incoming request bodies."
            ]
        },
        "xss_stored": {
            "title": "Stored Cross-Site Scripting (XSS) in comment forum",
            "threat_agent": "Malicious forum poster injecting arbitrary JavaScript",
            "vulnerability": "Unescaped HTML rendering of user-generated content in browser",
            "key_factors": [
                "Execution occurs in victim browsers with victim credentials",
                "Potential theft of session tokens and keystroke logging",
                "Legitimate domain origin creates high user trust"
            ],
            "mitigations": [
                "Implement context-aware HTML output encoding before rendering user input.",
                "Set HttpOnly, Secure, and SameSite=Strict flags on session cookies.",
                "Deploy a restrictive Content Security Policy (CSP) header prohibiting inline scripts."
            ]
        },
        "phishing_credential": {
            "title": "Spear-phishing email mimicking corporate single sign-on (SSO)",
            "threat_agent": "Advanced threat actor sending spoofed internal communications",
            "vulnerability": "User susceptibility to artificial urgency and typosquatted domains",
            "key_factors": [
                "Deceptive typosquatted domain name mimicking organization",
                "Harvests plaintext credentials directly through fake login portal",
                "Absence of hardware-bound multi-factor authentication (MFA)"
            ],
            "mitigations": [
                "Mandate FIDO2 / WebAuthn hardware security keys immune to proxy phishing.",
                "Enforce domain authentication with strict SPF, DKIM, and DMARC reject policies.",
                "Conduct regular security awareness and simulated phishing drills."
            ]
        },
        "spear_phishing_credential_theft": {
            "title": "Spear-phishing email mimicking corporate single sign-on (SSO)",
            "threat_agent": "Advanced threat actor sending spoofed internal communications",
            "vulnerability": "User susceptibility to artificial urgency and typosquatted domains",
            "key_factors": [
                "Deceptive typosquatted domain name mimicking organization",
                "Harvests plaintext credentials directly through fake login portal",
                "Absence of hardware-bound multi-factor authentication (MFA)"
            ],
            "mitigations": [
                "Mandate FIDO2 / WebAuthn hardware security keys immune to proxy phishing.",
                "Enforce domain authentication with strict SPF, DKIM, and DMARC reject policies.",
                "Conduct regular security awareness and simulated phishing drills."
            ]
        },
        "ransomware_lateral_spread": {
            "title": "Ransomware payload execution with lateral network movement",
            "threat_agent": "Ransomware-as-a-Service (RaaS) affiliate operator",
            "vulnerability": "Flat internal network architecture and unsegmented backup shares",
            "key_factors": [
                "Lateral propagation via SMB and privileged administrative credentials",
                "VSS shadow copies deleted using vssadmin",
                "Double extortion exfiltration threatening public data disclosure"
            ],
            "mitigations": [
                "Implement network micro-segmentation and strict zero-trust access controls.",
                "Maintain immutable, air-gapped offline backups with regular restore testing.",
                "Deploy EDR with automated behavioral ransomware containment heuristics."
            ]
        },
        "insider_data_leak": {
            "title": "Privileged insider unauthorized data export and exfiltration",
            "threat_agent": "Disgruntled employee with excessive read permissions",
            "vulnerability": "Lack of data loss prevention (DLP) and anomalous volume alerts",
            "key_factors": [
                "Bulk export of student KYC and financial database records",
                "Legitimate user credentials bypassing basic perimeter firewalls",
                "Removable USB media or unsanctioned cloud storage uploads"
            ],
            "mitigations": [
                "Enforce principle of least privilege and Role-Based Access Control (RBAC).",
                "Deploy Endpoint Data Loss Prevention (DLP) and disable unauthorized USB ports.",
                "Implement User and Entity Behavior Analytics (UEBA) for abnormal volume downloads."
            ]
        },
        "weak_passwords": {
            "title": "Credential Stuffing & Weak Password Spraying",
            "threat_agent": "Automated botnet replaying leaked credential dumps",
            "vulnerability": "Single-factor password auth without rate-limiting or salt/Argon2",
            "key_factors": [
                "Password reuse across public breaches",
                "No CAPTCHA or lockout on repeated failures",
                "Low-entropy passwords vulnerable to dictionary attacks"
            ],
            "mitigations": [
                "Enforce multi-factor authentication (MFA) across all user logins.",
                "Implement progressive IP rate-limiting and account lockout thresholds.",
                "Hash passwords using memory-hard algorithms (Argon2id or bcrypt) with unique cryptographic salts."
            ]
        }
    }

    profile = SCENARIO_PROFILES.get(scenario_key)
    if not profile:
        profile = {
            "title": custom_desc[:80] if custom_desc else "Custom Evaluated Security Scenario",
            "threat_agent": "Identified threat source in custom context",
            "vulnerability": "Security weakness or lack of defensive controls",
            "key_factors": [
                "Assessed Threat Likelihood: Level " + str(likelihood) + " of 5",
                "Assessed Asset Impact: Level " + str(impact) + " of 5"
            ],
            "mitigations": [
                "Implement defense-in-depth security layers.",
                "Apply the principle of least privilege.",
                "Enforce continuous monitoring and verifiable audit logging."
            ]
        }

    return jsonify({
        "status": "success",
        "method": "Rule-Based Deterministic Risk Matrix (NIST SP 800-30 / ISO 27005 Aligned)",
        "scenario_title": profile["title"],
        "threat_agent": profile["threat_agent"],
        "vulnerability": profile["vulnerability"],
        "likelihood": likelihood,
        "impact": impact,
        "effective_likelihood": effective_likelihood,
        "effective_impact": effective_impact,
        "score": composite_score,
        "tier": tier,
        "tier_color": tier_color,
        "applied_controls": controls,
        "key_factors": profile["key_factors"],
        "mitigations": profile["mitigations"]
    })


@main_bp.route("/attack-lab/forensics-event", methods=["POST"])
@login_required
def attack_lab_forensics_event():
    """Interactive endpoint for analyzing sample forensic events from
    the fictional 'Operation SpoofedCaller' incident log.
    Returns expert forensic triage, artifacts, and recommended response steps.
    """
    data = request.json if request.is_json else request.form
    event_id = data.get("event_id", "").strip()

    EVENTS_DB = {
        "E-101": {
            "timestamp": "2026-10-26 09:14:22 UTC",
            "event_type": "VPN User Authentication",
            "severity": "Benign",
            "is_anomaly": False,
            "summary": "Employee authenticated via corporate Cisco AnyConnect VPN from recognized domestic ISP.",
            "evidence_artifact": "Source IP: 203.0.113.45 | Protocol: TLS 1.3 | Client Cert: Valid | MFA: Approved",
            "forensic_verdict": "Normal operational behavior. IP geolocation aligns with employee home address; valid client certificate presented.",
            "ir_phase": "Preparation / Normal Baseline Monitoring",
            "recommended_action": "Log event in SIEM; retain in 180-day audit log per CERT-In guidelines."
        },
        "E-102": {
            "timestamp": "2026-10-26 11:03:45 UTC",
            "event_type": "Inbound SIP VoIP Audio Packet",
            "severity": "Suspicious",
            "is_anomaly": True,
            "summary": "Inbound VoIP call claiming to be Chief Technology Officer requesting emergency wire transfer authorization.",
            "evidence_artifact": "SIP Header: Spoofed CallerID | Acoustic Artifacts: Phase jitter & unnatural spectral flatness | SHA-256: 7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069",
            "forensic_verdict": "Voice-Cloning Indicators Detected. Acoustic analysis reveals synthetic vocoder phase artifacts and lack of natural micro-tremors in fundamental frequency (F0). Caller ID spoofed via open SIP trunk.",
            "ir_phase": "Detection & Analysis (NIST SP 800-61 Phase 2)",
            "recommended_action": "Do NOT execute wire transfer. Initiate secondary out-of-band verification. Preserve raw .pcap and .wav with SHA-256 hash in Evidence Vault."
        },
        "E-103": {
            "timestamp": "2026-10-26 11:08:12 UTC",
            "event_type": "Administrative Password Reset Request",
            "severity": "Anomalous",
            "is_anomaly": True,
            "summary": "Self-service password reset initiated for executive account from Tor exit node.",
            "evidence_artifact": "Source IP: 198.51.100.22 (Known Tor Exit Node) | User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0",
            "forensic_verdict": "High-Risk Account Takeover Vector. Password reset initiated within 5 minutes of spoofed call from anonymized IP address.",
            "ir_phase": "Detection & Triage",
            "recommended_action": "Block password reset request. Revoke existing active sessions for the targeted user. Force administrator MFA re-authentication."
        },
        "E-104": {
            "timestamp": "2026-10-26 11:15:30 UTC",
            "event_type": "ERP Financial Transaction Staging",
            "severity": "Critical",
            "is_anomaly": True,
            "summary": "Attempt to create an out-of-cycle vendor disbursement of ₹4,50,000 to an unverified offshore IBAN.",
            "evidence_artifact": "Transaction ID: TXN-994821 | Amount: INR 4,50,000 | Destination: Foreign Acct XX-8902 | Approval Gate: Incomplete",
            "forensic_verdict": "Active Fraud Execution Attempt. Matches Section 66D (cheating by personation using computer resource) and Section 43 (unauthorized access to computer resource).",
            "ir_phase": "Containment (NIST SP 800-61 Phase 3)",
            "recommended_action": "Immediately freeze transaction queue in ERP. Isolate compromised workstation from network. Notify Bank Fraud Helpline 1930 and CERT-In within 6 hours."
        },
        "E-105": {
            "timestamp": "2026-10-26 11:18:00 UTC",
            "event_type": "Automated Security Containment",
            "severity": "Defensive Action",
            "is_anomaly": False,
            "summary": "VoiceShield AI & SOC analyst triggered emergency token revocation and quarantined host.",
            "evidence_artifact": "Action: Host Quarantined | API Call: Revoke-AllTokens | Status: Success | Actor: SecurityAnalyst_1",
            "forensic_verdict": "Successful Incident Containment. Lateral movement halted; session hijack terminated before financial funds left the institution.",
            "ir_phase": "Containment & Eradication",
            "recommended_action": "Capture volatile RAM image of host using FTK Imager; verify write-blocker attached before persistent disk acquisition."
        },
        "E-106": {
            "timestamp": "2026-10-26 11:45:00 UTC",
            "event_type": "Forensic Evidence Vault Registration",
            "severity": "Forensic Custody",
            "is_anomaly": False,
            "summary": "Bit-stream disk image and SIP packet captures registered with cryptographic hash verification.",
            "evidence_artifact": "Image: host_forensic.E01 | SHA-256: d8578edf8458ce06fbc5bb76a58c5ca4 | Chain of Custody: CustodyOfficer_1",
            "forensic_verdict": "Admissible Forensic Baseline Established. Section 65B Indian Evidence Act / Section 63 BSA certificate prepared.",
            "ir_phase": "Recovery & Lessons Learned (NIST SP 800-61 Phase 4)",
            "recommended_action": "File formal complaint on National Cyber Crime Portal (cybercrime.gov.in) with certified evidence package."
        }
    }

    event = EVENTS_DB.get(event_id)
    if not event:
        return jsonify({"error": "Unknown event identifier."}), 404

    return jsonify({
        "status": "success",
        "event_id": event_id,
        "timestamp": event["timestamp"],
        "event_type": event["event_type"],
        "severity": event["severity"],
        "is_anomaly": event["is_anomaly"],
        "summary": event["summary"],
        "evidence_artifact": event["evidence_artifact"],
        "forensic_verdict": event["forensic_verdict"],
        "ir_phase": event["ir_phase"],
        "recommended_action": event["recommended_action"]
    })


# ===========================================================================
# CYBERSECURITY SUITE UPGRADE (FEATURES 1–7)
# ===========================================================================

# ---------------------------------------------------------------------------
# Feature 1: Phishing & Email Threat Analyzer (/phishing-checker)
# ---------------------------------------------------------------------------
PHISHING_INDICATORS = [
    {
        "id": "urgency",
        "category": "Urgency & Artificial Pressure",
        "pattern": r"\b(immediately|right\s+now|within\s+(?:\d+|24|48)\s*(?:hours?|hrs?|minutes?)|urgent\b|urgency|account\s+(?:will\s+be\s+)?suspended|action\s+required|final\s+notice|limited\s+time|account\s+restricted|immediate\s+verification)\b",
        "weight": 20,
        "explanation": "Threat actors engineer artificial time pressure to bypass critical thinking and force rushed compliance."
    },
    {
        "id": "impersonation",
        "category": "Authority & Organization Impersonation",
        "pattern": r"\b(it\s+support|helpdesk|security\s+team|billing\s+department|ceo\b|cfo\b|human\s+resources|hr\s+dept|courier\s+service|customs\s+office|tax\s+department|irs\b|income\s+tax|microsoft\s+security|google\s+alert|apple\s+support)\b",
        "weight": 20,
        "explanation": "Impersonates recognized corporate or governmental entities to exploit trust heuristics."
    },
    {
        "id": "credential_harvesting",
        "category": "Credential & OTP Solicitation",
        "pattern": r"\b(share\s+your\s+otp|enter\s+(?:your\s+)?password|verify\s+(?:your\s+)?(?:account|credentials|identity)|confirm\s+(?:your\s+)?pin|cvv\b|card\s+number|aadhaar|login\s+to\s+restore|update\s+security\s+details|click\s+here\s+to\s+log\s*in)\b",
        "weight": 30,
        "explanation": "Direct requests to enter or submit credentials, passwords, or one-time verification tokens."
    },
    {
        "id": "financial_demand",
        "category": "Unusual Payment & Fund Demands",
        "pattern": r"\b(wire\s+transfer|gift\s+cards?|cryptocurrency|bitcoin|unpaid\s+invoice|overdue\s+penalty|remit\s+funds?|bank\s+transfer\s+urgently|direct\s+deposit|western\s+union)\b",
        "weight": 25,
        "explanation": "Coercion into non-standard, irreversible financial disbursements or peer-to-peer transfers."
    }
]

SUSPICIOUS_TLDS = {".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".click", ".rest", ".buzz", ".club", ".work", ".fit", ".link"}
DECEPTIVE_BRANDS = ["paypa1", "bank-secure", "login-verify", "micros0ft", "g00gle", "apple-id-verify", "secure-update", "chase-verify", "sbi-kyc", "wellsfarg0"]


def analyze_phishing_content(raw_text: str) -> dict:
    """Deterministic, rule-based phishing and email threat analyzer.
    Analyzes message body and extracted URLs without external network requests.
    """
    if not raw_text or not raw_text.strip():
        return {
            "score": 0,
            "tier": "Unknown",
            "tier_color": "#64748b",
            "summary": "No content provided for analysis.",
            "matched_indicators": [],
            "urls_detected": [],
            "recommendations": ["Paste message text, email headers, or suspicious URLs to begin analysis."]
        }

    text = raw_text[:20000]  # Enforce 20k char safety limit
    score = 0
    matched = []
    recs = []

    # 1. Pattern checks on text
    for ind in PHISHING_INDICATORS:
        hits = re.findall(ind["pattern"], text, re.IGNORECASE)
        if hits:
            score += ind["weight"]
            matched.append({
                "category": ind["category"],
                "explanation": ind["explanation"],
                "sample_hit": hits[0] if isinstance(hits[0], str) else hits[0][0]
            })

    # 2. Defensive URL extraction & passive heuristic inspection
    url_pattern = r"(?:https?://|www\.)[^\s<>\"']+"
    detected_urls = re.findall(url_pattern, text)
    url_details = []

    for url in detected_urls[:10]:  # Inspect first 10 URLs
        url_lower = url.lower()
        threat_flags = []

        # Check for IP address host
        if re.search(r"https?://(?:\d{1,3}\.){3}\d{1,3}", url_lower):
            threat_flags.append("Raw IPv4 Address Hostname (Hides true domain origin)")
            score += 30

        # Check for suspicious TLDs
        for tld in SUSPICIOUS_TLDS:
            if tld in url_lower:
                threat_flags.append(f"High-Risk Free/Abused TLD detected ({tld})")
                score += 20
                break

        # Check for typosquatted brand strings
        for brand in DECEPTIVE_BRANDS:
            if brand in url_lower:
                threat_flags.append(f"Deceptive Look-alike / Typosquatted Brand string detected ('{brand}')")
                score += 35
                break

        # Check for '@' symbol in URL authority
        if "@" in url_lower:
            threat_flags.append("Userinfo '@' Symbol in URL (Bypasses naive domain inspection)")
            score += 25

        url_details.append({
            "url": url[:120] + ("..." if len(url) > 120 else ""),
            "threat_flags": threat_flags
        })
        if threat_flags:
            matched.append({
                "category": "Suspicious URL Structure",
                "explanation": f"URL exhibits deceptive characteristics: {', '.join(threat_flags)}",
                "sample_hit": url[:60]
            })

    # Cap score at 100
    score = min(100, score)

    # Determine risk tier
    if score == 0:
        tier = "Low"
        tier_color = "#22c55e"
        summary = "No overt phishing or deceptive indicators detected. Exercise standard digital vigilance."
        recs.append("Verify the sender's email address matches official corporate domain records.")
        recs.append("Ensure any expected transactions follow normal out-of-band operational approval.")
    elif score <= 29:
        tier = "Low"
        tier_color = "#22c55e"
        summary = "Minimal risk indicators observed. Likely benign or low-pressure communication."
        recs.append("Confirm sender identity before taking any requested actions.")
    elif score <= 54:
        tier = "Medium"
        tier_color = "#f59e0b"
        summary = "Moderate risk indicators detected. Elevated caution advised before interacting."
        recs.append("Do NOT click links directly; navigate to official web portals independently.")
        recs.append("Verify unusual requests via secondary out-of-band phone or in-person confirmation.")
    elif score <= 74:
        tier = "High"
        tier_color = "#ef4444"
        summary = "Multiple high-risk phishing indicators detected (urgency, impersonation, or deceptive URLs)."
        recs.append("Do NOT click links, download attachments, or reply to this communication.")
        recs.append("Report message to internal security team / SOC and mark as Phishing.")
        recs.append("If credentials were submitted, change your password immediately and revoke active sessions.")
    else:
        tier = "Critical"
        tier_color = "#a855f7"
        summary = "Critical threat characteristics detected. Strong probability of malicious credential theft or BEC fraud."
        recs.append("Treat this communication as an ACTIVE PHISHING ATTEMPT.")
        recs.append("Do NOT interact with any links or attachments.")
        recs.append("Forward raw headers to your SOC and report to cybercrime.gov.in (Helpline: 1930).")

    return {
        "score": score,
        "tier": tier,
        "tier_color": tier_color,
        "summary": summary,
        "matched_indicators": matched,
        "urls_detected": url_details,
        "recommendations": recs,
        "char_count": len(text)
    }


@main_bp.route("/phishing-checker", methods=["GET", "POST"])
@login_required
def phishing_checker():
    analysis = None
    input_text = ""

    if request.method == "POST":
        input_text = request.form.get("threat_text", "").strip()

        if not input_text:
            flash("Please paste or enter message text, email headers, or URL to analyze.", "warning")
            return redirect(url_for("main.phishing_checker"))

        if len(input_text) > 50000:
            flash("Input text exceeds maximum allowed length of 50,000 characters.", "warning")
            return redirect(url_for("main.phishing_checker"))

        analysis = analyze_phishing_content(input_text)
        if request.headers.get("X-Requested-With") == "XMLHttpRequest" or request.is_json:
            return jsonify({"status": "success", "analysis": analysis})

    return render_template("main/phishing_checker.html",
                           analysis=analysis,
                           input_text=input_text)



# ---------------------------------------------------------------------------
# Feature 2: Password Security Checker (/password-checker)
# ---------------------------------------------------------------------------
@main_bp.route("/password-checker")
@login_required
def password_checker():
    return render_template("main/password_checker.html")


# ---------------------------------------------------------------------------
# Feature 3: Security Incident Response Center (/incident-center)
# ---------------------------------------------------------------------------
SECURITY_CATEGORIES = [
    "Phishing",
    "Suspected Voice Impersonation",
    "Malware",
    "Account Compromise",
    "Data Exposure",
    "Other"
]
SECURITY_SEVERITIES = ["Low", "Medium", "High", "Critical"]
SECURITY_STATUSES = ["Open", "Investigating", "Contained", "Resolved"]


@main_bp.route("/incident-center")
@login_required
def incident_center():
    q = SecurityIncident.query.filter_by(user_id=current_user.id)

    cat_filter = request.args.get("category", "").strip()
    sev_filter = request.args.get("severity", "").strip()
    status_filter = request.args.get("status", "").strip()
    search = request.args.get("search", "").strip()

    if cat_filter and cat_filter in SECURITY_CATEGORIES:
        q = q.filter(SecurityIncident.category == cat_filter)
    if sev_filter and sev_filter in SECURITY_SEVERITIES:
        q = q.filter(SecurityIncident.severity == sev_filter)
    if status_filter and status_filter in SECURITY_STATUSES:
        q = q.filter(SecurityIncident.status == status_filter)
    if search:
        q = q.filter(SecurityIncident.title.ilike(f"%{search}%"))

    incidents = q.order_by(SecurityIncident.created_at.desc()).all()

    # Statistics for dashboard cards
    total_sec = SecurityIncident.query.filter_by(user_id=current_user.id).count()
    open_sec = SecurityIncident.query.filter_by(user_id=current_user.id).filter(
        SecurityIncident.status.in_(["Open", "Investigating"])).count()
    critical_sec = SecurityIncident.query.filter_by(user_id=current_user.id).filter(
        SecurityIncident.severity.in_(["High", "Critical"])).count()
    resolved_sec = SecurityIncident.query.filter_by(user_id=current_user.id).filter_by(
        status="Resolved").count()

    return render_template("main/incident_center.html",
                           incidents=incidents,
                           categories=SECURITY_CATEGORIES,
                           severities=SECURITY_SEVERITIES,
                           statuses=SECURITY_STATUSES,
                           cat_filter=cat_filter,
                           sev_filter=sev_filter,
                           status_filter=status_filter,
                           search=search,
                           total_sec=total_sec,
                           open_sec=open_sec,
                           critical_sec=critical_sec,
                           resolved_sec=resolved_sec)


@main_bp.route("/incident-center/new", methods=["GET", "POST"])
@login_required
def incident_center_new():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        category = request.form.get("category", "Other")
        severity = request.form.get("severity", "Medium")
        description = request.form.get("description", "").strip()
        assigned_responder = request.form.get("assigned_responder", "").strip() or "SOC Tier 1 Analyst"

        if not title:
            flash("Please specify an incident title.", "warning")
            return redirect(url_for("main.incident_center_new"))
        if not description:
            flash("Please provide incident narrative description.", "warning")
            return redirect(url_for("main.incident_center_new"))

        if category not in SECURITY_CATEGORIES:
            category = "Other"
        if severity not in SECURITY_SEVERITIES:
            severity = "Medium"

        sec_inc = SecurityIncident(
            user_id=current_user.id,
            title=title,
            category=category,
            severity=severity,
            status="Open",
            description=description,
            assigned_responder=assigned_responder,
            response_notes="Initial incident intake logged."
        )
        db.session.add(sec_inc)
        db.session.flush()

        # Add initial timeline log
        initial_log = SecurityIncidentLog(
            incident_id=sec_inc.id,
            actor=current_user.username,
            action="Incident Created",
            note=f"Triage initialized with category '{category}' and severity '{severity}'."
        )
        db.session.add(initial_log)
        db.session.commit()

        flash(f"Security Incident #{sec_inc.id} created successfully.", "success")
        return redirect(url_for("main.incident_center_detail", incident_id=sec_inc.id))

    return render_template("main/incident_center_new.html",
                           categories=SECURITY_CATEGORIES,
                           severities=SECURITY_SEVERITIES)


@main_bp.route("/incident-center/<int:incident_id>")
@login_required
def incident_center_detail(incident_id: int):
    incident = SecurityIncident.query.filter_by(
        id=incident_id, user_id=current_user.id).first_or_404()
    logs = incident.logs.all()

    return render_template("main/incident_center_detail.html",
                           incident=incident,
                           logs=logs,
                           categories=SECURITY_CATEGORIES,
                           severities=SECURITY_SEVERITIES,
                           statuses=SECURITY_STATUSES)


@main_bp.route("/incident-center/<int:incident_id>/update", methods=["POST"])
@login_required
def incident_center_update(incident_id: int):
    incident = SecurityIncident.query.filter_by(
        id=incident_id, user_id=current_user.id).first_or_404()

    new_status = request.form.get("status", incident.status).strip()
    new_severity = request.form.get("severity", incident.severity).strip()
    new_responder = request.form.get("assigned_responder", incident.assigned_responder).strip()
    note_text = request.form.get("note", "").strip()

    changes = []
    if new_status in SECURITY_STATUSES and new_status != incident.status:
        changes.append(f"Status changed from {incident.status} to {new_status}")
        incident.status = new_status

    if new_severity in SECURITY_SEVERITIES and new_severity != incident.severity:
        changes.append(f"Severity changed from {incident.severity} to {new_severity}")
        incident.severity = new_severity

    if new_responder and new_responder != incident.assigned_responder:
        changes.append(f"Responder re-assigned to '{new_responder}'")
        incident.assigned_responder = new_responder

    if note_text:
        incident.response_notes = (incident.response_notes or "") + f"\n[{datetime.utcnow().strftime('%Y-%m-%d %H:%M')}] {note_text}"
        changes.append("Response notes updated")

    if changes:
        incident.updated_at = datetime.utcnow()
        log_entry = SecurityIncidentLog(
            incident_id=incident.id,
            actor=current_user.username,
            action="; ".join(changes),
            note=note_text or "Field update applied."
        )
        db.session.add(log_entry)
        db.session.commit()
        flash("Incident details and activity log updated.", "success")
    else:
        flash("No changes detected.", "info")

    return redirect(url_for("main.incident_center_detail", incident_id=incident.id))


@main_bp.route("/incident-center/<int:incident_id>/close", methods=["POST"])
@login_required
def incident_center_close(incident_id: int):
    incident = SecurityIncident.query.filter_by(
        id=incident_id, user_id=current_user.id).first_or_404()

    closure_note = request.form.get("closure_note", "Incident marked resolved by responder.").strip()
    incident.status = "Resolved"
    incident.updated_at = datetime.utcnow()
    incident.response_notes = (incident.response_notes or "") + f"\n[CLOSED {datetime.utcnow().strftime('%Y-%m-%d %H:%M')}] {closure_note}"

    close_log = SecurityIncidentLog(
        incident_id=incident.id,
        actor=current_user.username,
        action="Incident Resolved & Closed",
        note=closure_note
    )
    db.session.add(close_log)
    db.session.commit()

    flash(f"Incident #{incident.id} marked as Resolved.", "info")
    return redirect(url_for("main.incident_center_detail", incident_id=incident.id))


@main_bp.route("/incident-center/<int:incident_id>/delete", methods=["POST"])
@login_required
def incident_center_delete(incident_id: int):
    incident = SecurityIncident.query.filter_by(
        id=incident_id, user_id=current_user.id).first_or_404()

    db.session.delete(incident)
    db.session.commit()
    flash(f"Incident #{incident_id} permanently deleted.", "info")
    return redirect(url_for("main.incident_center"))


# ---------------------------------------------------------------------------
# Feature 4: Cybersecurity Awareness Training (/security-training)
# ---------------------------------------------------------------------------
@main_bp.route("/security-training")
@login_required
def security_training():
    return render_template("main/security_training.html")


# ---------------------------------------------------------------------------
# Feature 5: Threat Intelligence Dashboard (/threat-intelligence)
# ---------------------------------------------------------------------------
@main_bp.route("/threat-intelligence")
@login_required
def threat_intelligence():
    return render_template("main/threat_intelligence.html")


# ---------------------------------------------------------------------------
# Feature 6: File Integrity Checker (/file-integrity)
# ---------------------------------------------------------------------------
@main_bp.route("/file-integrity", methods=["GET", "POST"])
@login_required
def file_integrity():
    result = None

    if request.method == "POST":
        file = request.files.get("check_file")
        reference_hash = request.form.get("reference_hash", "").strip().lower()

        if not file or not file.filename:
            flash("Please choose a file to compute its cryptographic hash.", "warning")
            return redirect(url_for("main.file_integrity"))

        orig_filename = secure_filename(file.filename) or "uploaded_file.bin"
        temp_filename = f"integrity_{uuid.uuid4().hex}_{orig_filename}"
        temp_path = os.path.join(current_app.config["UPLOAD_FOLDER"], temp_filename)

        sha256_hash = hashlib.sha256()
        sha1_hash = hashlib.sha1()
        md5_hash = hashlib.md5()
        file_size = 0

        try:
            file.save(temp_path)
            file_size = os.path.getsize(temp_path)

            # Check max size (50MB)
            if file_size > current_app.config.get("MAX_CONTENT_LENGTH", 50 * 1024 * 1024):
                flash("File exceeds maximum allowed size of 50 MB.", "danger")
                return redirect(url_for("main.file_integrity"))

            # Streaming chunk-based hash read (64 KB chunks)
            with open(temp_path, "rb") as f:
                while chunk := f.read(65536):
                    sha256_hash.update(chunk)
                    sha1_hash.update(chunk)
                    md5_hash.update(chunk)

            computed_sha256 = sha256_hash.hexdigest().lower()
            computed_sha1 = sha1_hash.hexdigest().lower()
            computed_md5 = md5_hash.hexdigest().lower()

            match_status = None
            if reference_hash:
                # Clean reference hash (remove spaces, 0x prefix if present)
                clean_ref = reference_hash.replace(" ", "").replace("0x", "").lower()
                if clean_ref == computed_sha256:
                    match_status = "MATCH"
                else:
                    match_status = "MISMATCH"

            result = {
                "filename": orig_filename,
                "file_size": file_size,
                "sha256": computed_sha256,
                "sha1": computed_sha1,
                "md5": computed_md5,
                "reference_hash": reference_hash,
                "match_status": match_status
            }

        except Exception as exc:
            flash(f"Error computing hash: {str(exc)[:120]}", "danger")
        finally:
            # Immediate safe cleanup: file is deleted immediately
            if os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except OSError:
                    pass

    return render_template("main/file_integrity.html", result=result)


# ---------------------------------------------------------------------------
# Feature 7: Personal Cybersecurity Audit (/personal-security-audit)
# ---------------------------------------------------------------------------
@main_bp.route("/personal-security-audit", methods=["GET", "POST"])
@login_required
def personal_security_audit():
    return render_template("main/personal_security_audit.html")


