from datetime import datetime
from extensions import db, login_manager
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    incidents = db.relationship("Incident", backref="owner", lazy="dynamic",
                                cascade="all, delete-orphan")
    security_incidents = db.relationship("SecurityIncident", backref="user", lazy="dynamic",
                                         cascade="all, delete-orphan")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f"<User {self.username}>"


class Incident(db.Model):
    __tablename__ = "incidents"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    # Metadata
    title = db.Column(db.String(200), nullable=False)
    category = db.Column(db.String(80), nullable=False, default="General")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Transcription
    transcript = db.Column(db.Text, nullable=True)
    transcription_status = db.Column(db.String(30), default="pending")
    # values: pending | success | failed | unavailable

    # Scam analysis
    risk_score = db.Column(db.Integer, default=0)          # 0-100
    risk_level = db.Column(db.String(20), default="Unknown")  # Low/Medium/High/Critical
    matched_phrases = db.Column(db.Text, nullable=True)     # JSON list
    recommendations = db.Column(db.Text, nullable=True)     # JSON list

    # Acoustic measurements (NOT deepfake detection)
    clipping_ratio = db.Column(db.Float, nullable=True)
    spectral_flatness = db.Column(db.Float, nullable=True)
    snr_db = db.Column(db.Float, nullable=True)
    duration_seconds = db.Column(db.Float, nullable=True)
    sample_rate = db.Column(db.Integer, nullable=True)
    acoustic_note = db.Column(db.String(300), nullable=True)

    # Storage (temp file deleted after analysis)
    original_filename = db.Column(db.String(260), nullable=True)
    audio_deleted = db.Column(db.Boolean, default=False)

    def to_dict(self):
        import json
        return {
            "id": self.id,
            "title": self.title,
            "category": self.category,
            "created_at": self.created_at.strftime("%Y-%m-%d %H:%M"),
            "transcript": self.transcript,
            "transcription_status": self.transcription_status,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "matched_phrases": json.loads(self.matched_phrases) if self.matched_phrases else [],
            "recommendations": json.loads(self.recommendations) if self.recommendations else [],
            "clipping_ratio": self.clipping_ratio,
            "spectral_flatness": self.spectral_flatness,
            "snr_db": self.snr_db,
            "duration_seconds": self.duration_seconds,
            "sample_rate": self.sample_rate,
            "acoustic_note": self.acoustic_note,
            "original_filename": self.original_filename,
            "audio_deleted": self.audio_deleted,
        }


# ---------------------------------------------------------------------------
# Security Incident Response Center Models (Feature 3)
# ---------------------------------------------------------------------------
class SecurityIncident(db.Model):
    __tablename__ = "security_incidents"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    title = db.Column(db.String(200), nullable=False)
    category = db.Column(db.String(80), nullable=False, default="Other")
    # Categories: Phishing, Suspected Voice Impersonation, Malware, Account Compromise, Data Exposure, Other
    description = db.Column(db.Text, nullable=False)
    severity = db.Column(db.String(20), nullable=False, default="Medium")
    # Severities: Low, Medium, High, Critical
    status = db.Column(db.String(30), nullable=False, default="Open")
    # Statuses: Open, Investigating, Contained, Resolved
    assigned_responder = db.Column(db.String(100), default="SOC Tier 1 Analyst")
    response_notes = db.Column(db.Text, nullable=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    logs = db.relationship("SecurityIncidentLog", backref="incident", lazy="dynamic",
                           cascade="all, delete-orphan", order_by="desc(SecurityIncidentLog.timestamp)")

    def to_dict(self):
        return {
            "id": self.id,
            "title": self.title,
            "category": self.category,
            "description": self.description,
            "severity": self.severity,
            "status": self.status,
            "assigned_responder": self.assigned_responder,
            "response_notes": self.response_notes,
            "created_at": self.created_at.strftime("%Y-%m-%d %H:%M"),
            "updated_at": self.updated_at.strftime("%Y-%m-%d %H:%M") if self.updated_at else None,
        }


class SecurityIncidentLog(db.Model):
    __tablename__ = "security_incident_logs"
    id = db.Column(db.Integer, primary_key=True)
    incident_id = db.Column(db.Integer, db.ForeignKey("security_incidents.id"), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    actor = db.Column(db.String(80), default="Security Analyst")
    action = db.Column(db.String(120), nullable=False)
    note = db.Column(db.Text, nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "incident_id": self.incident_id,
            "timestamp": self.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "actor": self.actor,
            "action": self.action,
            "note": self.note,
        }

