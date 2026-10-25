import os
import secrets

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


def _get_or_create_secret_key(base_dir: str) -> str:
    """
    Return a stable secret key for local development without printing or exposing it.
    Priority:
    1. VS_SECRET_KEY or SECRET_KEY environment variable.
    2. Persisted local secret file (.secret_key) in base_dir.
    3. Securely generated random token if file operations fail.
    """
    env_secret = os.environ.get("VS_SECRET_KEY") or os.environ.get("SECRET_KEY")
    if env_secret:
        return env_secret

    secret_file = os.path.join(base_dir, ".secret_key")
    if os.path.isfile(secret_file):
        try:
            with open(secret_file, "r", encoding="utf-8") as f:
                key = f.read().strip()
                if key:
                    return key
        except OSError:
            pass

    # Generate a stable local dev secret and persist it
    new_key = secrets.token_hex(32)
    try:
        with open(secret_file, "w", encoding="utf-8") as f:
            f.write(new_key)
    except OSError:
        pass
    return new_key


class Config:
    # Secret key – override with VS_SECRET_KEY env var in production
    SECRET_KEY = _get_or_create_secret_key(BASE_DIR)

    # SQLite database
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL") or \
        "sqlite:///" + os.path.join(BASE_DIR, "voiceshield.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Server binding defaults: local-only 127.0.0.1, debug OFF by default
    SERVER_HOST = os.environ.get("VS_HOST", "127.0.0.1")
    SERVER_PORT = int(os.environ.get("VS_PORT", 5000))
    DEBUG = os.environ.get("FLASK_DEBUG", "0").lower() in ("1", "true")

    # Upload settings
    UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
    EVIDENCE_VAULT_FOLDER = os.path.join(BASE_DIR, "uploads", "evidence_vault")
    MAX_CONTENT_LENGTH = 50 * 1024 * 1024   # 50 MB
    ALLOWED_EXTENSIONS = {"wav", "mp3", "ogg", "flac", "m4a", "webm"}

    # Whisper model – tiny is fast; change to "base" or "small" for accuracy
    WHISPER_MODEL = os.environ.get("WHISPER_MODEL", "tiny")

    # Auto-delete uploads after analysis (seconds, 0 = immediate)
    UPLOAD_TTL_SECONDS = 0
