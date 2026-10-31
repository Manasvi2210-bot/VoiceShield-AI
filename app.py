"""
app.py – Application factory and entry point.
"""
import json
import os
from flask import Flask
from config import Config
from extensions import db, login_manager


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Ensure upload folders exist
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
    if "EVIDENCE_VAULT_FOLDER" in app.config:
        os.makedirs(app.config["EVIDENCE_VAULT_FOLDER"], exist_ok=True)

    # Init extensions
    db.init_app(app)
    login_manager.init_app(app)

    # Custom Jinja2 filters
    @app.template_filter("from_json")
    def from_json_filter(value):
        if not value:
            return []
        try:
            return json.loads(value)
        except (ValueError, TypeError):
            return []

    # Register blueprints
    from routes.auth import auth_bp
    from routes.main import main_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)

    # Create tables
    with app.app_context():
        db.create_all()

    return app


# Create Flask application for deployment
app = create_app()

if __name__ == "__main__":
    debug_mode = app.config.get("DEBUG", False)
    host = app.config.get("SERVER_HOST", "127.0.0.1")
    port = app.config.get("SERVER_PORT", 5000)
    app.run(debug=debug_mode, host=host, port=port)
