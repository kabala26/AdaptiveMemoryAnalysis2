from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from flask_cors import CORS
from dotenv import load_dotenv
from pathlib import Path
import os

load_dotenv()

db  = SQLAlchemy()
jwt = JWTManager()


def create_app():
    app = Flask(__name__)

    # ── Configuration ─────────────────────────────────────────────
    app.config['SECRET_KEY']        = os.environ['SECRET_KEY']
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ['DATABASE_URL']
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # Upload
    app.config['UPLOAD_FOLDER']      = os.getenv('UPLOAD_FOLDER', str(Path(__file__).parent.parent / 'uploads'))
    app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024 * 1024   # 2 GB hard cap

    # JWT
    app.config['JWT_SECRET_KEY']           = os.environ['JWT_SECRET_KEY']
    app.config['JWT_ACCESS_TOKEN_EXPIRES']  = int(os.getenv('JWT_ACCESS_EXPIRES_SECONDS',  900))   # 15 min
    app.config['JWT_REFRESH_TOKEN_EXPIRES'] = int(os.getenv('JWT_REFRESH_EXPIRES_SECONDS', 604800)) # 7 days

    # OAuth
    app.config['GOOGLE_CLIENT_ID']     = os.environ['GOOGLE_CLIENT_ID']
    app.config['GOOGLE_CLIENT_SECRET'] = os.environ['GOOGLE_CLIENT_SECRET']
    app.config['GITHUB_CLIENT_ID']     = os.environ['GITHUB_CLIENT_ID']
    app.config['GITHUB_CLIENT_SECRET'] = os.environ['GITHUB_CLIENT_SECRET']
    app.config['FRONTEND_URL']         = os.getenv('FRONTEND_URL', 'http://localhost:3000')
    app.config['BACKEND_URL']          = os.getenv('BACKEND_URL',  'http://localhost:5000')

    # ── Extensions ────────────────────────────────────────────────
    db.init_app(app)
    jwt.init_app(app)
    CORS(app, resources={r'/api/*': {'origins': app.config['FRONTEND_URL']}},
         supports_credentials=True)

    # ── Blueprints ────────────────────────────────────────────────
    from .routes.auth     import auth_bp
    from .routes.analysis import analysis_bp
    app.register_blueprint(auth_bp,     url_prefix='/api/auth')
    app.register_blueprint(analysis_bp, url_prefix='/api/analysis')

    # ── DB init ───────────────────────────────────────────────────
    with app.app_context():
        db.create_all()

    return app
