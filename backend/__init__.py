import os
from pathlib import Path

from dotenv import load_dotenv
from flask import Flask
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from flask_sqlalchemy import SQLAlchemy

load_dotenv()

db  = SQLAlchemy()
jwt = JWTManager()


def create_app():
    app = Flask(__name__)

    # ── Configuration ─────────────────────────────────────────────
    app.config['SECRET_KEY']        = os.environ['SECRET_KEY']
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ['DATABASE_URL']
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    # Supabase's pgbouncer pooler silently drops idle/long-lived connections.
    # pool_pre_ping validates a connection before reuse instead of failing mid-request;
    # pool_recycle proactively replaces connections before the pooler's own timeout hits.
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
        'pool_pre_ping': True,
        'pool_recycle':  280,
    }

    # Upload
    app.config['UPLOAD_FOLDER']      = os.getenv('UPLOAD_FOLDER', str(Path(__file__).parent.parent / 'uploads'))
    app.config['MAX_CONTENT_LENGTH'] = 8 * 1024 * 1024 * 1024   # 8 GB hard cap

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
        _mark_stale_processing_failed(app)

    # ── APScheduler — weekly adaptive retraining ──────────────────
    # Only start in the main process; the Werkzeug debug reloader spawns a
    # child process first — we must not schedule there or we'd get two jobs.
    _start_scheduler(app)

    return app


def _mark_stale_processing_failed(app: Flask) -> None:
    """Mark any dumps stuck in 'processing' as 'failed' on startup.

    If the server was killed mid-analysis the subprocess is gone but the DB
    row never got updated. Leaving it as 'processing' makes the frontend poll
    forever. Mark them failed so the UI shows the correct state immediately.
    """
    try:
        from .models.analysis import MemoryDump
        stale = MemoryDump.query.filter_by(status='processing').all()
        if stale:
            for dump in stale:
                dump.status = 'failed'
            db.session.commit()
            app.logger.warning(
                'Marked %d stale processing dump(s) as failed on startup.',
                len(stale),
            )
    except Exception as exc:
        app.logger.error('Could not clean up stale processing dumps: %s', exc)


def _start_scheduler(app: Flask) -> None:
    """Attach a BackgroundScheduler to app that fires adaptive_retrain weekly."""
    if app.debug and os.environ.get('WERKZEUG_RUN_MAIN') != 'true':
        return  # reloader child process — skip

    try:
        from apscheduler.schedulers.background import BackgroundScheduler
        from apscheduler.triggers.cron import CronTrigger
    except ImportError:
        app.logger.warning(
            'APScheduler is not installed — weekly retraining disabled. '
            'Run: pip install "APScheduler>=3.10.0,<4.0"'
        )
        return

    _app = app  # capture for the closure

    def _job():
        app.logger.info('APScheduler: starting weekly adaptive retrain.')
        try:
            from modules.model_trainer import adaptive_retrain
            result = adaptive_retrain(_app)
            _app.logger.info(
                'APScheduler: retrain finished — %s (acc %.4f)',
                result['outcome'], result['accuracy'],
            )
        except Exception as exc:
            _app.logger.error('APScheduler: retrain failed — %s', exc)

    scheduler = BackgroundScheduler(timezone='UTC', daemon=True)
    scheduler.add_job(
        _job,
        CronTrigger(day_of_week='sun', hour=2, minute=0, timezone='UTC'),
        id='weekly_adaptive_retrain',
        replace_existing=True,
        misfire_grace_time=3600,  # fire up to 1 h late if server was down
    )
    scheduler.start()
    app.scheduler = scheduler
    app.logger.info('APScheduler started — weekly retrain every Sunday 02:00 UTC.')
