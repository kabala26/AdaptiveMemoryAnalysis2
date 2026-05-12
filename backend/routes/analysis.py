"""
Analysis Blueprint
==================

Routes
------
POST /api/analysis/upload              →  upload a memory dump file
POST /api/analysis/analyze             →  trigger feature extraction + classification
GET  /api/analysis/results/<id>        →  fetch prediction, confidence, artifacts
POST /api/analysis/retrain             →  trigger model retraining (admin only)
GET  /api/analysis/dumps               →  list dumps (own for analyst, all for admin)
GET  /api/analysis/stats               →  system stats (admin only)
GET  /api/analysis/models              →  list trained models (admin only)
POST /api/analysis/models/<id>/activate→  set active model (admin only)
GET  /api/analysis/logs                →  audit log (admin only)

Role policy
-----------
  admin            — full access
  forensic_analyst — upload, analyze, view OWN results only; no retrain/admin ops
"""

import hashlib
import os
import shutil
import threading
from datetime import datetime, timezone
from pathlib import Path

import joblib
from flask import Blueprint, current_app, jsonify, request
from flask_jwt_extended import get_jwt, get_jwt_identity, jwt_required

from .. import db
from ..models.analysis import (
    AnalysisFeatures, AnalysisResult, AuditLog,
    LabeledSample, MemoryDump, MlModel,
)
from ..utils.roles import ADMIN, ANALYST, require_role

analysis_bp = Blueprint('analysis', __name__)

# ── Constants ─────────────────────────────────────────────────────────────────

_ALLOWED_EXTENSIONS = {'.raw', '.mem', '.dmp', '.vmem'}
_MAX_UPLOAD_BYTES   = 2 * 1024 * 1024 * 1024   # 2 GB

_retrain_lock = threading.Lock()


# ── Helpers ───────────────────────────────────────────────────────────────────

def _error(message: str, status: int = 400):
    return jsonify({'message': message}), status


def _upload_dir() -> Path:
    folder = Path(current_app.config['UPLOAD_FOLDER'])
    folder.mkdir(parents=True, exist_ok=True)
    return folder


def _latest_model() -> MlModel | None:
    """Return the model with the most recent activated_at timestamp."""
    return MlModel.query.order_by(MlModel.activated_at.desc()).first()


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def _audit(action: str, resource_type: str = None, resource_id: str = None, details: dict = None):
    """Append an audit log row. Caller must commit the session."""
    try:
        log = AuditLog(
            user_id       = get_jwt_identity(),
            action        = action,
            resource_type = resource_type,
            resource_id   = resource_id,
            ip_address    = request.remote_addr,
            details       = details,
        )
        db.session.add(log)
    except Exception:
        pass  # Audit failures must never block business logic


# ── Background workers ────────────────────────────────────────────────────────

def _analysis_worker(app, dump_id: str, file_path: str):
    """Run extraction + classification in a daemon thread."""
    with app.app_context():
        dump = db.session.get(MemoryDump, dump_id)
        if dump is None:
            return

        try:
            dump.status = 'processing'
            db.session.commit()

            from modules.feature_extractor import extract_features
            from modules.feature_mapper import map_to_feature_vector

            extracted = extract_features(file_path)
            vec = map_to_feature_vector(extracted)

            feat = AnalysisFeatures(
                dump_id       = dump_id,
                process_count = extracted.get('summary', {}).get('process_count'),
                dll_count     = extracted.get('summary', {}).get('dll_count'),
                feature_data  = extracted,
            )
            db.session.add(feat)

            model_row = _latest_model()
            if model_row and model_row.model_path and Path(model_row.model_path).is_file():
                clf        = joblib.load(model_row.model_path)
                label      = clf.predict(vec)[0]
                proba      = clf.predict_proba(vec)[0]
                prediction = 'Malware' if int(label) == 1 else 'Benign'
                confidence = float(max(proba))

                result = AnalysisResult(
                    dump_id    = dump_id,
                    model_id   = model_row.model_id,
                    prediction = prediction,
                    confidence = confidence,
                )
                db.session.add(result)

            dump.status = 'complete'
            db.session.commit()

        except Exception as exc:
            db.session.rollback()
            current_app.logger.error('Analysis failed for dump %s: %s', dump_id, exc)
            try:
                dump.status = 'failed'
                db.session.commit()
            except Exception:
                db.session.rollback()


def _retrain_worker(app):
    """Run adaptive retraining in a daemon thread, serialized by _retrain_lock."""
    with app.app_context():
        try:
            from modules.model_trainer import retrain_in_context
            result = retrain_in_context()
            current_app.logger.info(
                'Retrain complete — model %s | acc %.4f | %s',
                result['model_id'], result['accuracy'], result['outcome'],
            )
        except Exception as exc:
            db.session.rollback()
            current_app.logger.error('Retrain failed: %s', exc)
        finally:
            _retrain_lock.release()


# ══════════════════════════════════════════════════════════════════════════════
#  POST /upload
# ══════════════════════════════════════════════════════════════════════════════

@analysis_bp.post('/upload')
@require_role(ADMIN, ANALYST)
def upload():
    if 'file' not in request.files:
        return _error('No file field in request.')

    file = request.files['file']
    if not file.filename:
        return _error('Empty filename.')

    suffix = Path(file.filename).suffix.lower()
    if suffix not in _ALLOWED_EXTENSIONS:
        return _error(
            f'Unsupported file type "{suffix}". '
            f'Allowed: {", ".join(sorted(_ALLOWED_EXTENSIONS))}.',
            415,
        )

    declared = request.content_length
    if declared and declared > _MAX_UPLOAD_BYTES:
        return _error('File exceeds the 2 GB upload limit.', 413)

    user_id   = get_jwt_identity()
    dest_dir  = _upload_dir() / user_id
    dest_dir.mkdir(parents=True, exist_ok=True)

    import uuid as _uuid
    dump_id  = str(_uuid.uuid4())
    dest     = dest_dir / f"{dump_id}{suffix}"

    written = 0
    with open(dest, 'wb') as fh:
        for chunk in iter(lambda: file.stream.read(1 << 20), b''):
            written += len(chunk)
            if written > _MAX_UPLOAD_BYTES:
                fh.close()
                dest.unlink(missing_ok=True)
                return _error('File exceeds the 2 GB upload limit.', 413)
            fh.write(chunk)

    hash_value = _sha256(str(dest))

    dump = MemoryDump(
        dump_id    = dump_id,
        user_id    = user_id,
        file_path  = str(dest),
        file_name  = file.filename,
        file_size  = written,
        hash_value = hash_value,
        status     = 'pending',
    )
    db.session.add(dump)
    _audit('upload', 'dump', dump_id, {'file_name': file.filename, 'file_size': written})
    db.session.commit()

    return jsonify({
        'dump_id':   dump_id,
        'file_name': file.filename,
        'file_size': written,
        'hash':      hash_value,
        'status':    'pending',
    }), 201


# ══════════════════════════════════════════════════════════════════════════════
#  POST /analyze
# ══════════════════════════════════════════════════════════════════════════════

@analysis_bp.post('/analyze')
@require_role(ADMIN, ANALYST)
def analyze():
    data    = request.get_json(silent=True) or {}
    dump_id = (data.get('dump_id') or '').strip()

    if not dump_id:
        return _error('dump_id is required.')

    dump = db.session.get(MemoryDump, dump_id)
    if dump is None:
        return _error('Dump not found.', 404)

    role    = get_jwt().get('role', '')
    user_id = get_jwt_identity()
    if role != ADMIN and dump.user_id != user_id:
        return _error('Access denied — you can only analyze your own dumps.', 403)

    if dump.status == 'processing':
        return _error('Analysis already in progress for this dump.', 409)

    _audit('analyze', 'dump', dump_id)
    db.session.commit()

    app = current_app._get_current_object()
    t = threading.Thread(
        target=_analysis_worker,
        args=(app, dump_id, dump.file_path),
        daemon=True,
    )
    t.start()

    return jsonify({'dump_id': dump_id, 'status': 'processing'}), 202


# ══════════════════════════════════════════════════════════════════════════════
#  GET /results/<dump_id>
# ══════════════════════════════════════════════════════════════════════════════

@analysis_bp.get('/results/<dump_id>')
@require_role(ADMIN, ANALYST)
def get_results(dump_id: str):
    dump = db.session.get(MemoryDump, dump_id)
    if dump is None:
        return _error('Dump not found.', 404)

    role    = get_jwt().get('role', '')
    user_id = get_jwt_identity()
    if role != ADMIN and dump.user_id != user_id:
        return _error('Access denied — you can only view your own results.', 403)

    result = (
        AnalysisResult.query
        .filter_by(dump_id=dump_id)
        .order_by(AnalysisResult.classification_date.desc())
        .first()
    )

    artifacts = []
    if dump.features and dump.features.feature_data:
        fd      = dump.features.feature_data
        behav   = fd.get('behavioral_indicators', {})
        artifacts = behav.get('injection_evidence', [])

    feature_importance = None
    if result:
        model_row = db.session.get(MlModel, result.model_id)
        if model_row:
            feature_importance = model_row.feature_importance

    payload = {
        'dump_id':             dump_id,
        'file_name':           dump.file_name,
        'status':              dump.status,
        'dump':                dump.to_dict(),
        'prediction':          None,
        'confidence':          None,
        'classification_date': None,
        'suspicious_artifacts': artifacts,
        'feature_importance':  feature_importance,
    }

    if result:
        payload['prediction']          = result.prediction
        payload['confidence']          = result.confidence
        payload['classification_date'] = result.classification_date.isoformat()

    return jsonify(payload), 200


# ══════════════════════════════════════════════════════════════════════════════
#  POST /retrain
# ══════════════════════════════════════════════════════════════════════════════

@analysis_bp.post('/retrain')
@require_role(ADMIN)
def retrain():
    if not _retrain_lock.acquire(blocking=False):
        return _error('A retraining job is already in progress.', 409)

    _audit('retrain', 'model')
    db.session.commit()

    app = current_app._get_current_object()
    t = threading.Thread(target=_retrain_worker, args=(app,), daemon=True)
    t.start()

    return jsonify({'message': 'Retraining started.'}), 202


# ══════════════════════════════════════════════════════════════════════════════
#  GET /dumps  — list dumps with latest result inline
# ══════════════════════════════════════════════════════════════════════════════

@analysis_bp.get('/dumps')
@require_role(ADMIN, ANALYST)
def list_dumps():
    role    = get_jwt().get('role', '')
    user_id = get_jwt_identity()

    query = MemoryDump.query
    if role != ADMIN:
        query = query.filter_by(user_id=user_id)

    dumps = query.order_by(MemoryDump.upload_date.desc()).limit(200).all()

    # Pull user names for admin view
    from ..models.user import User
    user_cache: dict[str, dict] = {}

    rows = []
    for dump in dumps:
        latest = (
            AnalysisResult.query
            .filter_by(dump_id=dump.dump_id)
            .order_by(AnalysisResult.classification_date.desc())
            .first()
        )
        row = dump.to_dict()
        row['prediction'] = latest.prediction if latest else None
        row['confidence'] = latest.confidence if latest else None
        row['classification_date'] = (
            latest.classification_date.isoformat() if latest else None
        )

        if role == ADMIN:
            uid = dump.user_id
            if uid not in user_cache:
                u = db.session.get(User, uid)
                user_cache[uid] = {'name': u.name, 'email': u.email} if u else {}
            row['user_name']  = user_cache[uid].get('name')
            row['user_email'] = user_cache[uid].get('email')

        rows.append(row)

    return jsonify({'dumps': rows}), 200


# ══════════════════════════════════════════════════════════════════════════════
#  GET /stats  — admin system overview numbers
# ══════════════════════════════════════════════════════════════════════════════

@analysis_bp.get('/stats')
@require_role(ADMIN)
def stats():
    from datetime import date

    total     = MemoryDump.query.count()
    today_str = date.today().isoformat()

    malware_today = (
        AnalysisResult.query
        .filter(
            AnalysisResult.prediction == 'Malware',
            db.func.date(AnalysisResult.classification_date) == today_str,
        )
        .count()
    )

    total_results = AnalysisResult.query.count()
    malware_total = AnalysisResult.query.filter_by(prediction='Malware').count()
    detection_rate = (malware_total / total_results) if total_results else 0.0

    last_model = _latest_model()

    upload_dir = Path(current_app.config['UPLOAD_FOLDER'])
    disk_bytes = sum(f.stat().st_size for f in upload_dir.rglob('*') if f.is_file()) \
        if upload_dir.exists() else 0

    return jsonify({
        'total_analyses':   total,
        'malware_today':    malware_today,
        'detection_rate':   round(detection_rate, 4),
        'disk_usage_mb':    round(disk_bytes / (1024 * 1024), 1),
        'last_model_date':  last_model.training_date.isoformat() if last_model else None,
        'last_model_accuracy': last_model.accuracy if last_model else None,
    }), 200


# ══════════════════════════════════════════════════════════════════════════════
#  GET /models  — list all trained model versions
# ══════════════════════════════════════════════════════════════════════════════

@analysis_bp.get('/models')
@require_role(ADMIN)
def list_models():
    models = MlModel.query.order_by(MlModel.training_date.desc()).all()
    active = _latest_model()
    rows = []
    for m in models:
        d = m.to_dict()
        d['is_active'] = (active is not None and m.model_id == active.model_id)
        rows.append(d)
    return jsonify({'models': rows}), 200


# ══════════════════════════════════════════════════════════════════════════════
#  POST /models/<model_id>/activate
# ══════════════════════════════════════════════════════════════════════════════

@analysis_bp.post('/models/<model_id>/activate')
@require_role(ADMIN)
def activate_model(model_id: str):
    model = db.session.get(MlModel, model_id)
    if model is None:
        return _error('Model not found.', 404)

    model.activated_at = datetime.now(timezone.utc)
    _audit('activate_model', 'model', model_id)
    db.session.commit()

    return jsonify({'message': f'Model {model_id} is now active.', 'model': model.to_dict()}), 200


# ══════════════════════════════════════════════════════════════════════════════
#  GET /logs  — audit log (admin only)
# ══════════════════════════════════════════════════════════════════════════════

@analysis_bp.get('/logs')
@require_role(ADMIN)
def list_logs():
    from ..models.user import User

    page     = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    user_filter = request.args.get('user_id')

    query = AuditLog.query
    if user_filter:
        query = query.filter_by(user_id=user_filter)

    logs  = query.order_by(AuditLog.timestamp.desc()).offset((page - 1) * per_page).limit(per_page).all()
    total = query.count()

    user_cache: dict[str, dict] = {}
    rows = []
    for log in logs:
        row = log.to_dict()
        uid = log.user_id
        if uid and uid not in user_cache:
            u = db.session.get(User, uid)
            user_cache[uid] = {'name': u.name, 'email': u.email} if u else {}
        row['user_name']  = user_cache.get(uid or '', {}).get('name')
        row['user_email'] = user_cache.get(uid or '', {}).get('email')
        rows.append(row)

    return jsonify({'logs': rows, 'total': total, 'page': page, 'per_page': per_page}), 200


# ══════════════════════════════════════════════════════════════════════════════
#  GET /labeled-samples  — list confirmed labeled samples (admin)
# ══════════════════════════════════════════════════════════════════════════════

@analysis_bp.get('/labeled-samples')
@require_role(ADMIN)
def list_labeled_samples():
    page     = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)

    samples = (
        LabeledSample.query
        .order_by(LabeledSample.added_at.desc())
        .offset((page - 1) * per_page)
        .limit(per_page)
        .all()
    )
    total = LabeledSample.query.count()
    pending = LabeledSample.query.filter_by(included_in_model_id=None).count()

    return jsonify({
        'samples': [s.to_dict() for s in samples],
        'total':   total,
        'pending': pending,
        'page':    page,
        'per_page': per_page,
    }), 200


# ══════════════════════════════════════════════════════════════════════════════
#  POST /labeled-samples  — submit a confirmed ground-truth label (admin)
# ══════════════════════════════════════════════════════════════════════════════

@analysis_bp.post('/labeled-samples')
@require_role(ADMIN)
def add_labeled_sample():
    """
    Accept a ground-truth labeled sample for future adaptive retraining.

    Body (JSON):
      true_label      — required: "Benign" or "Malware"
      dump_id         — optional: link to an existing memory dump;
                        if provided and feature_vector is omitted,
                        the vector is derived from the dump's extracted features
      feature_vector  — optional 55-element list (overrides dump_id extraction)
    """
    data       = request.get_json(silent=True) or {}
    true_label = data.get('true_label', '').strip()
    dump_id    = (data.get('dump_id') or '').strip() or None
    fv         = data.get('feature_vector')

    if true_label not in ('Benign', 'Malware'):
        return _error('true_label must be "Benign" or "Malware".')

    # Derive feature vector from dump if not supplied directly
    if fv is None and dump_id:
        dump = db.session.get(MemoryDump, dump_id)
        if dump is None:
            return _error('Dump not found.', 404)
        if not dump.features or not dump.features.feature_data:
            return _error('Dump has no extracted features yet; run analysis first.', 422)
        try:
            from modules.feature_mapper import map_to_feature_vector
            fv = map_to_feature_vector(dump.features.feature_data).tolist()
        except Exception as exc:
            return _error(f'Could not extract feature vector from dump: {exc}', 422)

    if not isinstance(fv, list) or len(fv) == 0:
        return _error('feature_vector is required (or provide dump_id with extracted features).')

    sample = LabeledSample(
        dump_id        = dump_id,
        feature_vector = fv,
        true_label     = true_label,
        source         = 'confirmed_prediction' if dump_id else 'manual',
        added_by       = get_jwt_identity(),
    )
    db.session.add(sample)
    _audit('label_sample', 'labeled_sample', sample.sample_id,
           {'true_label': true_label, 'dump_id': dump_id})
    db.session.commit()

    return jsonify({
        'message':   'Labeled sample saved.',
        'sample_id': sample.sample_id,
    }), 201
