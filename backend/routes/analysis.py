"""
Analysis Blueprint
==================

Routes
------
POST /api/analysis/upload          →  upload a memory dump file (admin + analyst)
POST /api/analysis/analyze         →  trigger feature extraction + classification
GET  /api/analysis/results/<id>    →  fetch prediction, confidence, artifacts
POST /api/analysis/retrain         →  trigger model retraining (admin only)

Role policy
-----------
  admin   — full access: upload, analyze, view ALL results, retrain
  analyst — upload, analyze, view OWN results only; no retrain
"""

import hashlib
import os
import threading
from pathlib import Path

import joblib
from flask import Blueprint, current_app, g, jsonify, request
from flask_jwt_extended import get_jwt, get_jwt_identity, jwt_required

from .. import db
from ..models.analysis import AnalysisFeatures, AnalysisResult, MemoryDump, MlModel
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
    return MlModel.query.order_by(MlModel.training_date.desc()).first()


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


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

            # Persist features
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
    """Run model retraining in a daemon thread, serialized by _retrain_lock."""
    with app.app_context():
        try:
            from modules.classifier import train_and_evaluate

            result    = train_and_evaluate()
            model_row = MlModel(
                model_name    = 'RandomForest-CICMalMem2022',
                algorithm     = 'RandomForestClassifier',
                accuracy      = result['test_metrics']['accuracy'],
                model_path    = str(result['model_path']),
            )
            db.session.add(model_row)
            db.session.commit()
            current_app.logger.info('Retrain complete — new model id: %s', model_row.model_id)
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
    """
    Accept a memory dump file (multipart/form-data, field name: file).

    Validates extension, enforces 2 GB cap, writes to UPLOAD_FOLDER,
    computes SHA-256, persists a MemoryDump record, returns dump_id.
    """
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

    # Reject obviously-too-large uploads before writing anything
    declared = request.content_length
    if declared and declared > _MAX_UPLOAD_BYTES:
        return _error('File exceeds the 2 GB upload limit.', 413)

    user_id   = get_jwt_identity()
    dest_dir  = _upload_dir() / user_id
    dest_dir.mkdir(parents=True, exist_ok=True)

    # Use the DB-generated UUID as the on-disk filename to avoid collisions
    import uuid as _uuid
    dump_id  = str(_uuid.uuid4())
    dest     = dest_dir / f"{dump_id}{suffix}"

    # Stream write with size enforcement
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
    """
    Trigger background analysis for an uploaded dump.

    Body: { "dump_id": str }

    Analysts may only analyze their own dumps; admins may analyze any.
    """
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
    """
    Return prediction, confidence score, and suspicious artifacts for a dump.

    Analysts may only view their own dump results; admins may view any.
    """
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

    # Pull suspicious artifacts from stored feature_data
    artifacts = []
    if dump.features and dump.features.feature_data:
        fd      = dump.features.feature_data
        behav   = fd.get('behavioral_indicators', {})
        artifacts = behav.get('injection_evidence', [])

    payload = {
        'dump_id':    dump_id,
        'file_name':  dump.file_name,
        'status':     dump.status,
        'dump':       dump.to_dict(),
        'prediction': None,
        'confidence': None,
        'classification_date': None,
        'suspicious_artifacts': artifacts,
    }

    if result:
        payload['prediction']           = result.prediction
        payload['confidence']           = result.confidence
        payload['classification_date']  = result.classification_date.isoformat()

    return jsonify(payload), 200


# ══════════════════════════════════════════════════════════════════════════════
#  POST /retrain
# ══════════════════════════════════════════════════════════════════════════════

@analysis_bp.post('/retrain')
@require_role(ADMIN)
def retrain():
    """
    Trigger a full model retraining run (admin only).

    Returns immediately; training runs in a background thread.
    Only one retraining job may run at a time — returns 409 if busy.
    """
    if not _retrain_lock.acquire(blocking=False):
        return _error('A retraining job is already in progress.', 409)

    app = current_app._get_current_object()
    t = threading.Thread(target=_retrain_worker, args=(app,), daemon=True)
    t.start()

    return jsonify({'message': 'Retraining started.'}), 202
