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
    MemoryDump, MlModel,
)
from ..utils.roles import ADMIN, ANALYST, require_role

analysis_bp = Blueprint('analysis', __name__)

# ── Constants (all sourced from central config) ───────────────────────────────
from modules.config import (
    ALLOWED_EXTENSIONS       as _ALLOWED_EXTENSIONS,
    MAX_UPLOAD_BYTES         as _MAX_UPLOAD_BYTES,
    PSEUDO_LABEL_THRESHOLD   as _PSEUDO_LABEL_THRESHOLD,
    DRIFT_WINDOW             as _DRIFT_WINDOW,
    DRIFT_P_VALUE            as _DRIFT_P_VALUE,
)

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

from modules.config import (
    FAST_TIMEOUT_SECONDS         as _FAST_TIMEOUT_SECONDS,
    ANALYSIS_TIMEOUT_SECONDS     as _ANALYSIS_TIMEOUT_SECONDS,
    BENIGN_EARLY_EXIT_THRESHOLD  as _BENIGN_THRESHOLD,
    FAMILY_TOP_N                 as _FAMILY_TOP_N,
)


# ── CSV batch helper ──────────────────────────────────────────────────────────

def _classify_csv_batch(file_path: str) -> dict:
    """
    Classify every row in a CICMalMem-format CSV as Benign or Malware
    and return an aggregated batch summary.

    Raises ValueError if the file does not look like a feature CSV.
    """
    import numpy as np
    import pandas as pd
    from modules.feature_mapper import FEATURE_NAMES

    df = pd.read_csv(file_path)

    # Require at least half the expected feature columns to be present.
    present = [c for c in FEATURE_NAMES if c in df.columns]
    if len(present) < len(FEATURE_NAMES) // 2:
        raise ValueError(
            f'CSV has only {len(present)}/{len(FEATURE_NAMES)} expected feature '
            'columns — does not look like a CICMalMem feature file.'
        )

    # Build the feature matrix in the canonical 55-column order, filling gaps with 0.
    X = np.zeros((len(df), len(FEATURE_NAMES)), dtype=np.float64)
    for i, name in enumerate(FEATURE_NAMES):
        if name in df.columns:
            X[:, i] = pd.to_numeric(df[name], errors='coerce').fillna(0).values

    model_row = _latest_model()
    if not model_row or not model_row.model_path or not Path(model_row.model_path).is_file():
        raise ValueError('No trained model available.')

    clf        = joblib.load(model_row.model_path)
    labels     = clf.predict(X)
    probas     = clf.predict_proba(X)
    predictions = ['Malware' if int(l) == 1 else 'Benign' for l in labels]
    confidences = [float(max(p)) for p in probas]

    n_malware = sum(1 for p in predictions if p == 'Malware')
    n_benign  = len(predictions) - n_malware

    # Stage 2 — batch family classification on malicious rows only
    categories: dict[str, int] = {}
    families:   dict[str, int] = {}
    try:
        from modules.family_classifier import CATEGORY_MODEL_PATH, FAMILY_MODEL_PATH
        if CATEGORY_MODEL_PATH.is_file() and FAMILY_MODEL_PATH.is_file():
            mal_idx = [i for i, p in enumerate(predictions) if p == 'Malware']
            if mal_idx:
                X_mal = X[mal_idx]
                cat_b = joblib.load(CATEGORY_MODEL_PATH)
                for c in cat_b['label_encoder'].inverse_transform(cat_b['model'].predict(X_mal)):
                    categories[c] = categories.get(c, 0) + 1
                fam_b = joblib.load(FAMILY_MODEL_PATH)
                for f in fam_b['label_encoder'].inverse_transform(fam_b['model'].predict(X_mal)):
                    families[f] = families.get(f, 0) + 1
    except Exception as exc:
        current_app.logger.warning('Batch family classification failed: %s', exc)

    top_category = max(categories, key=categories.get) if categories else None
    top_family   = max(families,   key=families.get)   if families   else None

    return {
        'model_id':        model_row.model_id,
        'prediction':      'Malware' if n_malware > 0 else 'Benign',
        'confidence':      float(np.mean(confidences)),
        'malware_category': top_category,
        'malware_family':   top_family,
        'batch_summary': {
            'batch_mode':    True,
            'total':         len(predictions),
            'benign_count':  n_benign,
            'malware_count': n_malware,
            'malware_pct':   round(n_malware / len(predictions) * 100, 1) if predictions else 0.0,
            'categories':    categories,
            'families':      dict(sorted(families.items(), key=lambda x: -x[1])[:10]),
            'avg_confidence': round(float(np.mean(confidences)), 4),
        },
    }


# ── Analysis worker ───────────────────────────────────────────────────────────

def _analysis_worker(app, dump_id: str, file_path: str):
    """Run extraction + classification in a daemon thread."""
    import concurrent.futures as _cf
    import multiprocessing as _mp

    with app.app_context():
        dump = db.session.get(MemoryDump, dump_id)
        if dump is None:
            return

        try:
            dump.status = 'processing'
            db.session.commit()

            from modules.feature_mapper import map_to_feature_vector

            suffix = Path(file_path).suffix.lower()

            # ── CSV batch mode ────────────────────────────────────────────────
            if suffix == '.csv':
                current_app.logger.info(
                    'CSV batch mode for dump %s — classifying rows directly.', dump_id
                )
                batch = _classify_csv_batch(file_path)

                feat = AnalysisFeatures(
                    dump_id      = dump_id,
                    process_count = None,
                    dll_count     = None,
                    feature_data  = {'batch_mode': True,
                                     'batch_summary': batch['batch_summary']},
                )
                db.session.add(feat)

                result = AnalysisResult(
                    dump_id             = dump_id,
                    model_id            = batch['model_id'],
                    prediction          = batch['prediction'],
                    confidence          = batch['confidence'],
                    malware_category    = batch['malware_category'],
                    category_confidence = None,
                    malware_family      = batch['malware_family'],
                    family_confidence   = None,
                )
                db.session.add(result)
                dump.status = 'complete'
                db.session.commit()

            # ── Memory dump mode (two-phase) ──────────────────────────────────
            else:
                from modules.feature_extractor import (
                    SymbolsUnavailableError, extract_fast_features, extract_features,
                )

                # ── Helper: run extraction in a child process (killable) ───────
                def _run_in_process(fn, timeout_sec):
                    """
                    Run fn() in a child process and return its result.

                    Uses a temp file for IPC instead of multiprocessing.Queue or
                    Pipe.  Queue has a feeder-thread race (the OS pipe buffer is
                    64 KB; for multi-MB feature dicts the feeder may still be
                    writing when the parent polls the queue).  Pipe has a deadlock
                    when the parent is in p.join() instead of draining.  A temp
                    file has neither problem: the child writes the full pickle to
                    disk atomically, the parent reads it after the process exits.
                    """
                    import pickle  as _pickle
                    import tempfile as _tempfile
                    import time    as _time
                    import os      as _os

                    fd, result_path = _tempfile.mkstemp(suffix='.pkl', prefix='vol_result_')
                    _os.close(fd)

                    def _worker():
                        try:
                            payload = ('ok', fn())
                        except SymbolsUnavailableError as exc:
                            payload = ('sym_err', {
                                'message':  str(exc),
                                'pdb_name': exc.pdb_name,
                                'guid':     exc.guid,
                            })
                        except BaseException as exc:
                            import traceback as _tb
                            payload = ('err', f'{type(exc).__name__}: {exc}\n{_tb.format_exc()}')
                        with open(result_path, 'wb') as fh:
                            _pickle.dump(payload, fh)

                    p = _mp.Process(target=_worker)
                    p.start()

                    deadline  = _time.monotonic() + timeout_sec
                    timed_out = False

                    while _time.monotonic() < deadline:
                        _time.sleep(1.0)
                        if not p.is_alive():
                            break
                    else:
                        timed_out = True

                    p.join(timeout=10)
                    if p.is_alive():
                        p.kill()
                        p.join()

                    current_app.logger.info(
                        'Child process finished (exitcode=%s, timed_out=%s) for dump %s',
                        p.exitcode, timed_out, dump_id,
                    )

                    result = None
                    try:
                        if _os.path.getsize(result_path) > 0:
                            with open(result_path, 'rb') as fh:
                                result = _pickle.load(fh)
                    except Exception as load_exc:
                        current_app.logger.error(
                            'Could not read result file for dump %s: %s', dump_id, load_exc,
                        )
                    finally:
                        try:
                            _os.unlink(result_path)
                        except Exception:
                            pass

                    if result is None:
                        if timed_out:
                            raise TimeoutError(
                                f'Extraction exceeded {timeout_sec // 60} minutes — '
                                'dump may be too large or corrupted.'
                            )
                        raise TimeoutError('Extraction subprocess produced no result.')

                    return result

                # ── Helper: handle a sym_err result ───────────────────────────
                def _handle_sym_err(detail: dict) -> None:
                    """Persist a no_symbols outcome and return; do not raise."""
                    current_app.logger.error(
                        'Missing symbols for dump %s — PDB: %s  GUID: %s',
                        dump_id, detail.get('pdb_name', ''), detail.get('guid', ''),
                    )
                    feat = AnalysisFeatures(
                        dump_id       = dump_id,
                        process_count = None,
                        dll_count     = None,
                        feature_data  = {
                            'no_symbols': True,
                            'pdb_name':   detail.get('pdb_name', ''),
                            'guid':       detail.get('guid', ''),
                            'message':    detail.get('message', ''),
                        },
                    )
                    db.session.add(feat)
                    dump.status = 'no_symbols'
                    db.session.commit()
                    try:
                        Path(file_path).unlink(missing_ok=True)
                    except Exception:
                        pass

                # Phase 1 — fast plugins only (PsList, PsScan, DllList, VadInfo, Handles)
                status_fast, payload_fast = _run_in_process(
                    lambda: extract_fast_features(file_path),
                    _FAST_TIMEOUT_SECONDS,
                )

                if status_fast == 'sym_err':
                    _handle_sym_err(payload_fast)
                    return
                if status_fast == 'err':
                    raise RuntimeError(payload_fast)
                extracted_fast = payload_fast

                vec_fast  = map_to_feature_vector(extracted_fast)
                model_row = _latest_model()

                if not (model_row and model_row.model_path
                        and Path(model_row.model_path).is_file()):
                    # No model — persist what we have and bail gracefully.
                    feat = AnalysisFeatures(
                        dump_id       = dump_id,
                        process_count = extracted_fast['summary']['process_count'],
                        dll_count     = extracted_fast['summary']['dll_count'],
                        feature_data  = extracted_fast,
                    )
                    db.session.add(feat)
                    dump.status = 'complete'
                    db.session.commit()
                else:
                    clf            = joblib.load(model_row.model_path)
                    label_fast     = clf.predict(vec_fast)[0]
                    proba_fast     = clf.predict_proba(vec_fast)[0]
                    pred_fast      = 'Malware' if int(label_fast) == 1 else 'Benign'
                    conf_fast      = float(max(proba_fast))

                    if pred_fast == 'Benign' and conf_fast >= _BENIGN_THRESHOLD:
                        # ── Benign shortcut: skip Malfind and SvcScan ─────────
                        current_app.logger.info(
                            'Benign early-exit for dump %s (conf %.2f) — '
                            'skipping Malfind/SvcScan.', dump_id, conf_fast
                        )
                        extracted  = extracted_fast
                        prediction = pred_fast
                        confidence = conf_fast
                    else:
                        # ── Potentially malicious: run full extraction ─────────
                        current_app.logger.info(
                            'Dump %s classified as %s (conf %.2f) at fast phase — '
                            'running Malfind/SvcScan.', dump_id, pred_fast, conf_fast
                        )
                        status_full, payload_full = _run_in_process(
                            lambda: extract_features(file_path),
                            _ANALYSIS_TIMEOUT_SECONDS,
                        )

                        if status_full == 'sym_err':
                            _handle_sym_err(payload_full)
                            return
                        if status_full == 'err':
                            raise RuntimeError(payload_full)
                        extracted = payload_full

                        vec        = map_to_feature_vector(extracted)
                        label      = clf.predict(vec)[0]
                        proba      = clf.predict_proba(vec)[0]
                        prediction = 'Malware' if int(label) == 1 else 'Benign'
                        confidence = float(max(proba))

                    feat = AnalysisFeatures(
                        dump_id       = dump_id,
                        process_count = extracted['summary']['process_count'],
                        dll_count     = extracted['summary']['dll_count'],
                        feature_data  = extracted,
                    )
                    db.session.add(feat)

                    # Stage 2 — family classification (malicious dumps only)
                    malware_category    = None
                    category_confidence = None
                    malware_family      = None
                    family_confidence   = None

                    if prediction == 'Malware':
                        try:
                            from modules.family_classifier import predict_family
                            vec_for_family = map_to_feature_vector(extracted)
                            family_result  = predict_family(vec_for_family)
                            if family_result:
                                malware_category    = family_result['category']
                                category_confidence = family_result['category_confidence']
                                malware_family      = family_result['family']
                                family_confidence   = family_result['family_confidence']
                        except Exception as exc:
                            current_app.logger.warning(
                                'Family classification failed for dump %s: %s', dump_id, exc
                            )

                    result = AnalysisResult(
                        dump_id             = dump_id,
                        model_id            = model_row.model_id,
                        prediction          = prediction,
                        confidence          = confidence,
                        malware_category    = malware_category,
                        category_confidence = category_confidence,
                        malware_family      = malware_family,
                        family_confidence   = family_confidence,
                    )
                    db.session.add(result)
                    dump.status = 'complete'
                    db.session.commit()

            # Delete raw file — features are in the DB now
            try:
                Path(file_path).unlink(missing_ok=True)
                current_app.logger.info('Deleted dump file after analysis: %s', file_path)
            except Exception as del_exc:
                current_app.logger.warning(
                    'Could not delete dump file %s: %s', file_path, del_exc
                )

        except Exception as exc:
            db.session.rollback()
            current_app.logger.error('Analysis failed for dump %s: %s', dump_id, exc)
            try:
                dump.status = 'failed'
                db.session.commit()
                try:
                    Path(file_path).unlink(missing_ok=True)
                except Exception:
                    pass
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
#  GET /config  — upload constraints for the frontend
# ══════════════════════════════════════════════════════════════════════════════

@analysis_bp.get('/config')
@require_role(ADMIN, ANALYST)
def upload_config():
    return jsonify({
        'allowed_extensions': sorted(_ALLOWED_EXTENSIONS),
        'max_upload_bytes':   _MAX_UPLOAD_BYTES,
        'max_upload_gb':      round(_MAX_UPLOAD_BYTES / (1024 ** 3), 1),
    }), 200


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
    try:
        with open(dest, 'wb') as fh:
            for chunk in iter(lambda: file.stream.read(1 << 20), b''):
                written += len(chunk)
                if written > _MAX_UPLOAD_BYTES:
                    fh.close()
                    dest.unlink(missing_ok=True)
                    return _error('File exceeds the 8 GB upload limit.', 413)
                fh.write(chunk)
    except OSError as exc:
        dest.unlink(missing_ok=True)
        if exc.errno == 28:   # ENOSPC — no space left on device
            return _error(
                'Server storage is full. Please contact an administrator to free space.',
                507,
            )
        raise

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
    dump_feature_values = []
    is_batch = False
    batch_summary = None

    # ── Feature data / error details ────────────────────────────────────────
    no_symbols_detail = None

    if dump.features and dump.features.feature_data:
        fd = dump.features.feature_data

        if fd.get('no_symbols'):
            # Symbol-error outcome stored by _handle_sym_err
            no_symbols_detail = {
                'pdb_name':    fd.get('pdb_name', ''),
                'guid':        fd.get('guid', ''),
                'message':     fd.get('message', ''),
                'retry_after': 30,
            }
        elif fd.get('batch_mode'):
            is_batch      = True
            batch_summary = fd.get('batch_summary')
        else:
            behav     = fd.get('behavioral_indicators', {})
            artifacts = behav.get('injection_evidence', [])
            try:
                from modules.feature_mapper import map_to_feature_vector, FEATURE_NAMES
                vec = map_to_feature_vector(fd)[0]
                dump_feature_values = [
                    {'feature': name, 'value': float(val)}
                    for name, val in zip(FEATURE_NAMES, vec)
                ]
            except Exception:
                pass

    feature_importance = None
    if result:
        model_row = db.session.get(MlModel, result.model_id)
        if model_row:
            feature_importance = model_row.feature_importance

    # For malicious individual dumps, recompute full family rankings on the fly
    # so the UI can show all candidate families, not just the stored top-1.
    category_rankings = None
    family_rankings   = None
    if result and result.prediction == 'Malware' and not is_batch and dump_feature_values:
        try:
            import numpy as np
            from modules.feature_mapper import FEATURE_NAMES
            from modules.family_classifier import predict_family
            vec = np.array(
                [f['value'] for f in dump_feature_values], dtype=np.float64
            ).reshape(1, -1)
            fr = predict_family(vec, top_n=_FAMILY_TOP_N)
            if fr:
                category_rankings = fr.get('category_rankings')
                family_rankings   = fr.get('family_rankings')
        except Exception:
            pass

    payload = {
        'dump_id':              dump_id,
        'file_name':            dump.file_name,
        'status':               dump.status,
        'dump':                 dump.to_dict(),
        'error_type':           'no_symbols' if dump.status == 'no_symbols' else None,
        'no_symbols_detail':    no_symbols_detail,
        'is_batch':             is_batch,
        'batch_summary':        batch_summary,
        'prediction':           None,
        'confidence':           None,
        'classification_date':  None,
        'malware_category':     None,
        'category_confidence':  None,
        'malware_family':       None,
        'family_confidence':    None,
        'category_rankings':    category_rankings,
        'family_rankings':      family_rankings,
        'suspicious_artifacts': artifacts,
        'feature_importance':   feature_importance,
        'dump_feature_values':  dump_feature_values,
    }

    if result:
        payload['prediction']           = result.prediction
        payload['confidence']           = result.confidence
        payload['classification_date']  = result.classification_date.isoformat()
        payload['malware_category']     = result.malware_category
        payload['category_confidence']  = result.category_confidence
        payload['malware_family']       = result.malware_family
        payload['family_confidence']    = result.family_confidence

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

    # Detection rate: count only unique filenames to avoid test-upload skew.
    # Multiple uploads of the same file (retries, dev testing) are deduplicated
    # by taking the latest result per unique file_name.
    from sqlalchemy import func as _func
    latest_per_file = (
        db.session.query(
            _func.max(AnalysisResult.classification_date).label('latest'),
            MemoryDump.file_name,
        )
        .join(MemoryDump, MemoryDump.dump_id == AnalysisResult.dump_id)
        .group_by(MemoryDump.file_name)
        .subquery()
    )
    unique_results = (
        db.session.query(AnalysisResult.prediction)
        .join(MemoryDump, MemoryDump.dump_id == AnalysisResult.dump_id)
        .join(latest_per_file, (latest_per_file.c.file_name == MemoryDump.file_name) &
              (latest_per_file.c.latest == AnalysisResult.classification_date))
        .all()
    )
    total_results  = len(unique_results)
    malware_total  = sum(1 for r in unique_results if r.prediction == 'Malware')
    detection_rate = (malware_total / total_results) if total_results else 0.0

    last_model = _latest_model()

    upload_dir = Path(current_app.config['UPLOAD_FOLDER'])
    disk_bytes = sum(f.stat().st_size for f in upload_dir.rglob('*') if f.is_file()) \
        if upload_dir.exists() else 0

    # Average real-world confidence across all completed analyses
    from sqlalchemy import func as _func2
    avg_conf_row = db.session.query(
        _func2.avg(AnalysisResult.confidence),
        _func2.count(AnalysisResult.confidence),
    ).first()
    avg_confidence   = float(avg_conf_row[0]) if avg_conf_row[0] is not None else None
    confidence_count = int(avg_conf_row[1]) if avg_conf_row[1] else 0

    return jsonify({
        'total_analyses':    total,
        'malware_today':     malware_today,
        'detection_rate':    round(detection_rate, 4),
        'disk_usage_mb':     round(disk_bytes / (1024 * 1024), 1),
        'last_model_date':   last_model.training_date.isoformat() if last_model else None,
        'avg_confidence':    round(avg_confidence, 4) if avg_confidence is not None else None,
        'confidence_count':  confidence_count,
    }), 200


# ══════════════════════════════════════════════════════════════════════════════
#  GET /drift  — confidence drift detection
# ══════════════════════════════════════════════════════════════════════════════

@analysis_bp.get('/drift')
@require_role(ADMIN)
def confidence_drift():
    """
    Compare the confidence distribution of recent predictions against the
    historical baseline using a two-sample KS-test.

    Returns a drift_detected flag plus the statistics so the dashboard can
    show trend information.
    """
    try:
        from scipy import stats as _stats
    except ImportError:
        return _error('scipy is not installed; drift detection unavailable.', 503)

    rows = (
        AnalysisResult.query
        .order_by(AnalysisResult.classification_date.asc())
        .with_entities(AnalysisResult.confidence, AnalysisResult.classification_date)
        .all()
    )

    scores = [r.confidence for r in rows]
    n      = len(scores)

    if n < _DRIFT_WINDOW * 2:
        return jsonify({
            'status':        'insufficient_data',
            'total':         n,
            'min_required':  _DRIFT_WINDOW * 2,
            'drift_detected': False,
        }), 200

    baseline = scores[:_DRIFT_WINDOW]
    recent   = scores[-_DRIFT_WINDOW:]

    ks_stat, p_value = _stats.ks_2samp(baseline, recent)
    drift_detected   = bool(p_value < _DRIFT_P_VALUE)

    return jsonify({
        'status':          'ok',
        'drift_detected':  drift_detected,
        'ks_statistic':    round(float(ks_stat),  4),
        'p_value':         round(float(p_value),  4),
        'baseline_mean':   round(sum(baseline) / len(baseline), 4),
        'recent_mean':     round(sum(recent)   / len(recent),   4),
        'baseline_n':      len(baseline),
        'recent_n':        len(recent),
        'total':           n,
        'window':          _DRIFT_WINDOW,
        'threshold':       _DRIFT_P_VALUE,
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

    page         = request.args.get('page', 1, type=int)
    per_page     = request.args.get('per_page', 50, type=int)
    user_filter  = request.args.get('user_id')
    action_filter = request.args.get('action')

    query = AuditLog.query
    if user_filter:
        query = query.filter_by(user_id=user_filter)
    if action_filter:
        query = query.filter_by(action=action_filter)

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
#  DELETE /dumps/<dump_id>  — permanently delete a dump (admin only)
# ══════════════════════════════════════════════════════════════════════════════

@analysis_bp.delete('/dumps/<dump_id>')
@require_role(ADMIN)
def delete_dump(dump_id: str):
    """
    Permanently delete a dump and all associated DB records.
    FK cascades handle features and results automatically.
    """
    dump = db.session.get(MemoryDump, dump_id)
    if dump is None:
        return _error('Dump not found.', 404)

    if dump.status == 'processing':
        return _error('Cannot delete a dump that is currently being analysed.', 409)

    file_name = dump.file_name
    try:
        Path(dump.file_path).unlink(missing_ok=True)
    except Exception as exc:
        current_app.logger.warning('Could not delete file for dump %s: %s', dump_id, exc)

    _audit('delete_dump', 'dump', dump_id, {'file_name': file_name})
    db.session.delete(dump)
    db.session.commit()

    return jsonify({'message': f'Dump {dump_id} deleted.'}), 200


# ══════════════════════════════════════════════════════════════════════════════
#  POST /cleanup  — delete all dump files from disk (admin only)
# ══════════════════════════════════════════════════════════════════════════════

@analysis_bp.post('/cleanup')
@require_role(ADMIN)
def cleanup_uploads():
    """
    Delete every dump file that still exists on disk.
    DB records (metadata, features, results) are kept.
    Returns counts of files deleted and bytes freed.
    """
    dumps      = MemoryDump.query.all()
    deleted    = 0
    freed      = 0
    not_found  = 0
    errors     = []

    for dump in dumps:
        path = Path(dump.file_path)
        if not path.exists():
            not_found += 1
            continue
        try:
            size = path.stat().st_size
            path.unlink()
            deleted += 1
            freed   += size
        except Exception as exc:
            errors.append(str(exc))

    _audit('cleanup_uploads', details={
        'deleted': deleted, 'freed_bytes': freed, 'errors': len(errors),
    })
    db.session.commit()

    return jsonify({
        'deleted':    deleted,
        'not_found':  not_found,
        'freed_mb':   round(freed / (1024 * 1024), 1),
        'errors':     errors[:10],
    }), 200


# ══════════════════════════════════════════════════════════════════════════════
#  Additional Dataset management
# ══════════════════════════════════════════════════════════════════════════════

from ..models.analysis import AdditionalDataset as _AdditionalDataset

_DATASETS_DIR = Path(__file__).resolve().parent.parent.parent / 'datasets' / 'additional'


def _validate_and_compare(csv_path: Path) -> dict:
    """
    Validate an uploaded CSV against the CICMalMem-2022 schema and compare
    feature distributions using a KS-test.

    Returns a report dict with keys:
      errors, warnings, class_distribution, overlap, feature_comparison
    """
    import pandas as pd
    from scipy import stats as _stats
    from modules.classifier import DATASET_PATH, load_data

    report = {'errors': [], 'warnings': [], 'class_distribution': {},
              'overlap': {}, 'feature_comparison': {}}

    try:
        df_new = pd.read_csv(csv_path)
    except Exception as exc:
        report['errors'].append(f'Cannot read CSV: {exc}')
        return report

    # ── Schema checks ─────────────────────────────────────────────────────────
    if 'Class' not in df_new.columns:
        report['errors'].append("Missing required column: 'Class'")
        return report

    X_base, _, feature_names = load_data(DATASET_PATH)
    missing = [c for c in feature_names if c not in df_new.columns]
    if missing:
        report['errors'].append(
            f"{len(missing)} required feature column(s) missing: {missing[:5]}{'…' if len(missing)>5 else ''}"
        )
        return report

    invalid_labels = df_new[~df_new['Class'].isin(['Benign', 'Malware'])]['Class'].unique().tolist()
    if invalid_labels:
        report['errors'].append(f"Invalid Class values: {invalid_labels[:5]}")
        return report

    # ── Quality warnings ──────────────────────────────────────────────────────
    n_rows = len(df_new)
    if n_rows < 100:
        report['warnings'].append(f"Only {n_rows} samples — too small to be meaningful (recommend ≥ 100).")

    null_counts = df_new[feature_names].isnull().sum()
    cols_with_nulls = null_counts[null_counts > 0]
    if not cols_with_nulls.empty:
        report['warnings'].append(
            f"{len(cols_with_nulls)} feature column(s) have null values."
        )

    n_benign  = int((df_new['Class'] == 'Benign').sum())
    n_malware = int((df_new['Class'] == 'Malware').sum())
    majority_pct = max(n_benign, n_malware) / n_rows * 100 if n_rows else 0
    if majority_pct > 90:
        report['warnings'].append(
            f"Severe class imbalance: {majority_pct:.1f}% majority class."
        )

    report['class_distribution'] = {
        'total':        n_rows,
        'benign':       n_benign,
        'malware':      n_malware,
        'benign_pct':   round(n_benign  / n_rows * 100, 1) if n_rows else 0,
        'malware_pct':  round(n_malware / n_rows * 100, 1) if n_rows else 0,
    }

    # ── Duplicate / overlap detection ─────────────────────────────────────────
    df_base = pd.read_csv(DATASET_PATH)
    df_base_feats = df_base[feature_names].dropna()
    df_new_feats  = df_new[feature_names].dropna()

    merged    = pd.merge(df_new_feats, df_base_feats, how='inner')
    n_overlap = len(merged)
    report['overlap'] = {
        'exact_duplicates': n_overlap,
        'duplicate_pct':    round(n_overlap / n_rows * 100, 1) if n_rows else 0,
    }
    if n_overlap > 0:
        report['warnings'].append(
            f"{n_overlap} row(s) ({report['overlap']['duplicate_pct']}%) are exact duplicates of CICMalMem rows and will be deduplicated at merge time."
        )

    # ── Feature distribution comparison (KS-test) ─────────────────────────────
    drifted = []
    stable  = []
    for feat in feature_names:
        base_col = df_base_feats[feat].values
        new_col  = df_new_feats[feat].values if feat in df_new_feats.columns else None
        if new_col is None or len(new_col) == 0:
            continue
        ks, p = _stats.ks_2samp(base_col, new_col)
        entry = {'feature': feat, 'ks_stat': round(float(ks), 4), 'p_value': round(float(p), 4)}
        (drifted if p < 0.05 else stable).append(entry)

    n_total   = len(drifted) + len(stable)
    sim_score = round(len(stable) / n_total, 3) if n_total else 1.0
    report['feature_comparison'] = {
        'total_features':       n_total,
        'similar_features':     len(stable),
        'drifted_features':     len(drifted),
        'similarity_score':     sim_score,
        'top_drifted':          sorted(drifted, key=lambda x: x['ks_stat'], reverse=True)[:10],
    }
    if len(drifted) > n_total * 0.5:
        report['warnings'].append(
            f"{len(drifted)}/{n_total} features differ significantly from CICMalMem — "
            "this dataset may represent novel threat patterns (good) or a different collection methodology (verify)."
        )

    return report


@analysis_bp.post('/datasets/upload')
@require_role(ADMIN)
def upload_dataset():
    """Upload a new CSV dataset for admin review before retraining."""
    if 'file' not in request.files:
        return _error('No file uploaded.')
    f = request.files['file']
    if not f.filename.endswith('.csv'):
        return _error('Only CSV files are accepted.')

    _DATASETS_DIR.mkdir(parents=True, exist_ok=True)
    import uuid as _uuid
    safe_name = f"{_uuid.uuid4().hex}_{Path(f.filename).name}"
    dest      = _DATASETS_DIR / safe_name
    f.save(str(dest))

    try:
        report = _validate_and_compare(dest)
    except Exception as exc:
        dest.unlink(missing_ok=True)
        return _error(f'Validation failed: {exc}', 500)

    if report['errors']:
        dest.unlink(missing_ok=True)
        return jsonify({'valid': False, 'errors': report['errors']}), 422

    cd  = report['class_distribution']
    ds  = _AdditionalDataset(
        file_name         = f.filename,
        file_path         = str(dest),
        uploaded_by       = get_jwt_identity(),
        sample_count      = cd.get('total'),
        benign_count      = cd.get('benign'),
        malware_count     = cd.get('malware'),
        comparison_report = report,
    )
    db.session.add(ds)
    _audit('upload_dataset', 'additional_dataset', ds.dataset_id,
           {'file_name': f.filename, 'samples': cd.get('total')})
    db.session.commit()

    return jsonify({'dataset': ds.to_dict(), 'valid': True}), 201


@analysis_bp.get('/datasets')
@require_role(ADMIN)
def list_datasets():
    datasets = _AdditionalDataset.query.order_by(_AdditionalDataset.uploaded_at.desc()).all()
    return jsonify({'datasets': [d.to_dict() for d in datasets]}), 200


@analysis_bp.post('/datasets/<dataset_id>/approve')
@require_role(ADMIN)
def approve_dataset(dataset_id):
    ds = db.session.get(_AdditionalDataset, dataset_id)
    if not ds:
        return _error('Dataset not found.', 404)
    ds.status    = 'approved'
    ds.is_active = True
    _audit('approve_dataset', 'additional_dataset', dataset_id)
    db.session.commit()
    return jsonify({'dataset': ds.to_dict()}), 200


@analysis_bp.post('/datasets/<dataset_id>/reject')
@require_role(ADMIN)
def reject_dataset(dataset_id):
    ds = db.session.get(_AdditionalDataset, dataset_id)
    if not ds:
        return _error('Dataset not found.', 404)
    ds.status    = 'rejected'
    ds.is_active = False
    _audit('reject_dataset', 'additional_dataset', dataset_id)
    db.session.commit()
    return jsonify({'dataset': ds.to_dict()}), 200


@analysis_bp.post('/datasets/<dataset_id>/toggle')
@require_role(ADMIN)
def toggle_dataset(dataset_id):
    ds = db.session.get(_AdditionalDataset, dataset_id)
    if not ds:
        return _error('Dataset not found.', 404)
    if ds.status != 'approved':
        return _error('Only approved datasets can be toggled.')
    ds.is_active = not ds.is_active
    _audit('toggle_dataset', 'additional_dataset', dataset_id, {'is_active': ds.is_active})
    db.session.commit()
    return jsonify({'dataset': ds.to_dict()}), 200


@analysis_bp.delete('/datasets/<dataset_id>')
@require_role(ADMIN)
def delete_dataset(dataset_id):
    ds = db.session.get(_AdditionalDataset, dataset_id)
    if not ds:
        return _error('Dataset not found.', 404)
    try:
        Path(ds.file_path).unlink(missing_ok=True)
    except Exception:
        pass
    _audit('delete_dataset', 'additional_dataset', dataset_id, {'file_name': ds.file_name})
    db.session.delete(ds)
    db.session.commit()
    return jsonify({'message': 'Dataset deleted.'}), 200
