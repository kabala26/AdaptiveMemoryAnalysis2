"""
Tests for backend/routes/analysis.py (Flask REST API)

Uses Flask's test client with an in-memory SQLite database.
JWT tokens are minted directly so no real auth server is needed.
"""

import io
import json
import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from flask_jwt_extended import create_access_token

# ── App factory ───────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def app(tmp_path_factory):
    """Create a test Flask app with SQLite in-memory and a temp upload folder."""
    import os
    upload_dir = tmp_path_factory.mktemp("uploads")

    os.environ.setdefault("SECRET_KEY",           "test-secret")
    os.environ.setdefault("DATABASE_URL",          "sqlite:///:memory:")
    os.environ.setdefault("JWT_SECRET_KEY",        "test-jwt-secret-key-at-least-32-chars!!")
    os.environ.setdefault("JWT_ACCESS_EXPIRES_SECONDS",  "900")
    os.environ.setdefault("JWT_REFRESH_EXPIRES_SECONDS", "604800")
    os.environ.setdefault("GOOGLE_CLIENT_ID",      "g-id")
    os.environ.setdefault("GOOGLE_CLIENT_SECRET",  "g-secret")
    os.environ.setdefault("GITHUB_CLIENT_ID",      "gh-id")
    os.environ.setdefault("GITHUB_CLIENT_SECRET",  "gh-secret")
    os.environ.setdefault("FRONTEND_URL",          "http://localhost:3000")
    os.environ.setdefault("BACKEND_URL",           "http://localhost:5000")
    os.environ["UPLOAD_FOLDER"] = str(upload_dir)

    from backend import create_app
    application = create_app()
    application.config["TESTING"] = True

    with application.app_context():
        from backend import db
        db.create_all()

    yield application


@pytest.fixture(scope="module")
def client(app):
    return app.test_client()


# ── JWT helpers ───────────────────────────────────────────────────────────────

def _token(app, role: str, user_id: str | None = None) -> str:
    uid = user_id or str(uuid.uuid4())
    with app.app_context():
        return create_access_token(identity=uid, additional_claims={"role": role})


def _auth(app, role: str, user_id: str | None = None) -> dict:
    return {"Authorization": f"Bearer {_token(app, role, user_id)}"}


# ── Seed helpers ──────────────────────────────────────────────────────────────

def _seed_dump(app, user_id: str, status: str = "pending") -> str:
    """Insert a MemoryDump row and return its dump_id."""
    from backend import db
    from backend.models.analysis import MemoryDump
    dump_id = str(uuid.uuid4())
    with app.app_context():
        dump = MemoryDump(
            dump_id   = dump_id,
            user_id   = user_id,
            file_path = f"/tmp/{dump_id}.raw",
            file_name = "sample.raw",
            file_size = 1024,
            status    = status,
        )
        db.session.add(dump)
        db.session.commit()
    return dump_id


def _seed_result(app, dump_id: str, user_id: str) -> None:
    """Insert a minimal MlModel + AnalysisResult for a dump."""
    from backend import db
    from backend.models.analysis import AnalysisResult, MlModel
    model_id = str(uuid.uuid4())
    with app.app_context():
        ml = MlModel(
            model_id   = model_id,
            model_name = "TestRF",
            algorithm  = "RandomForestClassifier",
            accuracy   = 0.99,
            model_path = "/tmp/fake.joblib",
        )
        db.session.add(ml)
        db.session.flush()
        res = AnalysisResult(
            dump_id    = dump_id,
            model_id   = model_id,
            prediction = "Benign",
            confidence = 0.95,
        )
        db.session.add(res)
        db.session.commit()


# ══════════════════════════════════════════════════════════════════════════════
# POST /api/analysis/upload
# ══════════════════════════════════════════════════════════════════════════════

class TestUpload:
    def _post(self, client, headers, filename="sample.raw", data=b"FAKE"):
        return client.post(
            "/api/analysis/upload",
            headers=headers,
            data={"file": (io.BytesIO(data), filename)},
            content_type="multipart/form-data",
        )

    def test_requires_auth(self, client):
        rv = self._post(client, {})
        assert rv.status_code == 401

    def test_analyst_can_upload(self, app, client):
        uid = str(uuid.uuid4())
        rv  = self._post(client, _auth(app, "forensic_analyst", uid))
        assert rv.status_code == 201

    def test_admin_can_upload(self, app, client):
        rv = self._post(client, _auth(app, "admin"))
        assert rv.status_code == 201

    def test_response_has_dump_id(self, app, client):
        rv = self._post(client, _auth(app, "forensic_analyst"))
        body = rv.get_json()
        assert "dump_id" in body

    def test_response_has_hash(self, app, client):
        rv = self._post(client, _auth(app, "forensic_analyst"))
        body = rv.get_json()
        assert "hash" in body
        assert len(body["hash"]) == 64   # SHA-256 hex

    def test_response_status_pending(self, app, client):
        rv = self._post(client, _auth(app, "forensic_analyst"))
        body = rv.get_json()
        assert body["status"] == "pending"

    def test_no_file_field_returns_400(self, app, client):
        rv = client.post(
            "/api/analysis/upload",
            headers=_auth(app, "forensic_analyst"),
            data={},
            content_type="multipart/form-data",
        )
        assert rv.status_code == 400

    def test_unsupported_extension_returns_415(self, app, client):
        rv = self._post(client, _auth(app, "forensic_analyst"), filename="dump.exe")
        assert rv.status_code == 415

    def test_mem_extension_accepted(self, app, client):
        rv = self._post(client, _auth(app, "forensic_analyst"), filename="dump.mem")
        assert rv.status_code == 201

    def test_vmem_extension_accepted(self, app, client):
        rv = self._post(client, _auth(app, "forensic_analyst"), filename="dump.vmem")
        assert rv.status_code == 201

    def test_dmp_extension_accepted(self, app, client):
        rv = self._post(client, _auth(app, "forensic_analyst"), filename="dump.dmp")
        assert rv.status_code == 201

    def test_dump_stored_in_db(self, app, client):
        from backend import db
        from backend.models.analysis import MemoryDump
        rv   = self._post(client, _auth(app, "forensic_analyst"))
        body = rv.get_json()
        from backend import db
        with app.app_context():
            dump = db.session.get(MemoryDump, body["dump_id"])
            assert dump is not None
            assert dump.file_name == "sample.raw"

    def test_file_written_to_disk(self, app, client):
        rv   = self._post(client, _auth(app, "forensic_analyst"), data=b"MEMDATA")
        body = rv.get_json()
        from backend.models.analysis import MemoryDump
        from backend import db
        with app.app_context():
            dump = db.session.get(MemoryDump, body["dump_id"])
            assert Path(dump.file_path).is_file()


# ══════════════════════════════════════════════════════════════════════════════
# POST /api/analysis/analyze
# ══════════════════════════════════════════════════════════════════════════════

class TestAnalyze:
    def _post(self, client, headers, dump_id: str):
        return client.post(
            "/api/analysis/analyze",
            headers={**headers, "Content-Type": "application/json"},
            data=json.dumps({"dump_id": dump_id}),
        )

    def test_requires_auth(self, client):
        rv = self._post(client, {}, "some-id")
        assert rv.status_code == 401

    def test_missing_dump_id_returns_400(self, app, client):
        rv = client.post(
            "/api/analysis/analyze",
            headers={**_auth(app, "forensic_analyst"), "Content-Type": "application/json"},
            data=json.dumps({}),
        )
        assert rv.status_code == 400

    def test_nonexistent_dump_returns_404(self, app, client):
        rv = self._post(client, _auth(app, "forensic_analyst"), str(uuid.uuid4()))
        assert rv.status_code == 404

    def test_analyst_can_analyze_own_dump(self, app, client):
        uid     = str(uuid.uuid4())
        dump_id = _seed_dump(app, uid)
        rv      = self._post(client, _auth(app, "forensic_analyst", uid), dump_id)
        assert rv.status_code == 202

    def test_analyst_cannot_analyze_others_dump(self, app, client):
        owner   = str(uuid.uuid4())
        other   = str(uuid.uuid4())
        dump_id = _seed_dump(app, owner)
        rv      = self._post(client, _auth(app, "forensic_analyst", other), dump_id)
        assert rv.status_code == 403

    def test_admin_can_analyze_any_dump(self, app, client):
        uid     = str(uuid.uuid4())
        dump_id = _seed_dump(app, uid)
        rv      = self._post(client, _auth(app, "admin"), dump_id)
        assert rv.status_code == 202

    def test_response_contains_status_processing(self, app, client):
        uid     = str(uuid.uuid4())
        dump_id = _seed_dump(app, uid)
        rv      = self._post(client, _auth(app, "forensic_analyst", uid), dump_id)
        body    = rv.get_json()
        assert body.get("status") == "processing"

    def test_already_processing_returns_409(self, app, client):
        uid     = str(uuid.uuid4())
        dump_id = _seed_dump(app, uid, status="processing")
        rv      = self._post(client, _auth(app, "forensic_analyst", uid), dump_id)
        assert rv.status_code == 409


# ══════════════════════════════════════════════════════════════════════════════
# GET /api/analysis/results/<dump_id>
# ══════════════════════════════════════════════════════════════════════════════

class TestGetResults:
    def _get(self, client, headers, dump_id: str):
        return client.get(f"/api/analysis/results/{dump_id}", headers=headers)

    def test_requires_auth(self, client):
        rv = self._get(client, {}, str(uuid.uuid4()))
        assert rv.status_code == 401

    def test_nonexistent_dump_returns_404(self, app, client):
        rv = self._get(client, _auth(app, "forensic_analyst"), str(uuid.uuid4()))
        assert rv.status_code == 404

    def test_analyst_can_view_own_results(self, app, client):
        uid     = str(uuid.uuid4())
        dump_id = _seed_dump(app, uid, "complete")
        rv      = self._get(client, _auth(app, "forensic_analyst", uid), dump_id)
        assert rv.status_code == 200

    def test_analyst_cannot_view_others_results(self, app, client):
        owner   = str(uuid.uuid4())
        other   = str(uuid.uuid4())
        dump_id = _seed_dump(app, owner, "complete")
        rv      = self._get(client, _auth(app, "forensic_analyst", other), dump_id)
        assert rv.status_code == 403

    def test_admin_can_view_any_results(self, app, client):
        uid     = str(uuid.uuid4())
        dump_id = _seed_dump(app, uid, "complete")
        rv      = self._get(client, _auth(app, "admin"), dump_id)
        assert rv.status_code == 200

    def test_response_schema_pending_dump(self, app, client):
        uid     = str(uuid.uuid4())
        dump_id = _seed_dump(app, uid, "pending")
        rv      = self._get(client, _auth(app, "forensic_analyst", uid), dump_id)
        body    = rv.get_json()
        assert body["dump_id"]  == dump_id
        assert body["status"]   == "pending"
        assert body["prediction"] is None
        assert body["confidence"] is None

    def test_response_has_prediction_when_result_exists(self, app, client):
        uid     = str(uuid.uuid4())
        dump_id = _seed_dump(app, uid, "complete")
        _seed_result(app, dump_id, uid)
        rv      = self._get(client, _auth(app, "forensic_analyst", uid), dump_id)
        body    = rv.get_json()
        assert body["prediction"] in ("Benign", "Malware")
        assert body["confidence"] is not None

    def test_suspicious_artifacts_field_present(self, app, client):
        uid     = str(uuid.uuid4())
        dump_id = _seed_dump(app, uid, "pending")
        rv      = self._get(client, _auth(app, "forensic_analyst", uid), dump_id)
        body    = rv.get_json()
        assert "suspicious_artifacts" in body


# ══════════════════════════════════════════════════════════════════════════════
# POST /api/analysis/retrain
# ══════════════════════════════════════════════════════════════════════════════

class TestRetrain:
    def test_requires_auth(self, client):
        rv = client.post("/api/analysis/retrain")
        assert rv.status_code == 401

    def test_analyst_forbidden(self, app, client):
        rv = client.post(
            "/api/analysis/retrain",
            headers=_auth(app, "forensic_analyst"),
        )
        assert rv.status_code == 403

    def test_admin_triggers_retrain(self, app, client):
        with patch("backend.routes.analysis._retrain_worker"):
            with patch("backend.routes.analysis.threading.Thread") as mock_thread:
                mock_thread.return_value.start = MagicMock()
                rv = client.post(
                    "/api/analysis/retrain",
                    headers=_auth(app, "admin"),
                )
        # Release lock if it was acquired
        from backend.routes.analysis import _retrain_lock
        if _retrain_lock.locked():
            _retrain_lock.release()
        assert rv.status_code == 202

    def test_retrain_response_message(self, app, client):
        with patch("backend.routes.analysis.threading.Thread") as mock_thread:
            mock_thread.return_value.start = MagicMock()
            rv = client.post(
                "/api/analysis/retrain",
                headers=_auth(app, "admin"),
            )
        from backend.routes.analysis import _retrain_lock
        if _retrain_lock.locked():
            _retrain_lock.release()
        body = rv.get_json()
        assert "message" in body

    def test_concurrent_retrain_returns_409(self, app, client):
        from backend.routes.analysis import _retrain_lock
        # Force lock to be held
        acquired = _retrain_lock.acquire(blocking=False)
        try:
            rv = client.post(
                "/api/analysis/retrain",
                headers=_auth(app, "admin"),
            )
            assert rv.status_code == 409
        finally:
            if acquired:
                _retrain_lock.release()


# ══════════════════════════════════════════════════════════════════════════════
# Role enforcement (require_role decorator)
# ══════════════════════════════════════════════════════════════════════════════

class TestRoleEnforcement:
    def test_unknown_role_rejected_from_upload(self, app, client):
        with app.app_context():
            token = create_access_token(
                identity=str(uuid.uuid4()),
                additional_claims={"role": "superuser"},
            )
        rv = client.post(
            "/api/analysis/upload",
            headers={"Authorization": f"Bearer {token}"},
            data={"file": (io.BytesIO(b"x"), "x.raw")},
            content_type="multipart/form-data",
        )
        assert rv.status_code == 403

    def test_missing_role_claim_rejected(self, app, client):
        with app.app_context():
            token = create_access_token(identity=str(uuid.uuid4()))
        rv = client.post(
            "/api/analysis/retrain",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert rv.status_code == 403

    def test_403_body_contains_required_field(self, app, client):
        with app.app_context():
            token = create_access_token(
                identity=str(uuid.uuid4()),
                additional_claims={"role": "forensic_analyst"},
            )
        rv = client.post(
            "/api/analysis/retrain",
            headers={"Authorization": f"Bearer {token}"},
        )
        body = rv.get_json()
        assert "required" in body
        assert "your_role" in body


# ══════════════════════════════════════════════════════════════════════════════
# Upload — additional validation: size limit and empty filename
# ══════════════════════════════════════════════════════════════════════════════

class TestUploadValidation:
    def test_size_limit_via_content_length(self, app, client):
        # Fake a declared Content-Length of 3 GB — server must reject before reading body
        rv = client.open(
            "/api/analysis/upload",
            method="POST",
            headers=_auth(app, "forensic_analyst"),
            data={"file": (io.BytesIO(b"small"), "sample.raw")},
            content_type="multipart/form-data",
            environ_overrides={"CONTENT_LENGTH": str(3 * 1024 * 1024 * 1024)},
        )
        assert rv.status_code == 413

    def test_empty_filename_returns_400(self, app, client):
        rv = client.post(
            "/api/analysis/upload",
            headers=_auth(app, "forensic_analyst"),
            data={"file": (io.BytesIO(b"data"), "")},
            content_type="multipart/form-data",
        )
        assert rv.status_code == 400

    def test_all_allowed_extensions_accepted(self, app, client):
        for ext in (".raw", ".mem", ".vmem", ".dmp"):
            rv = client.post(
                "/api/analysis/upload",
                headers=_auth(app, "forensic_analyst"),
                data={"file": (io.BytesIO(b"x"), f"dump{ext}")},
                content_type="multipart/form-data",
            )
            assert rv.status_code == 201, f"Expected 201 for {ext}, got {rv.status_code}"

    def test_pdf_extension_rejected(self, app, client):
        rv = client.post(
            "/api/analysis/upload",
            headers=_auth(app, "forensic_analyst"),
            data={"file": (io.BytesIO(b"x"), "dump.pdf")},
            content_type="multipart/form-data",
        )
        assert rv.status_code == 415

    def test_no_extension_rejected(self, app, client):
        rv = client.post(
            "/api/analysis/upload",
            headers=_auth(app, "forensic_analyst"),
            data={"file": (io.BytesIO(b"x"), "dumpfile")},
            content_type="multipart/form-data",
        )
        assert rv.status_code == 415


# ── Seed helpers for admin-only endpoints ─────────────────────────────────────

def _seed_model(app, accuracy: float = 0.90) -> str:
    """Insert a MlModel row and return its model_id."""
    from datetime import datetime, timezone
    from backend import db
    from backend.models.analysis import MlModel
    model_id = str(uuid.uuid4())
    with app.app_context():
        ml = MlModel(
            model_id   = model_id,
            model_name = "TestRF",
            algorithm  = "RandomForestClassifier",
            accuracy   = accuracy,
            model_path = "/tmp/fake.joblib",
            activated_at = datetime.now(timezone.utc),
        )
        db.session.add(ml)
        db.session.commit()
    return model_id


def _seed_dump_with_features(app, user_id: str) -> str:
    """Insert a MemoryDump + AnalysisFeatures and return dump_id."""
    from backend import db
    from backend.models.analysis import AnalysisFeatures, MemoryDump
    dump_id = str(uuid.uuid4())
    with app.app_context():
        dump = MemoryDump(
            dump_id   = dump_id, user_id = user_id,
            file_path = f"/tmp/{dump_id}.raw", file_name = "sample.raw",
            file_size = 1024, status = "complete",
        )
        db.session.add(dump)
        db.session.flush()
        feat = AnalysisFeatures(
            dump_id      = dump_id,
            feature_data = {
                "process_features": {"total_count": 2, "hidden_count": 0, "processes": []},
                "dll_features":     {"total_loaded": 0, "suspicious_paths_count": 0, "dlls": []},
                "behavioral_indicators": {
                    "malfind_count": 0, "high_entropy_regions": 0, "injection_evidence": []
                },
                "summary": {"process_count": 2, "hidden_processes": 0, "dll_count": 0},
            },
        )
        db.session.add(feat)
        db.session.commit()
    return dump_id


# ══════════════════════════════════════════════════════════════════════════════
# GET /api/analysis/dumps
# ══════════════════════════════════════════════════════════════════════════════

class TestListDumps:
    def test_requires_auth(self, client):
        rv = client.get("/api/analysis/dumps")
        assert rv.status_code == 401

    def test_analyst_sees_own_dumps(self, app, client):
        uid     = str(uuid.uuid4())
        dump_id = _seed_dump(app, uid)
        rv      = client.get("/api/analysis/dumps", headers=_auth(app, "forensic_analyst", uid))
        body    = rv.get_json()
        assert rv.status_code == 200
        ids = [d["dump_id"] for d in body["dumps"]]
        assert dump_id in ids

    def test_analyst_does_not_see_others_dumps(self, app, client):
        owner  = str(uuid.uuid4())
        other  = str(uuid.uuid4())
        dump_id = _seed_dump(app, owner)
        rv      = client.get("/api/analysis/dumps", headers=_auth(app, "forensic_analyst", other))
        body    = rv.get_json()
        ids = [d["dump_id"] for d in body["dumps"]]
        assert dump_id not in ids

    def test_admin_sees_all_dumps(self, app, client):
        uid1 = str(uuid.uuid4())
        uid2 = str(uuid.uuid4())
        id1  = _seed_dump(app, uid1)
        id2  = _seed_dump(app, uid2)
        rv   = client.get("/api/analysis/dumps", headers=_auth(app, "admin"))
        body = rv.get_json()
        assert rv.status_code == 200
        ids  = [d["dump_id"] for d in body["dumps"]]
        assert id1 in ids and id2 in ids

    def test_response_has_dumps_key(self, app, client):
        rv = client.get("/api/analysis/dumps", headers=_auth(app, "admin"))
        assert "dumps" in rv.get_json()

    def test_dump_row_schema(self, app, client):
        uid     = str(uuid.uuid4())
        dump_id = _seed_dump(app, uid)
        rv      = client.get("/api/analysis/dumps", headers=_auth(app, "forensic_analyst", uid))
        rows    = rv.get_json()["dumps"]
        row     = next(r for r in rows if r["dump_id"] == dump_id)
        for key in ("dump_id", "file_name", "file_size", "upload_date", "status"):
            assert key in row, f"Missing key: {key}"

    def test_prediction_field_present(self, app, client):
        uid     = str(uuid.uuid4())
        dump_id = _seed_dump(app, uid, "complete")
        _seed_result(app, dump_id, uid)
        rv      = client.get("/api/analysis/dumps", headers=_auth(app, "forensic_analyst", uid))
        row     = next(r for r in rv.get_json()["dumps"] if r["dump_id"] == dump_id)
        assert "prediction" in row
        assert row["prediction"] in ("Benign", "Malware")

    def test_admin_response_includes_user_name(self, app, client):
        uid     = str(uuid.uuid4())
        dump_id = _seed_dump(app, uid)
        rv      = client.get("/api/analysis/dumps", headers=_auth(app, "admin"))
        rows    = rv.get_json()["dumps"]
        row     = next((r for r in rows if r["dump_id"] == dump_id), None)
        if row:
            assert "user_name" in row


# ══════════════════════════════════════════════════════════════════════════════
# GET /api/analysis/stats
# ══════════════════════════════════════════════════════════════════════════════

class TestStats:
    def test_requires_auth(self, client):
        rv = client.get("/api/analysis/stats")
        assert rv.status_code == 401

    def test_analyst_forbidden(self, app, client):
        rv = client.get("/api/analysis/stats", headers=_auth(app, "forensic_analyst"))
        assert rv.status_code == 403

    def test_admin_gets_200(self, app, client):
        rv = client.get("/api/analysis/stats", headers=_auth(app, "admin"))
        assert rv.status_code == 200

    def test_response_schema(self, app, client):
        rv   = client.get("/api/analysis/stats", headers=_auth(app, "admin"))
        body = rv.get_json()
        for key in ("total_analyses", "malware_today", "detection_rate",
                    "disk_usage_mb", "last_model_date", "last_model_accuracy"):
            assert key in body, f"Missing key: {key}"

    def test_detection_rate_in_range(self, app, client):
        rv   = client.get("/api/analysis/stats", headers=_auth(app, "admin"))
        rate = rv.get_json()["detection_rate"]
        assert 0.0 <= rate <= 1.0

    def test_total_analyses_is_nonneg_int(self, app, client):
        rv    = client.get("/api/analysis/stats", headers=_auth(app, "admin"))
        total = rv.get_json()["total_analyses"]
        assert isinstance(total, int) and total >= 0


# ══════════════════════════════════════════════════════════════════════════════
# GET /api/analysis/models
# ══════════════════════════════════════════════════════════════════════════════

class TestModels:
    def test_requires_auth(self, client):
        rv = client.get("/api/analysis/models")
        assert rv.status_code == 401

    def test_analyst_forbidden(self, app, client):
        rv = client.get("/api/analysis/models", headers=_auth(app, "forensic_analyst"))
        assert rv.status_code == 403

    def test_admin_gets_200(self, app, client):
        rv = client.get("/api/analysis/models", headers=_auth(app, "admin"))
        assert rv.status_code == 200

    def test_response_has_models_list(self, app, client):
        rv = client.get("/api/analysis/models", headers=_auth(app, "admin"))
        assert isinstance(rv.get_json()["models"], list)

    def test_seeded_model_appears_in_list(self, app, client):
        model_id = _seed_model(app, accuracy=0.92)
        rv       = client.get("/api/analysis/models", headers=_auth(app, "admin"))
        ids      = [m["model_id"] for m in rv.get_json()["models"]]
        assert model_id in ids

    def test_model_row_has_is_active_flag(self, app, client):
        _seed_model(app)
        rv   = client.get("/api/analysis/models", headers=_auth(app, "admin"))
        rows = rv.get_json()["models"]
        assert all("is_active" in m for m in rows)


# ══════════════════════════════════════════════════════════════════════════════
# POST /api/analysis/models/<model_id>/activate
# ══════════════════════════════════════════════════════════════════════════════

class TestActivateModel:
    def test_requires_auth(self, client):
        rv = client.post(f"/api/analysis/models/{uuid.uuid4()}/activate")
        assert rv.status_code == 401

    def test_analyst_forbidden(self, app, client):
        model_id = _seed_model(app)
        rv       = client.post(
            f"/api/analysis/models/{model_id}/activate",
            headers=_auth(app, "forensic_analyst"),
        )
        assert rv.status_code == 403

    def test_nonexistent_model_returns_404(self, app, client):
        rv = client.post(
            f"/api/analysis/models/{uuid.uuid4()}/activate",
            headers=_auth(app, "admin"),
        )
        assert rv.status_code == 404

    def test_activate_returns_200(self, app, client):
        model_id = _seed_model(app)
        rv       = client.post(
            f"/api/analysis/models/{model_id}/activate",
            headers=_auth(app, "admin"),
        )
        assert rv.status_code == 200

    def test_activate_updates_activated_at(self, app, client):
        from backend import db
        from backend.models.analysis import MlModel
        model_id = _seed_model(app)
        client.post(
            f"/api/analysis/models/{model_id}/activate",
            headers=_auth(app, "admin"),
        )
        with app.app_context():
            m = db.session.get(MlModel, model_id)
            assert m.activated_at is not None


# ══════════════════════════════════════════════════════════════════════════════
# GET /api/analysis/logs
# ══════════════════════════════════════════════════════════════════════════════

class TestAuditLogs:
    def test_requires_auth(self, client):
        rv = client.get("/api/analysis/logs")
        assert rv.status_code == 401

    def test_analyst_forbidden(self, app, client):
        rv = client.get("/api/analysis/logs", headers=_auth(app, "forensic_analyst"))
        assert rv.status_code == 403

    def test_admin_gets_200(self, app, client):
        rv = client.get("/api/analysis/logs", headers=_auth(app, "admin"))
        assert rv.status_code == 200

    def test_response_schema(self, app, client):
        rv   = client.get("/api/analysis/logs", headers=_auth(app, "admin"))
        body = rv.get_json()
        for key in ("logs", "total", "page", "per_page"):
            assert key in body, f"Missing key: {key}"

    def test_logs_is_list(self, app, client):
        rv = client.get("/api/analysis/logs", headers=_auth(app, "admin"))
        assert isinstance(rv.get_json()["logs"], list)

    def test_pagination_params_accepted(self, app, client):
        rv = client.get(
            "/api/analysis/logs?page=1&per_page=10",
            headers=_auth(app, "admin"),
        )
        body = rv.get_json()
        assert body["page"] == 1
        assert body["per_page"] == 10

    def test_upload_action_creates_log_entry(self, app, client):
        uid = str(uuid.uuid4())
        # Upload produces an audit log entry
        client.post(
            "/api/analysis/upload",
            headers=_auth(app, "forensic_analyst", uid),
            data={"file": (io.BytesIO(b"x"), "audit_test.raw")},
            content_type="multipart/form-data",
        )
        rv   = client.get("/api/analysis/logs", headers=_auth(app, "admin"))
        logs = rv.get_json()["logs"]
        assert any(l["action"] == "upload" for l in logs)


# ══════════════════════════════════════════════════════════════════════════════
# GET + POST /api/analysis/labeled-samples
# ══════════════════════════════════════════════════════════════════════════════

class TestLabeledSamples:
    _VEC = [0.0] * 55

    def test_get_requires_auth(self, client):
        rv = client.get("/api/analysis/labeled-samples")
        assert rv.status_code == 401

    def test_get_analyst_forbidden(self, app, client):
        rv = client.get(
            "/api/analysis/labeled-samples",
            headers=_auth(app, "forensic_analyst"),
        )
        assert rv.status_code == 403

    def test_get_admin_returns_200(self, app, client):
        rv = client.get(
            "/api/analysis/labeled-samples",
            headers=_auth(app, "admin"),
        )
        assert rv.status_code == 200

    def test_get_response_schema(self, app, client):
        rv   = client.get("/api/analysis/labeled-samples", headers=_auth(app, "admin"))
        body = rv.get_json()
        for key in ("samples", "total", "pending", "page", "per_page"):
            assert key in body

    def test_post_requires_auth(self, client):
        rv = client.post(
            "/api/analysis/labeled-samples",
            json={"true_label": "Benign", "feature_vector": self._VEC},
        )
        assert rv.status_code == 401

    def test_post_analyst_forbidden(self, app, client):
        rv = client.post(
            "/api/analysis/labeled-samples",
            headers={**_auth(app, "forensic_analyst"), "Content-Type": "application/json"},
            data=json.dumps({"true_label": "Benign", "feature_vector": self._VEC}),
        )
        assert rv.status_code == 403

    def test_post_missing_label_returns_400(self, app, client):
        rv = client.post(
            "/api/analysis/labeled-samples",
            headers={**_auth(app, "admin"), "Content-Type": "application/json"},
            data=json.dumps({"feature_vector": self._VEC}),
        )
        assert rv.status_code == 400

    def test_post_invalid_label_returns_400(self, app, client):
        rv = client.post(
            "/api/analysis/labeled-samples",
            headers={**_auth(app, "admin"), "Content-Type": "application/json"},
            data=json.dumps({"true_label": "Unknown", "feature_vector": self._VEC}),
        )
        assert rv.status_code == 400

    def test_post_with_feature_vector_returns_201(self, app, client):
        rv = client.post(
            "/api/analysis/labeled-samples",
            headers={**_auth(app, "admin"), "Content-Type": "application/json"},
            data=json.dumps({"true_label": "Malware", "feature_vector": self._VEC}),
        )
        assert rv.status_code == 201
        assert "sample_id" in rv.get_json()

    def test_post_with_dump_id_extracts_vector(self, app, client):
        uid     = str(uuid.uuid4())
        dump_id = _seed_dump_with_features(app, uid)
        rv      = client.post(
            "/api/analysis/labeled-samples",
            headers={**_auth(app, "admin"), "Content-Type": "application/json"},
            data=json.dumps({"true_label": "Benign", "dump_id": dump_id}),
        )
        assert rv.status_code == 201

    def test_post_dump_without_features_returns_422(self, app, client):
        uid     = str(uuid.uuid4())
        dump_id = _seed_dump(app, uid)   # no AnalysisFeatures attached
        rv      = client.post(
            "/api/analysis/labeled-samples",
            headers={**_auth(app, "admin"), "Content-Type": "application/json"},
            data=json.dumps({"true_label": "Benign", "dump_id": dump_id}),
        )
        assert rv.status_code == 422

    def test_post_nonexistent_dump_returns_404(self, app, client):
        rv = client.post(
            "/api/analysis/labeled-samples",
            headers={**_auth(app, "admin"), "Content-Type": "application/json"},
            data=json.dumps({"true_label": "Benign", "dump_id": str(uuid.uuid4())}),
        )
        assert rv.status_code == 404
