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
        rv  = self._post(client, _auth(app, "analyst", uid))
        assert rv.status_code == 201

    def test_admin_can_upload(self, app, client):
        rv = self._post(client, _auth(app, "admin"))
        assert rv.status_code == 201

    def test_response_has_dump_id(self, app, client):
        rv = self._post(client, _auth(app, "analyst"))
        body = rv.get_json()
        assert "dump_id" in body

    def test_response_has_hash(self, app, client):
        rv = self._post(client, _auth(app, "analyst"))
        body = rv.get_json()
        assert "hash" in body
        assert len(body["hash"]) == 64   # SHA-256 hex

    def test_response_status_pending(self, app, client):
        rv = self._post(client, _auth(app, "analyst"))
        body = rv.get_json()
        assert body["status"] == "pending"

    def test_no_file_field_returns_400(self, app, client):
        rv = client.post(
            "/api/analysis/upload",
            headers=_auth(app, "analyst"),
            data={},
            content_type="multipart/form-data",
        )
        assert rv.status_code == 400

    def test_unsupported_extension_returns_415(self, app, client):
        rv = self._post(client, _auth(app, "analyst"), filename="dump.exe")
        assert rv.status_code == 415

    def test_mem_extension_accepted(self, app, client):
        rv = self._post(client, _auth(app, "analyst"), filename="dump.mem")
        assert rv.status_code == 201

    def test_vmem_extension_accepted(self, app, client):
        rv = self._post(client, _auth(app, "analyst"), filename="dump.vmem")
        assert rv.status_code == 201

    def test_dmp_extension_accepted(self, app, client):
        rv = self._post(client, _auth(app, "analyst"), filename="dump.dmp")
        assert rv.status_code == 201

    def test_dump_stored_in_db(self, app, client):
        from backend import db
        from backend.models.analysis import MemoryDump
        rv   = self._post(client, _auth(app, "analyst"))
        body = rv.get_json()
        from backend import db
        with app.app_context():
            dump = db.session.get(MemoryDump, body["dump_id"])
            assert dump is not None
            assert dump.file_name == "sample.raw"

    def test_file_written_to_disk(self, app, client):
        rv   = self._post(client, _auth(app, "analyst"), data=b"MEMDATA")
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
            headers={**_auth(app, "analyst"), "Content-Type": "application/json"},
            data=json.dumps({}),
        )
        assert rv.status_code == 400

    def test_nonexistent_dump_returns_404(self, app, client):
        rv = self._post(client, _auth(app, "analyst"), str(uuid.uuid4()))
        assert rv.status_code == 404

    def test_analyst_can_analyze_own_dump(self, app, client):
        uid     = str(uuid.uuid4())
        dump_id = _seed_dump(app, uid)
        rv      = self._post(client, _auth(app, "analyst", uid), dump_id)
        assert rv.status_code == 202

    def test_analyst_cannot_analyze_others_dump(self, app, client):
        owner   = str(uuid.uuid4())
        other   = str(uuid.uuid4())
        dump_id = _seed_dump(app, owner)
        rv      = self._post(client, _auth(app, "analyst", other), dump_id)
        assert rv.status_code == 403

    def test_admin_can_analyze_any_dump(self, app, client):
        uid     = str(uuid.uuid4())
        dump_id = _seed_dump(app, uid)
        rv      = self._post(client, _auth(app, "admin"), dump_id)
        assert rv.status_code == 202

    def test_response_contains_status_processing(self, app, client):
        uid     = str(uuid.uuid4())
        dump_id = _seed_dump(app, uid)
        rv      = self._post(client, _auth(app, "analyst", uid), dump_id)
        body    = rv.get_json()
        assert body.get("status") == "processing"

    def test_already_processing_returns_409(self, app, client):
        uid     = str(uuid.uuid4())
        dump_id = _seed_dump(app, uid, status="processing")
        rv      = self._post(client, _auth(app, "analyst", uid), dump_id)
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
        rv = self._get(client, _auth(app, "analyst"), str(uuid.uuid4()))
        assert rv.status_code == 404

    def test_analyst_can_view_own_results(self, app, client):
        uid     = str(uuid.uuid4())
        dump_id = _seed_dump(app, uid, "complete")
        rv      = self._get(client, _auth(app, "analyst", uid), dump_id)
        assert rv.status_code == 200

    def test_analyst_cannot_view_others_results(self, app, client):
        owner   = str(uuid.uuid4())
        other   = str(uuid.uuid4())
        dump_id = _seed_dump(app, owner, "complete")
        rv      = self._get(client, _auth(app, "analyst", other), dump_id)
        assert rv.status_code == 403

    def test_admin_can_view_any_results(self, app, client):
        uid     = str(uuid.uuid4())
        dump_id = _seed_dump(app, uid, "complete")
        rv      = self._get(client, _auth(app, "admin"), dump_id)
        assert rv.status_code == 200

    def test_response_schema_pending_dump(self, app, client):
        uid     = str(uuid.uuid4())
        dump_id = _seed_dump(app, uid, "pending")
        rv      = self._get(client, _auth(app, "analyst", uid), dump_id)
        body    = rv.get_json()
        assert body["dump_id"]  == dump_id
        assert body["status"]   == "pending"
        assert body["prediction"] is None
        assert body["confidence"] is None

    def test_response_has_prediction_when_result_exists(self, app, client):
        uid     = str(uuid.uuid4())
        dump_id = _seed_dump(app, uid, "complete")
        _seed_result(app, dump_id, uid)
        rv      = self._get(client, _auth(app, "analyst", uid), dump_id)
        body    = rv.get_json()
        assert body["prediction"] in ("Benign", "Malware")
        assert body["confidence"] is not None

    def test_suspicious_artifacts_field_present(self, app, client):
        uid     = str(uuid.uuid4())
        dump_id = _seed_dump(app, uid, "pending")
        rv      = self._get(client, _auth(app, "analyst", uid), dump_id)
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
            headers=_auth(app, "analyst"),
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
                additional_claims={"role": "analyst"},
            )
        rv = client.post(
            "/api/analysis/retrain",
            headers={"Authorization": f"Bearer {token}"},
        )
        body = rv.get_json()
        assert "required" in body
        assert "your_role" in body
