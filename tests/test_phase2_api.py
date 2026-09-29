import importlib.util
import os
import unittest

REQUIRED_MODULES = (
    "fastapi", "sqlalchemy", "pydantic", "pydantic_settings", "pwdlib", "jwt", "httpx", "argon2"
)
HAS_API_DEPS = all(importlib.util.find_spec(module) for module in REQUIRED_MODULES)


@unittest.skipUnless(HAS_API_DEPS, "FastAPI/database/auth dependencies are not installed")
class IncidentAPITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["JWT_SECRET"] = "unit-test-secret-that-is-not-used-outside-this-process"
        os.environ["DATABASE_URL"] = "sqlite://"
        os.environ["AI_SERVICE_URL"] = "http://127.0.0.1:1"
        os.environ["PQC_PROVIDER"] = "unavailable"
        os.environ["BLOCKCHAIN_PROVIDER"] = "mock"
        os.environ["DEMO_MODE"] = "false"

        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        from sqlalchemy.pool import StaticPool
        from fastapi.testclient import TestClient

        from backend.app.core.config import get_settings
        get_settings.cache_clear()
        from backend.app.core.database import Base, get_db
        from backend.app.models import User
        from backend.app.models.user import UserRole
        from backend.app.core.security import hash_password
        from backend.app.main import app
        from blockchain_service.client import _mock_client

        _mock_client.cache_clear()
        cls.engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(cls.engine)
        cls.sessions = sessionmaker(bind=cls.engine, autoflush=False, expire_on_commit=False)

        def override_db():
            session = cls.sessions()
            try:
                yield session
            finally:
                session.close()

        app.dependency_overrides[get_db] = override_db
        cls.client = TestClient(app)
        signup = cls.client.post("/api/v1/auth/register", json={
            "username": "analyst1", "email": "analyst@example.com", "password": "strong-test-password-1"
        })
        assert signup.status_code == 201, signup.text
        login = cls.client.post("/api/v1/auth/login", json={
            "username": "analyst1", "password": "strong-test-password-1"
        })
        assert login.status_code == 200, login.text
        cls.analyst_headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
        with cls.sessions.begin() as db:
            db.add(User(
                username="operator1", email="operator@example.com",
                password_hash=hash_password("strong-test-password-2"),
                role=UserRole.OPERATOR,
            ))
        op_login = cls.client.post("/api/v1/auth/login", json={
            "username": "operator1", "password": "strong-test-password-2"
        })
        cls.operator_headers = {"Authorization": f"Bearer {op_login.json()['access_token']}"}

    @classmethod
    def tearDownClass(cls):
        from backend.app.core.database import get_db
        from backend.app.main import app
        app.dependency_overrides.pop(get_db, None)
        cls.engine.dispose()

    def _submit(self, **extra):
        payload = {
            "source": "test-runner",
            "incident_type": "suspicious_activity",
            "summary": "Test security event",
            "description": "Synthetic test evidence only",
        }
        payload.update(extra)
        return self.client.post("/api/v1/incidents", json=payload, headers=self.analyst_headers)

    def test_authentication_and_end_to_end_demo_pipeline(self):
        self.assertEqual(self.client.get("/api/v1/incidents").status_code, 401)
        response = self._submit()
        self.assertEqual(response.status_code, 201, response.text)
        incident = response.json()
        self.assertEqual(incident["ai_status"], "unavailable")
        self.assertEqual(incident["pqc_status"], "unavailable")
        self.assertEqual(incident["signature_verified"], None)
        self.assertEqual(incident["blockchain_status"], "mock_recorded")
        self.assertEqual(incident["blockchain_provider"], "mock")
        self.assertTrue(incident["blockchain_verified"])
        self.assertEqual(len(incident["record_hash"]), 64)
        events = self.client.get(
            f"/api/v1/incidents/{incident['id']}/audit", headers=self.analyst_headers
        )
        names = {event["event_type"] for event in events.json()}
        self.assertTrue({"incident.created", "ai.analysis", "pqc.sign", "pqc.verify", "blockchain.result"}.issubset(names))

    def test_filters_and_role_limited_status_transitions(self):
        created = self._submit().json()
        self.assertEqual(self.client.get(
            "/api/v1/incidents?severity=unknown", headers=self.analyst_headers
        ).status_code, 200)
        triaged = self.client.patch(
            f"/api/v1/incidents/{created['id']}/status",
            json={"status": "triaged"}, headers=self.analyst_headers,
        )
        self.assertEqual(triaged.status_code, 200, triaged.text)
        denied = self.client.patch(
            f"/api/v1/incidents/{created['id']}/status",
            json={"status": "resolved", "note": "checked"}, headers=self.analyst_headers,
        )
        self.assertEqual(denied.status_code, 403)
        allowed = self.client.patch(
            f"/api/v1/incidents/{created['id']}/status",
            json={"status": "resolved", "note": "verified by operator"}, headers=self.operator_headers,
        )
        self.assertEqual(allowed.status_code, 200, allowed.text)

    def test_required_encryption_fails_before_plaintext_persistence(self):
        before = len(self.client.get("/api/v1/incidents", headers=self.analyst_headers).json())
        response = self._submit(encryption_required=True)
        self.assertEqual(response.status_code, 503)
        after = len(self.client.get("/api/v1/incidents", headers=self.analyst_headers).json())
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
