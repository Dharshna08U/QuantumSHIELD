import importlib.util
import os
import unittest

REQUIRED = ("fastapi", "sqlalchemy", "pydantic", "pydantic_settings", "pwdlib", "jwt", "httpx", "argon2")
AVAILABLE = all(importlib.util.find_spec(name) for name in REQUIRED)


@unittest.skipUnless(AVAILABLE, "FastAPI/database/auth dependencies are not installed")
class KubernetesResponseAPITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ.update({
            "JWT_SECRET": "phase-three-test-secret-not-used-outside-this-process",
            "DATABASE_URL": "sqlite://", "AI_SERVICE_URL": "http://127.0.0.1:1",
            "PQC_PROVIDER": "unavailable", "BLOCKCHAIN_PROVIDER": "mock",
            "DEMO_MODE": "false",
            "KUBERNETES_PROVIDER": "unavailable", "KUBERNETES_REMEDIATION_ENABLED": "false",
            "KUBERNETES_ALLOWED_NAMESPACES": "payments", "KUBERNETES_ALLOWED_DEPLOYMENTS": "api",
        })
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
        cls.engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
        Base.metadata.create_all(cls.engine)
        cls.sessions = sessionmaker(bind=cls.engine, autoflush=False, expire_on_commit=False)

        def override_db():
            session = cls.sessions()
            try: yield session
            finally: session.close()

        app.dependency_overrides[get_db] = override_db
        cls.client = TestClient(app)
        analyst = cls.client.post("/api/v1/auth/register", json={"username": "phase3analyst", "email": "p3a@example.com", "password": "strong-phase-three-test-1"})
        assert analyst.status_code == 201, analyst.text
        login = cls.client.post("/api/v1/auth/login", json={"username": "phase3analyst", "password": "strong-phase-three-test-1"})
        cls.analyst_headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
        with cls.sessions.begin() as db:
            db.add(User(username="phase3operator", email="p3o@example.com", password_hash=hash_password("strong-phase-three-test-2"), role=UserRole.OPERATOR))
        op = cls.client.post("/api/v1/auth/login", json={"username": "phase3operator", "password": "strong-phase-three-test-2"})
        cls.operator_headers = {"Authorization": f"Bearer {op.json()['access_token']}"}

    @classmethod
    def tearDownClass(cls):
        from backend.app.core.database import get_db
        from backend.app.core.config import get_settings
        from backend.app.main import app
        app.dependency_overrides.pop(get_db, None)
        cls.engine.dispose()
        get_settings.cache_clear()

    def _incident(self):
        response = self.client.post("/api/v1/incidents", headers=self.analyst_headers, json={
            "source": "phase3-test", "incident_type": "resource_exhaustion",
            "summary": "Kubernetes response test", "description": "synthetic fixture event",
        })
        self.assertEqual(response.status_code, 201, response.text)
        # This test fixture exercises a policy-permitted simulated response; the AI endpoint is intentionally offline.
        from backend.app.models import Incident
        with self.sessions.begin() as db:
            db.get(Incident, response.json()["id"]).severity = "medium"
        return response.json()["id"]

    def test_provider_reports_unavailable_instead_of_fake_cluster(self):
        response = self.client.get("/api/v1/kubernetes/status", headers=self.analyst_headers)
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json()["available"])
        self.assertEqual(response.json()["status"], "UNAVAILABLE")

    def test_analyst_cannot_trigger_response(self):
        incident_id = self._incident()
        response = self.client.post("/api/v1/kubernetes/remediations/simulate", headers=self.analyst_headers, json={
            "incident_id": incident_id, "action": "restart_deployment", "namespace": "payments", "deployment": "api",
        })
        self.assertEqual(response.status_code, 403)

    def test_simulation_never_mutates_and_is_audited_through_integrity_flow(self):
        incident_id = self._incident()
        response = self.client.post("/api/v1/kubernetes/remediations/simulate", headers=self.operator_headers, json={
            "incident_id": incident_id, "action": "restart_deployment", "namespace": "payments", "deployment": "api",
        })
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["status"], "SIMULATION")
        self.assertFalse(response.json()["cluster_mutated"])
        self.assertEqual(response.json()["verification_status"], "SIMULATION")
        self.assertEqual(response.json()["integrity"]["blockchain_status"], "mock_recorded")
        events = self.client.get("/api/v1/kubernetes/audit", headers=self.analyst_headers).json()
        names = {event["event_type"] for event in events}
        self.assertTrue({"remediation.simulation", "remediation.verification", "pqc.sign", "pqc.verify", "blockchain.record", "blockchain.verify"}.issubset(names))

    def test_real_gate_and_arbitrary_command_rejection(self):
        incident_id = self._incident()
        payload = {"incident_id": incident_id, "action": "restart_deployment", "namespace": "payments", "deployment": "api"}
        blocked = self.client.post("/api/v1/kubernetes/remediations/execute", headers=self.operator_headers, json=payload)
        self.assertEqual(blocked.status_code, 200)
        self.assertEqual(blocked.json()["status"], "BLOCKED")
        self.assertFalse(blocked.json()["cluster_mutated"])
        injection = {**payload, "command": "kubectl delete namespace payments"}
        rejected = self.client.post("/api/v1/kubernetes/remediations/execute", headers=self.operator_headers, json=injection)
        self.assertEqual(rejected.status_code, 422)

    def test_simulated_verification_stays_simulation(self):
        incident_id = self._incident()
        created = self.client.post("/api/v1/kubernetes/remediations/simulate", headers=self.operator_headers, json={
            "incident_id": incident_id, "action": "restart_deployment", "namespace": "payments", "deployment": "api",
        }).json()
        response = self.client.post(f"/api/v1/kubernetes/remediations/{created['id']}/verify", headers=self.operator_headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["verification_status"], "SIMULATION")


if __name__ == "__main__":
    unittest.main()
