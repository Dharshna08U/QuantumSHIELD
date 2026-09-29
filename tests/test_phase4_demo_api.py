"""Connected demo-flow integration test (runs when optional API dependencies exist)."""
import importlib.util
import os
import unittest

REQUIRED = ("fastapi", "sqlalchemy", "pydantic", "pydantic_settings", "pwdlib", "jwt", "httpx", "argon2")
AVAILABLE = all(importlib.util.find_spec(name) for name in REQUIRED)


@unittest.skipUnless(AVAILABLE, "FastAPI/database/auth dependencies are not installed")
class PhaseFourDemoFlowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ.update({
            "JWT_SECRET": "phase-four-test-secret-not-used-outside-this-process",
            "DATABASE_URL": "sqlite://", "DEMO_MODE": "true", "KUBERNETES_WATCH_ENABLED": "false",
            "KUBERNETES_ALLOWED_NAMESPACES": "", "KUBERNETES_ALLOWED_DEPLOYMENTS": "",
            "KUBERNETES_APPROVAL_SEPARATION_OF_DUTIES": "true",
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
        cls.engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
        Base.metadata.create_all(cls.engine)
        cls.sessions = sessionmaker(bind=cls.engine, autoflush=False, expire_on_commit=False)

        def override_db():
            session = cls.sessions()
            try:
                yield session
            finally:
                session.close()

        app.dependency_overrides[get_db] = override_db
        cls.app, cls.client = app, TestClient(app)
        analyst = cls.client.post("/api/v1/auth/register", json={
            "username": "phase4analyst", "email": "p4a@example.com", "password": "strong-phase-four-test-1",
        })
        assert analyst.status_code == 201, analyst.text
        login = cls.client.post("/api/v1/auth/login", json={
            "username": "phase4analyst", "password": "strong-phase-four-test-1",
        })
        cls.analyst = {"Authorization": f"Bearer {login.json()['access_token']}"}
        with cls.sessions.begin() as db:
            db.add(User(username="phase4operator", email="p4o@example.com",
                        password_hash=hash_password("strong-phase-four-test-2"), role=UserRole.OPERATOR))
        login = cls.client.post("/api/v1/auth/login", json={
            "username": "phase4operator", "password": "strong-phase-four-test-2",
        })
        cls.operator = {"Authorization": f"Bearer {login.json()['access_token']}"}

    @classmethod
    def tearDownClass(cls):
        from backend.app.core.config import get_settings
        from backend.app.core.database import get_db
        cls.app.dependency_overrides.pop(get_db, None)
        cls.engine.dispose()
        get_settings.cache_clear()

    def setUp(self):
        from backend.app.models import AuditEvent, HealingAction, Incident, KubernetesCondition, RemediationApproval
        with self.sessions.begin() as db:
            for model in (RemediationApproval, KubernetesCondition, HealingAction, AuditEvent, Incident):
                db.query(model).delete()

    def test_observation_to_approval_simulation_audit_and_mock_ledger(self):
        observed = self.client.post("/api/v1/kubernetes/demo/run", headers=self.analyst)
        self.assertEqual(observed.status_code, 200, observed.text)
        result = observed.json()
        self.assertEqual(result["provider"], "demo")
        self.assertTrue(result["incidents"])
        incident = next(item for item in result["incidents"] if item["summary"].startswith("Deployment"))
        self.assertEqual(incident["ai_status"], "demo")
        self.assertEqual(incident["blockchain_status"], "mock_recorded")

        again = self.client.post("/api/v1/kubernetes/demo/run", headers=self.analyst).json()
        self.assertEqual(again["incidents"], [])  # Durable active-condition dedupe.

        body = {"incident_id": incident["id"], "action": "restart_deployment",
                "namespace": "demo", "deployment": "checkout-api", "reason": "Demo operator review"}
        request = self.client.post("/api/v1/kubernetes/approvals", headers=self.analyst, json=body)
        self.assertEqual(request.status_code, 201, request.text)
        approval_id = request.json()["id"]
        self.assertEqual(self.client.post(f"/api/v1/kubernetes/approvals/{approval_id}/approve",
                                          headers=self.analyst, json={}).status_code, 403)
        approved = self.client.post(f"/api/v1/kubernetes/approvals/{approval_id}/approve",
                                    headers=self.operator, json={})
        self.assertEqual(approved.status_code, 200, approved.text)
        simulation = self.client.post("/api/v1/kubernetes/remediations/simulate", headers=self.operator,
                                      json={"incident_id": incident["id"], "action": "restart_deployment",
                                            "namespace": "demo", "deployment": "checkout-api",
                                            "approval_id": approval_id})
        self.assertEqual(simulation.status_code, 200, simulation.text)
        self.assertEqual(simulation.json()["verification_status"], "SIMULATION")
        self.assertFalse(simulation.json()["cluster_mutated"])
        self.assertEqual(simulation.json()["integrity"]["blockchain_status"], "mock_recorded")
        audit = self.client.get(f"/api/v1/incidents/{incident['id']}/audit", headers=self.analyst).json()
        names = {event["event_type"] for event in audit}
        self.assertTrue({"kubernetes.condition_observed", "ai.analysis", "healing.decision",
                         "remediation.approval", "remediation.simulation", "remediation.verification",
                         "blockchain.record"}.issubset(names))

    def test_approval_rejection_and_disallowed_resources_are_blocked(self):
        incident_response = self.client.post("/api/v1/kubernetes/demo/run", headers=self.analyst).json()
        incident_id = incident_response["incidents"][0]["id"]
        disallowed = self.client.post("/api/v1/kubernetes/approvals", headers=self.analyst, json={
            "incident_id": incident_id, "action": "restart_deployment", "namespace": "kube-system",
            "deployment": "api", "reason": "negative test",
        })
        self.assertEqual(disallowed.status_code, 403)
        requested = self.client.post("/api/v1/kubernetes/approvals", headers=self.analyst, json={
            "incident_id": incident_id, "action": "restart_deployment", "namespace": "demo",
            "deployment": "checkout-api", "reason": "negative test",
        })
        approval_id = requested.json()["id"]
        self.assertEqual(self.client.post(f"/api/v1/kubernetes/approvals/{approval_id}/reject",
                                          headers=self.operator, json={"reason": "Rejected in test"}).status_code, 200)
        denied = self.client.post("/api/v1/kubernetes/remediations/execute", headers=self.operator, json={
            "incident_id": incident_id, "action": "restart_deployment", "namespace": "demo",
            "deployment": "checkout-api", "approval_id": approval_id,
        })
        self.assertEqual(denied.status_code, 200)
        self.assertEqual(denied.json()["status"], "BLOCKED")

    def test_expired_approval_and_global_execution_gate(self):
        from datetime import datetime, timedelta, timezone
        from backend.app.models import RemediationApproval
        incident = self.client.post("/api/v1/kubernetes/demo/run", headers=self.analyst).json()["incidents"][0]
        requested = self.client.post("/api/v1/kubernetes/approvals", headers=self.analyst, json={
            "incident_id": incident["id"], "action": "restart_deployment", "namespace": "demo",
            "deployment": "checkout-api", "reason": "expired approval fixture",
        })
        approval_id = requested.json()["id"]
        with self.sessions.begin() as db:
            approval = db.get(RemediationApproval, approval_id)
            approval.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
        response = self.client.post(f"/api/v1/kubernetes/approvals/{approval_id}/approve",
                                    headers=self.operator, json={})
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json()["error"]["message"], "Approval request expired")

        second = self.client.post("/api/v1/kubernetes/approvals", headers=self.analyst, json={
            "incident_id": incident["id"], "action": "restart_deployment", "namespace": "demo",
            "deployment": "checkout-api", "reason": "gate fixture",
        }).json()
        approved = self.client.post(f"/api/v1/kubernetes/approvals/{second['id']}/approve",
                                    headers=self.operator, json={})
        self.assertEqual(approved.status_code, 200)
        execution = self.client.post("/api/v1/kubernetes/remediations/execute", headers=self.operator, json={
            "incident_id": incident["id"], "action": "restart_deployment", "namespace": "demo",
            "deployment": "checkout-api", "approval_id": second["id"],
        })
        self.assertEqual(execution.status_code, 200)
        self.assertEqual(execution.json()["status"], "BLOCKED")
        self.assertFalse(execution.json()["cluster_mutated"])


if __name__ == "__main__":
    unittest.main()
