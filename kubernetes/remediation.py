"""Guarded Deployment remediation; no command execution path exists here."""
from __future__ import annotations

import json
import os
from uuid import uuid4
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from backend.app.models.healing_action import HealingAction
from backend.app.models.incident import Incident
from backend.app.models.user import User
from backend.app.models.remediation_approval import RemediationApproval
from backend.app.core.config import get_settings
from backend.app.services.approval_service import approval_is_valid_for_execution
from backend.app.services.audit_service import record_event
from kubernetes.actions import ALLOWED_ACTIONS
from kubernetes.providers import KubernetesProvider, KubernetesTimeout, KubernetesUnavailable, validate_resource_name
from kubernetes.response_policy import evaluate_response_policy
from kubernetes.verification import verify_with_retries
from pqc.record import canonical_record, sha256_hex
from pqc.service import protect_record

def _configured_names(setting: str) -> set[str]:
    try:
        from backend.app.core.config import get_settings
        settings = get_settings()
        attr = {"KUBERNETES_ALLOWED_NAMESPACES": "kubernetes_allowed_namespaces",
                "KUBERNETES_ALLOWED_DEPLOYMENTS": "kubernetes_allowed_deployments"}[setting]
        value = getattr(settings, attr)
    except (ImportError, AttributeError, KeyError):
        value = os.getenv(setting, "")
    names = {item.strip() for item in value.split(",") if item.strip()}
    if not names:
        try:
            from backend.app.core.config import get_settings
            if get_settings().demo_mode:
                return {"demo"} if setting == "KUBERNETES_ALLOWED_NAMESPACES" else {"checkout-api"}
        except (ImportError, AttributeError):
            pass
    return names


def _setting_enabled() -> bool:
    try:
        from backend.app.core.config import get_settings
        return get_settings().kubernetes_remediation_enabled
    except (ImportError, AttributeError):
        return os.getenv("KUBERNETES_REMEDIATION_ENABLED", "false").lower() == "true"


def _max_replicas() -> int:
    try:
        from backend.app.core.config import get_settings
        return get_settings().kubernetes_max_replicas
    except (ImportError, AttributeError):
        return int(os.getenv("KUBERNETES_MAX_REPLICAS", "10"))


def _deployment(provider: KubernetesProvider, namespace: str, name: str) -> dict[str, Any] | None:
    return next((item for item in provider.deployments(namespace) if (item.get("metadata") or {}).get("name") == name), None)


def _log(db: Session, incident: Incident, actor: User, event_type: str, result: str, **data: Any) -> None:
    record_event(db, event_type=event_type, actor_id=actor.id, actor_type=actor.role.value, incident_id=incident.id,
                 result=result, event_data=data)


def _execute_remediation(
    db: Session, *, incident: Incident, actor: User, provider: KubernetesProvider,
    action: str, namespace: str, deployment: str, replicas: int | None = None,
    approval_id: str | None = None, simulate: bool = True,
) -> dict[str, Any]:
    """Run simulation freely; real mutation requires policy, server gate, allowlists, and approval."""

    def blocked(reason: str, *, result: str = "BLOCKED") -> dict[str, Any]:
        _log(db, incident, actor, "remediation.attempt", result, action=action, reason=reason)
        if not simulate:
            action_row = HealingAction(incident_id=incident.id, requested_by=actor.id, action=action,
                                       status="blocked", mode="real", verification_status="NOT_PERFORMED",
                                       details=json.dumps({"namespace": namespace, "deployment": deployment,
                                                           "replicas": replicas, "reason": reason}))
            db.add(action_row)
        db.commit()
        return {"status": result, "verification_status": "NOT_PERFORMED", "cluster_mutated": False,
                "reason": reason, "action": action}

    try:
        namespace, deployment = validate_resource_name(namespace), validate_resource_name(deployment)
    except ValueError:
        return blocked("Invalid Kubernetes resource name")
    if action not in ALLOWED_ACTIONS:
        return blocked("Action is not allowlisted")
    if action == "scale_deployment" and (not isinstance(replicas, int) or isinstance(replicas, bool) or not 1 <= replicas <= _max_replicas()):
        return blocked("Replica count is outside configured limits")
    if namespace not in _configured_names("KUBERNETES_ALLOWED_NAMESPACES") or deployment not in _configured_names("KUBERNETES_ALLOWED_DEPLOYMENTS"):
        return blocked("Namespace or Deployment is not on the server allowlist")
    policy = evaluate_response_policy(incident.severity, requested_action=action)
    _log(db, incident, actor, "response.policy", policy.decision.upper(), severity=incident.severity, action=action, reason=policy.reason)
    if policy.decision == "blocked":
        _log(db, incident, actor, "remediation.approval", "BLOCKED", action=action, reason=policy.reason)
        return blocked(policy.reason)

    params = {"namespace": namespace, "deployment": deployment, "replicas": replicas}
    approval: RemediationApproval | None = None
    if not simulate or approval_id:
        approval, error = approval_is_valid_for_execution(
            db, approval_id=approval_id, incident=incident, actor=actor, action=action, params=params,
        )
        if error:
            _log(db, incident, actor, "remediation.approval", "BLOCKED", action=action, reason=error)
            return blocked(error)

    if simulate:
        reason = "No Kubernetes mutation was performed"
        _log(db, incident, actor, "remediation.simulation", "SIMULATION", action=action,
             namespace=namespace, deployment=deployment, replicas=replicas, reason=reason)
        action_row = HealingAction(incident_id=incident.id, requested_by=actor.id, action=action,
                                   status="simulation", mode="simulation", verification_status="SIMULATION",
                                   details=json.dumps({**params, "reason": reason}))
        db.add(action_row); db.flush()
        if approval is not None:
            approval.remediation_action_id = action_row.id
        _log(db, incident, actor, "remediation.verification", "SIMULATION", action_id=action_row.id,
             cluster_mutated=False)
        db.commit(); db.refresh(action_row)
        return {"id": action_row.id, "status": "SIMULATION", "verification_status": "SIMULATION",
                "cluster_mutated": False, "action": action, "reason": reason}

    if not _setting_enabled():
        _log(db, incident, actor, "remediation.execution", "BLOCKED", action=action,
             reason="KUBERNETES_REMEDIATION_ENABLED is false")
        return blocked("Real remediation is disabled by server configuration")
    if provider.provider != "kubernetes":
        return blocked("Real remediation requires the configured Kubernetes REST provider")

    before: dict[str, Any] | None = None
    action_row: HealingAction | None = None
    action_sent = False
    try:
        before = _deployment(provider, namespace, deployment)
        if before is None:
            raise KubernetesUnavailable("Allowlisted Deployment was not found")
        _log(db, incident, actor, "remediation.approval", "APPROVED", action=action,
             approval_id=approval.id if approval else None)
        _log(db, incident, actor, "remediation.execution", "PENDING", action=action, namespace=namespace, deployment=deployment)
        action_row = HealingAction(incident_id=incident.id, requested_by=actor.id, action=action, status="executing",
                                   mode="real", verification_status="pending",
                                   details=json.dumps({"namespace": namespace, "deployment": deployment,
                                                       "replicas": replicas, "before_generation": (before.get("metadata") or {}).get("generation")}))
        db.add(action_row); db.flush()
        if approval is not None:
            approval.remediation_action_id = action_row.id
        action_sent = True
        provider.act(action, namespace, deployment, replicas)
        _log(db, incident, actor, "remediation.execution", "EXECUTED", action=action, action_id=action_row.id)
        settings = get_settings()
        verification, observations = verify_with_retries(
            lambda: _deployment(provider, namespace, deployment), action=action, before=before,
            replicas=replicas, max_attempts=settings.kubernetes_verification_max_attempts,
            delay_seconds=settings.kubernetes_verification_delay_seconds,
        )
        for check in observations:
            _log(db, incident, actor, "remediation.verification_attempt", check["status"],
                 action_id=action_row.id, **check)
        action_row.status = "verified" if verification == "VERIFIED" else verification.lower()
        action_row.verification_status = verification
        action_row.verified_at = datetime.now(timezone.utc) if verification == "VERIFIED" else None
        action_row.details = json.dumps({"namespace": namespace, "deployment": deployment, "replicas": replicas,
                                         "before_generation": (before.get("metadata") or {}).get("generation", 0)})
        _log(db, incident, actor, "remediation.verification", verification, action=action, action_id=action_row.id)
        db.commit()
        return {"id": action_row.id, "status": "EXECUTED", "verification_status": verification,
                "cluster_mutated": True, "action": action}
    except KubernetesTimeout:
        _log(db, incident, actor, "remediation.execution", "TIMEOUT", action=action, namespace=namespace, deployment=deployment)
        if action_row is None:
            action_row = HealingAction(incident_id=incident.id, requested_by=actor.id, action=action, status="timeout",
                                       mode="real", verification_status="TIMEOUT", details="Kubernetes API timed out")
            db.add(action_row)
        else:
            action_row.status, action_row.verification_status = "timeout", "TIMEOUT"
        final_verification = "TIMEOUT"
        if action_sent and before is not None:
            settings = get_settings()
            final_verification, observations = verify_with_retries(
                lambda: _deployment(provider, namespace, deployment), action=action, before=before,
                replicas=replicas, max_attempts=settings.kubernetes_verification_max_attempts,
                delay_seconds=settings.kubernetes_verification_delay_seconds,
            )
            for check in observations:
                _log(db, incident, actor, "remediation.verification_attempt", check["status"], action=action, **check)
            action_row.status, action_row.verification_status = "timeout", final_verification
        _log(db, incident, actor, "remediation.verification", final_verification, action=action)
        db.commit()
        return {"id": action_row.id, "status": "TIMEOUT", "verification_status": final_verification, "cluster_mutated": None}
    except KubernetesUnavailable:
        _log(db, incident, actor, "remediation.execution", "UNAVAILABLE", action=action, namespace=namespace, deployment=deployment)
        if action_row is None:
            action_row = HealingAction(incident_id=incident.id, requested_by=actor.id, action=action, status="unavailable",
                                       mode="real", verification_status="UNAVAILABLE", details="Kubernetes provider unavailable")
            db.add(action_row)
        else:
            action_row.status, action_row.verification_status = "unavailable", "UNAVAILABLE"
        _log(db, incident, actor, "remediation.verification", "UNAVAILABLE", action=action)
        db.commit()
        return {"status": "UNAVAILABLE", "verification_status": "UNAVAILABLE", "cluster_mutated": False}
    except Exception:
        _log(db, incident, actor, "remediation.execution", "FAILED", action=action, reason="provider_error")
        _log(db, incident, actor, "remediation.verification", "UNAVAILABLE", action=action)
        if action_row is not None:
            action_row.status, action_row.verification_status = "failed", "UNAVAILABLE"
        db.commit()
        return {"status": "FAILED", "verification_status": "UNAVAILABLE", "cluster_mutated": None}


def _integrity_evidence(db: Session, incident: Incident, actor: User, result: dict[str, Any],
                        action: str, namespace: str, deployment: str) -> dict[str, Any]:
    evidence_id = str(result.get("id") or uuid4())
    evidence = {"evidence_id": evidence_id, "incident_id": incident.id, "action": action,
                "namespace": namespace, "deployment": deployment, "result": result.get("status"),
                "verification_status": result.get("verification_status"), "actor": actor.role.value,
                "timestamp": datetime.now(timezone.utc).isoformat()}
    digest = sha256_hex(canonical_record(evidence))
    provider = None
    try:
        from backend.app.core.config import get_settings
        if not get_settings().demo_mode and get_settings().pqc_provider == "oqs":
            from pqc.provider import configured_provider
            provider = configured_provider()
    except Exception:
        provider = None
    protected = protect_record(evidence, provider=provider)
    record_event(db, event_type="pqc.sign", actor_id=actor.id, actor_type=actor.role.value,
                 incident_id=incident.id, result="success" if protected.signature else protected.pqc_status,
                 event_data={"evidence_id": evidence_id, "record_hash": digest, "algorithm": protected.signature_algorithm})
    record_event(db, event_type="pqc.verify", actor_id=actor.id, actor_type=actor.role.value,
                 incident_id=incident.id, result="success" if protected.signature_verified else ("failed" if protected.signature_verified is False else "unavailable"),
                 event_data={"evidence_id": evidence_id, "verified": protected.signature_verified})
    try:
        from blockchain_service.client import BlockchainUnavailable, configured_client
        client = configured_client()
        receipt = client.record(evidence_id, digest, {**evidence, "signature": protected.signature,
                                                       "signature_algorithm": protected.signature_algorithm,
                                                       "signature_verified": protected.signature_verified})
        verified = client.verify(evidence_id, digest)
        ledger_result = "mock_recorded" if client.provider == "mock" else "recorded"
        record_event(db, event_type="blockchain.record", actor_id=actor.id, actor_type=actor.role.value,
                     incident_id=incident.id, result=ledger_result,
                     event_data={"evidence_id": evidence_id, "provider": client.provider, "transaction_id": receipt.transaction_id})
        record_event(db, event_type="blockchain.verify", actor_id=actor.id, actor_type=actor.role.value,
                     incident_id=incident.id, result="success" if verified else "failed",
                     event_data={"evidence_id": evidence_id, "verified": verified})
    except Exception:
        ledger_result = "unavailable"
        record_event(db, event_type="blockchain.record", actor_id=actor.id, actor_type=actor.role.value,
                     incident_id=incident.id, result="unavailable", event_data={"evidence_id": evidence_id})
    return {"evidence_id": evidence_id, "record_hash": digest, "pqc_status": protected.pqc_status,
            "signature_verified": protected.signature_verified, "blockchain_status": ledger_result}


def execute_remediation(
    db: Session, *, incident: Incident, actor: User, provider: KubernetesProvider,
    action: str, namespace: str, deployment: str, replicas: int | None = None,
    approval_id: str | None = None, simulate: bool = True,
) -> dict[str, Any]:
    result = _execute_remediation(db, incident=incident, actor=actor, provider=provider, action=action,
                                  namespace=namespace, deployment=deployment, replicas=replicas,
                                  approval_id=approval_id, simulate=simulate)
    try:
        integrity = _integrity_evidence(db, incident, actor, result, action, namespace, deployment)
        result["integrity"] = integrity
        db.commit()
    except Exception:
        # Remediation outcome remains visible even when optional integrity services fail.
        result["integrity"] = {"pqc_status": "failed", "blockchain_status": "failed"}
    return result
