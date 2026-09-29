from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import desc, select

from backend.app.api.dependencies import DbSession, Permission, require_permission
from backend.app.core.config import get_settings
from backend.app.models.healing_action import HealingAction
from backend.app.models.incident import Incident
from backend.app.models.remediation_approval import RemediationApproval
from backend.app.models.kubernetes_condition import KubernetesCondition
from backend.app.models.user import User
from backend.app.services.audit_service import record_event
from backend.app.services.approval_service import (
    ApprovalWorkflowError, decide_approval, expire_pending_approvals, request_approval,
)
from kubernetes.detection import detect_conditions
from kubernetes.monitoring import poll_and_create_incidents
from kubernetes.providers import KubernetesUnavailable, configured_provider, validate_resource_name
from kubernetes.remediation import execute_remediation
from kubernetes.response_policy import evaluate_response_policy
from kubernetes.verification import verify_with_retries

router = APIRouter(prefix="/api/v1/kubernetes", tags=["kubernetes"])
reader = require_permission(Permission.REPORT_READ)
ingester = require_permission(Permission.INCIDENT_CREATE)
executor = require_permission(Permission.REMEDIATION_EXECUTE)
approval_requester = require_permission(Permission.REMEDIATION_REQUEST)
approval_decider = require_permission(Permission.REMEDIATION_APPROVE)


class PolicyInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    severity: Literal["low", "medium", "high", "critical", "unknown"]
    action: str | None = Field(default=None, max_length=40)


class RemediationInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    incident_id: str = Field(min_length=1, max_length=36)
    action: Literal["restart_deployment", "scale_deployment"]
    namespace: str = Field(min_length=1, max_length=63)
    deployment: str = Field(min_length=1, max_length=63)
    replicas: int | None = Field(default=None, ge=1, le=10)
    approval_id: str | None = Field(default=None, max_length=36)


class ApprovalRequestInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    incident_id: str = Field(min_length=1, max_length=36)
    action: Literal["restart_deployment", "scale_deployment"]
    namespace: str = Field(min_length=1, max_length=63)
    deployment: str = Field(min_length=1, max_length=63)
    replicas: int | None = Field(default=None, ge=1, le=10)
    reason: str = Field(default="", max_length=1000)


class ApprovalDecisionInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str | None = Field(default=None, max_length=1000)


def _provider():
    return configured_provider()


def _audit_global(db, actor: User, event_type: str, result: str, data: dict[str, object]) -> None:
    record_event(db, event_type=event_type, actor_id=actor.id, actor_type=actor.role.value, result=result, event_data=data)


def _approval_dict(db, approval: RemediationApproval) -> dict[str, object]:
    incident = db.get(Incident, approval.incident_id)
    requester = db.get(User, approval.requested_by)
    decider = db.get(User, approval.decided_by) if approval.decided_by else None
    attrs = (incident.attributes or {}) if incident else {}
    return {
        "id": approval.id, "incident_id": approval.incident_id,
        "incident_summary": incident.summary if incident else "Incident unavailable",
        "condition": attrs.get("condition"), "requested_action": approval.requested_action,
        "action_parameters": approval.action_parameters, "policy_decision": approval.policy_decision,
        "policy_reason": approval.policy_reason, "decision": approval.decision,
        "requested_by": approval.requested_by, "requester": requester.username if requester else "unknown",
        "requested_at": approval.requested_at, "expires_at": approval.expires_at,
        "decided_by": approval.decided_by, "decider": decider.username if decider else None,
        "decided_at": approval.decided_at, "requester_reason": approval.requester_reason,
        "reason": approval.reason, "remediation_action_id": approval.remediation_action_id,
    }


@router.post("/approvals", status_code=201)
def create_approval(payload: ApprovalRequestInput, db: DbSession,
                    actor: Annotated[User, Depends(approval_requester)]) -> dict[str, object]:
    incident = db.get(Incident, payload.incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    try:
        approval = request_approval(db, incident=incident, actor=actor, action=payload.action,
                                    params={"namespace": payload.namespace, "deployment": payload.deployment,
                                            "replicas": payload.replicas}, reason=payload.reason)
    except ApprovalWorkflowError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc
    return _approval_dict(db, approval)


@router.get("/approvals/pending")
def pending_approvals(db: DbSession, _actor: Annotated[User, Depends(reader)]) -> list[dict[str, object]]:
    expire_pending_approvals(db)
    rows = db.scalars(select(RemediationApproval).where(RemediationApproval.decision == "PENDING")
                      .order_by(RemediationApproval.requested_at.asc()))
    return [_approval_dict(db, row) for row in rows]


@router.get("/approvals")
def approval_history(db: DbSession, _actor: Annotated[User, Depends(reader)],
                     limit: int = Query(default=100, ge=1, le=500)) -> list[dict[str, object]]:
    expire_pending_approvals(db)
    rows = db.scalars(select(RemediationApproval).order_by(desc(RemediationApproval.requested_at)).limit(limit))
    return [_approval_dict(db, row) for row in rows]


def _decide_approval(approval_id: str, db, actor: User, decision: str, reason: str | None):
    approval = db.get(RemediationApproval, approval_id)
    if approval is None:
        raise HTTPException(status_code=404, detail="Approval request not found")
    try:
        decide_approval(db, approval=approval, actor=actor, decision=decision, reason=reason)
    except ApprovalWorkflowError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc
    return _approval_dict(db, approval)


@router.post("/approvals/{approval_id}/approve")
def approve_remediation(approval_id: str, payload: ApprovalDecisionInput, db: DbSession,
                       actor: Annotated[User, Depends(approval_decider)]) -> dict[str, object]:
    return _decide_approval(approval_id, db, actor, "APPROVED", payload.reason)


@router.post("/approvals/{approval_id}/reject")
def reject_remediation(approval_id: str, payload: ApprovalDecisionInput, db: DbSession,
                       actor: Annotated[User, Depends(approval_decider)]) -> dict[str, object]:
    return _decide_approval(approval_id, db, actor, "REJECTED", payload.reason)


@router.get("/status")
def kubernetes_status(_actor: Annotated[User, Depends(reader)]) -> dict[str, object]:
    provider = _provider()
    try:
        return provider.health()
    except KubernetesUnavailable:
        return {"available": False, "provider": provider.provider, "status": "UNAVAILABLE", "simulation": False}


@router.get("/nodes")
def kubernetes_nodes(_actor: Annotated[User, Depends(reader)]) -> dict[str, object]:
    provider = _provider()
    try:
        return {"provider": provider.provider, "items": provider.nodes()}
    except KubernetesUnavailable:
        return {"provider": provider.provider, "status": "UNAVAILABLE", "items": []}


@router.get("/pods")
def kubernetes_pods(_actor: Annotated[User, Depends(reader)], namespace: str | None = Query(default=None, max_length=63)) -> dict[str, object]:
    provider = _provider()
    try:
        if namespace:
            namespace = validate_resource_name(namespace)
        return {"provider": provider.provider, "items": provider.pods(namespace)}
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="Invalid Kubernetes namespace") from exc
    except KubernetesUnavailable:
        return {"provider": provider.provider, "status": "UNAVAILABLE", "items": []}


@router.get("/conditions")
def kubernetes_conditions(_actor: Annotated[User, Depends(reader)]) -> dict[str, object]:
    provider = _provider()
    try:
        return {"provider": provider.provider, "conditions": detect_conditions(provider)}
    except KubernetesUnavailable:
        return {"provider": provider.provider, "status": "UNAVAILABLE", "conditions": []}


@router.get("/conditions/history")
def kubernetes_condition_history(db: DbSession, _actor: Annotated[User, Depends(reader)],
                                 limit: int = Query(default=100, ge=1, le=500)) -> list[dict[str, object]]:
    rows = db.scalars(select(KubernetesCondition).order_by(desc(KubernetesCondition.last_seen)).limit(limit))
    return [{"id": row.id, "fingerprint": row.fingerprint, "provider": row.provider, "cluster_id": row.cluster_id,
             "condition_type": row.condition_type, "namespace": row.namespace, "resource": row.resource,
             "summary": row.summary, "status": row.status, "first_seen": row.first_seen,
             "last_seen": row.last_seen, "occurrence_count": row.occurrence_count,
             "incident_id": row.incident_id, "resolved_at": row.resolved_at}
            for row in rows]


@router.post("/poll")
def kubernetes_poll(db: DbSession, actor: Annotated[User, Depends(ingester)]) -> dict[str, object]:
    result = poll_and_create_incidents(db, _provider(), actor=actor)
    result["incidents"] = [{"id": item.id, "summary": item.summary, "severity": item.severity} for item in result["incidents"]]
    return result


@router.post("/demo/run")
def run_demo(db: DbSession, actor: Annotated[User, Depends(ingester)]) -> dict[str, object]:
    if not get_settings().demo_mode:
        raise HTTPException(status_code=404, detail="Deterministic demo mode is disabled")
    result = poll_and_create_incidents(db, configured_provider(), actor=actor)
    _audit_global(db, actor, "kubernetes.demo", result["status"], {
        "conditions": len(result["conditions"]), "incidents_created": len(result["incidents"]),
        "provider": result["provider"],
    })
    db.commit()
    result["incidents"] = [{"id": item.id, "summary": item.summary, "severity": item.severity,
                            "ai_status": item.ai_status, "pqc_status": item.pqc_status,
                            "blockchain_status": item.blockchain_status} for item in result["incidents"]]
    return result


@router.get("/incidents")
def kubernetes_incidents(db: DbSession, _actor: Annotated[User, Depends(reader)], limit: int = Query(default=50, ge=1, le=200)) -> list[dict[str, object]]:
    rows = db.scalars(select(Incident).where(Incident.source == "kubernetes").order_by(desc(Incident.created_at)).limit(limit))
    return [{"id": row.id, "incident_type": row.incident_type, "summary": row.summary, "severity": row.severity,
             "status": row.status, "ai_status": row.ai_status, "created_at": row.created_at,
             "classification": row.classification, "recommended_action": row.recommended_action,
             "namespace": (row.attributes or {}).get("namespace"), "resource": (row.attributes or {}).get("resource"),
             "response_policy": {"decision": evaluate_response_policy(row.severity).decision,
                                 "reason": evaluate_response_policy(row.severity).reason,
                                 "approval_required": evaluate_response_policy(row.severity).approval_required}}
            for row in rows]


@router.post("/policy/evaluate")
def response_policy(payload: PolicyInput, db: DbSession, actor: Annotated[User, Depends(reader)]) -> dict[str, object]:
    decision = evaluate_response_policy(payload.severity, requested_action=payload.action)
    result = {"severity": decision.severity, "decision": decision.decision, "allowed_actions": list(decision.allowed_actions),
              "approval_required": decision.approval_required, "reason": decision.reason}
    _audit_global(db, actor, "response.policy", decision.decision.upper(), result)
    db.commit()
    return result


@router.post("/remediations/simulate")
def simulate_remediation(payload: RemediationInput, db: DbSession, actor: Annotated[User, Depends(executor)]) -> dict[str, object]:
    incident = db.get(Incident, payload.incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return execute_remediation(db, incident=incident, actor=actor, provider=_provider(), action=payload.action,
                               namespace=payload.namespace, deployment=payload.deployment, replicas=payload.replicas,
                               approval_id=payload.approval_id, simulate=True)


@router.post("/remediations/execute")
def execute_remediation_endpoint(payload: RemediationInput, db: DbSession, actor: Annotated[User, Depends(executor)]) -> dict[str, object]:
    incident = db.get(Incident, payload.incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return execute_remediation(db, incident=incident, actor=actor, provider=_provider(), action=payload.action,
                               namespace=payload.namespace, deployment=payload.deployment, replicas=payload.replicas,
                               approval_id=payload.approval_id, simulate=False)


@router.post("/remediations/{action_id}/verify")
def verify_remediation(action_id: str, db: DbSession, actor: Annotated[User, Depends(require_permission(Permission.REMEDIATION_VERIFY))]) -> dict[str, object]:
    action = db.get(HealingAction, action_id)
    if action is None:
        raise HTTPException(status_code=404, detail="Remediation action not found")
    if action.mode == "simulation":
        result = "SIMULATION"
        record_event(db, event_type="remediation.verification", actor_id=actor.id,
                     actor_type=actor.role.value, incident_id=action.incident_id,
                     result=result, event_data={"action_id": action.id, "cluster_mutated": False})
        db.commit()
    else:
        try:
            details = json.loads(action.details or "{}")
            provider = _provider()
            namespace, name = validate_resource_name(details["namespace"]), validate_resource_name(details["deployment"])
            before = {"metadata": {"generation": details.get("before_generation", 0)}}
            settings = get_settings()
            result, observations = verify_with_retries(
                lambda: next((d for d in provider.deployments(namespace)
                              if (d.get("metadata") or {}).get("name") == name), None),
                action=action.action, before=before, replicas=details.get("replicas"),
                max_attempts=settings.kubernetes_verification_max_attempts,
                delay_seconds=settings.kubernetes_verification_delay_seconds,
            )
            for check in observations:
                record_event(db, event_type="remediation.verification_attempt", actor_id=actor.id,
                             actor_type=actor.role.value, incident_id=action.incident_id,
                             result=check["status"], event_data={"action_id": action.id, **check})
            action.verification_status = result
            action.status = "verified" if result == "VERIFIED" else result.lower()
            action.verified_at = datetime.now(timezone.utc) if result == "VERIFIED" else None
        except (KubernetesUnavailable, ValueError, KeyError, json.JSONDecodeError):
            result = "UNAVAILABLE"
            action.verification_status = result
        record_event(db, event_type="remediation.verification", actor_id=actor.id, actor_type=actor.role.value,
                     incident_id=action.incident_id, result=result, event_data={"action_id": action.id, "action": action.action})
        db.commit()
    return {"id": action.id, "status": action.status.upper(), "verification_status": result, "mode": action.mode}


@router.get("/remediations")
def list_remediations(db: DbSession, _actor: Annotated[User, Depends(reader)], limit: int = Query(default=50, ge=1, le=200)) -> list[dict[str, object]]:
    rows = db.scalars(select(HealingAction).order_by(desc(HealingAction.created_at)).limit(limit))
    return [{"id": row.id, "incident_id": row.incident_id, "action": row.action, "status": row.status.upper(),
             "mode": row.mode.upper(), "verification_status": row.verification_status.upper(),
             "details": row.details, "created_at": row.created_at} for row in rows]


@router.get("/audit")
def kubernetes_audit(db: DbSession, _actor: Annotated[User, Depends(require_permission(Permission.AUDIT_READ))], limit: int = Query(default=100, ge=1, le=500)) -> list[dict[str, object]]:
    from backend.app.models.audit_event import AuditEvent
    event_prefixes = ("kubernetes.%", "remediation.%", "response.%", "pqc.%",
                      "blockchain.%", "ai.%", "healing.%", "severity.%")
    event_filter = AuditEvent.event_type.like(event_prefixes[0])
    for prefix in event_prefixes[1:]:
        event_filter = event_filter | AuditEvent.event_type.like(prefix)
    rows = db.scalars(select(AuditEvent).where(event_filter).order_by(desc(AuditEvent.created_at)).limit(limit))
    return [{"id": row.id, "incident_id": row.incident_id, "actor_type": row.actor_type,
             "event_type": row.event_type, "result": row.result, "event_data": row.event_data, "created_at": row.created_at} for row in rows]
