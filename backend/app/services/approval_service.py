from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.core.config import get_settings
from backend.app.models.healing_action import HealingAction
from backend.app.models.incident import Incident
from backend.app.models.remediation_approval import RemediationApproval
from backend.app.models.user import User, UserRole
from backend.app.services.audit_service import record_event
from kubernetes.actions import ALLOWED_ACTIONS
from kubernetes.providers import validate_resource_name
from kubernetes.response_policy import evaluate_response_policy


def _allowed_names(setting: str) -> set[str]:
    settings = get_settings()
    value = settings.kubernetes_allowed_namespaces if setting == "namespaces" else settings.kubernetes_allowed_deployments
    if not value and settings.demo_mode:
        return {"demo"} if setting == "namespaces" else {"checkout-api"}
    return {name.strip() for name in value.split(",") if name.strip()}


class ApprovalWorkflowError(ValueError):
    def __init__(self, message: str, status_code: int = 409):
        super().__init__(message)
        self.status_code = status_code


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


def _audit(db: Session, *, approval: RemediationApproval | None, incident_id: str,
           actor: User, result: str, data: dict[str, object]) -> None:
    record_event(db, event_type="remediation.approval", actor_id=actor.id,
                 actor_type=actor.role.value, incident_id=incident_id, result=result,
                 event_data={"approval_id": approval.id if approval else None, **data})


def _validate_resource(action: str, params: dict[str, object]) -> dict[str, object]:
    if action not in ALLOWED_ACTIONS:
        raise ApprovalWorkflowError("Action is not allowlisted", 422)
    try:
        namespace = validate_resource_name(str(params.get("namespace", "")))
        deployment = validate_resource_name(str(params.get("deployment", "")))
    except ValueError as exc:
        raise ApprovalWorkflowError("Invalid Kubernetes resource name", 422) from exc
    if namespace not in _allowed_names("namespaces") or deployment not in _allowed_names("deployments"):
        raise ApprovalWorkflowError("Namespace or Deployment is not on the server allowlist", 403)
    if action == "scale_deployment":
        replicas = params.get("replicas")
        if not isinstance(replicas, int) or isinstance(replicas, bool) or not 1 <= replicas <= get_settings().kubernetes_max_replicas:
            raise ApprovalWorkflowError("Replica count is outside configured limits", 422)
    elif params.get("replicas") is not None:
        raise ApprovalWorkflowError("Restart action does not accept a replica count", 422)
    return {"namespace": namespace, "deployment": deployment, "replicas": params.get("replicas")}


def request_approval(
    db: Session, *, incident: Incident, actor: User, action: str,
    params: dict[str, object], reason: str,
) -> RemediationApproval:
    if incident.status in {"resolved", "dismissed"}:
        raise ApprovalWorkflowError("Cannot request remediation for a closed incident")
    try:
        normalized = _validate_resource(action, params)
    except ApprovalWorkflowError as exc:
        record_event(db, event_type="remediation.approval", actor_id=actor.id,
                     actor_type=actor.role.value, incident_id=incident.id, result="BLOCKED",
                     event_data={"action": action, "reason": str(exc)})
        db.commit()
        raise
    policy = evaluate_response_policy(incident.severity, requested_action=action)
    if policy.decision == "blocked":
        record_event(db, event_type="remediation.approval", actor_id=actor.id,
                     actor_type=actor.role.value, incident_id=incident.id, result="blocked",
                     event_data={"action": action, "reason": policy.reason})
        db.commit()
        raise ApprovalWorkflowError(policy.reason, 403)
    existing = db.scalar(select(RemediationApproval).where(
        RemediationApproval.incident_id == incident.id,
        RemediationApproval.requested_by == actor.id,
        RemediationApproval.requested_action == action,
        RemediationApproval.decision == "PENDING",
    ))
    if existing and existing.action_parameters == normalized and _aware(existing.expires_at) > _now():
        _audit(db, approval=existing, incident_id=incident.id, actor=actor, result="duplicate_request",
               data={"action": action})
        db.commit()
        return existing
    if existing and _aware(existing.expires_at) <= _now():
        existing.decision = "EXPIRED"
        existing.decided_at = _now()
        existing.reason = "Approval request expired"
        _audit(db, approval=existing, incident_id=incident.id, actor=actor, result="EXPIRED",
               data={"requested_action": existing.requested_action})
    settings = get_settings()
    approval = RemediationApproval(
        incident_id=incident.id, requested_action=action, action_parameters=normalized,
        policy_decision=policy.decision, policy_reason=policy.reason,
        requested_by=actor.id, requested_at=_now(), decision="PENDING",
        expires_at=_now() + timedelta(minutes=settings.kubernetes_approval_ttl_minutes),
        requester_reason=reason[:1000] if reason else None,
    )
    db.add(approval)
    db.flush()
    _audit(db, approval=approval, incident_id=incident.id, actor=actor, result="PENDING",
           data={"action": action, "parameters": normalized, "policy_decision": policy.decision,
                 "policy_reason": policy.reason, "expires_at": approval.expires_at.isoformat()})
    db.commit()
    db.refresh(approval)
    return approval


def expire_pending_approvals(db: Session) -> int:
    now = _now()
    pending = list(db.scalars(select(RemediationApproval).where(
        RemediationApproval.decision == "PENDING", RemediationApproval.expires_at <= now
    )))
    for approval in pending:
        approval.decision, approval.decided_at = "EXPIRED", now
        approval.reason = "Approval request expired"
        record_event(db, event_type="remediation.approval", actor_type="SYSTEM",
                     incident_id=approval.incident_id, result="EXPIRED",
                     event_data={"approval_id": approval.id, "requested_action": approval.requested_action})
    if pending:
        db.commit()
    return len(pending)


def decide_approval(db: Session, *, approval: RemediationApproval, actor: User,
                    decision: str, reason: str | None = None) -> RemediationApproval:
    if actor.role not in {UserRole.ADMINISTRATOR, UserRole.OPERATOR}:
        raise ApprovalWorkflowError("Only operators and administrators may decide approvals", 403)
    if approval.decision != "PENDING":
        _audit(db, approval=approval, incident_id=approval.incident_id, actor=actor,
               result="BLOCKED", data={"reason": "approval_not_pending", "state": approval.decision})
        db.commit()
        raise ApprovalWorkflowError(f"Approval is already {approval.decision.lower()}")
    now = _now()
    if _aware(approval.expires_at) <= now:
        approval.decision, approval.decided_at = "EXPIRED", now
        approval.reason = "Approval request expired"
        _audit(db, approval=approval, incident_id=approval.incident_id, actor=actor,
               result="EXPIRED", data={"requested_action": approval.requested_action})
        db.commit()
        raise ApprovalWorkflowError("Approval request expired")
    if decision == "APPROVED" and get_settings().kubernetes_approval_separation_of_duties and approval.requested_by == actor.id:
        _audit(db, approval=approval, incident_id=approval.incident_id, actor=actor,
               result="BLOCKED", data={"reason": "separation_of_duties"})
        db.commit()
        raise ApprovalWorkflowError("Requester cannot approve their own request", 403)
    incident = db.get(Incident, approval.incident_id)
    if incident is None or incident.status in {"resolved", "dismissed"} or approval.remediation_action_id:
        _audit(db, approval=approval, incident_id=approval.incident_id, actor=actor,
               result="BLOCKED", data={"reason": "incident_closed_or_action_already_linked"})
        db.commit()
        raise ApprovalWorkflowError("Incident is closed or approval is already linked to a completed action")
    try:
        normalized = _validate_resource(approval.requested_action, approval.action_parameters)
    except ApprovalWorkflowError as exc:
        _audit(db, approval=approval, incident_id=approval.incident_id, actor=actor,
               result="BLOCKED", data={"reason": str(exc)})
        db.commit()
        raise
    policy = evaluate_response_policy(incident.severity, requested_action=approval.requested_action)
    if policy.decision == "blocked":
        _audit(db, approval=approval, incident_id=approval.incident_id, actor=actor,
               result="BLOCKED", data={"reason": policy.reason})
        db.commit()
        raise ApprovalWorkflowError(policy.reason, 403)
    approval.action_parameters = normalized
    approval.decision = decision
    approval.decided_by = actor.id
    approval.decided_at = now
    approval.reason = (reason or ("Approved by authorized operator" if decision == "APPROVED" else "Rejected by authorized operator"))[:1000]
    _audit(db, approval=approval, incident_id=approval.incident_id, actor=actor,
           result=decision, data={"requested_action": approval.requested_action, "reason": approval.reason})
    db.commit()
    db.refresh(approval)
    return approval


def approval_is_valid_for_execution(db: Session, *, approval_id: str | None, incident: Incident,
                                    actor: User, action: str, params: dict[str, object]) -> tuple[RemediationApproval | None, str | None]:
    if not approval_id:
        return None, "A persistent approved request is required for real remediation"
    approval = db.get(RemediationApproval, approval_id)
    if approval is None:
        return None, "Approval request does not exist"
    if approval.decision in {"PENDING", "APPROVED"} and _aware(approval.expires_at) <= _now():
        approval.decision, approval.decided_at, approval.reason = "EXPIRED", _now(), "Approval request expired"
        _audit(db, approval=approval, incident_id=incident.id, actor=actor, result="EXPIRED",
               data={"requested_action": approval.requested_action})
        db.commit()
        return None, "Approval request expired"
    if approval.decision != "APPROVED":
        return None, f"Approval state is {approval.decision}"
    if incident.status in {"resolved", "dismissed"}:
        return None, "Incident is closed"
    if actor.role not in {UserRole.ADMINISTRATOR, UserRole.OPERATOR}:
        return None, "Only operators and administrators may execute remediation"
    if approval.incident_id != incident.id or approval.requested_action != action or approval.action_parameters != params:
        return None, "Approval does not match incident, action, and parameters"
    if approval.remediation_action_id is not None:
        return None, "Approval has already been consumed"
    settings = get_settings()
    if settings.kubernetes_approval_separation_of_duties and approval.decided_by in {None, approval.requested_by}:
        return None, "Approval does not satisfy separation of duties"
    approver = db.get(User, approval.decided_by) if approval.decided_by else None
    if approver is None or approver.role not in {UserRole.ADMINISTRATOR, UserRole.OPERATOR} or not approver.is_active:
        return None, "Approver is no longer authorized"
    return approval, None
