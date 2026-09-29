from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import desc, select

from backend.app.api.dependencies import DbSession, Permission, require_permission
from backend.app.models.audit_event import AuditEvent
from backend.app.models.incident import Incident
from backend.app.models.user import User, UserRole
from backend.app.schemas.incident import (
    AuditEventRead,
    IncidentCreate,
    IncidentRead,
    IncidentStatus,
    IncidentStatusUpdate,
)
from backend.app.services.audit_service import record_event
from backend.app.services.incident_pipeline import IncidentPipeline, RequiredEncryptionUnavailable
from blockchain_service.client import BlockchainUnavailable, configured_client

router = APIRouter(prefix="/api/v1/incidents", tags=["incidents"])
read_incident = require_permission(Permission.INCIDENT_READ)
create_incident = require_permission(Permission.INCIDENT_CREATE)
triage_incident = require_permission(Permission.INCIDENT_TRIAGE)
update_status_permission = require_permission(Permission.INCIDENT_STATUS_UPDATE)
audit_permission = require_permission(Permission.AUDIT_READ)


@router.post("", response_model=IncidentRead, status_code=status.HTTP_201_CREATED)
def submit_incident(
    payload: IncidentCreate,
    db: DbSession,
    actor: Annotated[User, Depends(create_incident)],
) -> Incident:
    try:
        return IncidentPipeline().submit(
            db,
            actor=actor,
            source=payload.source,
            incident_type=payload.incident_type,
            summary=payload.summary,
            description=payload.description,
            encryption_required=payload.encryption_required,
            attributes=payload.attributes,
        )
    except RequiredEncryptionUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@router.get("", response_model=list[IncidentRead])
def list_incidents(
    db: DbSession,
    _actor: Annotated[User, Depends(read_incident)],
    severity: str | None = Query(default=None, max_length=24),
    incident_status: str | None = Query(default=None, alias="status", max_length=32),
    incident_type: str | None = Query(default=None, max_length=120),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> list[Incident]:
    statement = select(Incident)
    if severity:
        statement = statement.where(Incident.severity == severity.lower())
    if incident_status:
        statement = statement.where(Incident.status == incident_status.lower())
    if incident_type:
        statement = statement.where(Incident.incident_type == incident_type)
    return list(db.scalars(statement.order_by(desc(Incident.created_at)).limit(limit).offset(offset)))


@router.get("/{incident_id}", response_model=IncidentRead)
def get_incident(
    incident_id: str,
    db: DbSession,
    _actor: Annotated[User, Depends(read_incident)],
) -> Incident:
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@router.post("/{incident_id}/analyze", response_model=IncidentRead)
def analyze_incident(
    incident_id: str,
    db: DbSession,
    actor: Annotated[User, Depends(triage_incident)],
) -> Incident:
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    if incident.description is None:
        raise HTTPException(status_code=409, detail="Evidence is not available for re-analysis")
    if incident.blockchain_status in {"recorded", "mock_recorded"}:
        raise HTTPException(status_code=409, detail="Incident integrity record is immutable after ledger recording")
    return IncidentPipeline().analyze(db, incident, actor=actor)


@router.patch("/{incident_id}/status", response_model=IncidentRead)
def update_incident_status(
    incident_id: str,
    payload: IncidentStatusUpdate,
    db: DbSession,
    actor: Annotated[User, Depends(update_status_permission)],
) -> Incident:
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    new_status: IncidentStatus = payload.status
    allowed_transitions = {
        "detected": {"triaged", "investigating", "dismissed"},
        "triaged": {"investigating", "dismissed", "resolved"},
        "investigating": {"dismissed", "resolved"},
        "resolved": set(),
        "dismissed": set(),
    }
    if new_status not in allowed_transitions.get(incident.status, set()):
        raise HTTPException(status_code=409, detail="Invalid incident status transition")
    if actor.role == UserRole.SECURITY_ANALYST and new_status == "resolved":
        raise HTTPException(status_code=403, detail="Only an operator or administrator may resolve incidents")
    if actor.role == UserRole.OPERATOR and new_status not in {"resolved", "investigating"}:
        raise HTTPException(status_code=403, detail="Operator is not permitted to apply this status")
    if new_status == "resolved" and not payload.note:
        raise HTTPException(status_code=422, detail="A verification note is required to resolve an incident")
    previous = incident.status
    incident.status = new_status
    record_event(
        db,
        event_type="incident.status_changed",
        actor_id=actor.id,
        actor_type="user",
        incident_id=incident.id,
        event_data={"from": previous, "to": new_status, "verification_note_provided": bool(payload.note)},
    )
    db.commit()
    db.refresh(incident)
    return incident


@router.get("/{incident_id}/audit", response_model=list[AuditEventRead])
def incident_audit_trail(
    incident_id: str,
    db: DbSession,
    _actor: Annotated[User, Depends(audit_permission)],
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> list[AuditEvent]:
    if db.get(Incident, incident_id) is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    query = (
        select(AuditEvent)
        .where(AuditEvent.incident_id == incident_id)
        .order_by(AuditEvent.created_at.asc())
        .limit(limit)
        .offset(offset)
    )
    return list(db.scalars(query))


@router.get("/{incident_id}/ledger")
def incident_ledger_record(
    incident_id: str,
    db: DbSession,
    _actor: Annotated[User, Depends(read_incident)],
) -> dict[str, object]:
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    try:
        client = configured_client()
        record = client.get(incident_id)
    except BlockchainUnavailable as exc:
        raise HTTPException(status_code=503, detail="Blockchain provider is unavailable") from exc
    if record is None:
        raise HTTPException(status_code=404, detail="No ledger record exists for this incident")
    return {
        "provider": record.provider,
        "incident_id": record.incident_id,
        "record_hash": record.record_hash,
        "timestamp": record.timestamp,
        "transaction_id": record.transaction_id,
        "integrity_verified": client.verify(incident_id, incident.record_hash or ""),
        "metadata": record.metadata,
    }
