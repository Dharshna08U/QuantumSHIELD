from sqlalchemy.orm import Session

from backend.app.models.audit_event import AuditEvent


def record_event(
    db: Session,
    *,
    event_type: str,
    actor_id: str | None = None,
    incident_id: str | None = None,
    actor_type: str = "system",
    result: str = "success",
    event_data: dict[str, object] | None = None,
) -> AuditEvent:
    event = AuditEvent(
        event_type=event_type,
        actor_id=actor_id,
        actor_type=actor_type,
        incident_id=incident_id,
        result=result,
        event_data=event_data or {},
    )
    db.add(event)
    db.flush()
    return event
