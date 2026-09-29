"""Persistent Kubernetes observation correlation and incident intake."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.models.incident import Incident
from backend.app.models.kubernetes_condition import KubernetesCondition
from backend.app.models.user import User
from backend.app.services.audit_service import record_event
from backend.app.services.incident_pipeline import IncidentPipeline
from kubernetes.detection import condition_description, detect_conditions
from kubernetes.providers import KubernetesProvider, KubernetesUnavailable


def normalized_snapshot(provider: KubernetesProvider) -> dict[str, Any]:
    health = provider.health()
    if not health.get("available"):
        raise KubernetesUnavailable("Kubernetes provider is unavailable")
    return {
        "provider": health.get("provider", provider.provider),
        "cluster_id": getattr(provider, "cluster_id", provider.provider),
        "available": bool(health.get("available")),
        "simulation": bool(health.get("simulation", provider.provider in {"mock", "demo"})),
        "nodes": provider.nodes(), "namespaces": provider.namespaces(), "pods": provider.pods(),
        "deployments": provider.deployments(), "events": provider.events(),
    }


def _actor(actor: User | None) -> tuple[str | None, str]:
    return (actor.id, actor.role.value) if actor else (None, "SYSTEM")


def poll_and_create_incidents(
    db: Session, provider: KubernetesProvider, *, actor: User | None = None,
) -> dict[str, Any]:
    """Observe once, persist condition state, and send each new/reopened finding through Phase 2."""
    actor_id, actor_type = _actor(actor)
    try:
        snapshot = normalized_snapshot(provider)
    except KubernetesUnavailable:
        record_event(db, event_type="kubernetes.observation", actor_id=actor_id, actor_type=actor_type,
                     result="unavailable", event_data={"provider": provider.provider})
        db.commit()
        return {"provider": provider.provider, "available": False, "conditions": [], "incidents": [], "status": "UNAVAILABLE"}

    conditions = detect_conditions(provider, observations=snapshot)
    observed_fingerprints = {item["fingerprint"] for item in conditions}
    active_rows = list(db.scalars(select(KubernetesCondition).where(
        KubernetesCondition.status == "ACTIVE",
        KubernetesCondition.provider == snapshot["provider"],
        KubernetesCondition.cluster_id == snapshot["cluster_id"],
    )))
    active_by_fingerprint = {row.fingerprint: row for row in active_rows}
    created: list[Incident] = []
    now = datetime.now(timezone.utc)
    record_event(db, event_type="kubernetes.observation", actor_id=actor_id, actor_type=actor_type,
                 result="success", event_data={"provider": snapshot["provider"],
                 "cluster_id": snapshot["cluster_id"], "pod_count": len(snapshot["pods"]),
                 "node_count": len(snapshot["nodes"])})

    for condition in conditions:
        row = db.scalar(select(KubernetesCondition).where(
            KubernetesCondition.fingerprint == condition["fingerprint"]
        ).with_for_update())
        reopened = False
        new_incident = row is None or row.status != "ACTIVE"
        if row is None:
            row = KubernetesCondition(
                fingerprint=condition["fingerprint"], provider=snapshot["provider"], cluster_id=snapshot["cluster_id"],
                condition_type=condition["condition_type"], namespace=condition["namespace"],
                resource=condition["resource"], summary=condition["summary"], status="ACTIVE",
                first_seen=now, last_seen=now, occurrence_count=1,
                observation=condition,
            )
            db.add(row)
            db.flush()
        else:
            reopened = row.status in {"RESOLVED", "SUPPRESSED"}
            row.status = "ACTIVE"
            row.last_seen = now
            row.occurrence_count += 1
            row.observation = condition
            row.resolved_at = None

        record_event(db, event_type="kubernetes.condition_observed", actor_id=actor_id,
                     actor_type=actor_type, incident_id=row.incident_id,
                     result="new" if new_incident else "duplicate",
                     event_data={"condition_id": row.id, "fingerprint": row.fingerprint,
                                 "occurrence_count": row.occurrence_count,
                                 "reopened": reopened, "status": row.status})
        if not new_incident:
            continue

        incident = IncidentPipeline().submit(
            db, actor=actor, source="kubernetes", incident_type=condition["condition_type"],
            summary=condition["summary"], description=condition_description(condition),
            attributes={"kubernetes_fingerprint": condition["fingerprint"],
                        "condition_id": row.id, "condition_occurrence": row.occurrence_count,
                        "namespace": condition["namespace"], "resource": condition["resource"],
                        "condition": condition},
        )
        row.incident_id = incident.id
        created.append(incident)

    # Only a successful complete snapshot can resolve an active condition.
    for row in active_rows:
        if row.fingerprint in observed_fingerprints:
            continue
        row.status = "RESOLVED"
        row.resolved_at = now
        record_event(db, event_type="kubernetes.condition_resolved", actor_id=actor_id,
                     actor_type=actor_type, incident_id=row.incident_id,
                     result="resolved", event_data={"condition_id": row.id,
                     "fingerprint": row.fingerprint, "occurrence_count": row.occurrence_count})

    db.commit()
    return {"provider": snapshot["provider"], "cluster_id": snapshot["cluster_id"],
            "available": True, "conditions": conditions, "incidents": created,
            "status": "SIMULATION" if snapshot["simulation"] else "OBSERVED"}


def audit_response(db: Session, *, incident_id: str, actor: User, event_type: str,
                   result: str, data: dict[str, Any]) -> None:
    record_event(db, event_type=event_type, actor_id=actor.id, actor_type=actor.role.value,
                 incident_id=incident_id, result=result, event_data=data)
