"""Conservative rules that label observed conditions, not inferred attacks."""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, dataclass
from typing import Any

from kubernetes.providers import KubernetesProvider


@dataclass(frozen=True)
class DetectionRules:
    restart_threshold: int = 5
    repeated_crash_count: int = 3
    suspicious_event_reasons: tuple[str, ...] = ("FailedMount", "FailedCreate", "FailedScheduling", "BackOff")

    @classmethod
    def from_environment(cls) -> "DetectionRules":
        try:
            from backend.app.core.config import get_settings
            settings = get_settings()
        except (ImportError, AttributeError):
            settings = None
        return cls(
            restart_threshold=max(1, int(settings.kubernetes_restart_threshold if settings else os.getenv("KUBERNETES_RESTART_THRESHOLD", "5"))),
            repeated_crash_count=max(1, int(settings.kubernetes_repeated_crash_count if settings else os.getenv("KUBERNETES_REPEATED_CRASH_COUNT", "3"))),
            suspicious_event_reasons=tuple(x.strip() for x in (settings.kubernetes_event_reasons if settings else os.getenv("KUBERNETES_EVENT_REASONS", "FailedMount,FailedCreate,FailedScheduling,BackOff")).split(",") if x.strip()),
        )


def _metadata(item: dict[str, Any]) -> tuple[str, str, str]:
    meta = item.get("metadata") or {}
    return str(meta.get("namespace", "default")), str(meta.get("name", "unknown")), str(meta.get("uid", ""))


def detect_conditions(
    provider: KubernetesProvider, rules: DetectionRules | None = None,
    *, observations: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    rules = rules or DetectionRules.from_environment()
    found: dict[str, dict[str, Any]] = {}

    def items(key: str, getter):
        return observations[key] if observations is not None and key in observations else getter()

    def add(kind: str, namespace: str, resource: str, title: str, evidence: dict[str, Any]) -> None:
        identity = f"{getattr(provider, 'cluster_id', provider.provider)}:{kind}:{namespace}:{resource}:{title}"
        fingerprint = hashlib.sha256(identity.encode()).hexdigest()
        found[fingerprint] = {
            "fingerprint": fingerprint, "condition_type": kind, "namespace": namespace,
            "resource": resource, "summary": title, "classification": "operational_anomaly",
            "evidence": evidence,
        }

    for pod in items("pods", provider.pods):
        namespace, name, _ = _metadata(pod)
        status = pod.get("status") or {}
        phase = status.get("phase", "Unknown")
        restarts = 0
        crashing = []
        for container in status.get("containerStatuses") or []:
            restarts += int(container.get("restartCount", 0) or 0)
            waiting = ((container.get("state") or {}).get("waiting") or {}).get("reason")
            if waiting == "CrashLoopBackOff":
                crashing.append(str(container.get("name", "container")))
        if crashing and restarts >= rules.repeated_crash_count:
            add("pod_crash_loop", namespace, name, "Pod container is in CrashLoopBackOff", {"containers": crashing, "restart_count": restarts})
        if restarts >= rules.restart_threshold:
            add("excessive_pod_restarts", namespace, name, "Pod restart count exceeds configured threshold", {"restart_count": restarts, "threshold": rules.restart_threshold})
        if phase not in {"Running", "Succeeded"}:
            add("unhealthy_pod", namespace, name, "Pod is not healthy", {"phase": phase, "restart_count": restarts})

    for deployment in items("deployments", provider.deployments):
        namespace, name, _ = _metadata(deployment)
        spec, status = deployment.get("spec") or {}, deployment.get("status") or {}
        desired = int(spec.get("replicas", 1) or 0)
        ready = int(status.get("readyReplicas", 0) or 0)
        if desired > 0 and ready < desired:
            add("failed_deployment", namespace, name, "Deployment has fewer ready replicas than desired", {"desired_replicas": desired, "ready_replicas": ready})

    for node in items("nodes", provider.nodes):
        namespace, name, _ = _metadata(node)
        conditions = (node.get("status") or {}).get("conditions") or []
        ready = next((item.get("status") == "True" for item in conditions if item.get("type") == "Ready"), False)
        if not ready:
            add("unhealthy_node", namespace, name, "Kubernetes node is not Ready", {"conditions": conditions[:20]})

    for event in items("events", provider.events):
        reason = str(event.get("reason", ""))
        if reason not in rules.suspicious_event_reasons:
            continue
        namespace, name, _ = _metadata(event)
        involved = event.get("involvedObject") or {}
        resource = str(involved.get("name") or name)
        add("security_relevant_event" if reason in {"FailedCreate", "FailedMount"} else "operational_event", namespace, resource, f"Kubernetes reported {reason}", {"reason": reason, "event_type": event.get("type", "Unknown")})
    return list(found.values())


def condition_description(condition: dict[str, Any]) -> str:
    """Stable, bounded text for AI analysis and incident evidence."""
    return json.dumps({k: condition[k] for k in ("condition_type", "namespace", "resource", "summary", "evidence")}, sort_keys=True)[:4000]


def deduplicate_conditions(conditions: list[dict[str, Any]], known_fingerprints: set[str]) -> list[dict[str, Any]]:
    """Return only unseen condition identities, updating the supplied seen set."""
    unseen = []
    for condition in conditions:
        fingerprint = condition.get("fingerprint")
        if not isinstance(fingerprint, str) or fingerprint in known_fingerprints:
            continue
        known_fingerprints.add(fingerprint)
        unseen.append(condition)
    return unseen
