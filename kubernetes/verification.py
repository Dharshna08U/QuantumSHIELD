"""Post-action Deployment checks that do not depend on a live Kubernetes SDK."""
from time import sleep as default_sleep
from typing import Any, Callable

from kubernetes.providers import KubernetesTimeout, KubernetesUnavailable


def verify_deployment_action(
    action: str, before: dict[str, Any], after: dict[str, Any] | None, replicas: int | None = None,
) -> bool:
    if after is None:
        return False
    status = after.get("status") or {}
    spec = after.get("spec") or {}
    if action == "scale_deployment":
        return spec.get("replicas") == replicas and int(status.get("readyReplicas", 0) or 0) >= int(replicas or 0)
    if action != "restart_deployment":
        return False
    old_generation = int((before.get("metadata") or {}).get("generation", 0) or 0)
    meta = after.get("metadata") or {}
    observed = int(status.get("observedGeneration", 0) or 0)
    return int(meta.get("generation", 0) or 0) > old_generation and observed >= int(meta.get("generation", 0) or 0)


def verify_with_retries(
    fetch: Callable[[], dict[str, Any] | None], *, action: str,
    before: dict[str, Any], replicas: int | None, max_attempts: int,
    delay_seconds: float, sleeper: Callable[[float], None] = default_sleep,
) -> tuple[str, list[dict[str, Any]]]:
    """Bounded convergence check. A mismatch is pending until attempts are exhausted."""
    attempts = max(1, min(int(max_attempts), 30))
    delay = max(0.0, min(float(delay_seconds), 60.0))
    observations: list[dict[str, Any]] = []
    for attempt in range(1, attempts + 1):
        try:
            current = fetch()
        except KubernetesTimeout:
            observations.append({"attempt": attempt, "status": "TIMEOUT"})
            if attempt == attempts:
                return "TIMEOUT", observations
        except KubernetesUnavailable:
            observations.append({"attempt": attempt, "status": "UNAVAILABLE"})
            if attempt == attempts:
                return "UNAVAILABLE", observations
        else:
            verified = verify_deployment_action(action, before, current, replicas)
            status = "VERIFIED" if verified else "PENDING"
            meta = (current or {}).get("metadata") or {}
            state = (current or {}).get("status") or {}
            observations.append({"attempt": attempt, "status": status,
                                 "generation": meta.get("generation"),
                                 "observed_generation": state.get("observedGeneration"),
                                 "replicas": ((current or {}).get("spec") or {}).get("replicas"),
                                 "ready_replicas": state.get("readyReplicas")})
            if verified:
                return "VERIFIED", observations
            if attempt == attempts:
                return "TIMEOUT", observations
        if delay and attempt < attempts:
            sleeper(delay)
    return "TIMEOUT", observations
