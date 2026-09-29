"""Read-only Kubernetes observation plus a narrowly scoped Deployment writer.

The REST adapter deliberately uses the Kubernetes API directly so the project
package named ``kubernetes`` does not shadow the optional official Python SDK.
"""
from __future__ import annotations

import json
import os
import re
import ssl
from datetime import datetime, timezone
from hashlib import sha256
from urllib.parse import urlsplit
from dataclasses import dataclass, field
from typing import Any, Protocol
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


class KubernetesUnavailable(RuntimeError):
    pass


class KubernetesTimeout(KubernetesUnavailable):
    pass


class KubernetesProvider(Protocol):
    provider: str

    def health(self) -> dict[str, Any]: ...
    def nodes(self) -> list[dict[str, Any]]: ...
    def namespaces(self) -> list[dict[str, Any]]: ...
    def pods(self, namespace: str | None = None) -> list[dict[str, Any]]: ...
    def deployments(self, namespace: str | None = None) -> list[dict[str, Any]]: ...
    def events(self, namespace: str | None = None) -> list[dict[str, Any]]: ...
    def act(self, action: str, namespace: str, deployment: str, replicas: int | None = None) -> dict[str, Any]: ...


def validate_resource_name(value: str) -> str:
    if not isinstance(value, str) or len(value) > 63 or not re.fullmatch(r"[a-z0-9](?:[-a-z0-9]*[a-z0-9])?", value):
        raise ValueError("Invalid Kubernetes resource name")
    return value


def _item_namespace(item: dict[str, Any]) -> str | None:
    return item.get("namespace") or (item.get("metadata") or {}).get("namespace")


@dataclass
class UnavailableKubernetesProvider:
    provider: str = "unavailable"

    def _unavailable(self, *_: Any, **__: Any) -> Any:
        raise KubernetesUnavailable("Kubernetes is not configured")

    health = _unavailable
    nodes = _unavailable
    namespaces = _unavailable
    pods = _unavailable
    deployments = _unavailable
    events = _unavailable
    act = _unavailable


@dataclass
class MockKubernetesProvider:
    """Deterministic in-memory provider for tests; responses identify as mock."""
    node_items: list[dict[str, Any]] = field(default_factory=list)
    namespace_items: list[dict[str, Any]] = field(default_factory=list)
    pod_items: list[dict[str, Any]] = field(default_factory=list)
    deployment_items: list[dict[str, Any]] = field(default_factory=list)
    event_items: list[dict[str, Any]] = field(default_factory=list)
    provider: str = "mock"
    cluster_id: str = "mock-cluster"

    def health(self) -> dict[str, Any]:
        return {"available": True, "provider": self.provider, "simulation": True}

    def nodes(self) -> list[dict[str, Any]]: return list(self.node_items)
    def namespaces(self) -> list[dict[str, Any]]: return list(self.namespace_items)

    def pods(self, namespace: str | None = None) -> list[dict[str, Any]]:
        return [p for p in self.pod_items if namespace is None or _item_namespace(p) == namespace]

    def deployments(self, namespace: str | None = None) -> list[dict[str, Any]]:
        return [d for d in self.deployment_items if namespace is None or _item_namespace(d) == namespace]

    def events(self, namespace: str | None = None) -> list[dict[str, Any]]:
        return [e for e in self.event_items if namespace is None or _item_namespace(e) in (None, namespace)]

    def act(self, action: str, namespace: str, deployment: str, replicas: int | None = None) -> dict[str, Any]:
        raise KubernetesUnavailable("Mock provider never mutates a real cluster")


class KubernetesRESTProvider:
    """Authenticated API adapter. Mutation methods are limited to Deployment restart/scale."""
    provider = "kubernetes"

    def __init__(self, api_url: str, token: str, *, ca_file: str | None = None, timeout: float = 3.0):
        if not api_url.startswith("https://") or not token:
            raise ValueError("Kubernetes API requires an HTTPS URL and bearer token")
        self.api_url = api_url.rstrip("/")
        self.cluster_id = sha256(urlsplit(self.api_url).netloc.encode()).hexdigest()[:16]
        self.token = token
        self.context = ssl.create_default_context(cafile=ca_file)
        self.timeout = timeout

    def _request(self, path: str, *, method: str = "GET", body: dict[str, Any] | None = None) -> Any:
        data = json.dumps(body).encode() if body is not None else None
        request = Request(self.api_url + path, data=data, method=method, headers={
            "Authorization": f"Bearer {self.token}", "Accept": "application/json",
            **({"Content-Type": "application/strategic-merge-patch+json"} if body is not None else {}),
        })
        try:
            with urlopen(request, context=self.context, timeout=self.timeout) as response:
                raw = response.read()
                if response.status == 204 or not raw:
                    return {}
                try:
                    return json.loads(raw)
                except json.JSONDecodeError:
                    return {"message": raw.decode("utf-8", errors="replace")}
        except TimeoutError as exc:
            raise KubernetesTimeout("Kubernetes API request timed out") from exc
        except (HTTPError, URLError, OSError, json.JSONDecodeError) as exc:
            if isinstance(exc, URLError) and isinstance(exc.reason, TimeoutError):
                raise KubernetesTimeout("Kubernetes API request timed out") from exc
            raise KubernetesUnavailable("Kubernetes API request failed") from exc

    @staticmethod
    def _items(payload: dict[str, Any]) -> list[dict[str, Any]]:
        return payload.get("items", [])

    def health(self) -> dict[str, Any]:
        self._request("/readyz")
        return {"available": True, "provider": self.provider, "simulation": False}

    def nodes(self) -> list[dict[str, Any]]: return self._items(self._request("/api/v1/nodes"))
    def namespaces(self) -> list[dict[str, Any]]: return self._items(self._request("/api/v1/namespaces"))

    def pods(self, namespace: str | None = None) -> list[dict[str, Any]]:
        path = f"/api/v1/namespaces/{validate_resource_name(namespace)}/pods" if namespace else "/api/v1/pods"
        return self._items(self._request(path))

    def deployments(self, namespace: str | None = None) -> list[dict[str, Any]]:
        path = f"/apis/apps/v1/namespaces/{validate_resource_name(namespace)}/deployments" if namespace else "/apis/apps/v1/deployments"
        return self._items(self._request(path))

    def events(self, namespace: str | None = None) -> list[dict[str, Any]]:
        path = f"/api/v1/namespaces/{validate_resource_name(namespace)}/events" if namespace else "/api/v1/events"
        return self._items(self._request(path))

    def act(self, action: str, namespace: str, deployment: str, replicas: int | None = None) -> dict[str, Any]:
        namespace, deployment = validate_resource_name(namespace), validate_resource_name(deployment)
        path = f"/apis/apps/v1/namespaces/{namespace}/deployments/{deployment}"
        if action == "restart_deployment" and replicas is None:
            timestamp = datetime.now(timezone.utc).isoformat()
            return self._request(path, method="PATCH", body={"spec": {"template": {"metadata": {"annotations": {"quantumshield.io/restarted-at": timestamp}}}}})
        if action == "scale_deployment" and isinstance(replicas, int) and 1 <= replicas <= 10:
            return self._request(path, method="PATCH", body={"spec": {"replicas": replicas}})
        raise ValueError("Action is not allowlisted or its parameters are invalid")


def configured_provider() -> KubernetesProvider:
    try:
        from backend.app.core.config import get_settings
        settings = get_settings()
        mode = "demo" if settings.demo_mode else settings.kubernetes_provider
    except (ImportError, AttributeError):
        settings = None
        mode = "demo" if os.getenv("DEMO_MODE", "false").lower() == "true" else os.getenv("KUBERNETES_PROVIDER", "unavailable").lower()
    if mode == "mock":
        return MockKubernetesProvider()
    if mode == "demo":
        return DemoKubernetesProvider()
    if mode == "rest":
        url = settings.kubernetes_api_url if settings else os.getenv("KUBERNETES_API_URL", "")
        token_value = settings.kubernetes_bearer_token if settings else os.getenv("KUBERNETES_BEARER_TOKEN", "")
        token = token_value.get_secret_value() if hasattr(token_value, "get_secret_value") else token_value
        if not url or not token:
            return UnavailableKubernetesProvider()
        ca_file = settings.kubernetes_ca_file if settings else os.getenv("KUBERNETES_CA_FILE")
        timeout = settings.integration_timeout_seconds if settings else float(os.getenv("INTEGRATION_TIMEOUT_SECONDS", "3"))
        try:
            return KubernetesRESTProvider(url, token, ca_file=ca_file, timeout=timeout)
        except (ValueError, OSError):
            return UnavailableKubernetesProvider()
    return UnavailableKubernetesProvider()


@dataclass
class DemoKubernetesProvider(MockKubernetesProvider):
    """Stable, visibly simulated fixture used only when DEMO_MODE is enabled."""
    provider: str = "demo"
    cluster_id: str = "demo-cluster"
    node_items: list[dict[str, Any]] = field(default_factory=lambda: [{
        "metadata": {"name": "demo-node-1", "uid": "demo-node-1"},
        "status": {"conditions": [{"type": "Ready", "status": "True"}]},
    }])
    namespace_items: list[dict[str, Any]] = field(default_factory=lambda: [{"metadata": {"name": "demo"}}])
    pod_items: list[dict[str, Any]] = field(default_factory=lambda: [{
        "metadata": {"namespace": "demo", "name": "checkout-api-7c9d", "uid": "demo-pod-1"},
        "status": {"phase": "Running", "containerStatuses": [{"name": "api", "restartCount": 8,
            "state": {"waiting": {"reason": "CrashLoopBackOff"}}}]},
    }])
    deployment_items: list[dict[str, Any]] = field(default_factory=lambda: [{
        "metadata": {"namespace": "demo", "name": "checkout-api", "generation": 4},
        "spec": {"replicas": 3}, "status": {"readyReplicas": 1, "observedGeneration": 4},
    }])
    event_items: list[dict[str, Any]] = field(default_factory=lambda: [{
        "metadata": {"namespace": "demo", "name": "demo-event-1"},
        "reason": "BackOff", "type": "Warning", "message": "Demo fixture: container restart back-off",
    }])
