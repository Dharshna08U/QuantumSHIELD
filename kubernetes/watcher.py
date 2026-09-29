"""Opt-in supervised polling loop that reuses the shared Kubernetes pipeline."""
from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Any

from sqlalchemy.orm import Session, sessionmaker

from backend.app.services.audit_service import record_event
from backend.app.services.approval_service import expire_pending_approvals
from kubernetes.monitoring import poll_and_create_incidents
from kubernetes.providers import KubernetesProvider, configured_provider


class KubernetesWatchService:
    def __init__(
        self,
        sessions: sessionmaker[Session],
        *,
        interval_seconds: float,
        provider_factory: Callable[[], KubernetesProvider] = configured_provider,
    ):
        self.sessions = sessions
        self.interval_seconds = interval_seconds
        self.provider_factory = provider_factory

    def _audit(self, event: str, result: str, data: dict[str, Any] | None = None) -> None:
        with self.sessions() as db:
            record_event(db, event_type=event, actor_type="SYSTEM", result=result, event_data=data or {})
            db.commit()

    def poll_once(self) -> dict[str, Any]:
        provider = None
        with self.sessions() as db:
            try:
                provider = self.provider_factory()
                expired = expire_pending_approvals(db)
                result = poll_and_create_incidents(db, provider, actor=None)
                record_event(db, event_type="kubernetes.watcher.tick", actor_type="SYSTEM",
                             result=result["status"].lower(), event_data={
                                 "provider": result["provider"], "conditions": len(result["conditions"]),
                                 "incidents_created": len(result["incidents"]),
                                 "approvals_expired": expired,
                             })
                db.commit()
                return result
            except Exception as exc:
                db.rollback()
                record_event(db, event_type="kubernetes.watcher.error", actor_type="SYSTEM",
                             result="failed", event_data={"provider": getattr(provider, "provider", "unavailable"),
                                                          "error_type": type(exc).__name__})
                db.commit()
                return {"provider": getattr(provider, "provider", "unavailable"), "available": False, "status": "FAILED",
                        "conditions": [], "incidents": []}

    async def run(self, stop_event: asyncio.Event) -> None:
        self._audit("kubernetes.watcher", "started", {"interval_seconds": self.interval_seconds})
        try:
            while not stop_event.is_set():
                await asyncio.to_thread(self.poll_once)
                try:
                    await asyncio.wait_for(stop_event.wait(), timeout=self.interval_seconds)
                except TimeoutError:
                    pass
        finally:
            self._audit("kubernetes.watcher", "stopped")
