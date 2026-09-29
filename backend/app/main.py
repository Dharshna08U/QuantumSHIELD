import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.app.api.auth import router as auth_router
from backend.app.api.errors import register_error_handlers
from backend.app.api.incidents import router as incidents_router
from backend.app.api.kubernetes import router as kubernetes_router
from backend.app.core.config import get_settings
from backend.app.core.database import SessionLocal
from kubernetes.providers import configured_provider
from kubernetes.watcher import KubernetesWatchService

settings = get_settings()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    stop_event = asyncio.Event()
    task = None
    if settings.kubernetes_watch_enabled:
        watcher = KubernetesWatchService(
            SessionLocal, interval_seconds=settings.kubernetes_watch_interval_seconds,
            provider_factory=configured_provider,
        )
        task = asyncio.create_task(watcher.run(stop_event), name="quantumshield-kubernetes-watch")
    try:
        yield
    finally:
        if task is not None:
            stop_event.set()
            await task

app = FastAPI(
    title="QuantumSHIELD API",
    version="0.1.0",
    description="Security incident orchestration foundation",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH"],
    allow_headers=["Authorization", "Content-Type"],
)
app.include_router(auth_router)
app.include_router(incidents_router)
app.include_router(kubernetes_router)
register_error_handlers(app)


@app.get("/health", tags=["health"])
def health() -> dict[str, str]:
    return {"status": "ok", "environment": settings.app_env}
