"""Health endpoint — liveness check used by the frontend at boot."""
from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel

from api.core.config import SERVICE_NAME

router = APIRouter()


class HealthResponse(BaseModel):
    status: str
    service: str


@router.get("/api/health", response_model=HealthResponse)
def get_health() -> HealthResponse:
    """Return liveness status. Used by `web/` at startup to verify backend is reachable."""
    return HealthResponse(status="ok", service=SERVICE_NAME)
