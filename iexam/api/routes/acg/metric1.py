"""ACG Metric 1 routes."""
from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import StreamingResponse

from api.schemas.acg.metric1 import (
    OptionsResponse,
    PrepareResponse,
    ResultsResponse,
    SavedResponse,
    SetHeuristicRequest,
    SetOptionRequest,
)
from api.services.acg import metric1_service

router = APIRouter(prefix="/api/acg/metric1", tags=["acg-metric1"])


@router.post("/prepare", response_model=PrepareResponse)
def prepare() -> PrepareResponse:
    metric1_service.prepare()
    return PrepareResponse(ready=True)


@router.post("/heuristic", response_model=SavedResponse)
def set_heuristic(body: SetHeuristicRequest) -> SavedResponse:
    metric1_service.check_prereqs()
    metric1_service.set_heuristic(body.choice)
    return SavedResponse(saved=True)


@router.post("/options", response_model=OptionsResponse)
def options() -> OptionsResponse:
    return OptionsResponse(options=metric1_service.generate_options())


@router.post("/option", response_model=SavedResponse)
def set_option(body: SetOptionRequest) -> SavedResponse:
    metric1_service.check_prereqs()
    metric1_service.set_option(body.raw)
    return SavedResponse(saved=True)


@router.post("/analyze")
def analyze() -> StreamingResponse:
    metric1_service.check_prereqs()
    return StreamingResponse(
        metric1_service.analyze_stream(),
        media_type="text/event-stream",
    )


@router.get("/results", response_model=ResultsResponse)
def results() -> ResultsResponse:
    return ResultsResponse(**metric1_service.read_results())
