"""ACG Plan routes: list goals, set goal, run/get optimal plan."""
from __future__ import annotations

from fastapi import APIRouter

from api.core.errors import NotFoundError
from api.schemas.acg.start import (
    GoalsList,
    PlanExplanation,
    PlanResult,
    RunTopKRequest,
    SetGoalRequest,
    TopKResult,
)
from api.services.acg import llm_service, plan_service, topk_service

router = APIRouter(prefix="/api/acg/plan", tags=["acg-plan"])


@router.get("/goals", response_model=GoalsList)
def get_goals() -> GoalsList:
    return GoalsList(items=plan_service.list_goals(), current=plan_service.get_current_goal())


@router.put("/goal", response_model=GoalsList)
def put_goal(body: SetGoalRequest) -> GoalsList:
    plan_service.set_goal(body.goal)
    return GoalsList(items=plan_service.list_goals(), current=plan_service.get_current_goal())


@router.post("/optimal", response_model=PlanResult)
def run_optimal() -> PlanResult:
    return PlanResult(**plan_service.run_optimal_plan())


@router.get("/optimal", response_model=PlanResult)
def last_optimal() -> PlanResult:
    plan = plan_service.get_last_plan()
    if plan is None:
        raise NotFoundError("No optimal plan has been generated yet")
    return PlanResult(**plan)


@router.post("/optimal/explain", response_model=PlanExplanation)
def explain_optimal() -> PlanExplanation:
    return PlanExplanation(**llm_service.generate_explanation(force=False))


@router.get("/optimal/explain", response_model=PlanExplanation)
def get_explanation() -> PlanExplanation:
    cached = llm_service.get_cached_explanation()
    if cached is None:
        raise NotFoundError("No explanation cached for the current plan")
    return PlanExplanation(**cached)


@router.post("/topk", response_model=TopKResult)
def run_topk(body: RunTopKRequest) -> TopKResult:
    return TopKResult(**topk_service.run_topk(body.k))


@router.get("/topk", response_model=TopKResult)
def last_topk() -> TopKResult:
    result = topk_service.get_last_topk()
    if result is None:
        raise NotFoundError("No Top-K plans have been generated yet")
    return TopKResult(**result)


@router.post("/topk/{index}/explain", response_model=PlanExplanation)
def explain_topk(index: int) -> PlanExplanation:
    return PlanExplanation(**llm_service.generate_topk_explanation(index, force=False))


@router.get("/topk/{index}/explain", response_model=PlanExplanation)
def get_topk_explanation(index: int) -> PlanExplanation:
    cached = llm_service.get_cached_topk_explanation(index)
    if cached is None:
        raise NotFoundError("No explanation cached for this plan")
    return PlanExplanation(**cached)
