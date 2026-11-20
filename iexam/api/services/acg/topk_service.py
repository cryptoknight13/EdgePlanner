"""Top-K attack-plan enumeration via ForbidIterative.

Runs `planners.plan_topk` in-process (it shells out to Fast Downward internally
and returns a dict with pre-parsed plans). Results + per-plan LLM explanations
are cached to disk, keyed by the current goal.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path

from api.core.config import DOWNWARD_DIR, PDDL_DIR, PLAN_RESULTS_DIR
from api.core.errors import InputValidationError
from api.services.acg import dataset_service, pddl_service, plan_service

# ForbidIterative is vendored at Backend/forbiditerative/. Add to sys.path once.
_FORBID_ROOT = DOWNWARD_DIR.parent / "forbiditerative"
if str(_FORBID_ROOT) not in sys.path:
    sys.path.insert(0, str(_FORBID_ROOT))
# planners.py re-launches `python -m forbiditerative.plan`; the child must import the same vendored copy.
os.environ["PYTHONPATH"] = os.pathsep.join(filter(None, [str(_FORBID_ROOT), os.environ.get("PYTHONPATH")]))

from forbiditerative import planners  # noqa: E402  (path-mutated import)

RESULTS_FILE = PLAN_RESULTS_DIR / "topk_plans.json"
EXPLANATIONS_DIR = PLAN_RESULTS_DIR / "topk_explanations"

TOPK_TIMEOUT_SECONDS = 180
K_MIN = 1
K_MAX = 10
K_DEFAULT = 2


def _validate_k(k: int) -> int:
    if not isinstance(k, int) or k < K_MIN or k > K_MAX:
        raise InputValidationError(
            f"k must be between {K_MIN} and {K_MAX}", details={"k": k}
        )
    return k


def run_topk(k: int) -> dict:
    k = _validate_k(k)

    domain_path = PDDL_DIR / pddl_service.DOMAIN_FILENAME
    problem_path = plan_service.NEW_PROBLEM_FILE
    if not domain_path.exists():
        raise InputValidationError("Domain PDDL missing — regenerate on Start")
    if not problem_path.exists():
        raise InputValidationError("Set a goal before running Top-K")

    PLAN_RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    RESULTS_FILE.unlink(missing_ok=True)
    if EXPLANATIONS_DIR.exists():
        shutil.rmtree(EXPLANATIONS_DIR)

    try:
        raw = planners.plan_topk(
            domain_file=domain_path,
            problem_file=problem_path,
            number_of_plans_bound=k,
            timeout=TOPK_TIMEOUT_SECONDS,
            suppress_planner_output=True,
        )
    except Exception as exc:  # ForbidIterative raises broadly; surface cleanly
        raise InputValidationError(
            "Top-K planner crashed", details={"reason": str(exc)}
        ) from exc

    if raw is None or not raw.get("plans"):
        details: dict = {}
        if raw is not None:
            tail = (raw.get("planner_error") or "")[-2000:]
            if tail:
                details["stderr_tail"] = tail
        raise InputValidationError("Planner produced no plans", details=details)

    goal = plan_service.get_current_goal()
    plans_out: list[dict] = []
    for index, plan in enumerate(raw["plans"]):
        actions = list(plan.get("actions") or [])
        highlights = plan_service._extract_highlights(actions, goal)
        plans_out.append(
            {
                "index": index,
                "steps": actions,
                "step_count": len(actions),
                "cost": plan.get("cost"),
                "highlights": highlights,
            }
        )

    goal_node_id = plans_out[0]["highlights"].get("goal_node_id") if plans_out else None
    summary = {
        "goal": goal,
        "goal_node_id": goal_node_id,
        "k_requested": k,
        "k_returned": len(plans_out),
        "domain": str(domain_path),
        "problem": str(problem_path),
        "plans": plans_out,
    }
    RESULTS_FILE.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def get_last_topk() -> dict | None:
    if not RESULTS_FILE.exists():
        return None
    try:
        return json.loads(RESULTS_FILE.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def topk_exists() -> bool:
    return RESULTS_FILE.exists()


def clear_topk() -> None:
    RESULTS_FILE.unlink(missing_ok=True)
    if EXPLANATIONS_DIR.exists():
        shutil.rmtree(EXPLANATIONS_DIR)


def clear_topk_explanation(index: int) -> None:
    path = EXPLANATIONS_DIR / f"plan_{index}.json"
    path.unlink(missing_ok=True)
