"""topk_service unit tests. ForbidIterative is mocked to keep tests hermetic."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from api.core.errors import InputValidationError


def _seed_pddl_and_goal(monkeypatch, tmp_path):
    """Stand up just enough on-disk state for run_topk to proceed past its guards."""
    pddl_dir = tmp_path / "pddl"
    pddl_dir.mkdir()
    (pddl_dir / "NetDomain.pddl").write_text("(define (domain net))", encoding="utf-8")
    (pddl_dir / "newNetProblem.pddl").write_text(
        "(define (problem p) (:goal (exploited-host-web-server-a)))",
        encoding="utf-8",
    )
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    (data_dir / "goal.txt").write_text("Web Server A", encoding="utf-8")
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    from api.services.acg import plan_service, pddl_service, topk_service

    monkeypatch.setattr(pddl_service, "PDDL_DIR", pddl_dir)
    monkeypatch.setattr(plan_service, "PDDL_DIR", pddl_dir)
    monkeypatch.setattr(plan_service, "DATA_DIR", data_dir)
    monkeypatch.setattr(plan_service, "GOAL_FILE", data_dir / "goal.txt")
    monkeypatch.setattr(plan_service, "NEW_PROBLEM_FILE", pddl_dir / "newNetProblem.pddl")
    monkeypatch.setattr(topk_service, "PDDL_DIR", pddl_dir)
    monkeypatch.setattr(topk_service, "PLAN_RESULTS_DIR", results_dir)
    monkeypatch.setattr(topk_service, "RESULTS_FILE", results_dir / "topk_plans.json")
    monkeypatch.setattr(
        topk_service, "EXPLANATIONS_DIR", results_dir / "topk_explanations"
    )


def test_run_topk_returns_indexed_plan_dicts(monkeypatch, tmp_path):
    _seed_pddl_and_goal(monkeypatch, tmp_path)
    fake = {
        "plans": [
            {"cost": 8, "actions": ["(attacker-has-access-to-web-server-a)"]},
            {
                "cost": 9,
                "actions": [
                    "(attacker-has-access-to-router)",
                    "(attacker-exploit-cve-1-to-compromise-web-server-a-via-router)",
                ],
            },
        ],
        "planner_output": "",
        "planner_error": "",
    }
    with patch("api.services.acg.topk_service.planners.plan_topk", return_value=fake):
        from api.services.acg import topk_service

        result = topk_service.run_topk(2)

    assert result["k_requested"] == 2
    assert result["k_returned"] == 2
    assert [p["index"] for p in result["plans"]] == [0, 1]
    assert result["plans"][0]["cost"] == 8
    assert result["plans"][0]["step_count"] == 1
    assert result["plans"][1]["step_count"] == 2
    assert "highlights" in result["plans"][0]


def test_run_topk_rejects_k_below_min(monkeypatch, tmp_path):
    _seed_pddl_and_goal(monkeypatch, tmp_path)
    from api.services.acg import topk_service

    with pytest.raises(InputValidationError):
        topk_service.run_topk(0)


def test_run_topk_rejects_k_above_max(monkeypatch, tmp_path):
    _seed_pddl_and_goal(monkeypatch, tmp_path)
    from api.services.acg import topk_service

    with pytest.raises(InputValidationError):
        topk_service.run_topk(11)


def test_run_topk_errors_when_problem_missing(monkeypatch, tmp_path):
    _seed_pddl_and_goal(monkeypatch, tmp_path)
    from api.services.acg import plan_service, topk_service

    plan_service.NEW_PROBLEM_FILE.unlink()
    with pytest.raises(InputValidationError, match="Set a goal"):
        topk_service.run_topk(2)


def test_run_topk_surfaces_empty_planner_output(monkeypatch, tmp_path):
    _seed_pddl_and_goal(monkeypatch, tmp_path)
    fake = {"plans": [], "planner_output": "", "planner_error": "bad PDDL"}
    with patch("api.services.acg.topk_service.planners.plan_topk", return_value=fake):
        from api.services.acg import topk_service

        with pytest.raises(InputValidationError, match="no plans"):
            topk_service.run_topk(2)


def test_run_topk_returns_fewer_plans_than_requested(monkeypatch, tmp_path):
    _seed_pddl_and_goal(monkeypatch, tmp_path)
    fake = {
        "plans": [{"cost": 3, "actions": ["(attacker-has-access-to-router)"]}],
        "planner_output": "",
        "planner_error": "",
    }
    with patch("api.services.acg.topk_service.planners.plan_topk", return_value=fake):
        from api.services.acg import topk_service

        result = topk_service.run_topk(5)
    assert result["k_requested"] == 5
    assert result["k_returned"] == 1


def test_clear_topk_removes_results_and_explanations(monkeypatch, tmp_path):
    _seed_pddl_and_goal(monkeypatch, tmp_path)
    from api.services.acg import topk_service

    topk_service.RESULTS_FILE.write_text("{}", encoding="utf-8")
    topk_service.EXPLANATIONS_DIR.mkdir(parents=True, exist_ok=True)
    (topk_service.EXPLANATIONS_DIR / "plan_0.json").write_text("{}", encoding="utf-8")

    topk_service.clear_topk()

    assert not topk_service.RESULTS_FILE.exists()
    assert not topk_service.EXPLANATIONS_DIR.exists()
