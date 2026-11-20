"""Per-plan LLM explanation caching."""
from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from api.core.errors import NotFoundError


def _fake_topk():
    return {
        "goal": "Web Server A",
        "k_requested": 2, "k_returned": 2,
        "plans": [
            {"index": 0, "steps": ["(a)"], "step_count": 1, "cost": 5,
             "highlights": {"node_ids": [], "edge_ids": [], "cve_ids": [], "goal_node_id": "n3"}},
            {"index": 1, "steps": ["(a)", "(b)"], "step_count": 2, "cost": 6,
             "highlights": {"node_ids": [], "edge_ids": [], "cve_ids": [], "goal_node_id": "n3"}},
        ],
    }


def test_generate_topk_explanation_caches_per_index(monkeypatch, tmp_path):
    from api.services.acg import llm_service, topk_service

    monkeypatch.setattr(topk_service, "EXPLANATIONS_DIR", tmp_path / "explanations")
    monkeypatch.setattr(topk_service, "get_last_topk", _fake_topk)

    with patch.object(llm_service, "_resolve_credentials",
                      return_value=("http://x", "fake-model", "k")):
        with patch.object(llm_service, "_stream_completion",
                          return_value=("Plan 0 narrative", "reasoning")):
            first = llm_service.generate_topk_explanation(0)
    assert first["text"] == "Plan 0 narrative"
    assert first["cached"] is False

    # Cached fetch — no LLM call should happen.
    with patch.object(llm_service, "_stream_completion",
                      side_effect=AssertionError("should not be called")):
        second = llm_service.generate_topk_explanation(0)
    assert second["cached"] is True
    assert second["text"] == "Plan 0 narrative"


def test_generate_topk_explanation_index_out_of_range(monkeypatch, tmp_path):
    from api.services.acg import llm_service, topk_service

    monkeypatch.setattr(topk_service, "EXPLANATIONS_DIR", tmp_path / "explanations")
    monkeypatch.setattr(topk_service, "get_last_topk", _fake_topk)

    with pytest.raises(NotFoundError):
        llm_service.generate_topk_explanation(99)


def test_get_cached_topk_explanation_invalidates_on_goal_change(monkeypatch, tmp_path):
    from api.services.acg import llm_service, topk_service

    explanations_dir = tmp_path / "explanations"
    explanations_dir.mkdir()
    monkeypatch.setattr(topk_service, "EXPLANATIONS_DIR", explanations_dir)
    monkeypatch.setattr(topk_service, "get_last_topk", _fake_topk)

    (explanations_dir / "plan_0.json").write_text(
        json.dumps({"goal": "Old Goal", "text": "stale", "model": "m"}),
        encoding="utf-8",
    )
    assert llm_service.get_cached_topk_explanation(0) is None
