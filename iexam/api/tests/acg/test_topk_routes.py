"""Top-K route smoke tests."""
from __future__ import annotations

from unittest.mock import patch


def test_get_topk_returns_404_when_no_data(client):
    res = client.get("/api/acg/plan/topk")
    assert res.status_code == 404


def test_post_topk_validates_k(client):
    res = client.post("/api/acg/plan/topk", json={"k": 99})
    assert res.status_code == 422


def test_post_topk_happy_path(client, monkeypatch, tmp_path):
    fake = {
        "goal": "Web Server A",
        "goal_node_id": "n3",
        "k_requested": 2,
        "k_returned": 2,
        "domain": "/tmp/d.pddl",
        "problem": "/tmp/p.pddl",
        "plans": [
            {"index": 0, "steps": ["(a)"], "step_count": 1, "cost": 5,
             "highlights": {"node_ids": [], "edge_ids": [], "cve_ids": [], "goal_node_id": "n3"}},
            {"index": 1, "steps": ["(a)", "(b)"], "step_count": 2, "cost": 6,
             "highlights": {"node_ids": [], "edge_ids": [], "cve_ids": [], "goal_node_id": "n3"}},
        ],
    }
    with patch("api.routes.acg.plan.topk_service.run_topk", return_value=fake):
        res = client.post("/api/acg/plan/topk", json={"k": 2})
    assert res.status_code == 200
    body = res.json()
    assert body["k_returned"] == 2
    assert len(body["plans"]) == 2
    assert body["plans"][1]["cost"] == 6


def test_get_topk_after_run(client):
    with patch("api.routes.acg.plan.topk_service.get_last_topk", return_value={
        "goal": "Web Server A", "goal_node_id": "n3",
        "k_requested": 1, "k_returned": 1, "domain": None, "problem": None,
        "plans": [{"index": 0, "steps": ["(a)"], "step_count": 1, "cost": 5,
                   "highlights": {"node_ids": [], "edge_ids": [], "cve_ids": [], "goal_node_id": "n3"}}],
    }):
        res = client.get("/api/acg/plan/topk")
    assert res.status_code == 200
    assert res.json()["k_returned"] == 1
