"""Metric 1 route tests."""
from __future__ import annotations

from unittest.mock import patch


def test_metric1_prepare_returns_409_when_prereqs_missing(client, isolated_data_dir):
    res = client.post("/api/acg/metric1/prepare")
    assert res.status_code == 409
    assert res.json()["error"]["code"] == "metric1_prereq_missing"


def test_metric1_prepare_happy(client, isolated_data_dir, monkeypatch, tmp_path):
    from api.core import config as cfg
    (isolated_data_dir / "goal.txt").write_text("Web Server A")
    plan_results = tmp_path / "_build_plan" / "results"
    plan_results.mkdir(parents=True)
    (plan_results / "optimal_plan.json").write_text("{}")
    monkeypatch.setattr(cfg, "PLAN_RESULTS_DIR", plan_results)

    import importlib
    from api.services.acg import metric1_service
    importlib.reload(metric1_service)

    with patch.object(metric1_service, "prepare") as p:
        res = client.post("/api/acg/metric1/prepare")
        assert res.status_code == 200
        assert res.json() == {"ready": True}
        p.assert_called_once()


def test_set_heuristic_validates_choice(client, isolated_data_dir, monkeypatch, tmp_path):
    from api.core import config as cfg
    (isolated_data_dir / "goal.txt").write_text("g")
    plan_results = tmp_path / "_build_plan" / "results"
    plan_results.mkdir(parents=True)
    (plan_results / "optimal_plan.json").write_text("{}")
    monkeypatch.setattr(cfg, "PLAN_RESULTS_DIR", plan_results)
    import importlib
    from api.services.acg import metric1_service
    importlib.reload(metric1_service)

    res = client.post("/api/acg/metric1/heuristic", json={"choice": "maybe"})
    assert res.status_code == 422


def test_set_heuristic_happy(client, isolated_data_dir, monkeypatch, tmp_path):
    from api.core import config as cfg
    m1 = tmp_path / "_metric1"
    (m1 / "data").mkdir(parents=True)
    (isolated_data_dir / "goal.txt").write_text("g")
    plan_results = tmp_path / "_build_plan" / "results"
    plan_results.mkdir(parents=True)
    (plan_results / "optimal_plan.json").write_text("{}")
    monkeypatch.setattr(cfg, "PLAN_RESULTS_DIR", plan_results)
    monkeypatch.setattr(cfg, "METRIC1_DIR", m1)
    import importlib
    from api.services.acg import metric1_service
    importlib.reload(metric1_service)

    res = client.post("/api/acg/metric1/heuristic", json={"choice": "with"})
    assert res.status_code == 200
    assert metric1_service.HEURISTIC_FILE.read_text() == "2"


def test_options_returns_pairs(client, isolated_data_dir, monkeypatch, tmp_path):
    from api.core import config as cfg
    m1 = tmp_path / "_metric1"
    (m1 / "data").mkdir(parents=True)
    handler = tmp_path / "handler"
    handler.mkdir()
    monkeypatch.setattr(cfg, "METRIC1_DIR", m1)
    monkeypatch.setattr(cfg, "HANDLER_DIR", handler)
    (isolated_data_dir / "goal.txt").write_text("g")
    plan_results = tmp_path / "_build_plan" / "results"
    plan_results.mkdir(parents=True)
    (plan_results / "optimal_plan.json").write_text("{}")
    monkeypatch.setattr(cfg, "PLAN_RESULTS_DIR", plan_results)

    import importlib
    from api.services.acg import metric1_service
    importlib.reload(metric1_service)

    def fake_run(cmd, **kwargs):
        import subprocess
        path = str(cmd[1])
        if path.endswith("build_metric1_main.py"):
            (m1 / "data" / "pddl_options.txt").write_text("{'a'}\n")
        elif path.endswith("pddl_option_m1.py"):
            (m1 / "data" / "pddl_options_normalized.txt").write_text("Option 1: a\n")
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(metric1_service.subprocess, "run", fake_run)

    res = client.post("/api/acg/metric1/options")
    assert res.status_code == 200
    assert res.json()["options"] == [{"label": "Option 1: a", "raw": "{'a'}"}]


def test_set_option_rejects_unknown(client, isolated_data_dir, monkeypatch, tmp_path):
    from api.core import config as cfg
    m1 = tmp_path / "_metric1"
    (m1 / "data").mkdir(parents=True)
    (m1 / "data" / "pddl_options.txt").write_text("{'a'}\n")
    (isolated_data_dir / "goal.txt").write_text("g")
    plan_results = tmp_path / "_build_plan" / "results"
    plan_results.mkdir(parents=True)
    (plan_results / "optimal_plan.json").write_text("{}")
    monkeypatch.setattr(cfg, "METRIC1_DIR", m1)
    monkeypatch.setattr(cfg, "PLAN_RESULTS_DIR", plan_results)
    import importlib
    from api.services.acg import metric1_service
    importlib.reload(metric1_service)

    res = client.post("/api/acg/metric1/option", json={"raw": "{'nope'}"})
    assert res.status_code == 422


def test_analyze_streams_done(client, isolated_data_dir, monkeypatch, tmp_path):
    from api.core import config as cfg
    m1 = tmp_path / "_metric1"
    (m1 / "data").mkdir(parents=True)
    handler = tmp_path / "handler"
    handler.mkdir()
    (isolated_data_dir / "goal.txt").write_text("g")
    plan_results = tmp_path / "_build_plan" / "results"
    plan_results.mkdir(parents=True)
    (plan_results / "optimal_plan.json").write_text("{}")
    monkeypatch.setattr(cfg, "METRIC1_DIR", m1)
    monkeypatch.setattr(cfg, "HANDLER_DIR", handler)
    monkeypatch.setattr(cfg, "PLAN_RESULTS_DIR", plan_results)
    import importlib
    from api.services.acg import metric1_service
    importlib.reload(metric1_service)

    def fake_run(cmd, **kwargs):
        import subprocess
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")
    monkeypatch.setattr(metric1_service.subprocess, "run", fake_run)

    with client.stream("POST", "/api/acg/metric1/analyze") as res:
        assert res.status_code == 200
        body = b"".join(res.iter_bytes()).decode()
    assert "event: done" in body
    assert body.count('"status": "completed"') == 4


def test_results_returns_explanation_and_cves(client, isolated_data_dir, monkeypatch, tmp_path):
    from api.core import config as cfg
    m1 = tmp_path / "_metric1"
    explanations = m1 / "metric1_output" / "results" / "explanations"
    explanations.mkdir(parents=True)
    (explanations / "all_explanations.txt").write_text("hello")
    (m1 / "data").mkdir(parents=True)
    (m1 / "data" / "cves.txt").write_text("CVE-1\nCVE-2\n")
    monkeypatch.setattr(cfg, "METRIC1_DIR", m1)
    import importlib
    from api.services.acg import metric1_service
    importlib.reload(metric1_service)

    res = client.get("/api/acg/metric1/results")
    assert res.status_code == 200
    body = res.json()
    assert body["explanation"] == "hello"
    assert body["cves"] == ["CVE-1", "CVE-2"]


def test_results_returns_404_when_missing(client, isolated_data_dir, monkeypatch, tmp_path):
    from api.core import config as cfg
    m1 = tmp_path / "_metric1"
    (m1 / "data").mkdir(parents=True)
    monkeypatch.setattr(cfg, "METRIC1_DIR", m1)
    import importlib
    from api.services.acg import metric1_service
    importlib.reload(metric1_service)

    res = client.get("/api/acg/metric1/results")
    assert res.status_code == 404
