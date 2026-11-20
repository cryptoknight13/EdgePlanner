"""Metric 1 service tests."""
from __future__ import annotations


def test_config_has_metric1_and_handler_dirs():
    from api.core import config as cfg
    assert cfg.METRIC1_DIR.name == "_metric1"
    assert cfg.HANDLER_DIR.name == "handler"
    assert cfg.METRIC1_DIR.parent == cfg.HANDLER_DIR.parent


def test_metric1_schemas_validate_request_bodies():
    import pytest
    from pydantic import ValidationError
    from api.schemas.acg.metric1 import (
        OptionsResponse,
        PrepareResponse,
        ResultsResponse,
        SavedResponse,
        SetHeuristicRequest,
        SetOptionRequest,
    )

    SetHeuristicRequest(choice="with")
    SetHeuristicRequest(choice="without")
    with pytest.raises(ValidationError):
        SetHeuristicRequest(choice="maybe")  # type: ignore[arg-type]

    SetOptionRequest(raw="{'foo bar'}")
    with pytest.raises(ValidationError):
        SetOptionRequest(raw="")

    PrepareResponse(ready=True)
    SavedResponse(saved=True)
    OptionsResponse(options=[{"label": "Option 1: …", "raw": "{'foo'}"}])
    ResultsResponse(explanation="hello", cves=["CVE-2024-0001"])


def test_metric1_error_classes_present():
    from api.core import errors
    assert errors.Metric1PrereqError.status_code == 409
    assert errors.Metric1PrereqError.code == "metric1_prereq_missing"
    assert errors.Metric1ScriptError.status_code == 500
    assert errors.Metric1ScriptError.code == "metric1_script_failed"
    assert errors.Metric1NoOptionsError.status_code == 404
    assert errors.Metric1NoOptionsError.code == "metric1_no_options"


def test_check_prereqs_passes_when_goal_and_plan_present(isolated_data_dir, monkeypatch, tmp_path):
    from api.core import config as cfg

    (isolated_data_dir / "goal.txt").write_text("Web Server A")

    plan_results = tmp_path / "_build_plan" / "results"
    plan_results.mkdir(parents=True)
    (plan_results / "optimal_plan.json").write_text("{}")
    monkeypatch.setattr(cfg, "PLAN_RESULTS_DIR", plan_results)

    import importlib
    from api.services.acg import metric1_service
    importlib.reload(metric1_service)

    metric1_service.check_prereqs()


def test_check_prereqs_raises_when_goal_missing(isolated_data_dir, monkeypatch, tmp_path):
    import pytest
    from api.core import config as cfg, errors

    plan_results = tmp_path / "_build_plan" / "results"
    plan_results.mkdir(parents=True)
    (plan_results / "optimal_plan.json").write_text("{}")
    monkeypatch.setattr(cfg, "PLAN_RESULTS_DIR", plan_results)

    import importlib
    from api.services.acg import metric1_service
    importlib.reload(metric1_service)

    with pytest.raises(errors.Metric1PrereqError):
        metric1_service.check_prereqs()


def test_check_prereqs_raises_when_plan_missing(isolated_data_dir, monkeypatch, tmp_path):
    import pytest
    from api.core import config as cfg, errors

    (isolated_data_dir / "goal.txt").write_text("Web Server A")
    monkeypatch.setattr(cfg, "PLAN_RESULTS_DIR", tmp_path / "missing")

    import importlib
    from api.services.acg import metric1_service
    importlib.reload(metric1_service)

    with pytest.raises(errors.Metric1PrereqError):
        metric1_service.check_prereqs()


def test_prepare_invokes_build_files_script(isolated_data_dir, monkeypatch, tmp_path):
    import subprocess
    from api.core import config as cfg

    (isolated_data_dir / "goal.txt").write_text("Web Server A")
    plan_results = tmp_path / "_build_plan" / "results"
    plan_results.mkdir(parents=True)
    (plan_results / "optimal_plan.json").write_text("{}")
    monkeypatch.setattr(cfg, "PLAN_RESULTS_DIR", plan_results)

    handler_dir = tmp_path / "handler"
    handler_dir.mkdir()
    (handler_dir / "build_metric1_files.py").write_text("# stub")
    monkeypatch.setattr(cfg, "HANDLER_DIR", handler_dir)

    import importlib
    from api.services.acg import metric1_service
    importlib.reload(metric1_service)

    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["kwargs"] = kwargs
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(metric1_service.subprocess, "run", fake_run)

    metric1_service.prepare()

    assert str(captured["cmd"][1]).endswith("build_metric1_files.py")
    assert captured["kwargs"]["check"] is False
    assert captured["kwargs"]["capture_output"] is True


def test_set_heuristic_writes_1_for_without(isolated_data_dir, monkeypatch, tmp_path):
    from api.core import config as cfg
    m1 = tmp_path / "_metric1"
    (m1 / "data").mkdir(parents=True)
    monkeypatch.setattr(cfg, "METRIC1_DIR", m1)

    import importlib
    from api.services.acg import metric1_service
    importlib.reload(metric1_service)

    metric1_service.set_heuristic("without")
    assert metric1_service.HEURISTIC_FILE.read_text() == "1"


def test_set_heuristic_writes_2_for_with(isolated_data_dir, monkeypatch, tmp_path):
    from api.core import config as cfg
    m1 = tmp_path / "_metric1"
    (m1 / "data").mkdir(parents=True)
    monkeypatch.setattr(cfg, "METRIC1_DIR", m1)

    import importlib
    from api.services.acg import metric1_service
    importlib.reload(metric1_service)

    metric1_service.set_heuristic("with")
    assert metric1_service.HEURISTIC_FILE.read_text() == "2"


def test_set_heuristic_rejects_unknown_choice(isolated_data_dir):
    import pytest
    from api.core import errors
    from api.services.acg import metric1_service
    with pytest.raises(errors.InputValidationError):
        metric1_service.set_heuristic("maybe")  # type: ignore[arg-type]


def test_generate_options_parses_normalized_and_raw_pairs(isolated_data_dir, monkeypatch, tmp_path):
    import subprocess
    from api.core import config as cfg
    m1 = tmp_path / "_metric1"
    (m1 / "data").mkdir(parents=True)
    handler = tmp_path / "handler"
    handler.mkdir()
    monkeypatch.setattr(cfg, "METRIC1_DIR", m1)
    monkeypatch.setattr(cfg, "HANDLER_DIR", handler)

    (isolated_data_dir / "goal.txt").write_text("Web Server A")
    plan_results = tmp_path / "_build_plan" / "results"
    plan_results.mkdir(parents=True)
    (plan_results / "optimal_plan.json").write_text("{}")
    monkeypatch.setattr(cfg, "PLAN_RESULTS_DIR", plan_results)

    import importlib
    from api.services.acg import metric1_service
    importlib.reload(metric1_service)

    raw = "{'has-initial-state-has-n6-driver-1-dot-1 request-handling'}\n{'has-initial-state-has-n7-system-2 db-engine'}\n"
    norm = "Option 1: Make a change in request handling\nOption 2: Make a change in db engine\n"

    def fake_run(cmd, **kwargs):
        path = str(cmd[1])
        if path.endswith("build_metric1_main.py"):
            (m1 / "data" / "pddl_options.txt").write_text(raw)
        elif path.endswith("pddl_option_m1.py"):
            (m1 / "data" / "pddl_options_normalized.txt").write_text(norm)
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(metric1_service.subprocess, "run", fake_run)

    options = metric1_service.generate_options()
    assert len(options) == 2
    assert options[0]["label"] == "Option 1: Make a change in request handling"
    assert options[0]["raw"].startswith("{'has-initial-state-has-n6-driver")
    assert options[1]["label"] == "Option 2: Make a change in db engine"


def test_generate_options_empty_raises_no_options(isolated_data_dir, monkeypatch, tmp_path):
    import pytest
    import subprocess
    from api.core import config as cfg, errors
    m1 = tmp_path / "_metric1"
    (m1 / "data").mkdir(parents=True)
    handler = tmp_path / "handler"
    handler.mkdir()
    monkeypatch.setattr(cfg, "METRIC1_DIR", m1)
    monkeypatch.setattr(cfg, "HANDLER_DIR", handler)
    (isolated_data_dir / "goal.txt").write_text("Web Server A")
    plan_results = tmp_path / "_build_plan" / "results"
    plan_results.mkdir(parents=True)
    (plan_results / "optimal_plan.json").write_text("{}")
    monkeypatch.setattr(cfg, "PLAN_RESULTS_DIR", plan_results)

    import importlib
    from api.services.acg import metric1_service
    importlib.reload(metric1_service)

    def fake_run(cmd, **kwargs):
        (m1 / "data" / "pddl_options.txt").write_text("")
        (m1 / "data" / "pddl_options_normalized.txt").write_text("")
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(metric1_service.subprocess, "run", fake_run)

    with pytest.raises(errors.Metric1NoOptionsError):
        metric1_service.generate_options()


def test_set_option_writes_when_raw_present(isolated_data_dir, monkeypatch, tmp_path):
    from api.core import config as cfg
    m1 = tmp_path / "_metric1"
    (m1 / "data").mkdir(parents=True)
    monkeypatch.setattr(cfg, "METRIC1_DIR", m1)

    import importlib
    from api.services.acg import metric1_service
    importlib.reload(metric1_service)
    metric1_service.PDDL_OPTIONS.write_text("{'a'}\n{'b'}\n")

    metric1_service.set_option("{'b'}")
    assert metric1_service.USER_OPTION.read_text() == "{'b'}"


def test_set_option_rejects_raw_not_in_file(isolated_data_dir, monkeypatch, tmp_path):
    import pytest
    from api.core import config as cfg, errors
    m1 = tmp_path / "_metric1"
    (m1 / "data").mkdir(parents=True)
    monkeypatch.setattr(cfg, "METRIC1_DIR", m1)

    import importlib
    from api.services.acg import metric1_service
    importlib.reload(metric1_service)
    metric1_service.PDDL_OPTIONS.write_text("{'a'}\n{'b'}\n")

    with pytest.raises(errors.InputValidationError):
        metric1_service.set_option("{'nope'}")


def test_analyze_stream_yields_started_completed_per_step(isolated_data_dir, monkeypatch, tmp_path):
    import subprocess
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
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")
    monkeypatch.setattr(metric1_service.subprocess, "run", fake_run)

    chunks = list(metric1_service.analyze_stream())
    assert len(chunks) == 9
    assert "event: step" in chunks[0]
    assert '"step": "solutions"' in chunks[0]
    assert '"status": "started"' in chunks[0]
    assert '"status": "completed"' in chunks[1]
    assert "event: done" in chunks[-1]


def test_analyze_stream_emits_error_event_and_stops_on_failure(isolated_data_dir, monkeypatch, tmp_path):
    import subprocess
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

    call_counter = {"n": 0}

    def fake_run(cmd, **kwargs):
        call_counter["n"] += 1
        if call_counter["n"] == 2:
            return subprocess.CompletedProcess(args=cmd, returncode=1, stdout="", stderr="boom")
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")
    monkeypatch.setattr(metric1_service.subprocess, "run", fake_run)

    chunks = list(metric1_service.analyze_stream())
    assert any('"step": "validation"' in c and '"status": "error"' in c for c in chunks)
    assert not any('"step": "explanations"' in c for c in chunks)
    assert not any("event: done" in c for c in chunks)


def test_read_results_parses_explanation_and_cves(isolated_data_dir, monkeypatch, tmp_path):
    from api.core import config as cfg
    m1 = tmp_path / "_metric1"
    explanations_dir = m1 / "metric1_output" / "results" / "explanations"
    explanations_dir.mkdir(parents=True)
    (explanations_dir / "all_explanations.txt").write_text("Explanation body")
    (m1 / "data").mkdir(parents=True)
    (m1 / "data" / "cves.txt").write_text("CVE-2024-0001\nCVE-2024-0002\n\n")
    monkeypatch.setattr(cfg, "METRIC1_DIR", m1)

    import importlib
    from api.services.acg import metric1_service
    importlib.reload(metric1_service)

    out = metric1_service.read_results()
    assert out["explanation"] == "Explanation body"
    assert out["cves"] == ["CVE-2024-0001", "CVE-2024-0002"]


def test_read_results_raises_when_explanation_missing(isolated_data_dir, monkeypatch, tmp_path):
    import pytest
    from api.core import config as cfg, errors
    m1 = tmp_path / "_metric1"
    (m1 / "data").mkdir(parents=True)
    monkeypatch.setattr(cfg, "METRIC1_DIR", m1)

    import importlib
    from api.services.acg import metric1_service
    importlib.reload(metric1_service)

    with pytest.raises(errors.NotFoundError):
        metric1_service.read_results()
