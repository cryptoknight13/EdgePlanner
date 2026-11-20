"""Phase 7 — iEXAM plan: attack graph, PDDL, optimal and top-K attack plans, plan explanations.

Drives the ported iEXAM services (iexam/api/services/acg) in-process; the planners run as
subprocesses exactly as in iEXAM. iEXAM keeps one workspace (iexam/Backend/...), so runs are
sequential; every artifact is copied into runs/<run-id>/plans/ afterwards.
"""
import json
import shutil
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import llmconf

IEXAM = Path(__file__).resolve().parent.parent / "iexam"
if str(IEXAM) not in sys.path:
    sys.path.insert(0, str(IEXAM))

from api.core.config import PDDL_DIR  # noqa: E402
from api.core.errors import ApiException  # noqa: E402
from api.services.acg import (  # noqa: E402
    dataset_service, llm_service, pddl_service, plan_service, topk_service)
from api.services.acg.pddl_service import curate  # noqa: E402

SCHEMA_VERSION = "1.0"
FILES = {"nodes": "node-data.json", "edges": "connectivity-edge.json",
         "cves": "cve-data.json", "cve_in_node": "cve-in-node.json"}


def load_dataset(export_dir: Path) -> None:
    """Validate our phase-6 files with iEXAM's own parser and install them as iEXAM's dataset."""
    dataset_service.reset_dataset()
    for slot, name in FILES.items():
        validated = dataset_service.parse_and_validate(slot, (export_dir / name).read_text())
        dataset_service.save_slot(slot, validated)


def attack_graph() -> dict:
    """iEXAM's attack connectivity graph: one attack edge per (connectivity edge, CVE on its target)."""
    nodes = dataset_service.require_slot("nodes")
    edges = dataset_service.require_slot("edges")
    cve_in_node = dataset_service.require_slot("cve_in_node")
    labels = curate.node_labels(nodes)
    return {
        "nodes": [{"id": nid, "label": labels[nid], "ip": a.get("IP"), "cve_count": len(cve_in_node.get(nid, []))}
                  for nid, a in nodes.items()],
        "edges": [{"id": eid, "source": s, "target": t} for eid, (s, t) in edges.items()],
        "attack_edges": [{"edge": eid, "source": s, "target": t, "cve": c}
                         for eid, (s, t) in edges.items() for c in cve_in_node.get(t, [])],
    }


def _explain(fn, notes: list[str], what: str, server_log: Path | None) -> dict | None:
    s = llmconf.settings()
    if not llmconf.configured(s):
        notes.append(f"{what}: {llmconf.not_configured_hint(s)}")
        return None
    llmconf.export_env(s)
    try:
        # The local model runs only for the explanation, never while the planners use the memory.
        with llmconf.local_server(s, server_log or Path("llm-server.log")):
            return fn()
    except ApiException as exc:
        notes.append(f"{what}: {exc}")
    except Exception as exc:  # LLM transport errors: the plan stands without its explanation
        notes.append(f"{what} failed: {exc}")
    return None


def optimal_for(target: str, explain: bool, notes: list[str], server_log: Path | None = None) -> dict:
    """Optimal plan (and its LLM explanation) for one goal; the goal must already be set."""
    out: dict = {}
    t = time.monotonic()
    try:
        out["optimal"] = plan_service.run_optimal_plan()
    except ApiException as exc:
        return {"error": str(exc), "details": getattr(exc, "details", None)}
    out["optimal_seconds"] = round(time.monotonic() - t, 2)
    if explain:
        out["optimal_explanation"] = _explain(lambda: llm_service.generate_explanation(force=True), notes,
                                              f"explanation for {target}", server_log)
    return out


def topk_for(target: str, k: int, notes: list[str]) -> dict:
    """Top-K plans for one goal; the goal must already be set."""
    t = time.monotonic()
    try:
        topk = topk_service.run_topk(k)
    except ApiException as exc:
        notes.append(f"top-{k} for {target}: {exc}")
        return {"topk": None, "topk_error": str(exc), "topk_seconds": round(time.monotonic() - t, 2)}
    return {"topk": topk, "topk_seconds": round(time.monotonic() - t, 2)}


def plan_target(target: str, k: int, explain: bool, notes: list[str], server_log: Path | None = None) -> dict:
    """Optimal + top-K plans (and explanations) for one goal node."""
    plan_service.set_goal(target)
    out = {"goal": target, **optimal_for(target, explain, notes, server_log)}
    if "error" in out:
        return out
    return {**out, **topk_for(target, k, notes)}


def _workspace(run_dir: Path) -> None:
    """iEXAM keeps one workspace: load this run's files and regenerate the PDDL before any planning."""
    load_dataset(run_dir / "iexam")
    pddl_service.generate_pddl()


def _result(run_dir: Path, targets: list[dict], unreachable: list[str], notes: list[str], k: int | None) -> dict:
    out_dir = run_dir / "plans"
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)
    for f in PDDL_DIR.glob("*.pddl"):
        shutil.copy2(f, out_dir / f.name)
    return {
        "schema_version": SCHEMA_VERSION,
        "run_id": run_dir.name,
        "collected_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "planner": {"optimal": "Fast Downward astar(lmcut())", "topk": f"ForbidIterative top-{k}" if k else "ForbidIterative"},
        "attack_graph": attack_graph(),
        "unreachable_goals": unreachable,
        "targets": targets,
        "pddl_dir": str(out_dir),
        "notes": notes,
    }


def run(run_dir: Path, k: int, targets: list[str] | None, explain: bool) -> dict:
    """Everything at once: optimal + top-K for every goal (the CLI default)."""
    notes: list[str] = []
    _workspace(run_dir)
    goals = targets or plan_service.list_goals()
    unreachable = plan_service.unreachable_goals()
    results = [plan_target(g, k, explain, notes, run_dir / "llm-server.log") for g in goals]
    return _result(run_dir, results, unreachable, notes, k)


def prepare(run_dir: Path) -> dict:
    """Attack graph, PDDL and goal list only; plans are found per goal later (plan_one)."""
    _workspace(run_dir)
    return _result(run_dir, [{"goal": g} for g in plan_service.list_goals()], plan_service.unreachable_goals(), [], None)


def plan_one(run_dir: Path, goal: str, optimal: bool, k: int | None, explain: bool) -> dict:
    """Find the optimal and/or top-K plans for one goal and merge them into the run's plans.json."""
    result = json.loads((run_dir / "plans" / "plans.json").read_text())
    entry = next((t for t in result["targets"] if t["goal"] == goal), None)
    if entry is None:
        raise ValueError(f"{goal!r} is not a goal in this run's attack model")
    _workspace(run_dir)
    plan_service.set_goal(goal)
    notes = result.setdefault("notes", [])
    if optimal:
        for key in ("optimal", "optimal_seconds", "optimal_explanation", "error", "details"):
            entry.pop(key, None)
        entry.update(optimal_for(goal, explain, notes, run_dir / "llm-server.log"))
    if k:
        entry.pop("topk_error", None)
        entry.update(topk_for(goal, k, notes))
    result["collected_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    return result


def write(result: dict, run_dir: Path) -> Path:
    path = run_dir / "plans" / "plans.json"
    path.write_text(json.dumps(result, indent=2))
    return path
