"""Goal selection + optimal plan generation via Fast Downward.

The goal is the node name the attacker should compromise (e.g. "Web Server A").
We rewrite the PDDL problem's :goal block to a single (exploited-...) atom for
that node, write it as `newNetProblem.pddl`, and feed both files to Fast Downward
with `astar(lmcut())`.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path

from api.core.config import (
    DATA_DIR,
    DOWNWARD_DIR,
    PDDL_DIR,
    PLAN_RESULTS_DIR,
)
from api.core.errors import InputValidationError, NotFoundError
from api.services.acg import dataset_service, pddl_service
from api.services.acg.pddl_service import curate

EXPLANATION_FILE = DATA_DIR.parent / "_build_plan" / "results" / "explanation_for_plan.txt"
GOAL_FILE = DATA_DIR / "goal.txt"
NEW_PROBLEM_FILE = PDDL_DIR / "newNetProblem.pddl"
PLAN_TXT = PLAN_RESULTS_DIR / "optimal_plan.txt"
PLAN_JSON = PLAN_RESULTS_DIR / "optimal_plan.json"
FAST_DOWNWARD = DOWNWARD_DIR / "fast-downward.py"

PLANNER_TIMEOUT_SECONDS = 60


# ---------- Goal handling ----------

def list_goals() -> list[str]:
    """Return candidate goal node names (every non-attacker node)."""
    nodes = dataset_service.require_slot("nodes")
    return [
        label
        for nid, label in curate.node_labels(nodes).items()
        if nodes[nid].get("name") and nodes[nid].get("name") != "Attacker"
    ]


def unreachable_goals() -> list[str]:
    """Goal labels with no directed edge path from n0 through nodes that have
    CVEs (the only way the domain lets the attacker advance)."""
    nodes = dataset_service.read_slot("nodes") or {}
    edges = dataset_service.read_slot("edges") or {}
    cve_in_node = dataset_service.read_slot("cve_in_node") or {}
    reach, frontier = {"n0"}, ["n0"]
    while frontier:
        src = frontier.pop()
        for s, t in edges.values():
            if s == src and t not in reach and cve_in_node.get(t):
                reach.add(t)
                frontier.append(t)
    labels = curate.node_labels(nodes)
    return [labels[nid] for nid in nodes if nid not in reach and nid != "n0"]


def get_current_goal() -> str | None:
    if not GOAL_FILE.exists():
        return None
    return GOAL_FILE.read_text(encoding="utf-8").strip() or None


def _normalize_obj_name(name: str) -> str:
    s = name.strip().lower()
    s = re.sub(r"[\s_]+", "-", s)
    s = re.sub(r"[^a-z0-9\-\.]", "", s)
    return s


def _find_goal_block_span(text: str) -> tuple[int, int] | None:
    start = text.find("(:goal")
    if start == -1:
        return None
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if depth == 0:
                return (start, i + 1)
    return None


def _replace_goal_block(problem_text: str, target_name: str) -> str:
    span = _find_goal_block_span(problem_text)
    if not span:
        raise InputValidationError("Problem PDDL has no (:goal ...) block")
    start, end = span
    goal_block = problem_text[start:end]

    atoms: list[tuple[str, str]] = []
    for m in re.finditer(r"\(\s*exploited-[^)]+\)", goal_block):
        full = m.group(0)
        inner = full.strip()[1:-1].strip()
        parts = re.split(r"\s+", inner)
        atoms.append((full, parts[-1]))

    if not atoms:
        raise InputValidationError("Goal block has no (exploited-… <obj>) atoms")

    target_norm = _normalize_obj_name(target_name)
    # The PDDL holds curate.pddl_token(name) ('.' -> '-dot-', other symbols -> '-'): compare that form first.
    token = curate.pddl_token(target_name)
    matches = [full for (full, obj) in atoms if obj == token or _normalize_obj_name(obj) == target_norm]
    if not matches:
        cand = [full for (full, obj) in atoms if target_norm in _normalize_obj_name(obj)]
        if len(cand) == 1:
            matches = cand
        elif len(cand) > 1:
            raise InputValidationError(
                f"Ambiguous goal '{target_name}'", details={"candidates": cand}
            )
        else:
            available = [obj for _, obj in atoms]
            raise InputValidationError(
                f"Goal '{target_name}' not found", details={"available": available}
            )

    chosen = matches[0]
    new_goal_block = f"(:goal\n    {chosen}\n)\n"
    return problem_text[:start] + new_goal_block + problem_text[end:]


def set_goal(target_name: str) -> str:
    """Persist the goal and rewrite NetProblem.pddl → newNetProblem.pddl."""
    if not pddl_service.pddl_exists():
        raise InputValidationError("Generate PDDL on the Start page first")
    target_name = target_name.strip()
    if not target_name:
        raise InputValidationError("Goal cannot be empty")
    # Validate the goal is a known node.
    if target_name not in list_goals():
        raise InputValidationError(
            f"Unknown goal '{target_name}'", details={"available": list_goals()}
        )
    problem_text = (PDDL_DIR / pddl_service.PROBLEM_FILENAME).read_text(encoding="utf-8")
    new_text = _replace_goal_block(problem_text, target_name)
    NEW_PROBLEM_FILE.parent.mkdir(parents=True, exist_ok=True)
    NEW_PROBLEM_FILE.write_text(new_text, encoding="utf-8")
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    GOAL_FILE.write_text(target_name, encoding="utf-8")
    # Stale plan no longer matches new goal.
    PLAN_TXT.unlink(missing_ok=True)
    PLAN_JSON.unlink(missing_ok=True)
    _clear_topk_safely()
    return target_name


def clear_goal() -> None:
    GOAL_FILE.unlink(missing_ok=True)
    NEW_PROBLEM_FILE.unlink(missing_ok=True)
    PLAN_TXT.unlink(missing_ok=True)
    PLAN_JSON.unlink(missing_ok=True)
    EXPLANATION_FILE.unlink(missing_ok=True)
    _clear_topk_safely()


# ---------- Optimal plan ----------

_format_for_pddl = curate.pddl_token


def _node_id_by_name(nodes: dict, name: str) -> str | None:
    return curate.node_id_for(nodes, name)


def _extract_highlights(steps: list[str], goal_name: str | None) -> dict:
    """Walk plan steps and collect involved node/edge/cve IDs.

    Recognized action shapes (substring after the leading `(`):
      - attacker-has-access-to-<fmt_name>
      - attacker-exploit-<fmt_cve>-to-compromise-<fmt_name>
      - attacker-exploit-<fmt_cve>-to-compromise-<fmt_tgt>-via-<fmt_src>
    """
    nodes = dataset_service.read_slot("nodes") or {}
    edges = dataset_service.read_slot("edges") or {}
    cves = dataset_service.read_slot("cves") or {}

    fmt_to_node = {tok: nid for nid, tok in curate.node_tokens(nodes).items()}
    fmt_to_cve = {_format_for_pddl(cid): cid for cid in cves}

    def edge_id_between(src_id: str, tgt_id: str) -> str | None:
        for eid, pair in edges.items():
            if list(pair) == [src_id, tgt_id]:
                return eid
        return None

    nset: set[str] = {"n0"} if "n0" in nodes else set()
    eset: set[str] = set()
    cset: set[str] = set()

    for raw in steps:
        s = raw.strip()
        if s.startswith("("):
            s = s[1:]
        if s.endswith(")"):
            s = s[:-1]
        head = s.split()[0] if s else ""

        # attacker-has-access-to-<name>
        if head.startswith("attacker-has-access-to-"):
            fmt = head[len("attacker-has-access-to-"):]
            nid = fmt_to_node.get(fmt)
            if nid:
                nset.add(nid)
                eid = edge_id_between("n0", nid)
                if eid:
                    eset.add(eid)
            continue

        # attacker-exploit-<cve>-to-compromise-<tgt>[-via-<src>]
        if head.startswith("attacker-exploit-"):
            rest = head[len("attacker-exploit-"):]
            marker = "-to-compromise-"
            if marker not in rest:
                continue
            cve_fmt, tail = rest.split(marker, 1)
            cve_id = fmt_to_cve.get(cve_fmt)
            if cve_id:
                cset.add(cve_id)
            if "-via-" in tail:
                tgt_fmt, src_fmt = tail.rsplit("-via-", 1)
                tgt_id = fmt_to_node.get(tgt_fmt)
                src_id = fmt_to_node.get(src_fmt)
                if tgt_id:
                    nset.add(tgt_id)
                if src_id:
                    nset.add(src_id)
                if tgt_id and src_id:
                    eid = edge_id_between(src_id, tgt_id)
                    if eid:
                        eset.add(eid)
            else:
                tgt_id = fmt_to_node.get(tail)
                if tgt_id:
                    nset.add(tgt_id)
                    eid = edge_id_between("n0", tgt_id)
                    if eid:
                        eset.add(eid)

    goal_node_id = _node_id_by_name(nodes, goal_name) if goal_name else None
    return {
        "node_ids": sorted(nset),
        "edge_ids": sorted(eset),
        "cve_ids": sorted(cset),
        "goal_node_id": goal_node_id,
    }


def _read_plan_steps(path: Path) -> tuple[list[str], int | None]:
    steps: list[str] = []
    cost: int | None = None
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith(";"):
            if "cost =" in stripped:
                try:
                    cost = int(stripped.split("=", 1)[1].strip().split()[0])
                except (ValueError, IndexError):
                    pass
            continue
        steps.append(stripped)
    return steps, cost


def run_optimal_plan() -> dict:
    """Invoke Fast Downward; return a JSON-serializable plan summary."""
    domain_path = PDDL_DIR / pddl_service.DOMAIN_FILENAME
    problem_path = NEW_PROBLEM_FILE
    if not domain_path.exists():
        raise InputValidationError("Domain PDDL missing — regenerate on Start")
    if not problem_path.exists():
        raise InputValidationError("Set a goal before running the planner")

    PLAN_RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    PLAN_TXT.unlink(missing_ok=True)
    PLAN_JSON.unlink(missing_ok=True)

    cmd = [
        "python",
        str(FAST_DOWNWARD),
        "--plan-file",
        str(PLAN_TXT),
        str(domain_path),
        str(problem_path),
        "--search",
        "astar(lmcut())",
    ]
    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=PLANNER_TIMEOUT_SECONDS,
            cwd=str(DOWNWARD_DIR.parent),
        )
    except subprocess.TimeoutExpired as exc:
        raise InputValidationError(
            f"Planner exceeded {PLANNER_TIMEOUT_SECONDS}s timeout"
        ) from exc

    # Fast Downward returns non-zero even on success in some configs; check the
    # plan file as the source of truth.
    if not PLAN_TXT.exists() or PLAN_TXT.stat().st_size == 0:
        # Fast Downward exit 12 = task proven unsolvable. In this domain that
        # means no chain of connectivity edges + CVEs leads from the Attacker
        # to the goal — a property of the uploaded network, not a bug.
        if completed.returncode == 12:
            raise InputValidationError(
                f"Goal '{get_current_goal()}' is unreachable: no attack path from "
                "the Attacker through connected, vulnerable nodes reaches it. "
                "Pick another goal or check connectivity-edge.json / cve-in-node.json.",
                details={"returncode": 12, "unreachable_goals": unreachable_goals()},
            )
        raise InputValidationError(
            "Planner produced no plan",
            details={
                "returncode": completed.returncode,
                "stderr_tail": completed.stderr[-2000:] if completed.stderr else "",
            },
        )

    steps, cost = _read_plan_steps(PLAN_TXT)
    goal = get_current_goal()
    highlights = _extract_highlights(steps, goal)
    summary = {
        "goal": goal,
        "goal_node_id": highlights["goal_node_id"],
        "steps": steps,
        "step_count": len(steps),
        "cost": cost,
        "domain": str(domain_path),
        "problem": str(problem_path),
        "highlights": highlights,
    }
    PLAN_JSON.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    EXPLANATION_FILE.unlink(missing_ok=True)
    return summary


def get_last_plan() -> dict | None:
    if not PLAN_JSON.exists():
        return None
    try:
        return json.loads(PLAN_JSON.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def plan_exists() -> bool:
    return PLAN_JSON.exists() and PLAN_TXT.exists()


def _clear_topk_safely() -> None:
    """Local import avoids a circular dependency: topk_service imports plan_service."""
    try:
        from api.services.acg import topk_service
        topk_service.clear_topk()
    except Exception:
        # Don't let a topk cleanup failure mask the primary operation.
        pass
