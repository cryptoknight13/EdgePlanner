"""Generate NetDomain.pddl / NetProblem.pddl from the active dataset.

Ported (in-process) from `Backend/pages/_start_i_EXAM/generate_pddl_from_json.py`
so we don't shell out and so unit tests can exercise the generator directly.

Outputs are written atomically to `Backend/pddl/`.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path
from typing import Any

from api.core.config import DATA_DIR, HANDLER_DIR, PDDL_DIR
from api.core.errors import InputValidationError
from api.schemas.acg.start import CANONICAL_FILENAMES

# Shared with the Backend/ subprocess scripts.
if str(HANDLER_DIR) not in sys.path:
    sys.path.insert(0, str(HANDLER_DIR))
import curate  # noqa: E402

DOMAIN_FILENAME = "NetDomain.pddl"
PROBLEM_FILENAME = "NetProblem.pddl"

# Object-name formatting and the CVE-field subset that reaches the planner
# live in curate.py so every generator agrees on tokens.
_format_for_pddl = curate.pddl_token
_group_keys = curate.pddl_cve_fields


def _load_dataset() -> tuple[dict, dict, dict, dict]:
    paths = {slot: DATA_DIR / fname for slot, fname in CANONICAL_FILENAMES.items()}
    missing = [p.name for p in paths.values() if not p.exists()]
    if missing:
        raise InputValidationError(
            "Dataset is not fully loaded; cannot generate PDDL",
            details={"missing": missing},
        )
    with open(paths["nodes"]) as f:
        nodes = json.load(f)
    with open(paths["edges"]) as f:
        edges = json.load(f)
    with open(paths["cves"]) as f:
        cves = json.load(f)
    with open(paths["cve_in_node"]) as f:
        cve_in_node = json.load(f)
    return nodes, edges, cves, cve_in_node


def _generate_domain(nodes: dict, edges: dict, cves: dict, cve_in_node: dict) -> str:
    node_tok = curate.node_tokens(nodes)
    directly_connected = {target for _eid, (src, target) in edges.items() if src == "n0"}

    out = """(define (domain netdomain)
    (:requirements :strips :typing)
    (:types node function struct driver system cause adversary)

    (:predicates
"""
    for node_id in nodes:
        out += f"      (has-service-up-{node_id} ?Node - node)\n"
    out += "      (has-attacker ?atk - adversary)\n"
    out += "      (can-ping ?Node1 - node ?Node2 - node)\n"
    out += "      (has-connection-to ?Node - node)\n"

    for node_id in directly_connected:
        out += (
            f"      (has-access-to-{node_tok[node_id]}-node "
            "?node - node ?atk - adversary)\n"
        )

    for node_id, cve_ids in cve_in_node.items():
        out += f"        (exploited-{node_id} ?Node - node)\n"
        for cve_index, cve_id in enumerate(cve_ids, start=1):
            grouped = _group_keys(cves[cve_id])
            for base_key, items in grouped.items():
                if base_key in {"function", "struct", "driver", "system", "cause"}:
                    for key_index, _ in enumerate(items, start=1):
                        out += (
                            f"        (has-{node_id}-{base_key}-{cve_index}-dot-{key_index} "
                            f"?{base_key}{key_index} - {base_key})\n"
                        )

    out += "    )\n"

    for _eid, (src, target) in edges.items():
        if src == "n0":
            continue
        src_name = node_tok[src]
        tgt_name = node_tok[target]
        out += f"""
(:action connectivity-edge-between-{src_name}-and-{tgt_name}
    :parameters (?node1 - node ?node2 - node)
    :precondition (and (has-service-up-{src} ?node1) (has-service-up-{target} ?node2) (can-ping ?node1 ?node2)"""
        if src not in directly_connected:
            out += " (has-connection-to ?node1)"
        out += f""")
    :effect (and
        (has-connection-to ?node2)
    )
)
"""

    for node_id in directly_connected:
        node_name = node_tok[node_id]
        out += f"""
(:action attacker-has-access-to-{node_name}
    :parameters (?node - node ?atk - adversary)
    :precondition (and (has-attacker ?atk) (has-service-up-{node_id} ?node))
    :effect (and (has-access-to-{node_name}-node ?node ?atk))
)
"""

    for node_id, cve_ids in cve_in_node.items():
        target_name = node_tok[node_id]
        source_nodes = [src for _eid, (src, t) in edges.items() if t == node_id]
        for src in source_nodes:
            src_name = node_tok[src]
            for cve_index, cve_id in enumerate(cve_ids, start=1):
                grouped = _group_keys(cves[cve_id])
                if src == "n0":
                    out += f"""
(:action attacker-exploit-{_format_for_pddl(cve_id)}-to-compromise-{target_name}
    :parameters (?node - node ?atk - adversary"""
                    for base_key, items in grouped.items():
                        if base_key in {"function", "struct", "driver", "system", "cause"}:
                            for key_index, _ in enumerate(items, start=1):
                                out += f" ?{base_key}{key_index} - {base_key}"
                    out += ")\n    :precondition (and\n"
                    out += f"        (has-access-to-{target_name}-node ?node ?atk)\n"
                    out += f"        (has-service-up-{node_id} ?node)\n"
                    for base_key, items in grouped.items():
                        if base_key in {"function", "struct", "driver", "system", "cause"}:
                            for key_index, _ in enumerate(items, start=1):
                                out += (
                                    f"        (has-{node_id}-{base_key}-{cve_index}-dot-{key_index} "
                                    f"?{base_key}{key_index})\n"
                                )
                    out += "    )\n    :effect (and\n"
                    out += f"        (exploited-{node_id} ?node)\n"
                    out += "    )\n)\n"
                else:
                    out += f"""
(:action attacker-exploit-{_format_for_pddl(cve_id)}-to-compromise-{target_name}-via-{src_name}
    :parameters (?node2 - node ?node1 - node"""
                    for base_key, items in grouped.items():
                        if base_key in {"function", "struct", "driver", "system", "cause"}:
                            for key_index, _ in enumerate(items, start=1):
                                out += f" ?{base_key}{key_index} - {base_key}"
                    out += ")\n    :precondition (and\n"
                    out += "        (can-ping ?node1 ?node2)\n"
                    out += f"        (has-service-up-{src} ?node1)\n"
                    out += f"        (exploited-{src} ?node1)\n"
                    out += f"        (has-service-up-{node_id} ?node2)\n"
                    for base_key, items in grouped.items():
                        if base_key in {"function", "struct", "driver", "system", "cause"}:
                            for key_index, _ in enumerate(items, start=1):
                                out += (
                                    f"        (has-{node_id}-{base_key}-{cve_index}-dot-{key_index} "
                                    f"?{base_key}{key_index})\n"
                                )
                    out += "    )\n    :effect (and\n"
                    out += f"        (exploited-{node_id} ?node2)\n"
                    out += "    )\n)\n"

    out += ")"
    return out


def _generate_problem(nodes: dict, edges: dict, cves: dict, cve_in_node: dict) -> str:
    node_tok = curate.node_tokens(nodes)
    out = """(define (problem netproblem)
    (:domain netdomain)
    (:objects
"""
    for node_id, attrs in nodes.items():
        if node_id != "n0":
            out += f"        {node_tok[node_id]} - node\n"
    seen_objects: set[str] = set()
    for node_id, cve_ids in cve_in_node.items():
        for cve_index, cve_id in enumerate(cve_ids, start=1):
            grouped = _group_keys(cves[cve_id])
            for base_key, items in grouped.items():
                if base_key in {"function", "struct", "driver", "system", "cause"}:
                    for _, value in items:
                        formatted = _format_for_pddl(value)
                        if formatted in seen_objects:
                            continue
                        seen_objects.add(formatted)
                        out += f"        {formatted} - {base_key}\n"
    out += "        attacker1 - adversary\n    )\n\n    (:init\n"

    for node_id in nodes:
        if node_id != "n0":
            out += f"        (has-service-up-{node_id} {node_tok[node_id]})\n"
    out += "        (has-attacker attacker1)\n"
    for _eid, (src, target) in edges.items():
        if src != "n0" and target != "n0":
            out += (
                f"        (can-ping {node_tok[src]} "
                f"{node_tok[target]})\n"
            )
    for node_id, cve_ids in cve_in_node.items():
        for cve_index, cve_id in enumerate(cve_ids, start=1):
            grouped = _group_keys(cves[cve_id])
            for base_key, items in grouped.items():
                if base_key in {"function", "struct", "driver", "system", "cause"}:
                    for key_index, (_, value) in enumerate(items, start=1):
                        out += (
                            f"        (has-{node_id}-{base_key}-{cve_index}-dot-{key_index} "
                            f"{_format_for_pddl(value)})\n"
                        )

    out += "    )\n\n    (:goal\n        (and\n"
    for node_id in nodes:
        if nodes[node_id]["name"] != "Attacker":
            out += (
                f"            (exploited-{node_id} {node_tok[node_id]})\n"
            )
    out += "        )\n    )\n)"
    return out


def _atomic_write(path: Path, text: str) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text)
    os.replace(tmp, path)


def generate_pddl() -> tuple[str, str]:
    """Read the active dataset, generate domain+problem PDDL, persist to disk.

    Returns (domain_text, problem_text). Raises InputValidationError if any
    canonical file is missing.
    """
    nodes, edges, cves, cve_in_node = _load_dataset()
    domain = _generate_domain(nodes, edges, cves, cve_in_node)
    problem = _generate_problem(nodes, edges, cves, cve_in_node)

    PDDL_DIR.mkdir(parents=True, exist_ok=True)
    _atomic_write(PDDL_DIR / DOMAIN_FILENAME, domain)
    _atomic_write(PDDL_DIR / PROBLEM_FILENAME, problem)
    return domain, problem


def read_pddl(kind: str) -> str:
    """Return previously generated PDDL by kind ('domain' or 'problem')."""
    if kind == "domain":
        path = PDDL_DIR / DOMAIN_FILENAME
    elif kind == "problem":
        path = PDDL_DIR / PROBLEM_FILENAME
    else:
        raise InputValidationError(f"Unknown PDDL kind: {kind}")
    if not path.exists():
        raise InputValidationError(
            f"{kind} PDDL has not been generated yet",
            details={"file": path.name},
        )
    return path.read_text()


def pddl_exists() -> bool:
    return (PDDL_DIR / DOMAIN_FILENAME).exists() and (PDDL_DIR / PROBLEM_FILENAME).exists()


def clear_pddl() -> None:
    if PDDL_DIR.exists():
        for fname in (DOMAIN_FILENAME, PROBLEM_FILENAME):
            (PDDL_DIR / fname).unlink(missing_ok=True)
    # Any cached plan or goal is now stale.
    from api.services.acg import plan_service

    plan_service.clear_goal()
