"""PDDL generation must stay valid for every bundled example dataset —
including the scanner-derived `actual-test-network`, whose CVE `system`
strings would otherwise leak `;<>=` into object names."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from api.core.config import DOWNWARD_DIR, INPUT_DATA_DIR
from api.services.acg import pddl_service

DATASETS = sorted(p.name for p in INPUT_DATA_DIR.iterdir() if (p / "node-data.json").exists())


def _load(ds: str):
    d = INPUT_DATA_DIR / ds
    return tuple(
        json.loads((d / f).read_text())
        for f in ("node-data.json", "connectivity-edge.json", "cve-data.json", "cve-in-node.json")
    )


@pytest.mark.parametrize("ds", DATASETS)
def test_object_names_are_pddl_safe(ds: str):
    nodes, edges, cves, cin = _load(ds)
    problem = pddl_service._generate_problem(nodes, edges, cves, cin)
    for line in problem.splitlines():
        line = line.strip()
        if line.endswith(" - system") or line.endswith(" - driver") or line.endswith(" - cause"):
            name = line.split(" - ")[0]
            assert set(name) <= set("abcdefghijklmnopqrstuvwxyz0123456789-_"), name


@pytest.mark.parametrize("ds", DATASETS)
def test_fast_downward_translates(ds: str, tmp_path: Path):
    fd = DOWNWARD_DIR / "fast-downward.py"
    if not fd.exists() or not (DOWNWARD_DIR / "builds" / "release" / "bin").exists():
        pytest.skip("Fast Downward not built")
    nodes, edges, cves, cin = _load(ds)
    dom = tmp_path / "d.pddl"
    prob = tmp_path / "p.pddl"
    dom.write_text(pddl_service._generate_domain(nodes, edges, cves, cin))
    prob.write_text(pddl_service._generate_problem(nodes, edges, cves, cin))
    res = subprocess.run(
        [sys.executable, str(fd), "--translate", str(dom), str(prob)],
        cwd=tmp_path, capture_output=True, text=True, timeout=120,
    )
    assert res.returncode == 0, res.stdout[-800:] + res.stderr[-800:]
