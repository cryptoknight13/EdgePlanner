"""Fixtures for ACG tests.

`isolated_data_dir` overrides `api.core.config.DATA_DIR` and
`api.core.config.PDDL_DIR` to per-test temp dirs so tests don't write to
the real Backend/pages/data and don't see legacy PDDL files.
"""
from __future__ import annotations

import importlib
from pathlib import Path

import pytest


@pytest.fixture()
def isolated_data_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    data = tmp_path / "data"
    pddl = tmp_path / "pddl"
    data.mkdir()
    pddl.mkdir()

    from api.core import config as cfg

    monkeypatch.setattr(cfg, "DATA_DIR", data)
    monkeypatch.setattr(cfg, "PDDL_DIR", pddl)

    # The dataset_service module captured DATA_DIR at import time via
    # `from api.core.config import DATA_DIR` — reimport so it picks up the patched value.
    import api.services.acg.pddl_service as ps
    importlib.reload(ps)  # captures PDDL_DIR at import; must not clear the real one
    import api.services.acg.plan_service as pl
    importlib.reload(pl)
    import api.services.acg.dataset_service as ds
    importlib.reload(ds)
    import api.services.acg.metric1_service as m1
    importlib.reload(m1)
    yield data
    importlib.reload(ps)
    importlib.reload(pl)
    importlib.reload(ds)  # restore module state for the next test session
    importlib.reload(m1)


@pytest.fixture()
def sample_nodes() -> dict:
    return {
        "n0": {"name": "Attacker", "IP": "1.1.1.1", "location": "external",
               "internet": "yes", "label": "0"},
        "n1": {"name": "Web", "IP": "1.1.1.2", "location": "external",
               "internet": "yes", "label": "1", "port": "p-80",
               "protocol": "http"},
    }


@pytest.fixture()
def sample_edges() -> dict:
    return {"ce1": ["n0", "n1"]}


@pytest.fixture()
def sample_cves() -> dict:
    return {"CVE-2015-1635": {"cve-id": "CVE-2015-1635", "cvss_score": 10.0,
                              "system": "Windows"}}


@pytest.fixture()
def sample_cve_in_node() -> dict:
    return {"n1": ["CVE-2015-1635"]}
