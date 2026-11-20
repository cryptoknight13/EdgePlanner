"""example_service unit tests."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from api.core.errors import NotFoundError


@pytest.fixture()
def isolated_examples_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    examples = tmp_path / "input_data"
    examples.mkdir()
    from api.core import config as cfg
    monkeypatch.setattr(cfg, "INPUT_DATA_DIR", examples)
    import importlib
    import api.services.acg.example_service as es
    importlib.reload(es)
    yield examples
    importlib.reload(es)


def _seed(
    examples: Path,
    name: str,
    nodes: dict,
    edges: dict,
    cves: dict,
    cve_in_node: dict,
    *,
    label: str | None = None,
) -> Path:
    d = examples / name
    d.mkdir()
    (d / "manifest.json").write_text(json.dumps({
        "name": name,
        "label": label or name,
        "description": "fixture example",
        "files": {
            "nodes": "node-data.json",
            "edges": "connectivity-edge.json",
            "cves": "cve-data.json",
            "cve_in_node": "cve-in-node.json",
        },
    }))
    (d / "node-data.json").write_text(json.dumps(nodes))
    (d / "connectivity-edge.json").write_text(json.dumps(edges))
    (d / "cve-data.json").write_text(json.dumps(cves))
    (d / "cve-in-node.json").write_text(json.dumps(cve_in_node))
    return d


def test_list_examples_finds_seeded_example(
    isolated_examples_dir, isolated_data_dir,
    sample_nodes, sample_edges, sample_cves, sample_cve_in_node,
):
    _seed(isolated_examples_dir, "demo", sample_nodes, sample_edges,
          sample_cves, sample_cve_in_node, label="Demo Net")
    from api.services.acg import example_service
    out = example_service.list_examples()
    names = [e.name for e in out.items]
    labels = [e.label for e in out.items]
    assert "demo" in names
    assert "Demo Net" in labels


def test_list_examples_skips_dirs_without_manifest(isolated_examples_dir, isolated_data_dir):
    (isolated_examples_dir / "no_manifest_here").mkdir()
    from api.services.acg import example_service
    assert example_service.list_examples().items == []


def test_load_example_populates_dataset(
    isolated_examples_dir, isolated_data_dir,
    sample_nodes, sample_edges, sample_cves, sample_cve_in_node,
):
    _seed(isolated_examples_dir, "demo", sample_nodes, sample_edges,
          sample_cves, sample_cve_in_node)
    from api.services.acg import example_service, dataset_service
    example_service.load_example("demo")
    assert dataset_service.all_slots_filled()


def test_load_unknown_example_raises_not_found(isolated_examples_dir, isolated_data_dir):
    from api.services.acg import example_service
    with pytest.raises(NotFoundError):
        example_service.load_example("does-not-exist")


def test_load_example_resets_prior_dataset(
    isolated_examples_dir, isolated_data_dir,
    sample_nodes, sample_edges, sample_cves, sample_cve_in_node,
):
    """Stale state from a different upload must be wiped before the example loads."""
    from api.services.acg import dataset_service, example_service

    dataset_service.save_slot(
        "nodes",
        dataset_service.parse_and_validate("nodes", json.dumps({
            "junk": {"name": "x", "IP": "0.0.0.0", "location": "external",
                     "internet": "no", "label": "9"},
        })),
    )
    assert dataset_service.slot_state("nodes").filled

    _seed(isolated_examples_dir, "demo", sample_nodes, sample_edges,
          sample_cves, sample_cve_in_node)
    example_service.load_example("demo")

    nodes = dataset_service.require_slot("nodes")
    assert "junk" not in nodes
    assert "n0" in nodes
