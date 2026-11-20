"""dataset_service unit tests."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from api.core.errors import InputValidationError, NotFoundError


def test_parse_and_validate_accepts_valid_nodes(isolated_data_dir, sample_nodes):
    from api.services.acg import dataset_service as ds
    out = ds.parse_and_validate("nodes", json.dumps(sample_nodes))
    assert "n0" in out and out["n0"]["IP"] == "1.1.1.1"


def test_parse_and_validate_rejects_invalid_json(isolated_data_dir):
    from api.services.acg import dataset_service as ds
    with pytest.raises(InputValidationError) as ei:
        ds.parse_and_validate("nodes", "{not valid")
    assert "not valid JSON" in ei.value.message


def test_parse_and_validate_rejects_array_for_nodes_slot(isolated_data_dir):
    """Sanity check that schema rejects an array (would have happened under
    the original spec which assumed arrays — caught here)."""
    from api.services.acg import dataset_service as ds
    with pytest.raises(InputValidationError):
        ds.parse_and_validate("nodes", "[]")


def test_parse_and_validate_rejects_unknown_slot(isolated_data_dir):
    from api.services.acg import dataset_service as ds
    with pytest.raises(InputValidationError):
        ds.parse_and_validate("bogus", "{}")  # type: ignore[arg-type]


def test_save_slot_writes_under_canonical_name(isolated_data_dir: Path, sample_nodes):
    from api.services.acg import dataset_service as ds
    validated = ds.parse_and_validate("nodes", json.dumps(sample_nodes))
    stats = ds.save_slot("nodes", validated)
    assert stats.saved_as == "node-data.json"
    target = isolated_data_dir / "node-data.json"
    assert target.exists()
    on_disk = json.loads(target.read_text())
    assert on_disk == validated


def test_slot_state_reports_count_after_save(isolated_data_dir, sample_nodes):
    from api.services.acg import dataset_service as ds
    validated = ds.parse_and_validate("nodes", json.dumps(sample_nodes))
    ds.save_slot("nodes", validated)
    state = ds.slot_state("nodes")
    assert state.filled is True
    assert state.stats is not None
    assert state.stats.count == len(sample_nodes)


def test_reset_dataset_removes_all_files(
    isolated_data_dir, sample_nodes, sample_edges, sample_cves, sample_cve_in_node
):
    from api.services.acg import dataset_service as ds
    for slot, payload in (
        ("nodes", sample_nodes),
        ("edges", sample_edges),
        ("cves", sample_cves),
        ("cve_in_node", sample_cve_in_node),
    ):
        ds.save_slot(slot, ds.parse_and_validate(slot, json.dumps(payload)))
    assert ds.all_slots_filled()
    ds.reset_dataset()
    assert not ds.all_slots_filled()


def test_require_slot_raises_when_missing(isolated_data_dir):
    from api.services.acg import dataset_service as ds
    with pytest.raises(NotFoundError):
        ds.require_slot("nodes")


def test_dataset_status_envelope_shape(isolated_data_dir):
    from api.services.acg import dataset_service as ds
    status = ds.dataset_status()
    assert set(status.slots.keys()) == {"nodes", "edges", "cves", "cve_in_node"}
    assert status.consistency is None
    assert status.pddl_ready is False
