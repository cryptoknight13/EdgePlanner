"""Route-level tests for /api/acg/start.

Uses TestClient with the real app; isolated_data_dir keeps writes in tmp.
"""
from __future__ import annotations

import importlib
import json
from io import BytesIO

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def client(isolated_data_dir):
    # Ensure dataset_service was reloaded against patched DATA_DIR (conftest does this),
    # then build a fresh app instance.
    import api.routes.acg.start as start_module
    importlib.reload(start_module)
    from api.main import create_app
    return TestClient(create_app())


def _upload(client: TestClient, slot: str, payload: dict, filename: str = "x.json"):
    return client.post(
        f"/api/acg/upload/{slot}",
        files={"file": (filename, BytesIO(json.dumps(payload).encode()), "application/json")},
    )


def test_upload_nodes_saves_under_canonical_name(client, sample_nodes):
    response = _upload(client, "nodes", sample_nodes, filename="my-fancy-name.json")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["ok"] is True
    assert body["saved_as"] == "node-data.json"
    assert body["dataset"]["slots"]["nodes"]["filled"] is True


def test_upload_with_invalid_json_returns_422_with_error_envelope(client):
    response = client.post(
        "/api/acg/upload/nodes",
        files={"file": ("x.json", BytesIO(b"{not valid"), "application/json")},
    )
    assert response.status_code == 422
    body = response.json()
    assert "error" in body
    assert body["error"]["code"] == "validation_error"


def test_upload_with_unknown_slot_returns_422(client, sample_nodes):
    response = client.post(
        "/api/acg/upload/bogus",
        files={"file": ("x.json", BytesIO(json.dumps(sample_nodes).encode()))},
    )
    # FastAPI's path Literal validator rejects unknown slot before our code runs:
    assert response.status_code == 422


def test_dataset_endpoint_returns_envelope_when_empty(client):
    response = client.get("/api/acg/dataset")
    assert response.status_code == 200
    body = response.json()
    assert all(slot["filled"] is False for slot in body["slots"].values())
    assert body["consistency"] is None


def test_full_upload_run_yields_consistency_result(
    client, sample_nodes, sample_edges, sample_cves, sample_cve_in_node
):
    _upload(client, "nodes", sample_nodes)
    _upload(client, "edges", sample_edges)
    _upload(client, "cves", sample_cves)
    response = _upload(client, "cve_in_node", sample_cve_in_node)
    assert response.status_code == 200
    body = response.json()
    assert body["dataset"]["consistency"] is not None
    assert body["dataset"]["consistency"]["ok"] is True


def test_reset_clears_dataset(client, sample_nodes):
    _upload(client, "nodes", sample_nodes)
    response = client.post("/api/acg/dataset/reset")
    assert response.status_code == 200
    body = response.json()
    assert body["slots"]["nodes"]["filled"] is False
