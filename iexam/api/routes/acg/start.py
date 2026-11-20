"""ACG Start-page routes: upload, dataset status, reset, examples (slice 5)."""
from __future__ import annotations

from fastapi import APIRouter, UploadFile

from api.core.errors import InputValidationError, NotFoundError
from api.schemas.acg.start import (
    DatasetStatus,
    ExamplesList,
    GraphAttackEdge,
    GraphEdge,
    GraphNode,
    GraphPayload,
    SlotName,
    UploadResponse,
)
from api.services.acg import consistency_service, dataset_service, example_service
from api.services.acg.pddl_service import curate

router = APIRouter(prefix="/api/acg", tags=["acg-start"])

MAX_UPLOAD_BYTES = 10 * 1024 * 1024  # 10 MB hard cap; raise if real datasets need more


@router.post("/upload/{slot}", response_model=UploadResponse)
async def upload_slot(slot: SlotName, file: UploadFile) -> UploadResponse:
    """Upload one of the four named files into its slot.

    The user may upload with any filename; the saved file always uses the
    slot's canonical name (e.g., `node-data.json`).
    """
    raw_bytes = await file.read()
    if len(raw_bytes) > MAX_UPLOAD_BYTES:
        raise InputValidationError(
            f"File exceeds size cap of {MAX_UPLOAD_BYTES} bytes",
            details={"size": len(raw_bytes), "cap": MAX_UPLOAD_BYTES},
        )
    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InputValidationError(
            "File is not UTF-8 encoded",
            details={"reason": exc.reason},
        ) from exc

    validated = dataset_service.parse_and_validate(slot, text)
    stats = dataset_service.save_slot(slot, validated)

    consistency = _maybe_consistency()
    return UploadResponse(
        ok=True,
        slot=slot,
        saved_as=stats.saved_as,
        stats=stats,
        dataset=dataset_service.dataset_status(consistency=consistency),
    )


def _maybe_consistency():
    """Run consistency checks only if all 4 slots are populated."""
    if not dataset_service.all_slots_filled():
        return None
    nodes = dataset_service.require_slot("nodes")
    edges = dataset_service.require_slot("edges")
    cves = dataset_service.require_slot("cves")
    cve_in_node = dataset_service.require_slot("cve_in_node")
    return consistency_service.check_consistency(nodes, edges, cves, cve_in_node)


@router.get("/dataset", response_model=DatasetStatus)
def get_dataset() -> DatasetStatus:
    """Current dataset envelope: per-slot state + consistency (when complete)."""
    return dataset_service.dataset_status(consistency=_maybe_consistency())


@router.post("/dataset/reset", response_model=DatasetStatus)
def reset_dataset() -> DatasetStatus:
    """Delete all 4 canonical files. Idempotent."""
    dataset_service.reset_dataset()
    return dataset_service.dataset_status(consistency=None)


@router.get("/examples", response_model=ExamplesList)
def list_examples() -> ExamplesList:
    """List bundled example datasets discovered under `input_data/`."""
    return example_service.list_examples()


@router.post("/upload/example/{name}", response_model=DatasetStatus)
def load_example(name: str) -> DatasetStatus:
    """Load a bundled example into the active dataset, replacing prior state."""
    example_service.load_example(name)
    return dataset_service.dataset_status(consistency=_maybe_consistency())


@router.get("/graph", response_model=GraphPayload)
def get_graph() -> GraphPayload:
    """Return a Cytoscape-friendly view of the active dataset's topology.

    Includes attack_edges: for each connectivity edge whose target has CVEs,
    one attack_edge per (target_cve) is emitted so the frontend can render a
    clickable CVE box between source and target.
    """
    if not dataset_service.all_slots_filled():
        raise NotFoundError("Dataset is not fully loaded")
    nodes = dataset_service.require_slot("nodes")
    edges = dataset_service.require_slot("edges")
    cve_in_node = dataset_service.require_slot("cve_in_node")
    cves = dataset_service.require_slot("cves")

    labels = curate.node_labels(nodes)
    graph_nodes = [
        GraphNode(
            id=node_id,
            label=labels[node_id],
            is_attacker=node_id == "n0" or attrs.get("name") == "Attacker",
            cve_count=len(cve_in_node.get(node_id, [])),
            attrs=attrs,
            cve_ids=list(cve_in_node.get(node_id, [])),
        )
        for node_id, attrs in nodes.items()
    ]
    graph_edges = [
        GraphEdge(id=edge_id, source=src, target=tgt)
        for edge_id, (src, tgt) in edges.items()
    ]
    attack_edges: list[GraphAttackEdge] = []
    for edge_id, (src, tgt) in edges.items():
        for cve_id in cve_in_node.get(tgt, []):
            attack_edges.append(
                GraphAttackEdge(
                    id=f"{edge_id}::{cve_id}",
                    source=src,
                    target=tgt,
                    cve_id=cve_id,
                )
            )
    return GraphPayload(
        nodes=graph_nodes,
        edges=graph_edges,
        attack_edges=attack_edges,
        cves=cves,
    )
