"""Pydantic schemas for the ACG Start-page flow.

The four uploaded JSON files are object/dict-keyed (NOT arrays):
  * node-data.json         {node_id: NodeRecord}
  * connectivity-edge.json {edge_id: [source_node_id, target_node_id]}
  * cve-data.json          {cve_id: CveRecord}     (note hyphenated "cve-id" key)
  * cve-in-node.json       {node_id: [cve_id, ...]}

CVE records carry many optional/free-form fields, so CveRecord allows extras.
NodeRecord likewise tolerates extras to absorb future iEXAM additions.
"""
from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, RootModel


# ---------- Slot identifiers ----------

SlotName = Literal["nodes", "edges", "cves", "cve_in_node"]
SLOT_NAMES: tuple[SlotName, ...] = ("nodes", "edges", "cves", "cve_in_node")

# Maps slot name → canonical filename written to Backend/pages/data/.
CANONICAL_FILENAMES: dict[SlotName, str] = {
    "nodes": "node-data.json",
    "edges": "connectivity-edge.json",
    "cves": "cve-data.json",
    "cve_in_node": "cve-in-node.json",
}


# ---------- Per-record models ----------

class NodeRecord(BaseModel):
    """A single network node. iEXAM tolerates additional fields per node."""

    name: str
    IP: str
    location: str
    internet: str
    label: str
    port: Optional[str] = None
    protocol: Optional[str] = None

    model_config = ConfigDict(extra="allow")


class CveRecord(BaseModel):
    """A single CVE entry. Many optional fields vary across CVEs."""

    cve_id: str = Field(alias="cve-id")
    cvss_score: float

    model_config = ConfigDict(extra="allow", populate_by_name=True)


# ---------- File-level RootModels ----------

class NodesFile(RootModel[dict[str, NodeRecord]]):
    """node-data.json — keyed by node id."""


class EdgesFile(RootModel[dict[str, tuple[str, str]]]):
    """connectivity-edge.json — keyed by edge id; value is [source, target]."""


class CvesFile(RootModel[dict[str, CveRecord]]):
    """cve-data.json — keyed by CVE id."""


class CveInNodeFile(RootModel[dict[str, list[str]]]):
    """cve-in-node.json — keyed by node id; value is list of CVE ids."""


# ---------- Response models ----------

class SlotStats(BaseModel):
    """Surface-level stats for a populated slot."""

    count: int
    saved_as: str


class SlotState(BaseModel):
    """Per-slot status reported by GET /api/acg/dataset."""

    filled: bool
    stats: Optional[SlotStats] = None


class ConsistencyIssue(BaseModel):
    """A single cross-file integrity finding."""

    severity: Literal["error", "warning"]
    code: str
    message: str
    details: Optional[dict] = None


class ConsistencyResult(BaseModel):
    """Aggregated cross-file consistency report."""

    ok: bool
    issues: list[ConsistencyIssue]


class DatasetStatus(BaseModel):
    """The dataset envelope returned by GET /api/acg/dataset."""

    slots: dict[SlotName, SlotState]
    consistency: Optional[ConsistencyResult] = None
    pddl_ready: bool = False


class UploadResponse(BaseModel):
    """Returned by POST /api/acg/upload/{slot}."""

    ok: bool
    slot: SlotName
    saved_as: str
    stats: SlotStats
    dataset: DatasetStatus


class ExampleManifest(BaseModel):
    """Lightweight description of a bundled example dataset."""

    name: str
    label: str
    description: str


class ExamplesList(BaseModel):
    items: list[ExampleManifest]


class PddlGenerateResponse(BaseModel):
    """Returned by POST /api/acg/pddl/generate."""

    ok: bool
    domain_chars: int
    problem_chars: int
    dataset: DatasetStatus


class PddlFile(BaseModel):
    """Returned by GET /api/acg/pddl/{kind}."""

    kind: Literal["domain", "problem"]
    filename: str
    content: str


class GraphNode(BaseModel):
    id: str
    label: str
    is_attacker: bool = False
    cve_count: int = 0
    attrs: dict[str, object] = Field(default_factory=dict)
    cve_ids: list[str] = Field(default_factory=list)


class GraphEdge(BaseModel):
    id: str
    source: str
    target: str


class GraphAttackEdge(BaseModel):
    """An exploit path: attacker (via src) compromises target through cve_id."""

    id: str
    source: str
    target: str
    cve_id: str


class PlanHighlights(BaseModel):
    """IDs to highlight on the network graph for a given plan."""

    node_ids: list[str] = Field(default_factory=list)
    edge_ids: list[str] = Field(default_factory=list)
    cve_ids: list[str] = Field(default_factory=list)
    goal_node_id: Optional[str] = None


class PlanResult(BaseModel):
    """Optimal plan summary returned by POST/GET /api/acg/plan/optimal."""

    goal: Optional[str] = None
    goal_node_id: Optional[str] = None
    steps: list[str]
    step_count: int
    cost: Optional[int] = None
    domain: Optional[str] = None
    problem: Optional[str] = None
    highlights: PlanHighlights = Field(default_factory=PlanHighlights)


class PlanExplanation(BaseModel):
    """LLM-generated narrative of an optimal plan."""

    text: str
    model: Optional[str] = None
    cached: bool = False


class TopKPlan(BaseModel):
    """One plan in a Top-K enumeration."""

    index: int
    steps: list[str]
    step_count: int
    cost: Optional[int] = None
    highlights: PlanHighlights = Field(default_factory=PlanHighlights)


class TopKResult(BaseModel):
    """Top-K planner output returned by POST/GET /api/acg/plan/topk."""

    goal: Optional[str] = None
    goal_node_id: Optional[str] = None
    k_requested: int
    k_returned: int
    domain: Optional[str] = None
    problem: Optional[str] = None
    plans: list[TopKPlan] = Field(default_factory=list)


class RunTopKRequest(BaseModel):
    k: int = Field(default=2, ge=1, le=10)


class GoalsList(BaseModel):
    items: list[str]
    current: Optional[str] = None


class SetGoalRequest(BaseModel):
    goal: str


class GraphPayload(BaseModel):
    """Cytoscape-friendly view of the active dataset."""

    nodes: list[GraphNode]
    edges: list[GraphEdge]
    attack_edges: list[GraphAttackEdge] = Field(default_factory=list)
    cves: dict[str, dict[str, object]] = Field(default_factory=dict)
