"""Cross-file consistency checks for the ACG dataset.

Run once all 4 slots are populated. Each issue carries a code so the frontend
can render specific guidance. Issues are split into errors (block proceeding)
and warnings (informational, but proceed allowed).
"""
from __future__ import annotations

from typing import Any

from api.schemas.acg.start import ConsistencyIssue, ConsistencyResult


def check_consistency(
    nodes: dict[str, Any],
    edges: dict[str, Any],
    cves: dict[str, Any],
    cve_in_node: dict[str, Any],
) -> ConsistencyResult:
    """Aggregate all cross-file checks. `ok=True` only if no errors."""
    issues: list[ConsistencyIssue] = []
    issues.extend(_edges_reference_known_nodes(nodes, edges))
    issues.extend(_cve_in_node_keys_known(nodes, cve_in_node))
    issues.extend(_cve_in_node_values_known(cves, cve_in_node))
    issues.extend(_orphan_cves(cves, cve_in_node))
    issues.extend(_nodes_without_cves(nodes, cve_in_node))
    has_error = any(issue.severity == "error" for issue in issues)
    return ConsistencyResult(ok=not has_error, issues=issues)


def _edges_reference_known_nodes(
    nodes: dict[str, Any], edges: dict[str, Any]
) -> list[ConsistencyIssue]:
    out: list[ConsistencyIssue] = []
    node_ids = set(nodes.keys())
    for edge_id, endpoints in edges.items():
        if not isinstance(endpoints, (list, tuple)) or len(endpoints) != 2:
            out.append(ConsistencyIssue(
                severity="error",
                code="edge_malformed",
                message=f"Edge '{edge_id}' is not a 2-element [source, target] tuple",
                details={"edge_id": edge_id, "value": endpoints},
            ))
            continue
        src, dst = endpoints
        for unknown in (n for n in (src, dst) if n not in node_ids):
            out.append(ConsistencyIssue(
                severity="error",
                code="edge_unknown_node",
                message=f"Edge '{edge_id}' references unknown node '{unknown}'",
                details={"edge_id": edge_id, "unknown_node": unknown},
            ))
    return out


def _cve_in_node_keys_known(
    nodes: dict[str, Any], cve_in_node: dict[str, Any]
) -> list[ConsistencyIssue]:
    node_ids = set(nodes.keys())
    return [
        ConsistencyIssue(
            severity="error",
            code="cve_in_node_unknown_node",
            message=f"cve-in-node entry references unknown node '{node_id}'",
            details={"node_id": node_id},
        )
        for node_id in cve_in_node.keys()
        if node_id not in node_ids
    ]


def _cve_in_node_values_known(
    cves: dict[str, Any], cve_in_node: dict[str, Any]
) -> list[ConsistencyIssue]:
    cve_ids = set(cves.keys())
    out: list[ConsistencyIssue] = []
    for node_id, cve_list in cve_in_node.items():
        if not isinstance(cve_list, list):
            out.append(ConsistencyIssue(
                severity="error",
                code="cve_in_node_value_malformed",
                message=f"cve-in-node['{node_id}'] is not a list",
                details={"node_id": node_id, "value": cve_list},
            ))
            continue
        for cve_id in cve_list:
            if cve_id not in cve_ids:
                out.append(ConsistencyIssue(
                    severity="error",
                    code="cve_in_node_unknown_cve",
                    message=f"Node '{node_id}' references unknown CVE '{cve_id}'",
                    details={"node_id": node_id, "unknown_cve": cve_id},
                ))
    return out


def _orphan_cves(
    cves: dict[str, Any], cve_in_node: dict[str, Any]
) -> list[ConsistencyIssue]:
    referenced: set[str] = set()
    for cve_list in cve_in_node.values():
        if isinstance(cve_list, list):
            referenced.update(cve_list)
    orphans = [cid for cid in cves.keys() if cid not in referenced]
    if not orphans:
        return []
    return [ConsistencyIssue(
        severity="warning",
        code="orphan_cves",
        message=f"{len(orphans)} CVE record(s) are not referenced by any node",
        details={"orphan_cves": orphans},
    )]


def _nodes_without_cves(
    nodes: dict[str, Any], cve_in_node: dict[str, Any]
) -> list[ConsistencyIssue]:
    nodes_with_cves = {
        node_id for node_id, cve_list in cve_in_node.items()
        if isinstance(cve_list, list) and cve_list
    }
    bare = [nid for nid in nodes.keys() if nid not in nodes_with_cves]
    if not bare:
        return []
    return [ConsistencyIssue(
        severity="warning",
        code="nodes_without_cves",
        message=f"{len(bare)} node(s) have no CVE entries (this may be intentional)",
        details={"nodes_without_cves": bare},
    )]
