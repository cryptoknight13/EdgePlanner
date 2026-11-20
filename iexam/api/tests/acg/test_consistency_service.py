"""consistency_service unit tests."""
from __future__ import annotations

from api.services.acg.consistency_service import check_consistency


def test_clean_dataset_has_no_errors(
    sample_nodes, sample_edges, sample_cves, sample_cve_in_node, isolated_data_dir
):
    result = check_consistency(
        sample_nodes, sample_edges, sample_cves, sample_cve_in_node
    )
    errors = [i for i in result.issues if i.severity == "error"]
    assert errors == []
    assert result.ok is True


def test_edge_referencing_unknown_node_is_error(sample_nodes, sample_cves):
    edges = {"ce_bad": ["n0", "n_missing"]}
    cve_in_node = {}
    result = check_consistency(sample_nodes, edges, sample_cves, cve_in_node)
    codes = [i.code for i in result.issues if i.severity == "error"]
    assert "edge_unknown_node" in codes
    assert result.ok is False


def test_malformed_edge_tuple_is_error(sample_nodes, sample_cves):
    edges = {"ce_bad": ["only_one"]}
    result = check_consistency(sample_nodes, edges, sample_cves, {})
    assert any(i.code == "edge_malformed" for i in result.issues)


def test_cve_in_node_with_unknown_node_is_error(
    sample_nodes, sample_edges, sample_cves
):
    cve_in_node = {"n_missing": ["CVE-2015-1635"]}
    result = check_consistency(sample_nodes, sample_edges, sample_cves, cve_in_node)
    assert any(i.code == "cve_in_node_unknown_node" for i in result.issues)


def test_cve_in_node_with_unknown_cve_is_error(
    sample_nodes, sample_edges, sample_cves
):
    cve_in_node = {"n1": ["CVE-DOES-NOT-EXIST"]}
    result = check_consistency(sample_nodes, sample_edges, sample_cves, cve_in_node)
    assert any(i.code == "cve_in_node_unknown_cve" for i in result.issues)


def test_orphan_cves_are_warnings_not_errors(sample_nodes, sample_edges):
    cves = {
        "CVE-2015-1635": {"cve-id": "CVE-2015-1635", "cvss_score": 10.0},
        "CVE-2099-9999": {"cve-id": "CVE-2099-9999", "cvss_score": 5.0},  # orphan
    }
    cve_in_node = {"n1": ["CVE-2015-1635"]}
    result = check_consistency(sample_nodes, sample_edges, cves, cve_in_node)
    warnings = [i for i in result.issues if i.severity == "warning"]
    assert any(w.code == "orphan_cves" for w in warnings)
    # Orphan CVEs alone don't make the dataset invalid:
    assert result.ok is True
