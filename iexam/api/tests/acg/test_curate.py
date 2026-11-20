"""Curation layer: PDDL-safe tokens and the CVE field subset the planner sees."""
from __future__ import annotations

import sys

from api.core.config import HANDLER_DIR

if str(HANDLER_DIR) not in sys.path:
    sys.path.insert(0, str(HANDLER_DIR))

import curate  # noqa: E402


def test_token_matches_legacy_formatter_on_legacy_values():
    legacy = lambda v: v.replace(" ", "-").replace(".", "-dot-").lower()  # noqa: E731
    for v in ["Web Server A", "http.sys remote code execution", "Windows 7 SPI",
              "mod_copy", "pre-auth", "http-dot-system"]:
        assert curate.pddl_token(v) == legacy(v)


def test_token_strips_cpe_range_characters():
    tok = curate.pddl_token("debian debian linux <=10.0; vsftpd project vsftpd 2.3.4")
    assert set(tok) <= set("abcdefghijklmnopqrstuvwxyz0123456789-_")
    assert "--" not in tok
    assert tok == "debian-debian-linux-10-dot-0-vsftpd-project-vsftpd-2-dot-3-dot-4"


def test_token_never_empty():
    assert curate.pddl_token(";;;") == "unnamed"


def test_installed_version_replaces_system():
    cve = {
        "cve-id": "CVE-1", "cvss_score": 9.8,
        "system": "debian debian linux <=10.0; vsftpd project vsftpd 2.3.4",
        "installed_version": "vsftpd 2.3.4",
        "driver": "ftp server download", "cause": "backdoor",
        "cwes": ["CWE-78"], "host_checks": {"n5": []},
    }
    fields = curate.pddl_cve_fields(cve)
    assert fields["system"] == [("system", "vsftpd 2.3.4")]
    assert fields["driver"] == [("driver", "ftp server download")]
    assert fields["cause"] == [("cause", "backdoor")]
    assert "cwes" not in fields and "host_checks" not in fields


def test_legacy_cve_keeps_system_and_numbered_keys():
    cve = {"cve-id": "CVE-2", "cvss_score": 5.0, "function": "f", "struct": "s",
           "system1": "sys a", "system2": "sys b", "capability": "rce"}
    fields = curate.pddl_cve_fields(cve)
    assert fields["system"] == [("system1", "sys a"), ("system2", "sys b")]
    assert fields["function"] == [("function", "f")]
    assert "capability" not in fields


def test_llm_summaries_are_one_line_and_skip_noise():
    cve = {"cvss_score": 9.8, "vulnerability": "backdoor", "capability": "remote access",
           "installed_version": "vsftpd 2.3.4", "cwes": ["CWE-78"],
           "metasploit_modules": ["exploits/unix/ftp/vsftpd_234_backdoor.rb"],
           "host_checks": {"n5": [{"status": "fail"}]}}
    line = curate.llm_cve_summary("CVE-2011-2523", cve)
    assert "\n" not in line and "host_checks" not in line and "fail" not in line
    assert "vsftpd 2.3.4" in line and "CWE-78" in line

    node = {"name": "john", "IP": "10.0.0.4", "location": "internal",
            "services": [{"port": "p-139", "protocol": "netbios-ssn",
                          "product": "Samba smbd", "version": "4.3.13",
                          "important_files": [{"type": "config", "path": "/etc/x"}]}]}
    line = curate.llm_node_summary("n1", node)
    assert line.startswith("n1: john (IP 10.0.0.4, internal)")
    assert "139/netbios-ssn Samba smbd 4.3.13" in line and "/etc/x" not in line


def test_duplicate_node_names_get_disambiguated_labels_and_tokens():
    nodes = {"n0": {"name": "Attacker"}, "n1": {"name": "john"},
             "n2": {"name": "john"}, "n3": {"name": "Web Server A"}}
    assert curate.node_labels(nodes) == {
        "n0": "Attacker", "n1": "john (n1)", "n2": "john (n2)", "n3": "Web Server A"}
    assert curate.node_tokens(nodes) == {
        "n0": "attacker", "n1": "john-n1", "n2": "john-n2", "n3": "web-server-a"}
    assert curate.node_id_for(nodes, "john (n2)") == "n2"
    assert curate.node_id_for(nodes, "john-n2") == "n2"
    assert curate.node_id_for(nodes, "web-server-a") == "n3"
    assert curate.node_id_for(nodes, "Web Server A") == "n3"
    assert curate.node_id_for(nodes, "john") is None  # ambiguous
    assert curate.node_id_for(nodes, "n1") == "n1"
