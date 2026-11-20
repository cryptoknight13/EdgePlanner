"""Curate raw dataset records for the planner and the LLM.

Real-network datasets (see input_data/actual-test-network) carry far more per
CVE / per node than the planner can use: CPE range strings, Metasploit module
options, per-host check results, service inventories. The raw JSON is kept
untouched for the graph UI; this module is the single place that decides what
subset reaches PDDL object names and LLM prompts.

Shared by api/ (in-process) and the Backend/ subprocess scripts, so keep it
dependency-free.
"""
from __future__ import annotations

import re
from typing import Any

# CVE keys that become PDDL objects (numbered variants like driver1/driver2
# are grouped by their base key). `system` is sourced from installed_version
# when present — see pddl_cve_fields.
PDDL_CVE_KEYS = ("function", "struct", "driver", "system", "cause")

_STRIP_RE = re.compile(r"[^a-z0-9_-]+")
_DASHES_RE = re.compile(r"-{2,}")


def pddl_token(value: Any) -> str:
    """Turn a free-form value into a PDDL-safe identifier.

    Superset of the historical `_format_for_pddl` (space → '-', '.' → '-dot-',
    lowercase): values that only contained letters, digits, spaces, dots,
    '-' and '_' produce the exact same token as before, so existing example
    datasets generate byte-identical PDDL.
    """
    s = str(value).strip().lower()
    s = s.replace(".", "-dot-")
    s = re.sub(r"\s+", "-", s)
    s = _STRIP_RE.sub("-", s)
    s = _DASHES_RE.sub("-", s).strip("-")
    return s or "unnamed"


def _base_key(key: str) -> str:
    return re.sub(r"\d+$", "", key)


def pddl_cve_fields(cve: dict[str, Any]) -> dict[str, list[tuple[str, str]]]:
    """Return {base_key: [(key, value), ...]} for the CVE fields that become
    PDDL objects, in dataset key order.

    - Only string values are kept (lists/dicts such as cwes, host_checks are
      display-only).
    - `installed_version` replaces `system`: the real-network `system` field is
      a CPE range string, useless as an object name. Old datasets have no
      installed_version and fall back to `system` unchanged.
    """
    if not isinstance(cve, dict):
        return {}
    has_installed = isinstance(cve.get("installed_version"), str) and cve[
        "installed_version"
    ].strip()
    grouped: dict[str, list[tuple[str, str]]] = {}
    for key, value in cve.items():
        if not isinstance(value, str) or not value.strip():
            continue
        base = _base_key(key)
        if base == "installed_version":
            grouped.setdefault("system", []).append(("system", value))
            continue
        if base not in PDDL_CVE_KEYS:
            continue
        if base == "system" and has_installed:
            continue
        grouped.setdefault(base, []).append((key, value))
    return grouped


def pddl_cve_values(cve: dict[str, Any]) -> set[str]:
    """All PDDL tokens a CVE contributes — used to map plan atoms back to CVEs."""
    return {
        pddl_token(value)
        for items in pddl_cve_fields(cve).values()
        for _key, value in items
    }


# ---------- LLM summaries ----------

def _join(values: Any, limit: int = 4) -> str:
    if not isinstance(values, list):
        return ""
    strs = [str(v) for v in values if isinstance(v, (str, int, float))]
    if len(strs) > limit:
        return ", ".join(strs[:limit]) + f" (+{len(strs) - limit} more)"
    return ", ".join(strs)


def llm_cve_summary(cve_id: str, cve: dict[str, Any]) -> str:
    """One line per CVE for prompts. Skips host_checks / extracted_facts /
    exploit_requirements / system on purpose — noisy and per-host."""
    c = cve if isinstance(cve, dict) else {}
    parts: list[str] = []
    vuln = c.get("vulnerability") or ""
    cap = c.get("capability") or ""
    if vuln:
        parts.append(str(vuln))
    if cap:
        parts.append(f"capability: {cap}")
    if c.get("installed_version"):
        parts.append(f"installed: {c['installed_version']}")
    cwes = _join(c.get("cwes"))
    if cwes:
        parts.append(f"CWE: {cwes}")
    mods = _join(c.get("metasploit_modules"), limit=2)
    if mods:
        parts.append(f"metasploit: {mods}")
    body = "; ".join(parts)
    return f"{cve_id} (CVSS {c.get('cvss_score', '?')}): {body}".rstrip(": ")


def _service_line(svc: dict[str, Any]) -> str:
    port = str(svc.get("port", "")).replace("p-", "")
    proto = svc.get("protocol", "")
    product = svc.get("product") or svc.get("package") or svc.get("process") or ""
    version = svc.get("version", "")
    head = "/".join(p for p in (port, proto) if p)
    tail = " ".join(p for p in (product, version) if p)
    return f"{head} {tail}".strip()


def llm_node_summary(node_id: str, node: dict[str, Any]) -> str:
    """`n1: john (IP 192.168.50.104, internal) — services: 139/netbios-ssn Samba smbd 3.X, …`"""
    n = node if isinstance(node, dict) else {}
    line = f"{node_id}: {n.get('name')} (IP {n.get('IP')}, {n.get('location')})"
    services = n.get("services")
    if isinstance(services, list) and services:
        svc = [_service_line(s) for s in services if isinstance(s, dict)]
        svc = [s for s in svc if s]
        if svc:
            line += " — services: " + "; ".join(svc[:6])
            if len(svc) > 6:
                line += f" (+{len(svc) - 6} more)"
    return line


# ---------- Node identity ----------
#
# PDDL objects, goals and plan-step parsing all key nodes by *name*. Real
# scans produce duplicate hostnames (seven "john"s in actual-test-network), so
# a node's label is its name when unique and "name (nid)" otherwise. The PDDL
# token is derived from the label — "john (n3)" → "john-n3". Datasets with
# unique names are unaffected.

def node_labels(nodes: dict[str, Any]) -> dict[str, str]:
    counts: dict[str, int] = {}
    for attrs in nodes.values():
        name = str((attrs or {}).get("name", "")).strip()
        counts[name] = counts.get(name, 0) + 1
    labels: dict[str, str] = {}
    for nid, attrs in nodes.items():
        name = str((attrs or {}).get("name", "")).strip() or nid
        labels[nid] = name if counts.get(name, 0) <= 1 else f"{name} ({nid})"
    return labels


def node_tokens(nodes: dict[str, Any]) -> dict[str, str]:
    return {nid: pddl_token(label) for nid, label in node_labels(nodes).items()}


def node_id_for(nodes: dict[str, Any], ref: str | None) -> str | None:
    """Resolve a node id, label, raw name or PDDL token back to the node id.

    Raw names are accepted only when unambiguous.
    """
    if not ref:
        return None
    ref = str(ref).strip()
    if ref in nodes:
        return ref
    labels = node_labels(nodes)
    for nid, label in labels.items():
        if label == ref:
            return nid
    tok = pddl_token(ref)
    for nid, label in labels.items():
        if pddl_token(label) == tok:
            return nid
    by_name = [nid for nid, a in nodes.items()
               if str((a or {}).get("name", "")).strip().lower() == ref.lower()]
    return by_name[0] if len(by_name) == 1 else None
