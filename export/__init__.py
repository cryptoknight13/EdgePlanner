"""Phase 6 — Export: the run's network model as iEXAM's four input files.

Format: upstream/iEXAM input_data/*/ and api/schemas/acg/start.py. PDDL-relevant CVE fields are
deterministic (product -> installed_version, exposed service -> driverN); LLM text only in display
fields. See phases/phase-6.md.
"""
import ipaddress
import json
from datetime import datetime, timezone
from pathlib import Path

from netmodel import build

REACHABLE_VECTORS = {"NETWORK", "ADJACENT_NETWORK", "ADJACENT"}


def product_name(c: dict) -> str:
    """Human product name used as the PDDL `system` object: 'm1014_firmware' -> 'axis m1014 firmware'."""
    product = (c.get("product") or "service").replace("_", " ")
    vendor = c.get("vendor") or ""
    return f"{vendor} {product}" if product.endswith("firmware") and vendor else product


def keep_reason(row: dict, info: dict, cfg: dict) -> str | None:
    """None if the CVE row is kept, else why it was dropped."""
    if row["weak"] and not cfg.get("include_weak", False):
        return "weak match (NVD lists no version)"
    vector = ((info.get("cvss") or {}).get("attack_vector") or "").upper()
    if vector and vector not in REACHABLE_VECTORS:
        return f"not network-reachable (attack vector {vector.lower()})"
    if (row["cvss"] or 0) < cfg.get("min_cvss", 0):
        return f"below min_cvss {cfg['min_cvss']}"
    if cfg.get("require_public_exploit") and not row["public_exploit"]:
        return "no public exploit"
    return None


def subnet_label(ip: str, subnets: list[str]) -> str:
    for i, s in enumerate(subnets, start=1):
        if ipaddress.ip_address(ip) in ipaddress.ip_network(s):
            return str(i)
    return str(len(subnets) + 1)


def cve_record(cve_id: str, rows: list[dict], info: dict, services: dict[tuple, str]) -> dict:
    """One cve-data.json entry. rows: every kept (node, row) occurrence of this CVE."""
    cvss = info.get("cvss") or {}
    rec = {"cve-id": cve_id, "cvss_score": float(cvss.get("score") or rows[0]["cvss"] or 0.0)}
    rec["installed_version"] = product_name(rows[0])
    # Only port-bound CVEs get a service fact; firmware CVEs cannot be mitigated by closing a port.
    drivers = sorted({services.get((r["node"], r["port"])) or f"port {r['port']} service" for r in rows if r["port"]})
    for i, d in enumerate(drivers, start=1):
        rec[f"driver{i}" if len(drivers) > 1 else "driver"] = d
    ex = info.get("explanation") or {}
    rec.update({
        "service-up": True,
        "vulnerability": ex.get("cause") or (info.get("description") or "")[:200],
        "capability": ex.get("consequence") or "",
        "explanation_source": ex.get("model") and f"llm:{ex['model']}",
        "description": info.get("description"),
        "versions": sorted({f"{r['product']} {r['version']}" for r in rows if r["product"] and r["version"]}),
        "ports": sorted({r["port"] for r in rows if r["port"]}),
        "cvss_vector": cvss.get("vector"), "cvss_version": cvss.get("version"),
        "cwes": info.get("cwes", []),
        "epss": (info.get("epss") or {}).get("epss"),
        "kev": bool((info.get("exploit") or {}).get("kev")),
        "public_exploit": any(r["public_exploit"] for r in rows),
        "fixed_in": sorted({f["version"] for f in (info.get("fixed") or {}).get("nvd", []) if f["kind"] == "fixed_in"}),
        "match_types": sorted({r["match_type"] for r in rows}),
    })
    return {k: v for k, v in rec.items() if v not in (None, "")}


def export(run_dir: Path, attacker_ip: str, cfg: dict) -> dict:
    m = build(run_dir)
    info = m["cves"]
    dropped: dict[str, int] = {}
    kept: dict[str, list[dict]] = {}
    for n in m["nodes"]:
        if n["kind"] in ("attacker", "self"):
            continue
        rows = []
        for r in n["cves"]:
            reason = keep_reason(r, info.get(r["id"], {}), cfg)
            if reason:
                dropped[reason] = dropped.get(reason, 0) + 1
            else:
                rows.append({**r, "node": n["id"]})
        kept[n["id"]] = rows

    by_id = {n["id"]: n for n in m["nodes"]}
    excluded = []
    for n in m["nodes"]:
        if n["kind"] == "self":
            excluded.append({"ip": n["ip"], "name": n["name"], "reason": "this monitoring machine"})
        elif n["kind"] != "attacker" and not kept[n["id"]]:
            excluded.append({"ip": n["ip"], "name": n["name"],
                             "reason": "no CVE left after filtering" if n["cves"] else "no known CVE"})
    exported = [nid for nid, rows in kept.items() if rows]

    # Renumber: n0 attacker, then exported nodes in model order (iEXAM expects n0..nK).
    new_id = {"n0": "n0", **{nid: f"n{i}" for i, nid in enumerate(exported, start=1)}}
    nodes = {"n0": {"name": "Attacker", "IP": attacker_ip, "location": "external", "internet": "yes", "label": "0"}}
    services: dict[tuple, str] = {}
    for nid in exported:
        n = by_id[nid]
        for p in n["ports"]:
            services[(nid, p["port"])] = f"{p['service'] or 'unknown'} service"
        main = kept[nid][0]
        nodes[new_id[nid]] = {
            "name": n["name"], "IP": n["ip"],
            "location": "external" if n["kind"] == "router" else "internal",
            "internet": "yes", "label": subnet_label(n["ip"], m["subnets"]),
            "port": f"p-{main['port']}" if main["port"] else None,
            "protocol": services.get((nid, main["port"]), "service").removesuffix(" service"),
            "device_type": n["label"], "mac": n["mac"], "vendor": n["vendor"],
            "os": (n["os"] or {}).get("name"),
            "firmware": (n["identity"] or {}).get("firmware"),
            "services": [{"port": f"p-{p['port']}", "protocol": p["service"], "product": p["product"],
                          "version": p["version"]} for p in n["ports"]],
        }
        nodes[new_id[nid]] = {k: v for k, v in nodes[new_id[nid]].items() if v is not None}

    edges, seen = {}, set()

    def edge(a: str, b: str) -> None:
        if a in new_id and b in new_id and a != b and (a, b) not in seen:
            seen.add((a, b))
            edges[f"ce{len(edges) + 1}"] = [new_id[a], new_id[b]]

    notes = []
    for e in m["edges"]:
        if e["kind"] in ("wan", "lan"):
            edge(e["source"], e["target"])
    gateway = next((e["target"] for e in m["edges"] if e["kind"] == "wan"), None)
    if gateway and gateway not in exported:
        notes.append("The gateway router has no kept CVE, so the attacker cannot get past it: "
                     "nothing behind it is reachable in this model.")
    if cfg.get("lateral_edges"):
        devices = [nid for nid in exported if by_id[nid]["kind"] == "device"]
        for a in devices:
            for b in devices:
                edge(a, b)

    occurrences: dict[str, list[dict]] = {}
    for nid in exported:
        for r in kept[nid]:
            occurrences.setdefault(r["id"], []).append(r)
    cve_data = {cid: cve_record(cid, rows, info.get(cid, {}), services) for cid, rows in sorted(occurrences.items())}
    cve_in_node = {new_id[nid]: sorted({r["id"] for r in kept[nid]}) for nid in exported}

    manifest = {
        "name": f"home-{m['run_id']}", "label": f"Home network {m['run_id']}",
        "description": f"Exported by EdgePlanner from run {m['run_id']}: "
                       f"{len(exported)} exploitable node(s) on {', '.join(m['subnets'])}.",
        "files": {"nodes": "node-data.json", "edges": "connectivity-edge.json",
                  "cves": "cve-data.json", "cve_in_node": "cve-in-node.json"},
        "exported_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "filter": {"include_weak": cfg.get("include_weak", False), "min_cvss": cfg.get("min_cvss", 0),
                   "require_public_exploit": cfg.get("require_public_exploit", False),
                   "lateral_edges": cfg.get("lateral_edges", False), "network_reachable_only": True},
        "cve_rows_dropped": dropped,
        "node_ids": {new_id[nid]: by_id[nid]["ip"] for nid in exported},
        "excluded_nodes": excluded,
        "notes": notes,
    }
    return {"node-data": nodes, "connectivity-edge": edges, "cve-in-node": cve_in_node,
            "cve-data": cve_data, "manifest": manifest}


def write(files: dict, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    for name, content in files.items():
        (out_dir / f"{name}.json").write_text(json.dumps(content, indent=2))
