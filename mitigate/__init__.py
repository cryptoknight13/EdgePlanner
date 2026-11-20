"""Phase 8 — Metric 1 mitigation: option sets that make each goal unreachable, as concrete actions.

Drives iEXAM's metric1_service (iexam/Backend/pages/_metric1) in-process, like attackplan does for
phase 7. Metric 1 searches subsets of PDDL facts and our export has one fact per CVE, which is
exponential; Metric 1 therefore sees one representative CVE per (node, product, services) group.
Every option is then verified on the full network with Fast Downward.
"""
import ast
import json
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path

import attackplan
from api.core.errors import ApiException
from api.services.acg import metric1_service, plan_service
from api.services.acg.pddl_service import curate

SCHEMA_VERSION = "1.0"
FACT = re.compile(r"has-(n\d+)-(system|driver|cause|struct|function)-\S+ (\S+)$")
NVD = "https://nvd.nist.gov/vuln/detail/"


def _product(rec: dict) -> str:
    return rec.get("installed_version") or rec.get("system") or ""


def _drivers(rec: dict) -> list[str]:
    return [v for k, v in sorted(rec.items()) if k.startswith("driver") and isinstance(v, str)]


def group_cves(cve_in_node: dict, cve_data: dict) -> dict[str, list[str]]:
    """One representative CVE per (node, product, services): their facts block or allow the same moves."""
    out: dict[str, list[str]] = {}
    for nid, ids in cve_in_node.items():
        seen: set = set()
        out[nid] = []
        for cid in ids:
            key = (_product(cve_data[cid]), tuple(_drivers(cve_data[cid])))
            if key not in seen:
                seen.add(key)
                out[nid].append(cid)
    return out


def write_m1_input(export_dir: Path, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    for name in attackplan.FILES.values():
        shutil.copy2(export_dir / name, out_dir / name)
    cin = json.loads((export_dir / "cve-in-node.json").read_text())
    data = json.loads((export_dir / "cve-data.json").read_text())
    (out_dir / "cve-in-node.json").write_text(json.dumps(group_cves(cin, data), indent=2))


def parse_option(raw: str) -> list[tuple[str, str, str]]:
    """iEXAM option set literal -> [(node id, fact kind, PDDL token)]."""
    try:
        items = ast.literal_eval(raw)
    except (ValueError, SyntaxError):
        return []
    if not isinstance(items, (set, list, tuple)):
        return []
    return [m.groups() for m in (FACT.search(str(i).strip()) for i in sorted(items)) if m]


def _vkey(v: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", v))


def _matches(rec: dict, kind: str, token: str) -> bool:
    if kind == "system":
        return curate.pddl_token(_product(rec)) == token
    if kind == "driver":
        return any(curate.pddl_token(d) == token for d in _drivers(rec))
    return curate.pddl_token(rec.get(kind, "")) == token


def _evidence(cid: str, rec: dict, info: dict) -> dict:
    fixed = (info.get("fixed") or {}).get("nvd", [])
    refs = [r["url"] for r in info.get("references") or []
            if set(r.get("tags") or []) & {"Patch", "Vendor Advisory", "Release Notes"}]
    return {
        "cve": cid,
        "cvss": rec.get("cvss_score"),
        "nvd": NVD + cid,
        "fixed_in": sorted({f["version"] for f in fixed if f["kind"] == "fixed_in"}, key=_vkey),
        "last_affected": sorted({f["version"] for f in fixed if f["kind"] == "last_affected"}, key=_vkey),
        "fix_commits": [p["url"] for p in info.get("patches") or [] if p.get("for_our_product")],
        "advisories": refs[:5],
    }


def action(nid: str, kind: str, token: str, nodes: dict, cve_in_node: dict, cve_data: dict,
           cveinfo: dict) -> dict:
    """One removed fact -> the real change it stands for, with the CVEs it fixes."""
    node = nodes[nid]
    recs = {c: cve_data[c] for c in cve_in_node.get(nid, []) if _matches(cve_data[c], kind, token)}
    ev = [_evidence(c, r, cveinfo.get(c, {})) for c, r in recs.items()]
    where = f"{node['name']} ({node.get('IP')})"
    # cve-data versions/ports are per CVE across all nodes; cveinfo's affects is per host.
    here = [a for c in recs for a in cveinfo.get(c, {}).get("affects") or [] if a.get("ip") == node.get("IP")]
    out = {"node": nid, "node_name": node["name"], "ip": node.get("IP"), "fact": kind, "token": token,
           "cves_fixed": len(ev), "evidence": ev}
    if kind == "system":
        product = _product(next(iter(recs.values()))) if recs else token
        installed = (sorted({f"{a['product']} {a['version']}" for a in here}) if here else
                     sorted({v for r in recs.values() for v in r.get("versions", [])}))
        # shortcut: the highest fixed version across branches is assumed to carry every older-branch fix; per-branch targets if a vendor breaks that.
        fixed = max((v for e in ev for v in e["fixed_in"]), key=_vkey, default=None)
        after = max((v for e in ev for v in e["last_affected"]), key=_vkey, default=None)
        unfixed = [e["cve"] for e in ev if not e["fixed_in"] and not e["last_affected"]]
        if after and (not fixed or _vkey(after) >= _vkey(fixed)):
            target = f"a version later than {after}"
        else:
            target = f"{fixed} or later" if fixed else None
        frm = f" from {', '.join(installed)}" if installed else ""
        text = (f"Upgrade {product} on {where}{frm} to {target}" if target else
                f"Upgrade or replace {product} on {where}{frm}: no fixed version is published; check the vendor")
        if target and unfixed:
            text += f"; {len(unfixed)} CVE(s) have no published fix, confirm with the vendor"
        out.update(type="upgrade", product=product, installed=installed, target_version=fixed,
                   later_than=after, unfixed_cves=unfixed, text=text)
    elif kind == "driver":
        service = next((d for r in recs.values() for d in _drivers(r) if curate.pddl_token(d) == token), token)
        ports = (sorted({a["port"] for a in here if a.get("port")}) if here else
                 sorted({p for r in recs.values() for p in r.get("ports", [])}))
        on = f" (port {', '.join(map(str, ports))})" if ports else ""
        out.update(type="close", service=service, ports=ports,
                   text=f"Close or firewall {service}{on} on {where}")
    else:
        out.update(type="change", text=f"Change {kind} '{token.replace('-', ' ')}' on {where}")
    return out


def _without(problem: str, facts: list[tuple[str, str, str]]) -> str:
    pats = [re.compile(rf"\(has-{n}-{k}-\S+ {re.escape(t)}\)") for n, k, t in facts]
    return "".join(l for l in problem.splitlines(keepends=True) if not any(p.search(l) for p in pats))


def blocks(problem: str, facts: list[tuple[str, str, str]]) -> bool:
    """Fast Downward on the full network with the facts removed must prove the goal unreachable."""
    plan_service.NEW_PROBLEM_FILE.write_text(_without(problem, facts))
    try:
        plan_service.run_optimal_plan()
    except ApiException as exc:
        if (getattr(exc, "details", None) or {}).get("returncode") == 12:
            return True
        raise
    return False


def _options(goal: str) -> list[str]:
    plan_service.set_goal(goal)
    plan_service.run_optimal_plan()
    metric1_service.prepare()
    metric1_service.set_heuristic("without")
    return [o["raw"] for o in metric1_service.generate_options()]


def run(run_dir: Path, targets: list[str] | None) -> dict:
    export_dir, out_dir = run_dir / "iexam", run_dir / "mitigation"
    if out_dir.exists():
        shutil.rmtree(out_dir)
    write_m1_input(export_dir, out_dir / "m1-input")
    nodes = json.loads((export_dir / "node-data.json").read_text())
    cve_in_node = json.loads((export_dir / "cve-in-node.json").read_text())
    cve_data = json.loads((export_dir / "cve-data.json").read_text())
    ci = run_dir / "cveinfo.json"
    cveinfo = json.loads(ci.read_text())["cves"] if ci.exists() else {}

    # Full network: goal problems for verification, and which goals are reachable at all.
    attackplan.load_dataset(export_dir)
    attackplan.pddl_service.generate_pddl()
    goals = targets or plan_service.list_goals()
    unreachable = set(plan_service.unreachable_goals())
    full: dict[str, str] = {}
    for g in goals:
        if g not in unreachable:
            plan_service.set_goal(g)
            full[g] = plan_service.NEW_PROBLEM_FILE.read_text()

    notes: list[str] = []
    raw: dict[str, list[str]] = {}
    attackplan.load_dataset(out_dir / "m1-input")
    attackplan.pddl_service.generate_pddl()
    for g in full:
        try:
            raw[g] = _options(g)
        except ApiException as exc:
            notes.append(f"Metric 1 for {g}: {exc}")
            raw[g] = []

    attackplan.load_dataset(export_dir)
    attackplan.pddl_service.generate_pddl()
    results = []
    for g in goals:
        if g in unreachable:
            results.append({"goal": g, "unreachable": True, "options": []})
            continue
        opts = []
        for i, r in enumerate(raw[g], 1):
            facts = parse_option(r)
            opts.append({"option": i, "pddl": r, "blocks_all_plans": blocks(full[g], facts),
                         "actions": [action(*f, nodes, cve_in_node, cve_data, cveinfo) for f in facts]})
        results.append({"goal": g, "unreachable": False, "options": opts})
    return {
        "schema_version": SCHEMA_VERSION,
        "run_id": run_dir.name,
        "collected_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "method": "iEXAM Metric 1 (no heuristic) on one CVE per (node, product, services); "
                  "each option verified unsolvable on the full network (Fast Downward astar(lmcut()))",
        "targets": results,
        "notes": notes,
    }


def write(result: dict, run_dir: Path) -> Path:
    path = run_dir / "mitigation" / "mitigation.json"
    path.write_text(json.dumps(result, indent=2))
    return path
