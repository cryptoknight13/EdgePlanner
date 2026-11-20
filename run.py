"""Orchestrator.

  python run.py discover              phase 1: find and label every host -> runs/<run-id>/discover.json
  python run.py gather [--run ID]     phase 2: ports, services, versions, OS, identity -> runs/<run-id>/gather.json
  python run.py scan [--run ID]       phase 3: CVE ids per host (NVD CPE match + nuclei) -> runs/<run-id>/scan.json
  python run.py cveinfo [--run ID] [--no-llm]  phase 4: CVE facts, fixes, patches, exploits, explanation -> cveinfo.json
  python run.py web [--host H] [--port P]       phase 5: network view in the browser (default 127.0.0.1:8080)
  python run.py export [--run ID]               phase 6: iEXAM input files -> runs/<run-id>/iexam/
  python run.py plan [--run ID] [--k K] [--target NAME ...] [--no-llm]  phase 7: iEXAM attack plans -> plans/
  python run.py mitigate [--run ID] [--target NAME ...]  phase 8: Metric 1 mitigation options -> mitigation/
  python run.py guide [--run ID] --target NAME  phase 8b: LLM fix guide per mitigation action -> mitigation/guide.json
  python run.py llmbench [--run ID] [--models a,b] [--api] [--repeat N]  phase 8c: small-LLM benchmark -> llmbench/
  python run.py probe --target camera phase 0: single-target evidence record -> output/
"""
import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

from collector import active, link, passive
from collector.schema import new_record
from discover import discover
from gather import gather
from scan import scan
from cveinfo import cveinfo
import cve
import resolver

ROOT = Path(__file__).resolve().parent


def load_env() -> None:
    """KEY=VALUE lines from .env into the environment (existing variables win)."""
    env = ROOT / ".env"
    if env.exists():
        for line in env.read_text().splitlines():
            key, sep, value = line.partition("=")
            if sep and not key.strip().startswith("#"):
                os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def load(name: str) -> dict:
    with open(ROOT / "config" / name) as f:
        return yaml.safe_load(f)


def summary(r: dict) -> str:
    ports = ", ".join(f"{p['port']}/{p['service']} ({' '.join(filter(None, [p['product'], p['version']])) or '?'})"
                      for p in r["active"]["ports"]) or "none"
    res = r["resolved"]
    lines = [
        f"target   : {r['target']['label']} {r['target']['ip']}",
        f"mac      : {r['link']['mac']}  vendor: {r['link']['oui_vendor']}",
        f"ports    : {ports}",
        f"onvif    : {r['onvif']['status']}",
        f"identity : make={res.get('make')} model={res.get('model')} firmware={res.get('firmware')}",
    ]
    lines += [f"note     : {n}" for n in r["notes"]]
    return "\n".join(lines)


def probe(args: argparse.Namespace) -> int:
    comps, targets = load("components.yaml"), load("targets.yaml")
    on = comps["components"]
    if args.target not in targets["targets"]:
        sys.exit(f"unknown target {args.target!r}; known: {', '.join(targets['targets'])}")
    t = targets["targets"][args.target]

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = ROOT / "output"
    out.mkdir(exist_ok=True)
    record = new_record(t["label"], t["ip"])

    link.collect(record, ROOT / comps["link"]["oui_file"], comps["link"]["oui_url"])
    if on.get("passive"):
        passive.collect(record, targets["interface"], comps["passive"]["window_seconds"],
                        out / f"{stamp}-{args.target}-passive.pcap")
    if on.get("active"):
        active.collect(record, comps["active"]["nmap_args"])
    if on.get("resolver"):
        record = resolver.resolve(record)
    if on.get("cve"):
        record = cve.lookup(record)

    path = out / f"{stamp}-{args.target}.json"
    path.write_text(json.dumps(record, indent=2))
    print(summary(record))
    print(f"record   : {path}")
    return 0


def discover_table(d: dict) -> str:
    rows = [f"{'IP':<16}{'MAC':<19}{'VENDOR':<28}{'LABEL':<10}{'CONF':<6}HOSTNAME / EVIDENCE"]
    for h in d["hosts"]:
        tag = {"self": " (self)", "router": " (router)"}.get(h["role"], "")
        rows.append(f"{h['ip']:<16}{(h['mac'] or '-'):<19}{(h['vendor'] or '-')[:27]:<28}"
                    f"{h['label']:<10}{h['confidence']:<6}{', '.join(h['hostnames'][:2]) or '-'}{tag}")
        rows += [f"{'':<79}- {e}" for e in h["evidence"][:4]]
    rows += [f"note: {n}" for n in d["notes"]]
    return "\n".join(rows)


def run_discover(args: argparse.Namespace) -> int:
    settings = load("settings.yaml")
    run_dir = ROOT / "runs" / (args.run or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"))
    if (run_dir / "discover.json").exists():
        sys.exit(f"{run_dir.name} already has discover.json; discover starts a new run")
    run_dir.mkdir(parents=True, exist_ok=True)  # the web pipeline creates it first for its log
    result = discover(settings, ROOT / settings["oui_file"], settings["oui_url"], run_dir)
    path = run_dir / "discover.json"
    path.write_text(json.dumps(result, indent=2))
    print(discover_table(result))
    print(f"hosts: {len(result['hosts'])}  record: {path}")
    return 0


def run_dir_for(run_id: str | None, needs: str) -> Path:
    """The named run, or the latest run that already has `needs`."""
    if run_id:
        d = ROOT / "runs" / run_id
    else:
        runs = sorted(d for d in (ROOT / "runs").glob("*") if (d / needs).exists())
        if not runs:
            sys.exit(f"no run with {needs}; run the previous phase first")
        d = runs[-1]
    if not (d / needs).exists():
        sys.exit(f"{d / needs} not found")
    return d


def gather_table(g: dict) -> str:
    rows = []
    for h in g["hosts"]:
        i = h["identity"]
        os_name = f"{h['os']['name']} ({h['os']['accuracy']}%)" if h["os"] else "-"
        rows.append(f"{h['ip']}  {h['label']}  make={i['make']} model={i['model']} firmware={i['firmware']}  os={os_name}")
        for p in h["ports"]:
            ver = " ".join(filter(None, [p["product"], p["version"], f"({p['extrainfo']})" if p["extrainfo"] else None]))
            rows.append(f"    {p['port']:>5}/{p['proto']:<4}{(p['service'] or '?'):<14}{ver or '-'}")
        rows += [f"    note: {n}" for n in h["notes"]]
    rows += [f"note: {n}" for n in g["notes"]]
    return "\n".join(rows)


def run_gather(args: argparse.Namespace) -> int:
    d = run_dir_for(args.run, "discover.json")
    settings = load("settings.yaml")
    result = gather(json.loads((d / "discover.json").read_text()), settings.get("gather_top_ports", 1000))
    path = d / "gather.json"
    path.write_text(json.dumps(result, indent=2))
    print(gather_table(result))
    print(f"hosts: {len(result['hosts'])}  skipped (self): {result['skipped']}  record: {path}")
    return 0


def scan_table(r: dict) -> str:
    rows = []
    for h in r["hosts"]:
        rows.append(f"{h['ip']}  {h['label']}  CVEs: {h['cve_count']} ({h['strong_cve_count']} version-matched)")
        per: dict[str, list] = {}
        for c in h["cves"]:
            key = f"{c['product'] or c['source']} {c['version'] or ''}".strip()
            per.setdefault(key, []).append(c)
        for key, cs in per.items():
            ids = sorted({c["cve_id"] for c in cs})
            top = max((c["cvss"] or 0) for c in cs)
            weak = " (weak)" if all(c["weak_match"] for c in cs) else ""
            rows.append(f"    {key:<34}{len(ids):>4} CVEs  max CVSS {top}{weak}  e.g. {', '.join(ids[:3])}")
        rows += [f"    skipped {s['where']} {s['product']}: {s['reason']}" for s in h["skipped"]]
        if h["nuclei"]:
            rows += [f"    nuclei: {f['template']} {f['matched_at']}" for f in h["nuclei"]]
    rows += [f"note: {n}" for n in r["notes"]]
    return "\n".join(rows)


def run_scan(args: argparse.Namespace) -> int:
    d = run_dir_for(args.run, "gather.json")
    settings = load("settings.yaml")
    result = scan(json.loads((d / "gather.json").read_text()), settings.get("scan", {}),
                  ROOT / "data" / "nvd-cache", d)
    path = d / "scan.json"
    path.write_text(json.dumps(result, indent=2))
    print(scan_table(result))
    print(f"record: {path}")
    return 0


def cveinfo_table(r: dict) -> str:
    rows = [f"{'CVE':<17}{'CVSS':<6}{'EPSS':<7}{'KEV':<5}{'EXPL':<6}{'FIXED IN':<22}{'PATCHES':<9}WHERE / CAUSE"]
    order = sorted(r["cves"].values(), key=lambda c: -((c["cvss"] or {}).get("score") or 0))
    for c in order:
        fixed = ", ".join(sorted({f["version"] for f in c["fixed"]["nvd"] if f["kind"] == "fixed_in"})) or "-"
        where = ", ".join(sorted({f"{a['ip']} {a['product'] or ''}".strip() for a in c["affects"]}))
        epss = f"{c['epss']['epss']:.3f}" if c["epss"] else "-"
        rows.append(f"{c['id']:<17}{(c['cvss'] or {}).get('score') or '-':<6}{epss:<7}"
                    f"{'yes' if c['exploit']['kev'] else '-':<5}{'yes' if c['exploit']['public_exploit'] else '-':<6}"
                    f"{fixed[:21]:<22}{len(c['patches']):<9}{where}")
        if c["explanation"]:
            rows.append(f"{'':<72}cause: {c['explanation']['cause']}")
    rows += [f"note: {n}" for n in r["notes"]]
    return "\n".join(rows)


def run_cveinfo(args: argparse.Namespace) -> int:
    d = run_dir_for(args.run, "scan.json")
    result = cveinfo(json.loads((d / "scan.json").read_text()), ROOT / "data", d, use_llm=not args.no_llm)
    path = d / "cveinfo.json"
    path.write_text(json.dumps(result, indent=2))
    print(cveinfo_table(result))
    print(f"CVEs: {len(result['cves'])}  record: {path}")
    return 0


def run_web(args: argparse.Namespace) -> int:
    from web.server import serve
    user, password = os.environ.get("EDGEPLANNER_USER"), os.environ.get("EDGEPLANNER_PASSWORD")
    if not (user and password):
        sys.exit("Set EDGEPLANNER_USER and EDGEPLANNER_PASSWORD (the page login) in .env first.")
    serve(ROOT / "runs", args.host, args.port, tuple(load("settings.yaml").get("web", {}).get("hostnames", [])),
          (user, password))
    return 0


def run_export(args: argparse.Namespace) -> int:
    from export import export, write
    d = run_dir_for(args.run, "scan.json")
    settings = load("settings.yaml")
    files = export(d, settings.get("attacker_ip", "0.0.0.0"), settings.get("export", {}))
    write(files, d / "iexam")
    nodes, mf = files["node-data"], files["manifest"]
    for nid, n in nodes.items():
        cves = files["cve-in-node"].get(nid, [])
        print(f"{nid:<4}{n['name']:<24}{n['IP']:<16}{len(cves):>4} CVEs")
    print("edges: " + ", ".join(f"{a}->{b}" for a, b in files["connectivity-edge"].values()))
    for x in mf["excluded_nodes"]:
        print(f"excluded {x['ip']} {x['name']}: {x['reason']}")
    for reason, n in mf["cve_rows_dropped"].items():
        print(f"dropped {n} CVE rows: {reason}")
    for n in mf["notes"]:
        print(f"note: {n}")
    print(f"CVEs exported: {len(files['cve-data'])}  files: {d / 'iexam'}")
    return 0


def run_plan(args: argparse.Namespace) -> int:
    import attackplan
    d = run_dir_for(args.run, "iexam/node-data.json")
    k = args.k or load("settings.yaml").get("plan", {}).get("k", 3)
    if args.prepare:
        result = attackplan.prepare(d)
    elif args.optimal or args.topk:
        if not args.target or len(args.target) != 1:
            sys.exit("--optimal / --topk need exactly one --target")
        try:
            result = attackplan.plan_one(d, args.target[0], args.optimal, args.topk, explain=not args.no_llm)
        except (ValueError, FileNotFoundError) as exc:
            sys.exit(f"{exc} (run `plan --prepare` first)" if isinstance(exc, FileNotFoundError) else str(exc))
    else:
        result = attackplan.run(d, k, args.target, explain=not args.no_llm)
    path = attackplan.write(result, d)
    g = result["attack_graph"]
    print(f"attack graph: {len(g['nodes'])} nodes, {len(g['edges'])} edges, {len(g['attack_edges'])} attack edges")
    for t in result["targets"]:
        if "optimal" not in t and "topk" not in t and "error" not in t:
            print(f"goal {t['goal']}: not planned yet")
            continue
        if "error" in t:
            print(f"\ngoal {t['goal']}: {t['error']}")
            continue
        print(f"\ngoal {t['goal']}:")
        if t.get("optimal"):
            o = t["optimal"]
            print(f"  optimal plan, {o['step_count']} steps, cost {o['cost']} ({t['optimal_seconds']}s)")
            for i, step in enumerate(o["steps"], 1):
                print(f"  {i}. {step}")
        if t.get("topk"):
            print(f"  top-{t['topk']['k_requested']}: {t['topk']['k_returned']} plans ({t['topk_seconds']}s), "
                  f"CVEs used: {sorted({c for p in t['topk']['plans'] for c in p['highlights'].get('cve_ids', [])})[:8]}")
        if t.get("optimal_explanation"):
            print("  explanation: " + t["optimal_explanation"]["text"][:300].replace("\n", " ") + " ...")
    for n in result["notes"]:
        print(f"note: {n}")
    print(f"\nrecord: {path}")
    return 0


def run_mitigate(args: argparse.Namespace) -> int:
    import mitigate
    d = run_dir_for(args.run, "iexam/node-data.json")
    result = mitigate.run(d, args.target)
    path = mitigate.write(result, d)
    for t in result["targets"]:
        if t["unreachable"]:
            print(f"\ngoal {t['goal']}: unreachable, nothing to mitigate")
            continue
        print(f"\ngoal {t['goal']}: {len(t['options'])} option(s)")
        for o in t["options"]:
            print(f"  option {o['option']} ({'blocks all plans' if o['blocks_all_plans'] else 'DOES NOT BLOCK'}):")
            for a in o["actions"]:
                print(f"    - {a['text']}  [{a['cves_fixed']} CVEs]")
    for n in result["notes"]:
        print(f"note: {n}")
    print(f"\nrecord: {path}")
    return 0


def run_guide(args: argparse.Namespace) -> int:
    from mitigate import guide
    d = run_dir_for(args.run, "mitigation/mitigation.json")
    try:
        import llmconf
        s = llmconf.settings()
        if not llmconf.configured(s):
            sys.exit(llmconf.not_configured_hint(s))
        with llmconf.local_server(s, d / "llm-server.log"):
            result = guide.run(d, args.target)
    except (ValueError, RuntimeError) as exc:
        sys.exit(str(exc))
    for key, g in result["guides"].items():
        if g["goal"] != args.target:
            continue
        print(f"\n{key}{'  (no source page fetched)' if g['no_sources'] else ''}\n  {g['how_it_blocks']}")
        for n, s in enumerate(g["steps"], 1):
            print(f"  {n}. {s}")
        for link in g["links"]:
            print(f"  - {link['title']}: {link['url']}")
    for n in result["notes"]:
        print(f"note: {n}")
    print(f"\nrecord: {d / 'mitigation' / 'guide.json'}")
    return 0


def run_llmbench(args: argparse.Namespace) -> int:
    import llmbench
    import llmconf
    d = run_dir_for(args.run, "cveinfo.json")
    models = args.models.split(",") if args.models else list(llmconf._config()["models"])
    unknown = [m for m in models if m not in llmconf._config()["models"]]
    if unknown:
        sys.exit(f"unknown model(s): {', '.join(unknown)} (see llm.models in config/settings.yaml)")
    out = llmbench.run(d, models, args.api, args.repeat)
    print(f"host: {out['host']['cpu']}, {out['host']['ram_mb']} MB RAM, {out['host']['llama_cpp']}")
    print(f"inputs: " + ", ".join(f"{i['task']} {i['id']} ({i['prompt_chars']} chars)" for i in out["inputs"]))
    print(f"\n{'model':<40}{'task':<7}{'valid':>7}{'wall s':>9}{'out tok/s':>11}{'load s':>8}{'anon MB':>9}{'peak MB':>9}")
    for m in out["models"]:
        if m["status"] != "ok":
            print(f"{m['model']:<40}{m['status']}: {m['error'].splitlines()[-1] if m.get('error') else ''}")
            continue
        for task in dict.fromkeys(r["task"] for r in m["results"]):
            rows = [r for r in m["results"] if r["task"] == task]
            tps = [r["output_tps"] for r in rows if r.get("output_tps")]
            mem = m.get("memory_mb") or {}
            print(f"{m['model']:<40}{task:<7}{sum(r['valid'] for r in rows):>4}/{len(rows):<2}"
                  f"{sum(r['wall_seconds'] for r in rows) / len(rows):>9.1f}{(sum(tps) / len(tps)) if tps else float('nan'):>11.1f}"
                  f"{m['load_seconds'] or 0:>8.1f}{mem.get('anon', float('nan')):>9.0f}{mem.get('peak', float('nan')):>9.0f}")
    print(f"\nrecord: {out['path']}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    di = sub.add_parser("discover", help="phase 1: find and label every host")
    di.add_argument("--run", help="id for the new run (default: now, UTC)")
    g = sub.add_parser("gather", help="phase 2: ports, services, versions, OS, identity")
    g.add_argument("--run", help="run id under runs/ (default: latest with discover.json)")
    sc = sub.add_parser("scan", help="phase 3: CVE ids per host")
    sc.add_argument("--run", help="run id under runs/ (default: latest with gather.json)")
    ci = sub.add_parser("cveinfo", help="phase 4: CVE facts, fixes, patches, exploits, explanation")
    ci.add_argument("--run", help="run id under runs/ (default: latest with scan.json)")
    ci.add_argument("--no-llm", action="store_true", help="skip the LLM cause/consequence step")
    w = sub.add_parser("web", help="phase 5: network view in the browser")
    w.add_argument("--host", default="127.0.0.1", help="bind address (0.0.0.0 to view from another machine)")
    w.add_argument("--port", type=int, default=8080)
    ex = sub.add_parser("export", help="phase 6: iEXAM input files")
    ex.add_argument("--run", help="run id under runs/ (default: latest with scan.json)")
    pl = sub.add_parser("plan", help="phase 7: iEXAM attack graph, PDDL, attack plans")
    pl.add_argument("--run", help="run id under runs/ (default: latest with iexam/ files)")
    pl.add_argument("--k", type=int, help="number of top-K plans (default: settings plan.k)")
    pl.add_argument("--target", action="append", help="goal node name (repeatable; default: every node)")
    pl.add_argument("--no-llm", action="store_true", help="skip LLM plan explanations")
    pl.add_argument("--prepare", action="store_true", help="attack graph and goals only; no planning")
    pl.add_argument("--optimal", action="store_true", help="optimal plan for the one --target, merged into plans.json")
    pl.add_argument("--topk", type=int, metavar="K", help="top-K plans for the one --target, merged into plans.json")
    mi = sub.add_parser("mitigate", help="phase 8: Metric 1 mitigation options as concrete actions")
    mi.add_argument("--run", help="run id under runs/ (default: latest with iexam/ files)")
    mi.add_argument("--target", action="append", help="goal node name (repeatable; default: every node)")
    gu = sub.add_parser("guide", help="phase 8b: LLM fix guide (how it blocks, steps, links) per mitigation action")
    gu.add_argument("--run", help="run id under runs/ (default: latest with mitigation/mitigation.json)")
    gu.add_argument("--target", required=True, help="goal node name")
    lb = sub.add_parser("llmbench", help="phase 8c: compare small local LLMs (and the API) on the pipeline's LLM tasks")
    lb.add_argument("--run", help="run id under runs/ (default: latest with cveinfo.json)")
    lb.add_argument("--models", help="comma-separated keys from llm.models (default: all)")
    lb.add_argument("--api", action="store_true", help="also run the API model as a baseline (needs the key)")
    lb.add_argument("--repeat", type=int, default=1, help="run each input this many times")
    p = sub.add_parser("probe", help="phase 0: evidence record for one configured target")
    p.add_argument("--target", required=True, help="target key in config/targets.yaml")
    args = ap.parse_args()
    load_env()
    import llmconf
    llmconf.exit_on_sigterm()  # web jobs and `kill` stop a stage with SIGTERM: let it stop the local model too
    return {"discover": run_discover, "gather": run_gather, "scan": run_scan, "cveinfo": run_cveinfo, "web": run_web, "export": run_export, "plan": run_plan, "mitigate": run_mitigate, "guide": run_guide, "llmbench": run_llmbench, "probe": probe}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
