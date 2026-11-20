"""Phase 4 — CVE info: enrich every CVE from phase 3 with facts, fixes, patches, exploit signals and
an LLM cause/consequence explanation."""
from datetime import datetime, timezone
from pathlib import Path

import llmconf
from cveinfo import facts, llm, patches, sources
from scan import nvd

SCHEMA_VERSION = "1.0"
MAX_PATCHES = 3


def affects_index(scanned: dict) -> dict[str, list[dict]]:
    """CVE id -> where it was found (host, port, product, version, match)."""
    out: dict[str, list[dict]] = {}
    for h in scanned["hosts"]:
        for c in h["cves"]:
            entry = {"ip": h["ip"], "label": h["label"], "port": c["port"], "service": c["service"],
                     "vendor": c["vendor"], "product": c["product"], "version": c["version"],
                     "match_type": c["match_type"], "source": c["source"], "template": c.get("template")}
            if entry not in out.setdefault(c["cve_id"], []):
                out[c["cve_id"]].append(entry)
    return out


def nvd_records(scanned: dict, ids: set[str], cache_dir: Path, notes: list[str]) -> dict[str, dict]:
    """NVD records from the phase-3 product cache, fetching any id not covered by it."""
    records: dict[str, dict] = {}
    for h in scanned["hosts"]:
        for it in h["software"]:
            for cve in nvd.cves_for_product(it["part"], it["vendor"], it["product"], cache_dir):
                if cve["id"] in ids:
                    records[cve["id"]] = cve
    for cve_id in sorted(ids - records.keys()):
        try:
            rec = nvd.cve_by_id(cve_id, cache_dir)
        except RuntimeError as exc:
            notes.append(f"NVD fetch failed for {cve_id}: {exc}")
            continue
        if rec:
            records[cve_id] = rec
        else:
            notes.append(f"NVD has no record for {cve_id}")
    return records


def _safe(fn, default, notes: list[str], what: str):
    try:
        return fn()
    except Exception as exc:  # a failing external source is a note, never a crash
        notes.append(f"{what} failed: {exc}")
        return default


def cveinfo(scanned: dict, data_dir: Path, run_dir: Path, use_llm: bool = True) -> dict:
    notes: list[str] = []
    cache = data_dir / "nvd-cache"
    affects = affects_index(scanned)
    ids = set(affects)
    records = nvd_records(scanned, ids, cache, notes)
    kev = _safe(lambda: sources.kev(cache), {}, notes, "CISA KEV")
    epss = _safe(lambda: sources.epss(sorted(ids), cache), {}, notes, "EPSS")

    cves = {}
    for cve_id in sorted(ids):
        rec = records.get(cve_id, {})
        nf = facts.nvd_facts(rec) if rec else {"description": None, "published": None, "last_modified": None,
                                               "status": None, "cvss": None, "cwes": [], "references": []}
        of = facts.osv_facts(_safe(lambda: sources.osv(cve_id, cache), None, notes, f"OSV {cve_id}"))
        where = affects[cve_id]
        fixed_nvd = []
        for vendor, product in {(a["vendor"], a["product"]) for a in where if a["vendor"]}:
            fixed_nvd += [{"product": f"{vendor}:{product}", **f} for f in facts.fixed_in(rec, vendor, product)]
        commits = facts.patch_commits(nf["references"] + of["references"], of["fixes"])
        tokens = facts.product_tokens(a["product"] for a in where if a["product"])
        for c in commits:
            # A CVE shared by many projects (e.g. DNSSEC KeyTrap) lists other projects' fixes too.
            c["for_our_product"] = any(t in c["url"].lower() for t in tokens)
        commits.sort(key=lambda c: not c["for_our_product"])
        for c in [c for c in commits if c["for_our_product"] and patches.patch_url(c)][:MAX_PATCHES]:
            c["diff"] = patches.fetch(c, cve_id, run_dir / "patches")
        edb = sources.exploitdb(cve_id)
        exploit = {
            "kev": kev.get(cve_id),
            "nvd_exploit_refs": [r["url"] for r in nf["references"] if "Exploit" in r["tags"]],
            "nuclei_templates": sorted({a["template"] for a in where if a.get("template")}),
            "exploitdb": edb,
        }
        exploit["public_exploit"] = bool(exploit["kev"] or exploit["nvd_exploit_refs"] or edb)
        seen, refs = set(), []
        for r in nf["references"] + of["references"]:
            if r["url"] not in seen:
                seen.add(r["url"])
                refs.append(r)
        cves[cve_id] = {
            "id": cve_id, "description": nf["description"], "published": nf["published"],
            "last_modified": nf["last_modified"], "nvd_status": nf["status"],
            "cvss": nf["cvss"], "cwes": nf["cwes"], "epss": epss.get(cve_id),
            "exploit": exploit,
            "fixed": {"nvd": fixed_nvd, "osv": of["fixes"]},
            "patches": commits, "aliases": of["aliases"], "osv_id": of["osv_id"],
            "references": refs, "affects": where, "explanation": None,
        }

    llm_used = None
    if use_llm and llm.configured():
        items = [{"id": k, "cwes": v["cwes"], "description": v["description"]} for k, v in cves.items()]
        try:
            with llmconf.local_server(llmconf.settings(), run_dir / "llm-server.log"):
                explained = llm.explain(items, data_dir / "llm-cache.json", notes)
        except (RuntimeError, OSError) as exc:  # the local model would not start: CVE facts stand without it
            notes.append(f"LLM not available: {exc}")
            explained = {}
        for cve_id, e in explained.items():
            cves[cve_id]["explanation"] = {"cause": e["cause"], "consequence": e["consequence"],
                                           "model": e["model"], "source": "llm"}
        llm_used = llm.model()
    elif use_llm:
        notes.append(f"No LLM: {llmconf.not_configured_hint(llmconf.settings())} Cause/consequence explanations not generated.")

    return {
        "schema_version": SCHEMA_VERSION,
        "run_id": scanned["run_id"],
        "collected_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "sources": {"nvd": True, "osv": True, "kev": bool(kev), "epss": bool(epss),
                    "exploitdb": sources.exploitdb("CVE-0000-0000") is not None, "llm": llm_used},
        "cves": cves,
        "notes": notes,
    }
