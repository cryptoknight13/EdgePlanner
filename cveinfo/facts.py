"""Factual fields of a CVE from its NVD and OSV records."""
import re

from scan.version import split_cpe

COMMIT_RE = re.compile(
    r"https?://(?:www\.)?(github\.com|gitlab\.com)/([^/]+/[^/]+)/(?:-/)?commit/([0-9a-f]{7,40})", re.I)
GENERIC_COMMIT_RE = re.compile(r"(commit|commitdiff|[?;&]h=|/rev/|changeset)", re.I)


def nvd_facts(cve: dict) -> dict:
    """Description, CVSS, CWE, references from an NVD 2.0 `cve` object."""
    desc = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), None)
    cvss = None
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metrics = cve.get("metrics", {}).get(key)
        if metrics:
            m = next((x for x in metrics if x.get("type") == "Primary"), metrics[0])
            d = m["cvssData"]
            cvss = {"version": d.get("version"), "score": d.get("baseScore"),
                    "severity": d.get("baseSeverity") or m.get("baseSeverity"), "vector": d.get("vectorString"),
                    "attack_vector": d.get("attackVector") or d.get("accessVector"),
                    "exploitability": m.get("exploitabilityScore"), "impact": m.get("impactScore")}
            break
    cwes = sorted({d["value"] for w in cve.get("weaknesses", []) for d in w.get("description", [])
                   if d["value"].startswith("CWE-")})
    refs = [{"url": r["url"], "tags": r.get("tags", []), "source": "nvd"} for r in cve.get("references", [])]
    return {"description": desc, "published": cve.get("published", "")[:10],
            "last_modified": cve.get("lastModified", "")[:10], "status": cve.get("vulnStatus"),
            "cvss": cvss, "cwes": cwes, "references": refs}


def fixed_in(cve: dict, vendor: str, product: str) -> list[dict]:
    """Where NVD says the vulnerable range for vendor:product ends (one entry per vulnerable range)."""
    out = []
    for conf in cve.get("configurations", []):
        for node in conf.get("nodes", []):
            for e in node.get("cpeMatch", []):
                if not e.get("vulnerable"):
                    continue
                _, v, p, _ = split_cpe(e["criteria"])
                if (v, p) != (vendor, product):
                    continue
                if "versionEndExcluding" in e:
                    out.append({"version": e["versionEndExcluding"], "kind": "fixed_in", "source": "nvd"})
                elif "versionEndIncluding" in e:
                    out.append({"version": e["versionEndIncluding"], "kind": "last_affected", "source": "nvd"})
    return [dict(t) for t in {tuple(sorted(d.items())) for d in out}]


def product_tokens(products) -> set[str]:
    """Name fragments that identify a product's repo: libupnp -> {libupnp, upnp}, m1014_firmware -> {m1014}."""
    out = set()
    for p in products:
        p = p.lower().removesuffix("_firmware")
        out |= {p, p.removeprefix("lib")} if len(p.removeprefix("lib")) >= 4 else {p}
    return out


def osv_facts(rec: dict | None) -> dict:
    """Fix versions/commits, aliases and references from an OSV record."""
    if not rec:
        return {"osv_id": None, "aliases": [], "fixes": [], "references": []}
    fixes = []
    for aff in rec.get("affected", []):
        pkg = aff.get("package", {})
        ranges = aff.get("ranges", []) + (aff.get("database_specific") or {}).get("unresolved_ranges", [])
        for r in ranges:
            for ev in r.get("events", []):
                if "fixed" in ev:
                    fixes.append({"ecosystem": pkg.get("ecosystem"), "package": pkg.get("name"),
                                  "type": r.get("type"), "repo": r.get("repo"), "fixed": ev["fixed"]})
    fixes = [dict(t) for t in {tuple(sorted(f.items())) for f in fixes}]
    refs = [{"url": r["url"], "tags": [r["type"]], "source": "osv"} for r in rec.get("references", [])]
    return {"osv_id": rec.get("id"), "aliases": rec.get("aliases", []), "fixes": fixes, "references": refs}


def patch_commits(references: list[dict], osv_fixes: list[dict]) -> list[dict]:
    """Fix commits: NVD refs tagged Patch, OSV FIX refs, and OSV GIT ranges. Deduplicated by URL."""
    commits: dict[str, dict] = {}
    for r in references:
        is_fix = "Patch" in r["tags"] or "FIX" in r["tags"]
        m = COMMIT_RE.search(r["url"])
        if m:
            commits.setdefault(r["url"], {"url": r["url"], "host": m.group(1).lower(), "repo": m.group(2),
                                          "sha": m.group(3), "source": r["source"]})
        elif is_fix and GENERIC_COMMIT_RE.search(r["url"]):
            commits.setdefault(r["url"], {"url": r["url"], "host": None, "repo": None, "sha": None,
                                          "source": r["source"]})
    for f in osv_fixes:
        if f["type"] == "GIT" and f.get("repo"):
            url = f"{f['repo'].rstrip('/').removesuffix('.git')}/commit/{f['fixed']}"
            m = COMMIT_RE.search(url)
            commits.setdefault(url, {"url": url, "host": m.group(1).lower() if m else None,
                                     "repo": m.group(2) if m else f["repo"], "sha": f["fixed"], "source": "osv"})
    return list(commits.values())
