"""Phase 3 — Scan: CVE ids per host from CPE->NVD version matching, plus nuclei detections."""
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from scan import nuclei, nvd
from scan.software import software_list
from scan.version import match_cve

SCHEMA_VERSION = "1.0"
WEAK = {"all-versions", "unversioned"}


def cvss(cve: dict) -> tuple[float | None, str | None, str | None]:
    """(base score, severity, version) from the newest CVSS metric NVD has."""
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            m = next((x for x in metrics[key] if x.get("type") == "Primary"), metrics[key][0])
            data = m["cvssData"]
            return data.get("baseScore"), data.get("baseSeverity") or m.get("baseSeverity"), data.get("version")
    return None, None, None


def nvd_matches(items: list[dict], cache_dir: Path, notes: list[str]) -> list[dict]:
    hits = []
    for it in items:
        try:
            records = nvd.cves_for_product(it["part"], it["vendor"], it["product"], cache_dir)
        except (RuntimeError, OSError) as exc:
            notes.append(f"NVD lookup failed for {it['vendor']}:{it['product']}: {exc}")
            continue
        for cve in records:
            mtype = match_cve(cve, it["vendor"], it["product"], it["version"])
            if not mtype:
                continue
            score, severity, cvss_version = cvss(cve)
            hits.append({
                "cve_id": cve["id"], "port": it["port"], "service": it["service"],
                "vendor": it["vendor"], "product": it["product"], "version": it["version"],
                "source": "nvd-cpe", "match_type": mtype, "weak_match": mtype in WEAK,
                "cvss": score, "severity": severity, "cvss_version": cvss_version,
                "published": cve.get("published", "")[:10],
            })
    return hits


def nuclei_software(findings: list[dict], ip: str, ports: list[dict]) -> list[dict]:
    """Exact versions nuclei read from a service, as extra NVD lookups."""
    service = {p["port"]: p["service"] for p in ports}
    return [{"port": f["port"], "service": service.get(f["port"]), "part": "a",
             "vendor": f["vendor"], "product": f["product"], "version": f["extracted_version"],
             "source": f"nuclei {f['template']} read version {f['extracted_version']}"}
            for f in findings if f["ip"] == ip and f["vendor"] and f["product"] and f["extracted_version"]]


def scan(gathered: dict, settings: dict, cache_dir: Path, run_dir: Path) -> dict:
    exclude = set(settings.get("exclude_products", ["linux_kernel"]))
    mode = settings.get("nuclei_mode", "fast")
    notes: list[str] = []

    findings, nuclei_ran = [], False
    if mode != "off":
        try:
            findings = nuclei.scan_hosts(gathered["hosts"], run_dir, mode)
            nuclei_ran = True
        except (OSError, subprocess.CalledProcessError) as exc:
            notes.append(f"nuclei failed: {getattr(exc, 'stderr', '') or exc}")

    hosts = []
    for h in gathered["hosts"]:
        items, skipped = software_list(h, exclude, cache_dir)
        seen = {(i["vendor"], i["product"], i["version"]) for i in items}
        for extra in nuclei_software(findings, h["ip"], h["ports"]):
            if (extra["vendor"], extra["product"], extra["version"]) not in seen:
                items.append(extra)
                seen.add((extra["vendor"], extra["product"], extra["version"]))
                # The precise version supersedes an earlier "no clean version" skip of the same product.
                skipped = [x for x in skipped if x["product"] != f"{extra['vendor']}:{extra['product']}"]
        mine = [f for f in findings if f["ip"] == h["ip"]]
        cves = nvd_matches(items, cache_dir, notes)
        for f in mine:
            for cve_id in f["cve_ids"]:
                cves.append({"cve_id": cve_id, "port": f["port"], "service": None,
                             "vendor": f["vendor"], "product": f["product"], "version": f["extracted_version"],
                             "source": "nuclei", "match_type": "detected", "weak_match": False,
                             "cvss": None, "severity": f["severity"], "cvss_version": None,
                             "published": None, "template": f["template"]})
        cves.sort(key=lambda c: (c["weak_match"], -(c["cvss"] or 0), c["cve_id"]))
        hosts.append({"ip": h["ip"], "label": h["label"], "identity": h["identity"],
                      "software": items, "skipped": skipped, "cves": cves, "nuclei": mine,
                      "cve_count": len({c["cve_id"] for c in cves}),
                      "strong_cve_count": len({c["cve_id"] for c in cves if not c["weak_match"]})})
    return {
        "schema_version": SCHEMA_VERSION,
        "run_id": gathered["run_id"],
        "collected_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "sources": {"nvd": True, "nuclei": nuclei_ran, "nuclei_mode": mode,
                    "nuclei_excluded_tags": nuclei.EXCLUDED_TAGS, "excluded_products": sorted(exclude)},
        "hosts": hosts,
        "notes": notes,
    }
