"""External CVE sources besides NVD: OSV.dev, CISA KEV, FIRST EPSS, Exploit-DB (searchsploit)."""
import json
import shutil
import subprocess
from pathlib import Path

import requests

from scan.nvd import cached

OSV_API = "https://api.osv.dev/v1/vulns/"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API = "https://api.first.org/data/v1/epss"
UA = {"User-Agent": "EdgePlanner/1.0 (home network security monitor)"}


def osv(cve_id: str, cache_dir: Path) -> dict | None:
    """OSV record for a CVE id, or None if OSV has none."""
    def fetch():
        resp = requests.get(OSV_API + cve_id, timeout=30, headers=UA)
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        return resp.json()
    return cached(cache_dir, "osv:" + cve_id, fetch)


def kev(cache_dir: Path) -> dict[str, dict]:
    """CISA Known Exploited Vulnerabilities, keyed by CVE id."""
    def fetch():
        resp = requests.get(KEV_URL, timeout=60, headers=UA)
        resp.raise_for_status()
        return {v["cveID"]: {"date_added": v["dateAdded"], "name": v["vulnerabilityName"],
                             "required_action": v["requiredAction"],
                             "ransomware": v["knownRansomwareCampaignUse"]}
                for v in resp.json()["vulnerabilities"]}
    return cached(cache_dir, "kev", fetch)


def epss(cve_ids: list[str], cache_dir: Path) -> dict[str, dict]:
    """EPSS probability and percentile per CVE id (batched, cached per batch)."""
    out = {}
    ids = sorted(set(cve_ids))
    for i in range(0, len(ids), 50):
        batch = ids[i:i + 50]

        def fetch(batch=batch):
            resp = requests.get(EPSS_API, params={"cve": ",".join(batch)}, timeout=30, headers=UA)
            resp.raise_for_status()
            return {r["cve"]: {"epss": float(r["epss"]), "percentile": float(r["percentile"]), "date": r["date"]}
                    for r in resp.json().get("data", [])}
        out.update(cached(cache_dir, "epss:" + ",".join(batch), fetch))
    return out


def exploitdb(cve_id: str) -> list[dict] | None:
    """Exploit-DB entries via local searchsploit; None when searchsploit is not installed (e.g. on the Pi)."""
    if not shutil.which("searchsploit"):
        return None
    try:
        out = subprocess.run(["searchsploit", "--cve", cve_id, "-j"], capture_output=True, text=True, timeout=30)
        data = json.loads(out.stdout or "{}")
    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
        return None
    return [{"id": e.get("EDB-ID"), "title": e.get("Title"), "type": e.get("Type"),
             "url": f"https://www.exploit-db.com/exploits/{e.get('EDB-ID')}"}
            for e in data.get("RESULTS_EXPLOIT", [])]
