"""NVD 2.0 API client with a disk cache. Pattern from BATs master/bat_master/cpe_scan.py + cve_ner.py.

Without an API key NVD allows ~5 requests / 30 s; with NVD_API_KEY ~50 / 30 s.
"""
import hashlib
import json
import os
import time
from pathlib import Path

import requests

CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CPE_API = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
CACHE_TTL = 7 * 24 * 3600
PAGE = 2000

_last_call = 0.0


def _spacing() -> float:
    return 0.7 if os.environ.get("NVD_API_KEY") else 6.5


def _get(url: str, params: dict, retries: int = 5) -> dict:
    """Rate-limited GET with backoff on throttling and transient errors."""
    global _last_call
    headers = {"apiKey": os.environ["NVD_API_KEY"]} if os.environ.get("NVD_API_KEY") else {}
    backoff = 10.0
    for _ in range(retries):
        wait = _last_call + _spacing() - time.monotonic()
        if wait > 0:
            time.sleep(wait)
        _last_call = time.monotonic()
        try:
            resp = requests.get(url, params=params, headers=headers, timeout=60)
        except requests.RequestException:
            time.sleep(backoff)
            backoff = min(backoff * 2, 120)
            continue
        if resp.status_code in (403, 429, 503):
            time.sleep(float(resp.headers.get("Retry-After", backoff)))
            backoff = min(backoff * 2, 120)
            continue
        resp.raise_for_status()
        return resp.json()
    raise RuntimeError(f"NVD request failed after {retries} attempts: {url} {params}")


def cached(cache_dir: Path, name: str, fetch) -> object:
    """Return the cached value for `name` if fresh, else fetch, store and return it."""
    path = cache_dir / (hashlib.sha256(name.encode()).hexdigest()[:24] + ".json")
    if path.exists():
        data = json.loads(path.read_text())
        if time.time() - data["fetched_at"] < CACHE_TTL:
            return data["value"]
    value = fetch()
    cache_dir.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"name": name, "fetched_at": time.time(), "value": value}))
    return value


def cves_for_product(part: str, vendor: str, product: str, cache_dir: Path) -> list[dict]:
    """Every CVE record NVD has against vendor:product (any version), as raw `cve` objects."""
    match = f"cpe:2.3:{part}:{vendor}:{product}"

    def fetch() -> list[dict]:
        out, start = [], 0
        while True:
            data = _get(CVE_API, {"virtualMatchString": match, "resultsPerPage": PAGE, "startIndex": start})
            out += [v["cve"] for v in data.get("vulnerabilities", [])]
            start += PAGE
            if start >= data.get("totalResults", 0):
                return out

    return cached(cache_dir, "cves:" + match, fetch)


def product_exists(part: str, vendor: str, product: str, cache_dir: Path) -> bool:
    """Whether NVD's CPE dictionary knows vendor:product at all."""
    match = f"cpe:2.3:{part}:{vendor}:{product}"
    return cached(cache_dir, "cpe:" + match,
                   lambda: _get(CPE_API, {"cpeMatchString": match, "resultsPerPage": 1}).get("totalResults", 0) > 0)


def cve_by_id(cve_id: str, cache_dir: Path) -> dict | None:
    """One CVE record by id (for CVEs not already fetched through a product lookup)."""
    def fetch():
        vulns = _get(CVE_API, {"cveId": cve_id}).get("vulnerabilities", [])
        return vulns[0]["cve"] if vulns else None
    return cached(cache_dir, "cve:" + cve_id, fetch)
