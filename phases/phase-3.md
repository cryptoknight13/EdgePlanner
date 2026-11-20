# Phase 3 — Scan (CVEs per host)

Read `CLAUDE.md` and `phases/README.md` first. Builds on phase 2's `gather.json`. Runs on Kali.

## Goal

For every host, the CVE ids that apply to the software it exposes, each tied to a port/service and to the evidence that produced it.

```
python run.py scan [--run <run-id>]       # default: latest run with a gather.json
```

writes `runs/<run-id>/scan.json` and prints CVE counts per host and per product.

## Sources

1. **CPE -> NVD (primary).** Build a software list per host from gather: nmap port CPEs + version, a small curated product-name -> CPE map for products nmap names without a CPE (e.g. "Portable SDK for UPnP devices" -> `libupnp_project:libupnp`), and the device firmware as `cpe:2.3:o:<make>:<model>_firmware` when NVD's CPE dictionary has that product. For each product, fetch every CVE from the NVD 2.0 API (`virtualMatchString`), cache on disk (7 days), and keep a CVE only if one of its vulnerable `cpeMatch` entries matches our version (exact or version range). Pattern ported from BATs `master/bat_master/cpe_scan.py`, extended with local range matching because NVD's dictionary often lacks the exact firmware version.
2. **nuclei (secondary, detection only).** `-tags cve` against the host's open web ports and `host:port` for other TCP ports, excluding `intrusive,dos,fuzz,bruteforce` tags. A hit is a CVE observed live.

## Rules

- Products without a clean single version (e.g. nmap "Samba 3.X - 4.X") are skipped and listed with the reason. No product-wide guesses.
- OS kernel CPEs are skipped by default (`scan.exclude_products` in settings): they match thousands of mostly local CVEs. The skip is recorded.
- Each CVE carries `match_type`: `exact`, `range`, `all-versions` (NVD says every version), or `unversioned` (NVD lists the product without a version). The last two are weaker and flagged.
- NVD API key optional, from `.env` (`NVD_API_KEY`). Respect NVD rate limits.
- No CVE invented. Every CVE has the source record that justifies it.

## Gate

- The camera gets CVEs against `axis:m1014_firmware` at 5.40.5.2 and/or `libupnp 1.4.1`.
- The router gets CVEs for dnsmasq 2.78, lighttpd 1.4.39, libupnp 1.6.19.
- Every skipped product is listed with its reason.
- nuclei ran without intrusive templates; its hits (if any) are listed separately.

Stop at the gate and report.
