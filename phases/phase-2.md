# Phase 2 — Gather

Read `CLAUDE.md` and `phases/README.md` first. Builds on phase 1's `discover.json`. Runs on Kali against the live LAN.

## Goal

For every discovered host, what an attacker learns from the outside: open ports, service, product, version, CPE, banners, OS guess, and the device identity (make, model, firmware) the device itself announces.

```
python run.py gather [--run <run-id>]     # default: latest run with a discover.json
```

writes `runs/<run-id>/gather.json` and prints a per-host port table.

## Scope

- Targets: every host in `discover.json` except `self` (the monitoring box). Nothing else.
- One nmap run over all targets: `--privileged -sV -O -Pn --top-ports N` (N in `settings.yaml`, default 1000) plus `ssl-cert` script. Keep port CPEs; keep OS match + CPE.
- Per host, reuse phase 0 probes: HTTP `Server` header per web port, RTSP `OPTIONS` banner if RTSP is open, unauthenticated ONVIF `GetDeviceInformation` for camera-like hosts.
- Carry identity over from discover: UPnP descriptions, mDNS models, vendor, label.
- `identity`: make, model, firmware, each with its source. `firmware_candidates` lists every version string that plausibly is firmware (ONVIF FirmwareVersion; a service version whose product names the device model) with its source. No guessing beyond that.

Out of scope: UDP port scans, CVEs (phase 3), credentials of any kind, NSE `vuln`/`intrusive` scripts.

## Gate

- The camera shows ports 21, 80, 554, 49152 with product/version, and `firmware_candidates` contains 5.40.5.2 from the FTP banner.
- The router shows its open ports with versions and the Linksys WRT3200ACM identity.
- Every target host has a `ports` list (empty is valid, stated plainly) and an OS guess or a note why not.
- No credentials used; no hosts outside discover.json touched.

Stop at the gate and report.
