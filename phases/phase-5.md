# Phase 5 — Visualize

Read `CLAUDE.md` and `phases/README.md` first. Builds on phases 1-4. Runs on Kali; must run unchanged on the Pi.

## Goal

The home network in the browser, the way an attacker reaches it, with every finding one click away.

```
python run.py web [--host 127.0.0.1] [--port 8080]
```

## Design

- **Server:** Python stdlib `http.server` (no Node, no build step, no new dependency). Serves `web/static/` and a JSON API:
  `GET /api/runs`, `GET /api/runs/<run-id>/model`. Only static files and well-formed run ids are served.
- **Model:** `netmodel.build(run_dir)` merges discover / gather / scan / cveinfo into nodes, edges and CVEs. Phase 6 reuses it for the iEXAM export. Partial runs work.
- **Page:** one HTML page, Cytoscape.js vendored at `web/static/vendor/` (works offline).
  - Headline sentence generated from the data (weakest device, count, exploited-in-the-wild).
  - Map left to right in attack direction: Internet attacker -> router(s) -> devices; the monitor itself dashed.
  - Node colour = risk tier: exploited in the wild (CISA KEV) / CVSS >= 7 / lower / none.
  - Side panel: devices ranked by exposure; a device shows identity, evidence, OS, firmware, ports, and its CVEs (weak NVD matches hidden by default) with cause / consequence, fixed-in version, EPSS, fix commits and NVD link.
  - `#n<k>` in the URL selects a device (linkable).
- Every device-supplied string is HTML-escaped; only http(s) links are rendered.

## Gate

- The page loads the latest run and shows attacker -> router -> camera / Pi / MacBook, monitor dashed.
- Selecting the camera shows firmware 5.40.5.2 and its CVEs with "Fixed in 5.51.5".
- Works at phone width; keyboard reachable (device list is buttons, CVEs are native `<details>`).
