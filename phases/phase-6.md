# Phase 6 — Export for iEXAM

Read `CLAUDE.md` and `phases/README.md` first. Builds on phases 1-4 through `netmodel`. Runs on Kali.

## Goal

The four iEXAM input files, in iEXAM's exact format, built from the run:

```
python run.py export [--run <run-id>]
```

writes `runs/<run-id>/iexam/{node-data,connectivity-edge,cve-in-node,cve-data,manifest}.json`.

## Model

- `n0` = `Attacker`, IP from settings (`0.0.0.0`), external. iEXAM excludes the node named `Attacker` from the goal.
- Edges (directed): `n0 -> gateway router`, `router -> every device behind it`, `router1 -> router2` for a mesh. Device <-> device edges only when `export.lateral_edges: true` (default false: the attacker reaches devices through the router, as the operator specified).
- Only nodes with at least one kept CVE are exported (iEXAM's default goal is "every node exploited"; a node with no exploit would make it unsolvable). Excluded nodes and the reason go to `manifest.json`. If the gateway router has no kept CVE, nothing behind it is reachable; the manifest says so.
- CVE filter (settings `export:`): strong version matches only (`include_weak: false`); network-reachable only (CVSS attack vector Network or Adjacent); optional `require_public_exploit` and `min_cvss`.

## CVE record -> PDDL facts

iEXAM turns string fields `system`, `driver`, `cause`, `struct`, `function` (and `installed_version`, which replaces `system`) into PDDL facts; Metric 1 proposes removing facts. We emit deterministic facts that map to real actions:

| field | value | removing it means |
|---|---|---|
| `installed_version` (-> system) | product, e.g. `dnsmasq`, `libupnp`, `axis m1014 firmware` | upgrade / replace that software |
| `driver1..n` | exposed service, e.g. `domain service`, `upnp service` | close or firewall that service |

No `cause` / `struct` / `function` facts. LLM text goes only to display fields (`vulnerability` = cause, `capability` = consequence), which iEXAM never puts in PDDL. Versions, ports, fixed-in, CVSS vector, EPSS, KEV are display fields.

## Gate

- iEXAM's own pydantic schemas and `check_consistency` accept the four files with no errors.
- iEXAM's own `generate_pddl_from_json.py` produces a domain and problem from them (run on a scratch copy; `upstream/` is never modified).
- manifest lists every excluded node and CVE count per filter step.

Stop at the gate and report.
