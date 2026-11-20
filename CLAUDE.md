# CLAUDE.md — EdgePlanner: Home-network BAT + iEXAM on a Pi 3

Standing context for Claude Code. Read this before any task. The roadmap is `phases/README.md`; the active build task is `phases/phase-<n>.md`. Build only what the active phase names.

## What this project is

An automated home-network security analyser that ends up running on a Raspberry Pi 3. It is a port of two existing systems, adapted to a home network where we have **no credentials and no access** on any device:

- **BATs** (`upstream/BATs`, github.com/cryptoknight13/BATs) — Blue Agent Teams. Original: agents on lab VMs over SSH+sudo. **Here: agentless.** Everything is observed from the network, like an attacker would.
- **iEXAM** (`upstream/iEXAM`, github.com/cryptoknight13/iEXAM-Toolset-main) — consumes `node-data.json`, `connectivity-edge.json`, `cve-in-node.json`, `cve-data.json`, builds the attack connectivity graph, generates PDDL, plans with Fast Downward / ForbidIterative, and computes Metric 1 (mitigation options) with LLM explanations.

`upstream/` holds unmodified clones for reference. Code we write or port lives outside `upstream/`. Never edit `upstream/` in place.

## Pipeline

```
discover -> gather -> scan (CVEs) -> cveinfo -> visualize -> export (iEXAM files) -> iEXAM plan -> Metric 1 mitigation -> single webpage
```

Every stage reads the previous stage's JSON from `runs/<run-id>/` and writes its own. Stages run independently and in order.

## Threat model and topology

- Attacker `n0` (0.0.0.0, external) -> home router -> every LAN device.
- Possible mesh: attacker -> router1 -> router2 -> devices, with router1 also having its own devices. Support it in the data model; the first target is the single-router case.
- No known IPs, no SSH, no passwords. Devices are found and identified from the network only.

## Nodes

- **Kali** (dev box, aarch64, same LAN). Everything is built and validated here first.
- **Pi 3** (1 GB RAM, ARM Cortex-A53). Final runtime. Shipped to over SSH, last phase.
- **Router** and **IoT devices** (first known one: Axis M1014 camera at 192.168.1.183).

## Hard constraints

- **Agentless.** Never log in to a device, never guess credentials, never run exploits. Read what devices announce and what their services answer.
- **Scope.** Discovery and scans touch only the network this machine is directly attached to, detected automatically (default-route interface and its own address/mask), or the subnets pinned in `config/settings.yaml`. Only RFC1918 ranges no larger than /16, whichever way they were found. No internet-facing scanning.
- **No destructive checks.** nmap/nuclei templates must be detection-only (no `intrusive`, `dos`, `brute`, `exploit` categories/tags).
- **Runs on ARM.** Pure Python where possible. Every dependency must have an aarch64 wheel or be pure Python; flag any that does not before using it. Native tools (nmap, nuclei, Fast Downward) must build or ship for ARM.
- **Memory.** Pi has 1 GB. Stream to disk; do not hold large captures or datasets in memory.
- **Secrets** (NVD_API_KEY, NVIDIA_API_KEY) live in `.env`, never in code, config, output or git.

## Conventions

- Python 3, formal and direct. Short functions. Type hints on public functions.
- Config in YAML under `config/`. No hardcoded IPs or interfaces in code.
- Each stage writes timestamped, schema-versioned JSON under `runs/<run-id>/`. The operator inspects these to validate.
- Reuse BATs/iEXAM code where it fits (e.g. BATs `cpe_scan.py`, `cve_ner.py`; iEXAM `generate_pddl_from_json.py`, Metric 1). Copy it in, then adapt; note the origin in the module docstring.
- Small self-check tests for every parser and every non-trivial transform.
- When a phase gate is met, stop and report. Do not start the next phase unprompted.
