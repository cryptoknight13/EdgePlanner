# Roadmap

One phase at a time. Each phase has a gate; stop there and report. Detailed instructions are written into `phase-<n>.md` when the phase starts, so they can use what earlier phases revealed.

All phases are built and validated on **Kali** against the live network. The Pi comes last.

| # | Phase | Input | Output (`runs/<run-id>/`) | Gate |
|---|---|---|---|---|
| 0 | Camera probe (prototype, **done**) | one known IP | evidence record | Axis M1014 identified via UPnP |
| 1 | **Discover** | subnets in config | `discover.json`: every live host, MAC, OUI vendor, hostname, first-guess device type + confidence | every device on the LAN found and labelled (router, camera, Pi, Kali, ...) |
| 2 | **Gather** | `discover.json` | `gather.json`: per host, open ports, service, product, version, CPE, banners, UPnP/ONVIF/mDNS identity, OS guess | camera shows its ports + versions; every host has a port list |
| 3 | **Scan (CVEs)** | `gather.json` | `scan.json`: per host, per port, CVE ids with source (`cpe`, `nuclei`, `nmap-vulners`) | camera gets CVEs from its product/version; no destructive templates ran |
| 4 | **CVE info** | `scan.json` | `cveinfo.json`: per CVE, CVSS, CWE, description, references, patch/fix commits, fixed version, exploit availability; LLM (NVIDIA API) `cause` + `consequence` for explanation only | every CVE enriched; LLM text clearly separated from PDDL fields |
| 5 | **Visualize** | phases 1-4 | webpage view: network graph (attacker -> router(s) -> devices), click a node for its ports and CVEs | operator sees the live home network in the browser |
| 6 | **Export for iEXAM** | phases 1-4 | `iexam/node-data.json`, `connectivity-edge.json`, `cve-in-node.json`, `cve-data.json` in iEXAM's exact format | iEXAM's own consistency check passes on our files |
| 7 | **iEXAM plan** | phase 6 files | attack connectivity graph, PDDL, optimal + top-K attack plans, explanations | plans make sense for the home network |
| 8 | **Metric 1 mitigation** | phase 7 | mitigation option sets that block all plans, mapped to concrete actions (mostly "upgrade X from version A to fixed version B", with source links) | every option is an actionable upgrade/config change with evidence |
| 8b | **Fix guides** | phase 8 | `mitigation/guide.json`: per mitigation action, LLM-written how-it-blocks + steps + links, links limited to fetched evidence pages | every camera-goal action has a guide; no invented links |
| 8c | **Local LLM + benchmark** | phases 4, 7, 8, 8b | `llm.provider: api \| local` (llama.cpp on the same machine) for every LLM step; `llmbench/<stamp>.json`: time, RAM, validity per small model and task | all LLM steps run locally on Kali with no request off 127.0.0.1; bench compares models + API |
| 9 | **Single webpage** | all | one page: discover -> scan -> CVEs -> graph -> plans -> mitigation, with explanations | whole pipeline runs from the page |
| 9b | **Bridge clusters + fingerprinting** | phases 1, 2, 5, 6 | hosts get `uplink` (shared-MAC bridge, e.g. Almond extender); bridge becomes a router node; labels refined from gather's nmap products/OS | Almond clients sit under the Almond in page + iEXAM edges; IoT devices labelled from their own answers |
| 10 | **Ship to Pi** | all | same pipeline on the Pi 3 | gates 1-9 re-pass on the Pi |

## Decisions still open (operator)

- **Device type labelling (phase 1).** Start with rules over OUI vendor + mDNS/SSDP/DHCP/nmap hints. Whether to add a classifier trained on public IoT fingerprint data, and which dataset, is decided after phase 2 shows how much the devices reveal.
- **Edges (phase 6).** Proposed: `n0 -> router`, `router -> every device`, and device <-> device on the same LAN (a switched LAN lets any compromised device reach the others). Mesh: `router1 -> router2 -> its devices`.
- **Webpage (phase 5/9).** Decided in phase 9: iEXAM's plan/metric views moved into the phase 5 stdlib page; iEXAM's React app is not used.
- **Router2 visibility.** Devices behind a second router in NAT mode are not discoverable from router1's LAN. Discovered only if router2 runs in bridge/AP mode, or the Pi sits behind router2.
