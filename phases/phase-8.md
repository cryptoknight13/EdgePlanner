# Phase 8 — Metric 1 mitigation

Read `CLAUDE.md` and `phases/README.md` first. Builds on phase 6's `runs/<run-id>/iexam/` and phase 4's `cveinfo.json`. Runs on Kali.

## Goal

For each goal node, iEXAM's Metric 1 option sets (smallest sets of changes that make the goal unreachable), each mapped to concrete actions with evidence:

```
python run.py mitigate [--run <run-id>] [--target "<node name>" ...]
```

writes `runs/<run-id>/mitigation/mitigation.json` and `mitigation/m1-input/` (the four files Metric 1 actually saw).

## Method

- iEXAM's own `metric1_service` (no-heuristic search) runs in-process, as in phase 7.
- **Grouping.** Metric 1 searches subsets of PDDL facts, and our export has one fact per CVE (193 on the first run: 2.7 GB RAM, no result after 10 min). CVEs on the same node with the same product and services share their facts' meaning, so Metric 1 sees one representative CVE per (node, product, services) group (7 groups on the first run: 7 s). Removing a group's product fact = upgrading the product; removing its service fact = closing the service. Each fixes every CVE in the group.
- **Verification.** Every option is checked against the full, ungrouped network: all matching facts removed, Fast Downward must prove the goal unreachable (exit 12). `blocks_all_plans` records the result.

## Actions

| removed fact | action | evidence |
|---|---|---|
| `system` (product) | upgrade `<product>` on `<node>` from installed version(s) to the highest NVD `fixed_in` (or later than the highest `last_affected`); CVEs with no published fix listed | per CVE: NVD link, fixed versions, fix commits (`for_our_product`), patch/vendor-advisory references |
| `driver` (service) | close or firewall `<service>` on `<node>` (ports) | per CVE: NVD link |

No LLM step here; the action text is built from data.

## Gate

- Every reachable goal has at least one option; each option is a list of upgrade/close actions with evidence.
- Every option has `blocks_all_plans: true` on the full network.
- iEXAM's own example network goes through the same code path (test).

Stop at the gate and report.
