# Phase 4 — CVE info

Read `CLAUDE.md` and `phases/README.md` first. Builds on phase 3's `scan.json`. Runs on Kali.

## Goal

Everything known about each CVE found in phase 3, so later phases can plan, mitigate and explain.

```
python run.py cveinfo [--run <run-id>] [--no-llm]
```

writes `runs/<run-id>/cveinfo.json` (+ `patches/*.diff`) and prints a per-CVE summary.

## Per CVE

| Field | Source |
|---|---|
| description, published, CWE, CVSS score/vector/severity, references (+ tags) | NVD 2.0 (cached from phase 3, else fetched by id) |
| `fixed_in` for the product we found: version where NVD's vulnerable range ends | NVD cpeMatch `versionEndExcluding` / `versionEndIncluding` |
| fixed versions and fix commits per ecosystem, aliases, extra references | OSV.dev (`/v1/vulns/<id>`) |
| patch commits (URL, repo, sha) and, for GitHub/GitLab, the patch diff saved under `patches/` | NVD refs tagged Patch + OSV FIX refs + OSV GIT ranges |
| known exploited | CISA KEV catalog |
| exploit probability | FIRST EPSS |
| public exploit evidence | NVD refs tagged Exploit, nuclei template exists, Exploit-DB via `searchsploit` when installed |
| `cause`, `consequence` (explanation only, never PDDL) | LLM via NVIDIA API (OpenAI-compatible), cached per CVE |
| `affects`: which host / port / product / version / match type | phase 3 |

## Rules

- Secrets (`NVIDIA_API_KEY`, `NVD_API_KEY`) from `.env` only.
- Every value keeps its source. The LLM text is stored under `explanation` with model name, separate from factual fields; it must not be invented-looking facts (versions, commits).
- Network sources are cached under `data/` so reruns are cheap; a failed source is a note, not a crash.
- Patch diffs are capped in size and saved to disk, not kept in memory.

## Gate

- Every CVE in `scan.json` has description, CVSS, CWE and references.
- Camera and router CVEs show a fixed version where NVD states one.
- At least the dnsmasq / libupnp / lighttpd CVEs show patch commit links; GitHub-hosted ones have their diff saved.
- With an NVIDIA key: every CVE has `explanation.cause` and `explanation.consequence`. Without one: a single note says so.

Stop at the gate and report.
