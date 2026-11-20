# Phase 9 — Single webpage

Read `CLAUDE.md` and `phases/README.md` first. Extends the phase 5 page. Runs on Kali; must run unchanged on the Pi.

## Decision

iEXAM's plan and metric views move into the phase 5 page (one lightweight page, stdlib server, no Node). iEXAM's React app is not used.

```
.venv/bin/python run.py web [--host 127.0.0.1] [--port 8080]
```

Start it with the project venv: stages run under the same interpreter, and Metric 1 needs `openai`.

## Server

- `GET /api/runs/<id>/plans`, `GET /api/runs/<id>/mitigation`: phase 7 and phase 8 results as written.
- `GET /api/runs` lists all seven stages per run (done = its output file exists).
- Five page stages, each one or more `run.py` steps: Discover Your Devices (`discover`), Gather (`gather`), Scan Your Network (`scan` + `cveinfo`; resumes with `cveinfo` alone when `scan.json` already exists), Start Planning (`export` + `plan --prepare`: iEXAM's four input files are rebuilt from the latest scan, the attack graph is built, no planner runs), Mitigate (`mitigate`). A stage is done when its last step's file exists.
- Planning actions, once Start Planning has run, for one goal from the run's attack model: `{"stage": "optimal", "goal": g}` (`plan --target g --optimal`, Fast Downward + AI explanation) and `{"stage": "topk", "goal": g, "k": 1..10}` (`plan --target g --topk k`, ForbidIterative). Results merge into `plans/plans.json`; other goals' results are kept.
- The page calls stage 4 **Security Profile** (address `#/plan`): goal picker, attack graph, Optimal / Top-K tabs, each with what it is and its own button. No PDDL is shown.
- `POST /api/pipeline {"run": id|null, "stage": stage}`: runs exactly that one stage as `run.py <step> --run <id>` subprocesses, one job at a time (409 while busy). `run: null` + `stage: discover` starts a new run; any other stage is refused (400) until the stage before it is done. The operator steps through the stages from the page. Output streams to `runs/<id>/pipeline.log`; nothing is held in memory.
- `GET /api/job`: state, current stage, finished stages, last 4 KB of the log.
- Guards: `Host` must be an IP literal or `localhost` (no DNS rebinding); POST must be same-origin JSON (no cross-site trigger). Default bind stays 127.0.0.1.

## Page

- Opens on an empty **Start** page (what it does, how it works, History of saved scans); nothing loads until a scan is opened or started.
- **New scan** runs Discover only. On Network, the stage chips and a **Next step** card run one stage at a time; later stages stay locked until the one before is done; a done stage can be run again on its own. Job status shows on the stage chips and the header **Logs** button; the log is in the Logs drawer.
- Device panel adds **How an attacker gets here** (optimal plan in plain words, path drawn red on the map, AI explanation marked as such, top-K list) and **How to block it** (Metric 1 options with their verified flag, actions and evidence links).
- Overview adds **What to fix**: the smallest option per device.
- iEXAM node ids differ from the page's; nodes are matched by IP.

## Gate

- From the page alone: a new scan runs discover -> mitigate and the page shows plans and fixes for it.
- Camera: attack path and verified fix options shown; works at phone width; keyboard reachable.

Stop at the gate and report.
