# Phase 7 — iEXAM plan

Read `CLAUDE.md` and `phases/README.md` first. Builds on phase 6's `runs/<run-id>/iexam/`. Runs on Kali.

## Goal

iEXAM, ported into this repo, consumes the exported network and produces the attack connectivity graph, the PDDL domain/problem, and for each target node the optimal attack plan, the top-K attack plans and an LLM explanation of the plan.

```
python run.py plan [--run <run-id>] [--k K] [--target "<node name>" ...] [--no-llm]
```

writes `runs/<run-id>/plans/` (`plans.json`, `NetDomain.pddl`, `NetProblem.pddl`, `newNetProblem.pddl`).

## Port

- `iexam/` is a copy of upstream iEXAM (`api/`, `Backend/`, `scripts/`, `input_data/`); `upstream/iEXAM` stays the untouched reference. The React `web/` is not ported (phase 9 decides).
- `attackplan/` drives iEXAM's own services in-process (`dataset_service`, `pddl_service`, `plan_service`, `topk_service`, `llm_service`). Our files are validated with iEXAM's own parser before use.
- Planners built natively on ARM with `iexam/scripts/fetch_planners.sh --build`. Adapted for new toolchains: CMake 4 policy minimum, GCC 14 `-Wno-template-body` for ForbidIterative, job cap (default 2) for low-memory boards. CMake comes from pip when the system has none.
- Python runtime subset of iEXAM's pins added to `requirements.txt` (all aarch64 wheels): fastapi, pydantic, openai, forbiditerative, pandas.

## Behaviour (iEXAM's, unchanged)

- Goal = one node exploited. Default: every exported node in turn.
- Optimal: Fast Downward `astar(lmcut())`, unit cost per action (shortest attack path, not highest severity).
- Top-K: ForbidIterative.
- Explanation: iEXAM's per-step prompt via the NVIDIA API (same `.env`).

## Gate

- Every exported node has an optimal plan; unreachable goals are reported, not crashed on.
- Top-K plans returned for each goal.
- With the NVIDIA key, each optimal plan has an explanation.
- iEXAM's own example network plans correctly through the same code path (test).

Stop at the gate and report.
