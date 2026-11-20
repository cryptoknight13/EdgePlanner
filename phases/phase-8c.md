# Phase 8c — Local LLM option and small-model benchmark

Read `CLAUDE.md` and `phases/README.md` first. Touches every LLM step (phases 4, 7, 8, 8b). Built and validated on Kali; Pi numbers come from re-running the benchmark there (phase 10).

## Goal

Every LLM step runs on either provider, chosen in one setting:

1. **api** — hosted OpenAI-compatible endpoint (NVIDIA NIM today), key in `.env`. Current behaviour.
2. **local** — a small model served by llama.cpp `llama-server` on the same machine. No scan data leaves the machine for LLM work.

And a benchmark that runs the four LLM tasks on several small models so they can be compared with each other and with the API model, on Kali and on the Pi 3.

Why: privacy (IPs, devices, CVEs stay home) and research on small LLMs for a resource-constrained edge device. The Pi has internet; it is used only to download models and to fetch public advisory pages (phase 8b).

## LLM tasks covered

| # | Task | Code |
|---|---|---|
| 1 | CVE cause / consequence | `cveinfo/llm.py` |
| 2 | Attack plan explanation | `iexam/api/services/acg/llm_service.py` |
| 3 | Metric 1 / top-K plan explanations | `iexam/Backend/pages/handler/build_api.py` |
| 4 | Fix guides | `mitigate/guide.py` |

## Settings (`config/settings.yaml`)

```yaml
llm:
  provider: api                # api | local
  api:
    base_url: https://integrate.api.nvidia.com/v1
    model: nvidia/nemotron-3-ultra-550b-a55b
    budget: {context: 32768, max_tokens: 4096, page_chars: 4000, pages_total_chars: 32000, cve_batch: 8, timeout: 120}
  local:
    server: tools/llama.cpp/build/bin/llama-server
    model: qwen3-0.6b          # key into models: below
    port: 8091
    threads: 4
    budget: {context: 4096, max_tokens: 512, page_chars: 1500, pages_total_chars: 6000, cve_batch: 2, timeout: 600}
  models:                      # GGUF files under models/; exact repo + file + sha256 pinned at build time
    qwen3-0.6b:     {file: models/<pinned>.gguf, url: <pinned>, sha256: <pinned>, no_think: true}
    qwen2.5-0.5b:   {file: ..., url: ..., sha256: ...}
    gemma3-270m:    {file: ..., url: ..., sha256: ...}
    smollm2-360m:   {file: ..., url: ..., sha256: ...}
    llama3.2-1b:    {file: ..., url: ..., sha256: ..., kali_only: true}   # ~770 MB, likely OOM on a 1 GB Pi
```

`.env` keeps only secrets (`NVIDIA_API_KEY`). Existing `LLM_BASE_URL` / `LLM_MODEL` env variables still override the `api` entries, so current setups keep working.

## `llmconf.py` (new, shared)

- `settings() -> dict`: the resolved provider: `base_url`, `model`, `api_key` (None for local), `budget`, `provider`.
- `configured() -> bool`: api → key present; local → server binary and model file present.
- `local_server()`: context manager. Starts `llama-server -m <file> --host 127.0.0.1 --port <port> -c <context> -t <threads>`, waits for `GET /health` = ok (timeout 120 s), yields, stops it (terminate, then kill after 10 s). Server output is appended to `runs/<run-id>/llm-server.log` (not `pipeline.log`, so the stage log stays readable), never held in memory; the last 20 lines go into the error if the server fails. Binds 127.0.0.1 only.
- `extra_body() -> dict`: NVIDIA-only fields (`reasoning_effort`) for api; for local `{"chat_template_kwargs": {"enable_thinking": false}}` when the model has `no_think`, else `{}`.

Each task uses `llmconf` instead of reading env variables, and takes its sizes from `budget`. Each stage that calls the LLM wraps its LLM part in `local_server()` when the provider is local, so the model's ~400 MB is free while nmap and Fast Downward run.

## Runtime

- llama.cpp built from source by `scripts/fetch_llama.sh` into `tools/llama.cpp/` at a pinned tag (CPU, no GPU backends). Builds on aarch64 (Kali, Pi OS 64-bit). `tools/` and `models/` are git-ignored.
- `scripts/fetch_model.sh <key>` downloads one model from its pinned `url` and checks `sha256`.
- No new Python dependency.

## Benchmark

Task 3 is not run anywhere in our pipeline (Metric 1 / top-K explanation scripts are not called), so it gets the provider switch but is not benchmarked.

**Limitation:** `build_api.py` follows the provider only when a stage has called `llmconf.export_env()` and started the local server. Run on its own (iEXAM's standalone scripts or API), it still goes to the API URL in `.env`, whatever `llm.provider` says. Nothing in EdgePlanner runs it that way today.

```
python run.py llmbench [--run <run-id>] [--models qwen3-0.6b,gemma3-270m,...] [--api] [--repeat 1]
```

- **Inputs:** fixed prompts built from one run, so every model sees the same input: 4 CVEs (task 1), the optimal plan of one goal (task 2), 2 fix-guide actions with their fetched pages cached in the bench folder (task 4). Prompts are built with the local budget for every model, the API included, so the comparison is fair. Pages are fetched once and reused.
- **Per model:** one `local_server()` start; load time and peak server RAM (`VmHWM` from `/proc/<pid>/status`) recorded.
- **Per model × task:** wall time; prompt tokens and prompt tokens/s, output tokens and tokens/s (from llama-server's `timings`; for the API, wall time and usage only); `valid`: the output passes that task's existing parser (`llm.parse`, `guide.parse_guide`, non-empty text for 2 and 3); the output text.
- `--api` adds the API model as a baseline (only if a key is set).
- `kali_only` models are skipped on a machine with < 2 GB RAM, with a note.
- **Output:** `runs/<run-id>/llmbench/<UTC stamp>.json` (schema-versioned, includes host: CPU model, RAM, OS, llama.cpp tag) and a summary table on the terminal.

## Errors

- Server does not become healthy, or dies (OOM): that model is recorded `failed` with the last log lines; the bench continues with the next model.
- A pipeline stage with provider local and no binary/model: the same "not configured" path as a missing key today, with the hint `run scripts/fetch_llama.sh and scripts/fetch_model.sh <model>`.
- Output that fails a parser: `valid: false`; in pipeline stages the existing per-task handling applies (note and continue).

## Not included

Fine-tuning; several models loaded at once; a benchmark web page; running the model on another LAN machine; GPU backends.

## Tests

`llmconf` resolution (api/local, env override, key needed only for api); `extra_body` per provider; `local_server` against a fake server script (start, health wait, stop, failure to start); budget used by `cveinfo` batching and `guide` page caps; bench record shape and `valid` scoring with a fake endpoint. No network or real model in tests.

## Gate

- With `provider: local` on Kali, phases 4, 7 (explanations), 8 and 8b complete on the latest run using a local model, and no LLM request leaves 127.0.0.1 (checked by running with the API keys set empty and `LLM_BASE_URL` pointing at NVIDIA: LLM output still appears and `llm-server.log` shows the requests).
- With `provider: api`, everything behaves as before (existing tests pass).
- `run.py llmbench --api` on Kali records all four tasks for every non-skipped model plus the API, with timings, RAM and validity.
- On the Pi (when phase 10 resumes): the same bench runs and its JSON is kept.

Stop at the gate and report.

## Result (2026-10-20/21, Kali)

| Gate item | Status |
|---|---|
| Local mode, no request off 127.0.0.1 | **Met.** cveinfo, plan explanation and fix guides ran on `qwen3-0.6b` with the API keys set empty and `LLM_BASE_URL` set to NVIDIA. Every LLM output was tagged `qwen3-0.6b`; the server log shows 46 requests on 127.0.0.1. |
| `provider: api` unchanged | **Met.** Full suite passes (107 tests). api mode no longer sets `LLM_MAX_TOKENS` / `LLM_EXTRA_BODY`, so iEXAM keeps its own limits. |
| `llmbench --api` on Kali | **Met, for 3 tasks** (CVE, plan, guide). Task 3 (`build_api.py`) is not run by the pipeline, so it is not benchmarked (see Benchmark). |
| Bench on the Pi | **Pending** (phase 10). Rebuild llama.cpp on the Pi with `scripts/fetch_llama.sh`; do not copy `tools/` (`GGML_NATIVE=ON`). |

Changes after review (each with a failing test first):
- refuse a server already on the port;
- never send the real key to the local server;
- stop the server on SIGTERM;
- api mode leaves iEXAM untouched;
- stop `cveinfo` when the local model stops responding;
- mark a benchmark model that died as failed.

Full results and discussion are in `docs/reports/2026-10-20-small-llm-benchmark.md`.
- **Pi 3 (1 GB):** `qwen3-0.6b`, 9/15 valid.
- **Pi 4/5 (2 GB+):** `qwen3-1.7b`, 15/15 valid. Neither matches the API's fix-guide quality.

The execution record is in `docs/superpowers/ledgers/2026-10-20-local-llm.md`: rulings and deferred minor findings.
