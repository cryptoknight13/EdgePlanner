# Phase 8b — Fix guides for mitigation actions

Read `CLAUDE.md` and `phases/README.md` first. Builds on phase 8's `runs/<run-id>/mitigation/mitigation.json`. Runs on Kali.

## Goal

For each mitigation action, a short guide the home owner can follow: how the change blocks the attack, what to do step by step, and the pages to use. Written by the LLM from pages we already have links to; no search engine.

```
python run.py guide [--run <run-id>] --target "<node name>"
```

writes (or extends) `runs/<run-id>/mitigation/guide.json`.

## Unit of work

One guide per unique action, keyed `<node>|<fact>|<token>` (e.g. `n3|system|axis-m1014-firmware`). The same action appears in several options; it gets one guide, shown under every option that contains it. Actions that already have a guide are skipped, so a rerun only fills gaps. Typical size on the home network: 2–5 unique actions per goal.

## Method (`mitigate/guide.py`)

1. **Links.** From the action's `evidence`: `advisories`, `fix_commits`, `nvd`. Deduplicated, at most 8 per action, advisories first.
2. **Fetch.** stdlib `urllib`, `http`/`https` only, 10 s timeout, at most 200 KB read (streamed, never more held), HTML stripped to text with `html.parser`, trimmed to 4,000 characters per page. Each URL is recorded as `fetched` or `failed` with the reason. Fetching public vendor/NVD pages is not scanning; no request goes to any LAN device.
3. **LLM.** One non-streaming chat request per action through the existing NVIDIA NIM settings (`NVIDIA_API_KEY`, `LLM_BASE_URL`, `LLM_MODEL` from `.env`, same defaults as `llm_service.py`). Hard timeout 120 s, one retry. The prompt gives: device name, IP, type, product, installed version(s), target version, CVEs (id, CVSS, one-line description), the action text, and the fetched page texts with their URLs. It asks for JSON only:
   ```json
   {"how_it_blocks": "1-2 sentences",
    "steps": ["3-6 short imperative steps"],
    "links": [{"title": "...", "url": "..."}]}
   ```
4. **Validate.** JSON is parsed (first `{...}` block if the model wraps it). `links` whose `url` is not in the fetched list are dropped. `steps` capped at 6, each at 200 characters; `how_it_blocks` at 400. Missing or bad JSON: that action gets no guide, a note is recorded, the rest continue.

## Output (`guide.json`)

```json
{"schema_version": "1.0", "run_id": "...", "model": "...",
 "guides": {"n3|system|axis-m1014-firmware": {
   "goal": "...", "generated_at": "...", "how_it_blocks": "...", "steps": ["..."],
   "links": [{"title": "...", "url": "..."}],
   "sources": [{"url": "...", "status": "fetched" | "failed", "reason": "..."}],
   "no_sources": false}},
 "notes": ["..."]}
```

`no_sources: true` when every fetch failed: the guide was written from our CVE data only.

## Page

- **Mitigate** page: a per-goal button **Explain how to fix**, run as a job action like `optimal`/`topk` (`ACTIONS` in `web/jobs.py`, one job at a time, output to `pipeline.log`). Never automatic.
- Under the selected option, each action shows its guide: how it blocks, numbered steps, links. Labelled **AI-written guidance — check against the vendor's page before acting.** Verified badge and evidence stay unchanged.
- Server serves `guide.json` as `GET /api/runs/<id>/guide` (optional, like `plans`).
- No key: the job fails with the hint `Set NVIDIA_API_KEY (or OPENAI_API_KEY) in .env, then retry.`, shown in the Logs drawer like any failed job.

## Not included

Search beyond known links; guides for all goals in one click; LLM option-level summaries.

## Tests (`tests/test_guide.py`)

HTML-to-text; link filtering against the fetched list; JSON parsing (clean, wrapped in prose, invalid); cached actions skipped; unique-action keying across options. No network in tests (fetch and LLM injected).

## Gate

- On the latest run, every action of the camera goal has a guide with 3–6 steps and at least one link from its fetched sources (or `no_sources: true` with a reason per URL).
- No link in `guide.json` falls outside the action's evidence links.
- The Mitigate page shows the guides under each option; checked with a headless screenshot.

Stop at the gate and report.

## Result (2026-10-20, Kali)

**Met; approved by the operator after checking the Mitigate page.**
- Live camera goal: 2 guides, 5–6 steps each, links only from the fetched evidence pages.
- Later changes (phase 8c):
  - sizes come from `llm.*.budget`;
  - the prompt lists the 8 most severe CVEs, 200 chars each, so it fits a 4k context;
  - template echoes ("...") are rejected;
  - each guide records the model that wrote it.
- Execution record: `docs/superpowers/ledgers/2026-10-20-fix-guides.md`.
