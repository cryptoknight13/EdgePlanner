# Fix Guides Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** For each mitigation action, an LLM-written guide (how it blocks, 3–6 steps, links) built from the evidence pages we already have, shown on the Mitigate page.

**Architecture:** New module `mitigate/guide.py` reads `mitigation/mitigation.json`, fetches each unique action's evidence links (stdlib urllib), asks the NVIDIA NIM endpoint once per action (same request style as `cveinfo/llm.py`), validates the JSON, and merges into `mitigation/guide.json`. `run.py guide --target` exposes it; `web/jobs.py` runs it as a per-goal action; the server serves the file; `iexam.js` renders it.

**Tech Stack:** Python 3 stdlib (`urllib.request`, `html.parser`), `requests` (already used by `cveinfo/llm.py`), `unittest`, vanilla JS.

**Spec:** `phases/phase-8b.md`

## Global Constraints

- No new dependency. Fetch with `urllib`, `http`/`https` only, 10 s timeout, at most 200 KB read, 4,000 characters of text per page, at most 8 links per action (advisories first, then fix commits, then NVD).
- LLM: `NVIDIA_API_KEY` (or `OPENAI_API_KEY`), `LLM_BASE_URL`, `LLM_MODEL` from `.env`; defaults from `cveinfo/llm.py`. Non-streaming, timeout 120 s, one retry.
- Output caps: `steps` ≤ 6 items, each ≤ 200 chars; `how_it_blocks` ≤ 400 chars. Links only from the action's fetched URLs.
- Never automatic: runs only from `run.py guide` or the page button. One job at a time.
- Page label, exact copy: `AI-written guidance — check against the vendor's page before acting.`
- No request to any LAN device. Secrets never written to `guide.json` or logs.
- Tests: `.venv/bin/python -m unittest tests.test_guide -v` (project uses unittest, no pytest). No network in tests.
- Project is not a git repo: there are no commit steps.

## Review Focus

- A link that redirects to another URL: the allowed set is the URLs we requested; the LLM's link must match one exactly, otherwise dropped (test in Task 1).
- A non-HTML or oversized page (PDF, 5 MB advisory): read stops at 200 KB; non-`text/*` content types are recorded `failed` with reason `content-type <x>` (test in Task 1).
- LLM returns steps as one string or links as plain strings: treated as bad shape → no guide for that action, note recorded (test in Task 1).
- Goal with options but zero evidence links (a `close` action with only an NVD link that fails): guide still written with `no_sources: true` (test in Task 2).
- Guide button pressed for a goal that Mitigate has not covered: job refused with a clear message (test in Task 3).

---

### Task 1: Pure helpers in `mitigate/guide.py`

**Files:**
- Modify: `cveinfo/llm.py` (extract the JSON-pulling part of `parse` into `extract_json`; `parse` calls it)
- Create: `mitigate/guide.py` (module docstring: phase 8b, origin of request style = `cveinfo/llm.py`)
- Test: `tests/test_guide.py`

**Interfaces:**
- Produces:
  - `cveinfo.llm.extract_json(text: str) -> dict` (strips `<think>…</think>`, first `{` to last `}`, raises `ValueError` if none)
  - `action_key(a: dict) -> str` → `f"{a['node']}|{a['fact']}|{a['token']}"`
  - `unique_actions(target: dict) -> dict[str, dict]` → key → action across all `target["options"]`, first occurrence wins, insertion order kept
  - `links_for(a: dict) -> list[str]` → advisories, then fix_commits, then nvd, over all `a["evidence"]`; deduped; first 8
  - `html_to_text(html: str) -> str` → visible text (skip `script`/`style`), whitespace collapsed, ≤ 4000 chars
  - `fetch(url: str) -> tuple[str | None, str | None]` → `(text, None)` or `(None, reason)`; never raises
  - `parse_guide(reply: str, allowed: set[str]) -> dict` → `{"how_it_blocks", "steps", "links"}`; raises `ValueError` on bad shape

- [ ] **Step 1: Write the failing tests** in `tests/test_guide.py`:

```python
A1 = {"node": "n2", "fact": "system", "token": "axis-fw", "evidence": [
    {"nvd": "https://nvd/1", "advisories": ["https://axis/adv"], "fix_commits": []},
    {"nvd": "https://nvd/2", "advisories": ["https://axis/adv"], "fix_commits": ["https://git/c1"]}]}

def test_unique_actions_dedupes_across_options(self):
    t = {"options": [{"actions": [A1]}, {"actions": [A1, {**A1, "fact": "driver", "token": "upnp"}]}]}
    self.assertEqual(list(guide.unique_actions(t)), ["n2|system|axis-fw", "n2|driver|upnp"])

def test_links_order_dedupe_cap(self):
    self.assertEqual(guide.links_for(A1), ["https://axis/adv", "https://git/c1", "https://nvd/1", "https://nvd/2"])
    many = {"evidence": [{"nvd": f"https://nvd/{i}", "advisories": [], "fix_commits": []} for i in range(12)]}
    self.assertEqual(len(guide.links_for(many)), 8)

def test_html_to_text(self):
    t = guide.html_to_text("<html><style>x{}</style><script>bad()</script><h1>Fix</h1>  <p>Upgrade\n to 5.51</p></html>")
    self.assertEqual(t, "Fix Upgrade to 5.51")
    self.assertEqual(len(guide.html_to_text("<p>" + "a " * 5000 + "</p>")), 4000)

def test_fetch_rejects_non_http_and_non_text(self):
    self.assertEqual(guide.fetch("file:///etc/passwd")[0], None)
    # non-text: patch guide.urllib.request.urlopen with a fake response whose headers say application/pdf
    # -> (None, "content-type application/pdf"); a fake text/html body of 300 KB -> only 200_000 bytes read

def test_parse_guide_filters_links_and_caps(self):
    reply = 'Sure! <think>hmm</think>```json\n{"how_it_blocks": "x", "steps": ["s"] , "links": [' \
            '{"title": "Axis", "url": "https://axis/adv"}, {"title": "Made up", "url": "https://evil/x"}]}```'
    g = guide.parse_guide(reply, {"https://axis/adv"})
    self.assertEqual(g["links"], [{"title": "Axis", "url": "https://axis/adv"}])
    long = '{"how_it_blocks": "' + "b" * 900 + '", "steps": ' + json.dumps(["s" * 300] * 9) + ', "links": []}'
    g = guide.parse_guide(long, set())
    self.assertEqual((len(g["how_it_blocks"]), len(g["steps"]), len(g["steps"][0])), (400, 6, 200))

def test_parse_guide_rejects_bad_shape(self):
    for bad in ("no json here", '{"how_it_blocks": "x", "steps": "one string", "links": []}',
                '{"how_it_blocks": "x", "steps": ["a"], "links": ["https://axis/adv"]}', '{"steps": ["a"], "links": []}'):
        with self.assertRaises(ValueError):
            guide.parse_guide(bad, {"https://axis/adv"})
```

Also keep `tests/test_cveinfo.py` passing (it covers `parse`).

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m unittest tests.test_guide -v`
Expected: FAIL / ERROR, `mitigate.guide` has no such attributes.

- [ ] **Step 3: Implement the helpers** with the signatures above. `fetch`: refuse non-`http(s)` scheme (reason `scheme <x>`); `urlopen(Request(url, headers={"User-Agent": "EdgePlanner/1.0"}), timeout=10)`; refuse non-`text/*` content type; `resp.read(200_000)`; decode with the response charset or utf-8 `errors="replace"`; return `html_to_text`. Catch `OSError` and `ValueError` → `(None, str(exc))`. `html_to_text`: `html.parser.HTMLParser` subclass collecting `handle_data` outside `script`/`style`. `parse_guide`: `extract_json`, then require `how_it_blocks` str, `steps` non-empty list of str, `links` list of dicts with str `title`/`url`; keep links whose `url in allowed`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m unittest tests.test_guide tests.test_cveinfo -v`
Expected: all PASS.

---

### Task 2: `guide.run` and `run.py guide`

**Files:**
- Modify: `mitigate/guide.py` (add `build_prompt`, `ask`, `run`)
- Modify: `run.py` (docstring line, `guide` subparser, `run_guide`, dispatch map)
- Test: `tests/test_guide.py`

**Interfaces:**
- Consumes: Task 1 helpers; `cveinfo.llm.configured()`, `cveinfo.llm.model()`, `cveinfo.llm.DEFAULT_BASE`.
- Produces:
  - `build_prompt(a: dict, node: dict, cves: dict, pages: list[tuple[str, str]]) -> str` (node from `iexam/node-data.json`: `name`, `IP`, `label`; cves from `cveinfo.json["cves"]`: `cvss`, `description` per evidence CVE; pages = (url, text))
  - `ask(prompt: str) -> str` (one non-streaming chat request, system prompt asks for the JSON shape in the spec; timeout 120 s; one retry on `requests.RequestException` or status 429/5xx; returns the message content)
  - `run(run_dir: Path, goal: str, fetch=fetch, ask=ask) -> dict` (returns the full `guide.json` content and writes it to `run_dir/"mitigation"/"guide.json"`)
  - CLI: `python run.py guide [--run ID] --target NAME` (`--target` required, single); default run = latest with `mitigation/mitigation.json`

`run` behaviour: load existing `guide.json` if present (else `{"schema_version": "1.0", "run_id", "model", "guides": {}, "notes": []}`); find the target with `goal`, raise `ValueError(f"no mitigation options for {goal}")` if missing or unreachable; for each `unique_actions` key not already in `guides`: fetch every `links_for` URL into `sources` (`{"url", "status", "reason"?}`), call `ask(build_prompt(...))`, `parse_guide(reply, fetched_urls)`; store `{goal, generated_at, how_it_blocks, steps, links, sources, no_sources}`; on `ValueError` or `requests.RequestException` append note `f"guide for {key}: {exc}"` and continue. Write the file after each action (a hang later keeps earlier work). If `not cveinfo.llm.configured()`: raise `ValueError` with the LLMNotConfigured hint text: `Set NVIDIA_API_KEY (or OPENAI_API_KEY) in .env, then retry.`

- [ ] **Step 1: Write the failing tests** using a temp run dir with `mitigation/mitigation.json` (one goal, two options sharing `A1` plus one `driver` action with only an NVD link), `iexam/node-data.json`, `cveinfo.json`; fake `fetch` and `ask`:

```python
def test_run_writes_one_guide_per_unique_action_and_skips_cached(self):
    calls = []
    def ask(prompt): calls.append(prompt); return json.dumps({"how_it_blocks": "b", "steps": ["s"],
        "links": [{"title": "Axis", "url": "https://axis/adv"}]})
    fetch = lambda u: ("page text", None) if "axis" in u else (None, "HTTP 404")
    out = guide.run(run, "camera", fetch=fetch, ask=ask)
    self.assertEqual(len(calls), 2)
    g = out["guides"]["n2|system|axis-fw"]
    self.assertEqual((g["links"], g["no_sources"]), ([{"title": "Axis", "url": "https://axis/adv"}], False))
    self.assertIn({"url": "https://nvd/1", "status": "failed", "reason": "HTTP 404"}, g["sources"])
    self.assertTrue(out["guides"]["n2|driver|upnp"]["no_sources"])
    self.assertEqual(out["guides"]["n2|driver|upnp"]["links"], [])  # nothing fetched -> no link survives
    guide.run(run, "camera", fetch=fetch, ask=ask)
    self.assertEqual(len(calls), 2)  # cached
    self.assertEqual(json.loads((run / "mitigation" / "guide.json").read_text())["guides"].keys(), out["guides"].keys())

def test_run_bad_reply_records_note_and_continues(self):
    replies = iter(["not json", json.dumps({"how_it_blocks": "b", "steps": ["s"], "links": []})])
    out = guide.run(run, "camera", fetch=lambda u: ("t", None), ask=lambda p: next(replies))
    self.assertEqual(len(out["guides"]), 1)
    self.assertTrue(any("n2|system|axis-fw" in n for n in out["notes"]))

def test_run_unknown_goal_and_missing_key(self):
    with self.assertRaises(ValueError): guide.run(run, "nope", fetch=..., ask=...)
    # with NVIDIA_API_KEY and OPENAI_API_KEY removed from os.environ (unittest.mock.patch.dict): ValueError mentioning NVIDIA_API_KEY

def test_prompt_has_device_versions_cves_and_pages(self):
    p = guide.build_prompt(A1_with_text, {"name": "cam", "IP": "192.168.1.183", "label": "camera"},
                           {"CVE-1": {"cvss": {"score": 9.8}, "description": "overflow"}}, [("https://axis/adv", "Upgrade to 5.51")])
    for s in ("cam", "192.168.1.183", "CVE-1", "overflow", "https://axis/adv", "Upgrade to 5.51", A1_with_text["text"]):
        self.assertIn(s, p)
```

Set the env key in `setUp` with `mock.patch.dict(os.environ, {"NVIDIA_API_KEY": "test"})` so `run` passes the configured check.

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m unittest tests.test_guide -v`
Expected: the new tests ERROR (`run`/`build_prompt` missing).

- [ ] **Step 3: Implement `build_prompt`, `ask`, `run`** as specified above. `build_prompt` includes the action `text`, `installed`/`target_version`/`ports` when present, and each page as `SOURCE <url>:\n<text>`. Add `run_guide(args)` in `run.py` printing each guide's steps and links, then `record: <path>`; register the `guide` subparser with `--run` and required `--target`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m unittest tests.test_guide tests.test_mitigate -v`
Expected: all PASS.

---

### Task 3: Job action and server route

**Files:**
- Modify: `web/jobs.py` (`ACTIONS += ("guide",)`, `steps_for`, goal check)
- Modify: `web/server.py` (`RESULTS["guide"] = "mitigation/guide.json"`, route regex `model|plans|mitigation|guide`, docstring line)
- Test: `tests/test_web.py`

**Interfaces:**
- Consumes: `run.py guide --target GOAL` (Task 2).
- Produces: `POST /api/pipeline {"run", "stage": "guide", "goal"}`; `GET /api/runs/<id>/guide` (404 when absent).

`steps_for(..., "guide", goal)` → `[["guide", "--target", goal]]`. In `start`, for `stage == "guide"` the goal must be a `goal` in `mitigation/mitigation.json` targets that is not `unreachable` and has options; otherwise `ValueError("run Mitigate for this goal first")`. The optimal/topk check stays as is.

- [ ] **Step 1: Write the failing tests** in `tests/test_web.py`, following `test_planning_actions_need_a_goal_from_the_attack_model`:

```python
def test_guide_action_needs_mitigation_for_the_goal(self):
    # run with plans.json listing "AXIS M1014"; no mitigation.json -> start(RUN, "guide", goal="AXIS M1014") raises ValueError
    # mitigation.json with that goal unreachable -> ValueError
    # mitigation.json with options -> job done, log_tail contains "ran guide --target AXIS M1014\n"

def test_serves_guide_json(self):
    # GET /api/runs/<RUN>/guide -> 404 before, 200 with the file's JSON after writing mitigation/guide.json
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m unittest tests.test_web -v`
Expected: the two new tests FAIL.

- [ ] **Step 3: Implement** the changes listed above.

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m unittest tests.test_web -v`
Expected: all PASS.

---

### Task 4: Mitigate page shows the guides

**Files:**
- Modify: `web/static/app.js` (global `let guide = null;` next to `mitigation`; load it in `load()` with `getOptional(`${base}/guide`)`; `STAGE_NAMES.guide = "Explain how to fix"`; reload after a `guide` job finishes the same way it does for `optimal`/`topk`)
- Modify: `web/static/iexam.js` (`renderMitigatePage`, `resultsCard`)
- Modify: `web/static/style.css` only if the existing `.actions`, `.hint`, `.flag`, `.empty` classes do not cover it

**Interfaces:**
- Consumes: `GET /api/runs/<id>/guide` (Task 3); `actionButton(action, label, again)` already in `iexam.js`; key format `node|fact|token` (Task 1).

UI:
- In the options card area for a goal with options: `actionButton("guide", "Explain how to fix", <every unique action of this goal already has a guide>)`, with a one-line `.hint`: `An LLM reads the advisories and patch pages linked below and writes the steps.`
- In `resultsCard`, under each action's text: if `guide?.guides[key]` exists, a block with `how_it_blocks`, an `<ol>` of `steps`, a list of `links` (`<a href target="_blank" rel="noopener noreferrer">title</a>`), and the exact label `AI-written guidance — check against the vendor's page before acting.`; when `no_sources`, add `No source page could be fetched; written from the CVE data only.` All strings through `esc()`; link `href` only if it starts with `https://` or `http://`.
- If the last guide job failed, the Logs drawer shows why (existing behaviour); no extra UI.

- [ ] **Step 1: Implement the UI** as above.

- [ ] **Step 2: Verify in the real app.** Start the server via `.venv` (see memory reference-env-gotchas), open the latest run's Mitigate page for the camera goal, press **Explain how to fix**, wait for the job, take a headless screenshot in dark and light mode at desktop and 390 px width.
Expected: each action of the selected option shows how-it-blocks, numbered steps, links and the AI label; no horizontal scroll at 390 px; contrast unchanged.

- [ ] **Step 3: Check the gate on the live run.**

Run:
```bash
.venv/bin/python - <<'EOF'
import json, glob
r = sorted(glob.glob("runs/*/mitigation/guide.json"))[-1]
g = json.load(open(r)); m = json.load(open(r.replace("guide.json", "mitigation.json")))
allowed = {k: {s["url"] for s in v["sources"]} for k, v in g["guides"].items()}
assert all(l["url"] in allowed[k] for k, v in g["guides"].items() for l in v["links"])
for k, v in g["guides"].items():
    assert 3 <= len(v["steps"]) <= 6 and (v["links"] or v["no_sources"]), k
print(r, len(g["guides"]), "guides ok", g["notes"])
EOF
```
Expected: `... guides ok` and every camera-goal action key present. If a guide has fewer than 3 steps, tighten the system prompt in `ask` and rerun (`guide.json` entry removed first).

- [ ] **Step 4: Run the whole test suite**

Run: `.venv/bin/python -m unittest discover -s tests -v`
Expected: all PASS (the tests skipped for missing planners stay skipped).

Stop at the gate and report.
