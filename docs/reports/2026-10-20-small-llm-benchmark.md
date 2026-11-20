# Small LLMs for an edge security analyser: benchmark report

**Project:** EdgePlanner, phase 8c (local LLM option). **Date:** 2026-10-20. **Status:** Kali results: single pass (§4), three repeats (§10), and models up to 4B (§11). The Raspberry Pi 3 run is pending (phase 10).

## Summary

- **No model that fits a 1 GB Pi matches the hosted model.** Five local models (270M–1B parameters, Q4_K_M) and the NVIDIA API were each run 3 times on the same 5 prompts. That is 15 requests per model, across the pipeline's three LLM tasks.
  - The API passed **15/15**.
  - The best small model, **Qwen3 0.6B, passed 9/15**: every fix guide (6/6) and half of the CVE explanations (3/6), but no plan explanation (0/3).
  - The others passed **0–3/15**.
- **Qwen3 1.7B matches the API on validity (15/15)** (§11). It needs about 1.4 GB, which suits a Pi 4/5 with 2 GB or more, not a Pi 3.
  - Llama 3.2 3B scored 9/15: every plan and guide valid, every CVE answer had extra text after the JSON.
  - Qwen3 4B could not be measured: it ran out of free memory on this machine and timed out.
  - 7B does not fit this machine at all.
- **Even valid local output is weaker.** Qwen3's fix guides have the right target version and only real links, but their steps are generic ("install the updated Samba version on the device" for a consumer router). The API's are actionable ("upgrade the router's firmware through its admin page").
  - Qwen3 1.7B and Llama 3.2 3B start in the right place, the router's web page, but still look for a "Samba update" option routers don't have.
  - Llama 3.2 3B invents menu names.
- **Qwen3 0.6B fits a 1 GB Pi, once the server is tuned.** It needs **329–336 MB of unreclaimable memory** plus a 386 MB mapped model file. The tuning was one parallel slot, no prompt cache, a q8_0 KV cache and no weight repacking. llama-server's defaults needed 911 MB unreclaimable, about 1.3 GB peak. Llama 3.2 1B peaks near 1 GB and does not fit.
- **Most failures are format, not knowledge.** Of the 19 invalid local outputs in the single pass:
  - 12 are broken, truncated, wrongly shaped or missing JSON;
  - 5 echo the prompt back;
  - 2 are empty.
- **The local models are deterministic at temperature 0.** 23 of 25 model × prompt cells gave the identical output in all three repeats, and validity never changed. The ranking is stable for these prompts. It says nothing yet about other prompts.
- **Local mode keeps the data local.** The full pipeline ran on Qwen3 0.6B with no API key and the API URL still configured: every output came from the local model and no LLM request left the machine.
- **Next:**
  1. force JSON output with a schema;
  2. write prompts for small models, including a device-type hint for guides;
  3. measure on a larger, more varied prompt set;
  4. repeat on the Pi 3, and on a Pi 4/5 or an 8 GB machine for 1.7B–7B. Speeds measured here do not carry over to either.

## 1. Purpose

EdgePlanner uses an LLM for explanation only, never for the attack model or the planner. The LLM has three jobs in the pipeline:

| Task | What the LLM produces | Where | Pipeline check that accepts the output |
|---|---|---|---|
| **CVE** | per CVE, a one-sentence `cause` and `consequence` for a home user | phase 4, `cveinfo/llm.py` | JSON object mapping every requested CVE id to `{cause, consequence}` strings |
| **Plan** | plain-language explanation of each step of the optimal attack plan | phase 7, iEXAM `llm_service.py` | non-empty text |
| **Guide** | per mitigation action: how it blocks the attack, 3–6 steps, links | phase 8b, `mitigate/guide.py` | JSON `{how_it_blocks, steps[], links[]}`; links only from fetched evidence pages |

Until now these jobs ran on a hosted model (NVIDIA NIM, `nvidia/nemotron-3-ultra-550b-a55b`). Two reasons to run them locally:

- **Privacy.** The prompts carry device names, IP addresses, products, versions and CVEs from the home network.
- **Research.** We want to know whether a small model can do this work on a resource-constrained edge device. The target is a Raspberry Pi 3: 1 GB RAM, 4× Cortex-A53.

The question this report answers: **which small models can run these tasks within the Pi's memory, how fast, and how good is the output compared with the hosted model?**

## 2. Setup

### 2.1 Hardware and software (this run)

| | |
|---|---|
| Machine | Kali development box, aarch64. `lscpu` reports vendor "Apple" (a virtual machine on Apple silicon); 4 cores, 3,908 MB RAM |
| OS | Linux 6.19.14+kali-arm64, glibc 2.43 |
| Runtime | llama.cpp `llama-server`, release tag **b11758** (commit 83c2d01), built from source, CPU only, `GGML_NATIVE=ON` |
| API baseline | NVIDIA NIM, `nvidia/nemotron-3-ultra-550b-a55b` |

This is **not** the target device. The Kali box has much faster cores and four times the RAM of a Pi 3. Memory figures carry over to the Pi; speeds do not (§8).

### 2.2 Models

All local models are instruct-tuned, Q4_K_M GGUF, pinned by Hugging Face commit and sha256 in `config/settings.yaml`.

| Key | Model | Source repo | File size | Notes |
|---|---|---|---|---|
| `qwen3-0.6b` | Qwen3 0.6B | unsloth/Qwen3-0.6B-GGUF | 397 MB | thinking disabled (`enable_thinking: false`) |
| `qwen2.5-0.5b` | Qwen2.5 0.5B Instruct | Qwen/Qwen2.5-0.5B-Instruct-GGUF | 491 MB | |
| `gemma3-270m` | Gemma 3 270M it | unsloth/gemma-3-270m-it-GGUF | 253 MB | |
| `smollm2-360m` | SmolLM2 360M Instruct | bartowski/SmolLM2-360M-Instruct-GGUF | 271 MB | |
| `llama3.2-1b` | Llama 3.2 1B Instruct | bartowski/Llama-3.2-1B-Instruct-GGUF | 808 MB | `kali_only`: expected not to fit a 1 GB Pi |

### 2.3 Local budget

Small models get smaller prompts than the API. These limits are applied to **every** model in the benchmark, the API included, so all models see identical prompts.

| Setting | Local | API in the pipeline |
|---|---|---|
| Context window | 4,096 tokens | 32,768 |
| Max output tokens | 512 | 4,096 (iEXAM plan explanation: 16,384) |
| Text per fetched page / per guide | 1,500 / 6,000 chars | 4,000 / 32,000 |
| CVEs per request | 2 | 8 |
| Request timeout | 600 s | 120 s |

**Exception, deliberate:** in the benchmark the API keeps its **own output limit**. The prompts are identical, but Nemotron is a reasoning model and spends output tokens on reasoning first. The first benchmark run capped it at 512 and cut its JSON off mid-way, which measured the cap rather than the model (§9).

### 2.4 Server configuration: the memory experiment

With llama-server's defaults, Qwen3 0.6B, a 397 MB file, peaked at **1,268–1,296 MB**. That does not fit a 1 GB Pi. The verbose log showed three causes:

- **4 parallel slots × 4,096-token context,** with an f16 KV cache: **448 MiB**.
- **A repacked copy of the weights** (`CPU_REPACK`, **372 MiB**), kept on top of the memory-mapped file.
- **A prompt cache of up to 8 GB** (`-cram`, default 8192 MiB).

Measured on Kali with one 674-token prompt and 200 output tokens. *Anon* is anonymous (unreclaimable) memory, what the device must actually fit. *File* is mapped model pages, which the kernel can drop and re-read.

| Server flags | Peak (MB) | Anon (MB) | File (MB) | Prompt tok/s | Output tok/s |
|---|---|---|---|---|---|
| defaults | 1,268 | — | — | 303 | 44.4 |
| `-np 1 -cram 0` | 1,296 | 911 | 384 | 390 | 61.3 |
| `+ -fa on -ctk q8_0 -ctv q8_0` | 1,069 | 708 | 361 | 303 | 65.8 |
| **`+ -nr` (no repack): adopted** | **722** | **335** | **386** | 226 | 58.6 |
| `+ --no-mmap` | — | — | — | — | not accepted by this build |

The adopted flags are `-np 1 -cram 0 -fa on -ctk q8_0 -ctv q8_0 -nr`, in `llm.local.server_args`. They cut anonymous memory by **63 %** (911 → 335 MB) at a small cost to prompt speed. Output speed is unchanged.

Repacking speeds up matrix kernels on CPUs with newer instruction sets. The Pi 3's Cortex-A53 has neither dot-product nor i8mm instructions, so turning repack off should cost the Pi little. This must be re-measured on the Pi.

## 3. Method

### 3.1 Inputs

One input set comes from run `20261020T170354Z` (the home network: Linksys WRT3200ACM router, Axis M1014 camera). It is built once and sent to every model unchanged.

| # | Task | Input | Prompt size |
|---|---|---|---|
| 1 | CVE | CVE-2010-0547, CVE-2010-1635 (Samba) | 646 chars |
| 2 | CVE | CVE-2010-1642, CVE-2010-2063 (Samba) | 629 chars |
| 3 | Plan | optimal attack plan to the Linksys router (3 steps) | 1,656 chars |
| 4 | Guide | close/firewall the router's HTTP service (lighttpd, ports 80/443/10000) | 5,591 chars |
| 5 | Guide | upgrade Samba on the router, 3.0.37 → 4.19.2 (49 CVEs) | 8,569 chars |

Guide prompts include the text of the evidence pages (advisories, patch commits, NVD), fetched once and cached in `llmbench/pages.json`. Every model therefore reads the same pages. The Samba prompt lists the 8 most severe of its 49 CVEs (§9).

### 3.2 Procedure

- **Server per model:** for each model, `llama-server` is started on 127.0.0.1, the five requests run in order, and the server is stopped. With `--repeat N` the five requests run N times in a row on the same server (§10: N = 3).
- **Request settings:** every request uses temperature 0, non-streaming, the system prompt the pipeline uses for that task, and output capped at 512 tokens (API: its own limit).
- **Memory:** read from `/proc/<pid>/status` after the last request (VmHWM for peak, RssAnon, RssFile).
- **Speeds:** from llama-server's own `timings`. For the API only wall time and token counts are available.

### 3.3 Validity: stricter than "it parsed"

An output is **valid** when it passes the pipeline's own check, plus two rules added after the first run showed that some models echo their input:

- **Guide:** `parse_guide` succeeds, the output has at least one word (it isn't only "..."), and it has **at least 3 steps**. The pipeline itself accepts fewer steps.
- **Plan:** at least **15 words outside the PDDL steps**. An output that only repeats the plan's steps explains nothing.
- **CVE:** every requested id is present with string `cause` and `consequence`.

Validity measures **format and minimum substance, not correctness**. §6 examines correctness by hand.

## 4. Results

### 4.1 Summary (Kali, single pass)

| Model | CVE valid | Plan valid | Guide valid | **All valid** | Load s | Anon MB | Peak MB |
|---|---|---|---|---|---|---|---|
| **qwen3-0.6b** | 1/2 | 0/1 | **2/2** | **3/5** | 7.6 | 336 | 722 |
| qwen2.5-0.5b | 0/2 | 1/1 | 0/2 | 1/5 | 6.0 | 141 | 575 |
| gemma3-270m | 0/2 | 1/1 | 0/2 | 1/5 | 1.0 | 108 | 358 |
| smollm2-360m | 0/2 | 0/1 | 0/2 | 0/5 | 4.1 | 148 | 418 |
| llama3.2-1b | 0/2 | 1/1 | 0/2 | 1/5 | 8.1 | 210 | 987 |
| **Nemotron (API)** | **2/2** | **1/1** | **2/2** | **5/5** | — | — | — |

### 4.2 Per input

`pt` = prompt tokens; `p/s` = prompt tokens per second; `ot` = output tokens; `o/s` = output tokens per second.

| Model | Input | Valid | Wall s | pt | p/s | ot | o/s |
|---|---|---|---|---|---|---|---|
| qwen3-0.6b | CVE 1 | ✔ | 5.8 | 303 | 134 | 147 | 42.0 |
| | CVE 2 | ✘ | 7.2 | 182 | 243 | 250 | 38.6 |
| | Plan | ✘ | 6.3 | 604 | 157 | 86 | 35.2 |
| | Guide HTTP | ✔ | 33.7 | 1,477 | 109 | 368 | 18.3 |
| | Guide Samba | ✔ | 49.8 | 2,486 | 76 | 245 | 14.4 |
| qwen2.5-0.5b | CVE 1 | ✘ | 2.1 | 299 | 222 | 40 | 53.2 |
| | CVE 2 | ✘ | 1.7 | 178 | 203 | 50 | 59.4 |
| | Plan | ✔ | 16.6 | 618 | 189 | 512 | 38.5 |
| | Guide HTTP | ✘ | 23.8 | 1,470 | 158 | 512 | 35.3 |
| | Guide Samba | ✘ | 37.1 | 2,482 | 124 | 512 | 29.9 |
| gemma3-270m | CVE 1 | ✘ | 0.5 | 301 | 607 | 1 | — |
| | CVE 2 | ✘ | 0.5 | 295 | 548 | 1 | — |
| | Plan | ✔ | 2.7 | 623 | 537 | 110 | 71.6 |
| | Guide HTTP | ✘ | 3.7 | 1,464 | 496 | 44 | 55.8 |
| | Guide Samba | ✘ | 7.4 | 2,904 | 433 | 44 | 61.1 |
| smollm2-360m | CVE 1 | ✘ | 2.8 | 315 | 213 | 80 | 58.9 |
| | CVE 2 | ✘ | 1.4 | 198 | 207 | 31 | 77.6 |
| | Plan | ✘ | 5.5 | 661 | 188 | 102 | 51.5 |
| | Guide HTTP | ✘ | 15.2 | 1,612 | 133 | 115 | 36.9 |
| | Guide Samba | ✘ | 36.8 | 2,828 | 88 | 114 | 23.8 |
| llama3.2-1b | CVE 1 | ✘ | 5.5 | 306 | 139 | 111 | 33.6 |
| | CVE 2 | ✘ | 5.0 | 167 | 109 | 109 | 31.3 |
| | Plan | ✔ | 26.4 | 536 | 131 | 512 | 22.9 |
| | Guide HTTP | ✘ | 40.6 | 1,376 | 94 | 426 | 16.4 |
| | Guide Samba | ✘ | 82.3 | 2,289 | 56 | 512 | 12.4 |
| Nemotron (API) | CVE 1 | ✔ | 8.8 | 315 | — | 666 | — |
| | CVE 2 | ✔ | 4.1 | 306 | — | 488 | — |
| | Plan | ✔ | 3.4 | 624 | — | 503 | — |
| | Guide HTTP | ✔ | 9.8 | 1,610 | — | 1,076 | — |
| | Guide Samba | ✔ | 14.1 | 2,831 | — | 931 | — |

Prompt token counts differ by model for the same text, because each model has its own tokenizer and chat template.

## 5. Why outputs failed

Every invalid output, by cause:

| Model | Input | Failure | Class |
|---|---|---|---|
| qwen3-0.6b | CVE 2 | copied an NVD description containing a backslash into a JSON string, unescaped (`Invalid \escape`) | broken JSON |
| qwen3-0.6b | Plan | repeated the three PDDL steps verbatim and explained nothing | echo |
| qwen2.5-0.5b | CVE 1, 2 | returned one flat `{cause, consequence}` instead of a map keyed by CVE id | wrong schema |
| qwen2.5-0.5b | Guide ×2 | ran to the 512-token cap; the JSON was never closed | truncated |
| gemma3-270m | CVE ×2 | emitted end-of-text immediately: empty reply (1 token) | no answer |
| gemma3-270m | Guide ×2 | returned the template from the system prompt (`"how_it_blocks": "..."`, `"steps": ["..."]`) | echo |
| smollm2-360m | CVE 1 | trailing comma; also flat schema | broken JSON |
| smollm2-360m | CVE 2 | flat schema | wrong schema |
| smollm2-360m | Plan | repeated the PDDL steps | echo |
| smollm2-360m | Guide HTTP | restated the instructions ("how_it_blocks: 1-2 plain sentences…") in prose | echo / no JSON |
| smollm2-360m | Guide Samba | free text about the Samba mailing list; no JSON | no JSON |
| llama3.2-1b | CVE ×2 | missing comma between entries (`Expecting ',' delimiter`) | broken JSON |
| llama3.2-1b | Guide HTTP | JSON not closed (426 tokens) | broken JSON |
| llama3.2-1b | Guide Samba | ran to the 512-token cap | truncated |

**Patterns:**

- **Format, not knowledge, is the main failure.** Of the 19 invalid local outputs:
  - **12** are broken, truncated, wrongly shaped or missing JSON;
  - **5** are "echo" failures, where the model gave the input back instead of an answer;
  - **2** are empty replies (Gemma, CVE).
- **Below ~0.5B parameters, models echo.** Gemma 3 270M and SmolLM2 360M copy the system prompt's template or instructions instead of following them.
- **The 512-token cap bites the wordier models.** Qwen2.5 and Llama 3.2 hit it on 2 of 2 and 1 of 2 guides. Qwen3 0.6B stayed under the cap on every input.
- **Plan explanations "pass" too easily.** Three models passed the plan check, but by writing loosely around the steps. The 15-word rule detects echoes, not quality.

## 6. Quality of valid output: valid ≠ actionable

Take the same input, the Samba guide (upgrade Samba on the Linksys router), from the best small model and from the API. The correct action, from phase 8's data, is: *"Upgrade samba on Linksys WRT3200ACM (192.168.1.1) from samba 3.0.37 to 4.19.2 or later"*. On a consumer router that means **a firmware update**; the user cannot install Samba separately.

**Qwen3 0.6B** (valid):

> *how_it_blocks:* "This change addresses the CVE-2010-2063 vulnerability by updating Samba to version 4.19.2 or later…"
> 1. "Download the updated Samba version from the official source."
> 2. "Install the updated Samba version on the device."
> 3. "Verify that the new version is installed and running correctly."
> 4. "Test the device to ensure the security changes have been applied."

**Nemotron (API)** (valid):

> *how_it_blocks:* "Upgrading Samba replaces the vulnerable 3.0.37 code with a version (≥4.19.2) that contains fixes for all listed CVEs…"
> 1. "Open a browser and go to the router's web interface at http://192.168.1.1."
> 2. "Log in with the admin credentials."
> 3. "Locate the firmware-upgrade section (… consult the device's web page or Linksys manual if the exact menu name is unclear)."
> 4. "Download the latest Linksys firmware for the WRT3200ACM from the official Linksys support site that includes Samba 4.19.2 or newer."
> 5. "Upload the firmware file … wait for the router to reboot."
> 6. "After reboot, verify the Samba version…"

**Comparison:**

- **Target version:** both get it right (4.19.2), and both link only to real evidence pages. The link filter guarantees that.
- **The action itself:** Qwen3's steps are generic and not doable on a router ("install the updated Samba version on the device"). The API's steps are the right action, a firmware update through the router's admin page, in the order a home user would take them.
- **In an earlier pipeline run,** Qwen3 also invented a configuration file ("open config.xml and modify the POST handling rules") for the camera's UPnP fix.

The format check cannot catch this. **The validity score is an upper bound on usefulness.**

## 7. The pipeline in local mode

Separately from the benchmark, the whole pipeline ran once with `provider: local` (Qwen3 0.6B), on a copy of the same run.

The privacy check: all API keys were set empty and `LLM_BASE_URL` was set to NVIDIA's address. Every output was still produced, tagged `qwen3-0.6b`, and the server log recorded 46 requests on 127.0.0.1. No LLM request left the machine.

| Stage | Wall time | Result |
|---|---|---|
| Phase 4 CVE explanations (77 CVEs, 39 requests; includes NVD/OSV fetching) | 168 s | 71/77 explained; one batch failed (bad JSON escape) and was retried per CVE |
| Phase 7 plan explanation (one goal) | 7 s | produced, but only repeated the steps |
| Phase 8b fix guides (camera, 2 actions) | 97 s | 2 guides, 3 steps each, 1–3 real links |

**The pipeline stays correct with a weak model.** Every failure became a note, and nothing invalid was shown as a fact. **But the explanations a user would read are poorer than with the API.**

## 8. Limitations and threats to validity

1. **Few, similar inputs.** There are five prompts from one run: two CVE batches, one plan, two guides, all about the same router and its Samba and web services. A single different answer moves a model's score by 20–50 %.
   - **Repeats have answered one question:** at temperature 0 the local models give the same answer every time (§10), so the scores are not noise.
   - **They cannot answer the other:** how a model copes with different devices, CVEs and plans. That needs a larger, more varied input set.
2. **Not the target device.** All numbers are from a Kali VM on Apple silicon:
   - **Memory carries over:** same binary flags, same model files.
   - **Speed does not:** a Cortex-A53 at 1.2 GHz without dot-product instructions will be several times slower, and much slower again if the model's file pages get evicted under memory pressure and re-read from the SD card. No Pi speed is claimed here.
3. **Noisy speeds.** Throughput varied between runs on the same box. Qwen3 0.6B produced 44–66 output tok/s in the short smoke tests and 14–42 tok/s in the benchmark. The difference comes from:
   - **Longer prompts:** decoding slows as the context grows (14 tok/s at 2,486 prompt tokens against 42 tok/s at 303).
   - **Other load:** whatever else was running on the box at the time.

   The repeat run confirmed this. With nothing changed, Qwen3's mean guide time fell from 41.7 s (§4) to 28.9 s (§10). Compare speeds within one run, not across runs.
4. **Heuristic validity.** The checks test format and a minimum of substance (§3.3). Correctness was judged by hand on examples only (§6), not scored.
5. **One quantisation, one prompt design.** All local models use Q4_K_M and the pipeline's existing prompts, which were written for a large model. Small models may do better with simpler prompts, with examples in the prompt, or with constrained decoding (§9).
6. **The memory figures are after five requests,** not a worst case. Peak memory can grow with longer contexts, up to the 4,096-token limit.

## 9. Discussion and recommendations

**Can a small local model replace the API for EdgePlanner's explanations today? Not at equal quality.**

- **Qwen3 0.6B is the only usable candidate.**
  - It is the only model with valid fix guides: 2/2 in the single pass, 6/6 over three repeats. It never ran into the output cap (at most 368 of 512 tokens).
  - At 329–336 MB of anonymous memory plus a 386 MB model file, it should fit a 1 GB Pi when nothing else is loaded. The pipeline makes sure of this: it starts the model only for the LLM step, after nmap and the planners have finished.
  - Its guides are generic. It fails the plan explanation by echoing the steps (0/3), and fails the same CVE batch every time (3/6), because it copies a backslash from the NVD text into the JSON unescaped.
- **Gemma 3 270M is the lightest and fastest** (108–114 MB, 433–607 prompt tok/s) but echoes or returns nothing on the structured tasks. It would only suit free-text tasks.
- **Llama 3.2 1B does not fit the Pi** (987–991 MB peak) and gives no better results here: 3/15, and it hit the output cap 6 times out of 15.
- **Qwen2.5 0.5B and SmolLM2 360M** fail the structured tasks through wrong schemas, truncation and echoes. Qwen2.5 hit the output cap 9 times out of 15.

**Methodology lessons from the first run.** The first benchmark run was discarded because four of my own defects skewed it:

- **API cut off:** the API was capped at the local 512-token limit, so its reasoning used up the output. It now keeps its own limit.
- **Oversized prompt:** the Samba guide prompt listed all 49 CVEs (20,904 chars), more than a 4k context holds, so llama-server returned HTTP 400. It now lists the 8 most severe; this also fixed a failure the pipeline itself would have hit.
- **Echoes scored valid:** a template echo and a step echo both passed. The stricter rules in §3.3 now reject them.
- **CPU unnamed:** the host CPU was recorded as "-". It now comes from the board name or `lscpu`.

All four were fixed with tests before the runs reported here (§4 and §10).

**What would most likely improve small-model results, in order of expected effect:**

1. **Constrained JSON output.** llama-server can force the output to match a JSON schema (`response_format` with a JSON schema, or a GBNF grammar). That removes broken, missing and wrongly shaped JSON by construction: 9 of the 19 failures (§5). It does not fix the 3 truncated replies (they still hit the cap; see 3. below), the echoes, or generic content.
2. **Prompts written for small models.** Shorter instructions, no template with "..." placeholders (Gemma and SmolLM2 copy it), one worked example, and for guides a hint about the device type ("this is a consumer router: changes are made through firmware updates").
3. **A larger output cap for guides** (768–1,024 tokens), if the Pi's speed allows it.
4. **A larger, more varied input set.** For example, every CVE batch, plan and guide from several runs and devices, including the camera. This would measure robustness, which repeats cannot (§10.3).
5. **Qwen3 1.7B on a bigger device.** Done on Kali in §11: 15/15 valid, real plan explanations, still not firmware-level guides. It needs about 1.4 GB, so it suits a Pi 4/5 with 2 GB or more.

**Recommended configuration for now:**
- **On a Pi 4/5 with 2 GB+ (or another home machine) in local mode:** `qwen3-1.7b` (§11).
- **On the Pi 3 in local mode:** `qwen3-0.6b` with the adopted server flags. Its CVE explanations and fix guides carry the "AI-generated" label already shown on the page.
- **Plan explanations:** treat as unreliable in local mode.
- **When output quality matters more than keeping data on the machine:** keep `provider: api`.

## 10. Repeat run (`--repeat 3`)

Record: `runs/20261020T170354Z/llmbench/20261020T235913Z.json`. Same machine, inputs, flags and models as §4. Each input ran 3 times, so each model has 15 requests.

### 10.1 Results

| Model | CVE valid | Plan valid | Guide valid | **All valid** | Mean guide wall s | Anon MB | Peak MB |
|---|---|---|---|---|---|---|---|
| **qwen3-0.6b** | 3/6 | 0/3 | **6/6** | **9/15** | 28.9 | 329 | 715 |
| qwen2.5-0.5b | 0/6 | 3/3 | 0/6 | 3/15 | 24.5 | 140 | 615 |
| gemma3-270m | 0/6 | 3/3 | 0/6 | 3/15 | 4.9 | 114 | 364 |
| smollm2-360m | 0/6 | 0/3 | 0/6 | 0/15 | 26.3 | 148 | 418 |
| llama3.2-1b | 0/6 | 3/3 | 0/6 | 3/15 | 43.3 | 215 | 991 |
| **Nemotron (API)** | **6/6** | **3/3** | **6/6** | **15/15** | 12.5 | — | — |

### 10.2 Consistency across repeats

Per input: how many of the 3 repeats were valid, and how many distinct outputs the 3 repeats gave.

| Model | CVE 1 | CVE 2 | Plan | Guide HTTP | Guide Samba |
|---|---|---|---|---|---|
| qwen3-0.6b | 3/3 · 2 | 0/3 · 2 | 0/3 · 1 | 3/3 · 1 | 3/3 · 1 |
| qwen2.5-0.5b | 0/3 · 1 | 0/3 · 1 | 3/3 · 1 | 0/3 · 1 | 0/3 · 1 |
| gemma3-270m | 0/3 · 1 | 0/3 · 1 | 3/3 · 1 | 0/3 · 1 | 0/3 · 1 |
| smollm2-360m | 0/3 · 1 | 0/3 · 1 | 0/3 · 1 | 0/3 · 1 | 0/3 · 1 |
| llama3.2-1b | 0/3 · 1 | 0/3 · 1 | 3/3 · 1 | 0/3 · 1 | 0/3 · 1 |
| Nemotron (API) | 3/3 · 2 | 3/3 · 3 | 3/3 · 3 | 3/3 · 3 | 3/3 · 3 |

Speed spread within this run, min–max over the 3 repeats:

| Model | Guide Samba wall s | Guide Samba out tok/s | CVE 1 out tok/s |
|---|---|---|---|
| qwen3-0.6b | 35.3–41.0 | 25.7–32.4 | 69.5–81.2 |
| qwen2.5-0.5b | 27.9–33.2 | 43.3–49.0 | 75.0–105.7 |
| gemma3-270m | 6.4–6.7 | 112.4–124.0 | — (empty replies) |
| smollm2-360m | 35.3–37.3 | 24.9–38.1 | 84.9–96.8 |
| llama3.2-1b | 51.4–57.4 | 22.9–24.4 | 44.8–59.6 |
| Nemotron (API) | 4.4–30.6 | — | — |

### 10.3 What the repeats show

1. **The single-pass verdicts were not luck.** Every model × input cell had the same validity in all three repeats as in §4: 25 of 25 local cells and all API cells. At temperature 0 the local models are essentially deterministic: 23 of 25 cells gave the identical output three times. Qwen3 gave two different wordings on both CVE inputs, but validity did not change. The ranking (Qwen3 0.6B ahead, the API at 100 %) is therefore stable **for these inputs**.
2. **Repeats cannot rescue a model.** Because the outputs repeat, a model that fails an input fails it every time. Robustness has to be measured with **more and different inputs**, not more repeats (§8, point 1).
3. **The API is not deterministic, and its latency varies a lot.** Its 15 requests produced 14 distinct texts, all valid. Its wall time ranged from 3.1 to 50.0 s on the same input. That is the cost of a shared remote service; local latency stayed within ±10–25 % of its mean.
4. **Memory is stable.** Anonymous memory was within 7 MB of §4 for every model (Qwen3 0.6B: 329 vs 336 MB). Llama 3.2 1B again peaked near 1 GB.
5. **Speeds were higher than in §4 on the same machine.** For example, Qwen3's mean guide time was 28.9 s against 41.7 s, and its CVE output speed 76 against 40 tok/s. Nothing in the setup changed, so this confirms limitation 3: throughput on this VM depends on what else is running. Compare speeds within a run, and measure the Pi separately.

### 10.4 Conclusions after the repeats

**No change to §9.**
- Qwen3 0.6B remains the only small model with valid fix guides (6/6), and the only one worth taking to the Pi.
- It reliably fails the plan explanation by repeating the steps (0/3), and it fails the same CVE batch every time.
- The next useful experiment is not more repeats. It is the improvements in §9 (forced JSON schema, prompts written for small models), measured on a **larger input set** drawn from several runs, and then the same benchmark on the Pi 3.

## 11. Bigger models: 1.7B to 4B

**Question:** how big must a local model be before its output is good enough? These models do **not** fit a 1 GB Pi 3. The answer matters for a Pi 4/5 with 2–8 GB, or for running the model on another home machine.

- **Record:** `runs/20261020T170354Z/llmbench/20261021T042142Z.json`.
- **Setup:** same inputs, flags, local budget and `--repeat 3` as §10. The API baseline was not re-sent; its §10 results stand.
- **Not tested:** 7B. A 7B model at Q4 (≈ 4.7 GB) is larger than this machine's total RAM (3.9 GB, about 2 GB free during the run).

| Key | Model | Source repo | File |
|---|---|---|---|
| `qwen3-1.7b` | Qwen3 1.7B (thinking off) | unsloth/Qwen3-1.7B-GGUF | 1,107 MB |
| `llama3.2-3b` | Llama 3.2 3B Instruct | bartowski/Llama-3.2-3B-Instruct-GGUF | 2,019 MB |
| `qwen3-4b` | Qwen3 4B (thinking off) | unsloth/Qwen3-4B-GGUF | 2,497 MB |

### 11.1 Results (3 repeats, 15 requests per model)

| Model | CVE valid | Plan valid | Guide valid | **All valid** | Mean guide wall s | Out tok/s (guides) | Anon MB | Peak MB |
|---|---|---|---|---|---|---|---|---|
| qwen3-0.6b *(§10)* | 3/6 | 0/3 | 6/6 | 9/15 | 28.9 | 26–42 | 329 | 715 |
| **qwen3-1.7b** | **6/6** | **3/3** | **6/6** | **15/15** | 60.9 | 12–27 | 365 | 1,430 |
| llama3.2-3b | 0/6 | 3/3 | 6/6 | 9/15 | 92.8 | 3–15 | 319 | 2,316 |
| qwen3-4b | 1/6 | 0/3 | 0/6 | 1/15 | 600 (timeout) | 0.5 | 293 | 2,388 |
| Nemotron (API) *(§10)* | 6/6 | 3/3 | 6/6 | 15/15 | 12.5 | — | — | — |

### 11.2 What happened

- **Qwen3 1.7B passed every request,** the first local model to match the API's score.
  - **CVE:** both CVE batches valid in all repeats, including the batch on which Qwen3 0.6B always broke the JSON with an unescaped backslash.
  - **Plan:** a real explanation, not an echo. *"The attacker exploits CVE-2010-1635, which allows remote attackers to crash the smbd process by sending crafted protocol requests…"*
  - **Determinism:** as in §10, identical outputs across repeats for 3 of 5 inputs; the CVE batches varied in wording only.
  - **Memory:** 365 MB anonymous plus 1,064 MB of mapped model file, so a device needs about 1.5 GB free for the model alone.
- **Llama 3.2 3B is uneven.** Every plan and every guide was valid. Every CVE request failed the same way: a complete, valid JSON object followed by more text (`Extra data`), which a strict parser rejects. That is a format problem, which a forced JSON schema (§9) would remove, not a knowledge problem.
- **Qwen3 4B could not be measured on this machine.** Its 2.5 GB file did not fit in the ~2 GB of free memory, so llama.cpp re-read model pages from disk while generating, at **0.5 tokens/s**. 14 of 15 requests ran into the 600 s request timeout before answering. Its 1/15 is a **memory result, not a quality result**: it needs a machine with more RAM.
- **Speeds here are lower bounds.** Llama 3.2 3B (2.0 GB file) was also partly squeezed: on the Samba guide its output speed varied from 3.4 to 12.5 tok/s across the three repeats. Qwen3 1.7B fitted in memory and is the only one of the three whose speeds are clean.

### 11.3 Quality: better, but still not right

The same Samba guide (§6). The correct action on a consumer router is a **firmware update**.

**Qwen3 1.7B:**

> *how_it_blocks:* "Upgrading Samba from 3.0.37 to 4.19.2 or later removes the affected CVEs…"
> 1. "Log in to the Linksys WRT3200ACM web interface at http://192.168.1.1."
> 2. "Navigate to the 'System' or 'Settings' section."
> 3. "Look for an option to update or upgrade the Samba version."
> 4. "Follow the prompts to upgrade to Samba 4.19.2 or later."
> 5. "After the update, verify that the Samba version is correctly set to 4.19.2."
> 6. "Restart the device to apply the changes."

**Llama 3.2 3B:**

> 1. "Log in to the Linksys WRT3200ACM web interface at 192.168.1.1"
> 2. "Click on the 'Administration' tab" → "'Setup Wizard'" → "'Advanced Setup'" → "'Samba'" → "'Update Samba'"
> 3. "Select the latest version of Samba (4.19.2 or later) from the list" …

**Comparison:**

- **The same pattern:** both now start in the right place, the router's web page. That is a clear step up from Qwen3 0.6B ("install the updated Samba version on the device"). But both assume a Samba update option that consumer routers do not have.
- **Qwen3 1.7B hedges:** "look for an option".
- **Llama 3.2 3B invents** five menu names. That is worse, because it reads as confident.
- **The API alone** names the real action: download and flash the vendor's firmware (§6).
- **Hint in the prompt:** as in §9, a hint about the device type ("consumer router: changes come as firmware updates") is the cheapest likely fix.

### 11.4 Conclusions on model size

1. **Quality jumps between 0.6B and 1.7B.** Within the Qwen3 family, the validity score went from 9/15 to 15/15 and the plan explanation from an echo to real prose. The memory cost: about 1.4 GB peak instead of 0.7 GB.
2. **Going bigger does not automatically help.** Llama 3.2 3B scored lower than Qwen3 1.7B (9/15) and needs 2.3 GB. Model family and format discipline matter as much as size.
3. **For a Pi 3 (1 GB), Qwen3 0.6B remains the only option.** It runs the pipeline correctly, with weaker text.
4. **For a Pi 4 or Pi 5 with 2 GB or more, Qwen3 1.7B is the recommended local model.** With 2 GB it would be tight once the OS and the pipeline are counted; with 4 GB it should be comfortable. This needs to be measured on such a device.
5. **4B and 7B need more RAM than this machine has free.** Their quality is untested; measure them on an 8 GB machine before drawing conclusions.

## 12. Reproduce

```bash
bash scripts/fetch_llama.sh                         # llama.cpp b11758 → tools/
for m in qwen3-0.6b qwen2.5-0.5b gemma3-270m smollm2-360m llama3.2-1b; do bash scripts/fetch_model.sh $m; done
.venv/bin/python run.py llmbench --run 20261020T170354Z --api            # this report (§4)
.venv/bin/python run.py llmbench --run 20261020T170354Z --api --repeat 3 # §10
for m in qwen3-1.7b qwen3-4b llama3.2-3b; do bash scripts/fetch_model.sh $m; done
.venv/bin/python run.py llmbench --run 20261020T170354Z --models qwen3-1.7b,qwen3-4b,llama3.2-3b --repeat 3  # §11
```

Raw records live under `runs/20261020T170354Z/llmbench/`:
- `20261020T232054Z.json`: the single pass (§4–§6), with every output.
- `20261020T235913Z.json`: the three repeats (§10), with every output.
- `20261021T042142Z.json`: the bigger models (§11), with every output.
- `pages.json`: the cached evidence pages.
- `llm-server.log`: the server's own log.
