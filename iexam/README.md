# i-EXAM Toolset

Network security analysis using AI planning (PDDL + Fast Downward / ForbidIterative) and an LLM (OpenAI-compatible) for natural-language explanations of attack plans and recovery metrics.

The app has two parts:

- **`api/`** — FastAPI service (port 8000) that drives PDDL generation, planners, and LLM explanation calls.
- **`web/`** — Vite + React SPA (port 5173 in dev) that consumes the API.

The original codebase under `Backend/` contains the planner scripts that `api/` shells out to.

### Planners are not stored in this repo

Three third-party planners are needed. `scripts/fetch_planners.sh` fetches
them into `Backend/` at the exact commits this project is tested with (the
directories are gitignored):

| Directory | Upstream | Commit |
| --------- | -------- | ------ |
| `Backend/downward` | [aibasel/downward](https://github.com/aibasel/downward) | `1ad981d8a` |
| `Backend/forbiditerative` | [IBM/forbiditerative](https://github.com/IBM/forbiditerative) | `67d2e84bc` |
| `Backend/VAL` | [KCL-Planning/VAL](https://github.com/KCL-Planning/VAL) | `3c7a1f330` |

---

## Quick start (local dev)

### 1. System prerequisites

| Tool | Purpose |
| ---- | ------- |
| Python 3.12+ | API + planner scripts |
| Node.js 20+ and npm | Web build |
| C++ toolchain (`g++`, `cmake`, `make`) | Build Fast Downward / ForbidIterative / VAL |
| `git` | Fetch the planner sources |
| `lsof` | `start.sh` uses it to free ports |

macOS:
```bash
brew install python@3.12 node cmake
xcode-select --install   # provides clang/g++/make
```

Debian/Ubuntu:
```bash
sudo apt update
sudo apt install -y python3.12 python3.12-venv python3-pip nodejs npm \
                    build-essential cmake g++ make lsof ca-certificates
```

### 2. Install Python + web deps

```bash
./install-dependencies.sh
```

This creates the `.iEXAM/` virtualenv, runs `pip install -r requirements.txt`, and runs `npm install` inside `web/`.

### 3. Fetch and build the planners (one-time)

```bash
./scripts/fetch_planners.sh --build
```

This clones Fast Downward, ForbidIterative and VAL at the pinned commits into
`Backend/`, then compiles them for your machine (~5-10 min). To re-fetch,
delete the directory and run the script again.

### 4. Configure environment

Create `.env` at the repo root:

```env
NVIDIA_API_KEY=nvapi-...
# Optional overrides (defaults shown):
# LLM_BASE_URL=https://integrate.api.nvidia.com/v1
# LLM_MODEL=nvidia/nemotron-3-ultra-550b-a55b
```

`cp .env.example .env` gives you a starting file. Any OpenAI-compatible
endpoint works: set `LLM_BASE_URL`, `LLM_MODEL` and `OPENAI_API_KEY` instead.

### 5. Run

```bash
./start.sh
```

`start.sh` will:

1. Activate `.iEXAM/`.
2. Load `.env` so `uvicorn` inherits it.
3. Free ports 8000 and 5173 if stale processes hold them.
4. Wipe stale workspace state (uploaded slot files, generated PDDL, cached plan results) so the sidebar starts locked and you go through `Start → Plan → Metric 1` in order.
5. Start `api/` on `http://127.0.0.1:8000` and `web/` (Vite dev server) on `http://127.0.0.1:5173`.

Open `http://localhost:5173`.

---

## Required input data

Upload these 4 JSON files (or load a built-in example) on the Start page:

- `node-data.json` — network nodes
- `connectivity-edge.json` — edges between nodes
- `cve-data.json` — CVE vulnerability data
- `cve-in-node.json` — CVE-to-node mapping

Sample datasets live in `input_data/`.

---

## Python dependencies (`requirements.txt`)

| Package | Why |
| ------- | --- |
| `fastapi`, `uvicorn[standard]`, `pydantic` | HTTP service |
| `python-multipart` | File uploads |
| `aiofiles`, `watchfiles` | Async I/O + SSE for graph reload |
| `openai` | LLM client (OpenAI-compatible; also drives NVIDIA Build endpoint) |
| `forbiditerative` | Top-K plan driver |
| `pandas` | Data wrangling in `Backend/pages` pipelines |
| `pytest`, `httpx` | Tests (`pytest api/tests/`) |

Versions are pinned. Update them with care — `forbiditerative` and `openai` both have breaking API surfaces.

---

## Frontend dependencies

Managed by `web/package.json`. Install with `npm install` from `web/`. The dev server proxies `/api/*` to `http://127.0.0.1:8000` (see `web/vite.config.ts`), so no CORS config is needed in dev.

---

## Running tests

```bash
source .iEXAM/bin/activate
pytest api/tests/
```

---

## Project layout

```
iEXAM-Toolset/
├── api/                       # FastAPI service
│   ├── main.py                # app factory + router wiring
│   ├── core/                  # config, errors, logging
│   ├── routes/acg/            # /api/acg/* endpoints
│   ├── services/acg/          # business logic (dataset, pddl, plan, metric1/2, llm)
│   └── tests/                 # pytest suite
├── web/                       # Vite + React SPA
│   └── src/modes/acg/         # ACG-mode pages and components
├── Backend/
│   ├── pages/                 # PDDL generation + planner orchestration scripts
│   ├── downward/              # Fast Downward (fetched by scripts/fetch_planners.sh)
│   ├── forbiditerative/       # ForbidIterative (fetched)
│   ├── VAL/                   # VAL plan validator (fetched)
│   └── pddl/                  # Generated PDDL files (cleared by start.sh)
├── input_data/                # Sample networks
├── scripts/fetch_planners.sh  # Fetch (and optionally build) the planners
├── Logs/log.txt               # All backend logging
├── start.sh                   # Dev launcher (kills ports, wipes state, starts api + web)
├── install-dependencies.sh    # One-time setup
└── requirements.txt
```

---

## Docker / docker-compose

A two-service compose stack is provided:

| Service | Image | Port | What it does |
| ------- | ----- | ---- | ------------ |
| `api`   | `Dockerfile` (this repo)           | `8000` | FastAPI + planners. Rebuilds Fast Downward and ForbidIterative for Linux during image build (the macOS binaries shipped in the repo won't run in a Linux container). |
| `web`   | `web/Dockerfile` (multi-stage)     | `8080` | nginx serving the built Vite SPA, proxying `/api/*` to `api:8000` with SSE-safe buffering. |

### Run

```bash
./scripts/fetch_planners.sh     # planner sources (no --build: the image compiles them)
cp .env.example .env            # then set NVIDIA_API_KEY

docker compose up --build
# open http://localhost:8080
```

First build takes several minutes because the planners are compiled from source inside the `planner-builder` stage. The build fails with `COPY Backend/downward: not found` if you skipped `fetch_planners.sh`. Subsequent builds reuse that layer.

> **Docker Desktop memory.** The `planner-builder` stage installs a C++ toolchain and compiles Fast Downward + ForbidIterative. Default Docker Desktop memory (2 GB) will OOM with `failed to solve: ResourceExhausted ... cannot allocate memory`. Raise it to **≥ 6 GB** in Docker Desktop → Settings → Resources → Memory before running `docker compose up --build`.

### Data persistence

By default the `api` container wipes uploaded slot files, generated PDDL, and cached plan results on every start (matches `./start.sh` behaviour) so the sidebar boots locked. To keep uploads across restarts, mount named volumes on those paths in `docker-compose.yml`:

```yaml
volumes:
  - iexam_data:/app/Backend/pages/data
  - iexam_pddl:/app/Backend/pddl
  - iexam_plan:/app/Backend/pages/_build_plan/results
```
and remove the matching `rm` lines from `docker/entrypoint.sh`.

### Hitting the api directly

The api is published on `8000:8000` for debugging — `curl http://localhost:8000/api/health` works without going through nginx. CORS is hardcoded in `api/main.py:26` to `http://localhost:5173` (dev Vite). In the compose flow all browser traffic comes via nginx on `8080`, so requests are same-origin and CORS doesn't fire.

---

## Troubleshooting

- **Sidebar stays unlocked across pages.** `./start.sh` must wipe `Backend/pages/data/*`, `Backend/pddl/*`, and `Backend/pages/_build_plan/results/`. If you started the server manually with `uvicorn`, run those `rm` lines yourself or use `start.sh`.
- **`./start.sh` says ERROR: virtualenv .iEXAM not found.** Run `./install-dependencies.sh` first.
- **`forbiditerative` planner errors.** Check that `Backend/forbiditerative/builds/release/bin/downward` exists and is executable on your platform. Rebuild it with `./scripts/fetch_planners.sh --build` (delete `Backend/forbiditerative` first to re-fetch).
- **LLM call fails with `LLMNotConfigured`.** No API key in environment. Set `OPENAI_API_KEY` (or `NVIDIA_API_KEY` + `LLM_BASE_URL` + `LLM_MODEL`) in `.env` and restart.
- **Port 8000 or 5173 busy.** `start.sh` already kills holders; if it warns "port still busy", find and kill the PID manually: `lsof -ti :8000 | xargs kill -9`.

---

## Hugging Face Space

The public demo (<https://huggingface.co/spaces/CryptoKnight007/i-EXAM>) runs
a single-container variant of this app (FastAPI serving the built SPA on port
7860). Its source and deploy instructions live in
[cryptoknight13/iEXAM-Toolset-hf](https://github.com/cryptoknight13/iEXAM-Toolset-hf).
