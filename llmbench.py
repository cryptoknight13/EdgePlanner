"""Phase 8c — small-LLM benchmark: the pipeline's LLM tasks on several local models (and the API) with one input set.

Inputs come from one run and are built with the local budget for every model, the API included, so the
comparison is fair. Per model: load time and memory of llama-server; per task: time, token speed (from
llama-server's own timings), whether the output passes that task's own parser, and the output itself.
Written to runs/<run-id>/llmbench/<UTC stamp>.json; the API key never reaches the record.
"""
import json
import platform
import re
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

import attackplan
import llmconf
from api.services.acg import llm_service
from cveinfo import llm
from mitigate import guide

SCHEMA_VERSION = "1.0"
CVES = 4
GUIDE_ACTIONS = 2
SMALL_RAM_MB = 2048
MIN_GUIDE_STEPS = 3
MIN_PLAN_WORDS = 15


def _cached(fetch, cache_file: Path):
    cache = json.loads(cache_file.read_text()) if cache_file.exists() else {}

    def get(url: str):
        if url not in cache:
            cache[url] = list(fetch(url))
            cache_file.parent.mkdir(parents=True, exist_ok=True)
            cache_file.write_text(json.dumps(cache))
        return tuple(cache[url])
    return get


def build_inputs(run_dir: Path, budget: dict, fetch=guide.fetch) -> list[dict]:
    """The same prompts for every model: CVE batches, one plan explanation, two fix guides."""
    ci = run_dir / "cveinfo.json"
    cves = json.loads(ci.read_text())["cves"] if ci.exists() else {}
    items = [{"id": k, "cwes": v.get("cwes", []), "description": v["description"]}
             for k, v in sorted(cves.items()) if v.get("description")][:CVES]
    size = budget["cve_batch"]
    out = [{"task": "cve", "id": ",".join(i["id"] for i in b), "system": llm.SYSTEM, "prompt": llm.user_prompt(b),
            "ids": [i["id"] for i in b]} for b in (items[n:n + size] for n in range(0, len(items), size))]

    plans = run_dir / "plans" / "plans.json"
    target = next((t for t in json.loads(plans.read_text())["targets"] if t.get("optimal")), None) if plans.exists() else None
    if target:
        attackplan.load_dataset(run_dir / "iexam")  # the iEXAM prompt names nodes and CVEs from the dataset
        out.append({"task": "plan", "id": target["goal"], "system": None,
                    "prompt": llm_service._build_prompt(target["optimal"])})

    mit = run_dir / "mitigation" / "mitigation.json"
    goal = next((t for t in json.loads(mit.read_text())["targets"] if not t.get("unreachable") and t.get("options")),
                None) if mit.exists() else None
    if goal:
        nodes = json.loads((run_dir / "iexam" / "node-data.json").read_text())
        get = _cached(fetch, run_dir / "llmbench" / "pages.json")
        for key, a in list(guide.unique_actions(goal).items())[:GUIDE_ACTIONS]:
            _, pages = guide._sources(a, get, budget)
            out.append({"task": "guide", "id": key, "system": guide.SYSTEM,
                        "prompt": guide.build_prompt(a, nodes.get(a["node"], {}), cves, pages),
                        "allowed": [u for u, _ in pages]})
    return out


def score(task: str, text: str, inp: dict) -> bool:
    """Valid = the output passes the parser the pipeline itself uses for that task."""
    try:
        if task == "cve":
            got = llm.parse(text)
            return all(i in got for i in inp["ids"])
        if task == "guide":
            return len(guide.parse_guide(text, set(inp["allowed"]))["steps"]) >= MIN_GUIDE_STEPS
        # A plan explanation that only repeats the PDDL steps explains nothing: count the words outside them.
        prose = re.sub(r"\([^)]*\)", " ", llm_service._strip_think(text))
        return len(re.findall(r"[A-Za-z]{2,}", prose)) >= MIN_PLAN_WORDS
    except (ValueError, KeyError, TypeError):
        return False


def _chat(s: dict, inp: dict) -> tuple[str, dict]:
    msgs = ([{"role": "system", "content": inp["system"]}] if inp["system"] else []) + \
           [{"role": "user", "content": inp["prompt"]}]
    headers = {"Authorization": f"Bearer {s['api_key']}"} if s["api_key"] else {}
    resp = requests.post(f"{s['base_url'].rstrip('/')}/chat/completions", headers=headers, timeout=s["budget"]["timeout"],
                         json={"model": s["model"], "temperature": 0, "max_tokens": s["budget"]["max_tokens"],
                               "messages": msgs, **llmconf.extra_body(s)})
    resp.raise_for_status()
    data = resp.json()
    return data["choices"][0]["message"]["content"] or "", data


def _row(s: dict, inp: dict) -> dict:
    t = time.monotonic()
    row = {"task": inp["task"], "id": inp["id"]}
    try:
        text, data = _chat(s, inp)
    except (requests.RequestException, ValueError, KeyError) as exc:
        return {**row, "wall_seconds": round(time.monotonic() - t, 2), "valid": False, "error": str(exc)}
    tm, usage = (data.get("timings") or {}) if s["provider"] == "local" else {}, data.get("usage") or {}
    return {**row, "wall_seconds": round(time.monotonic() - t, 2),
            "prompt_tokens": tm.get("prompt_n", usage.get("prompt_tokens")), "prompt_tps": tm.get("prompt_per_second"),
            "output_tokens": tm.get("predicted_n", usage.get("completion_tokens")),
            "output_tps": tm.get("predicted_per_second"), "valid": score(inp["task"], text, inp), "output": text}


def bench_model(s: dict, inputs: list[dict], log_path: Path, repeat: int, command: list[str] | None = None) -> dict:
    out = {"model": s["model"], "provider": s["provider"], "status": "ok", "load_seconds": None, "memory_mb": {},
           "results": []}
    try:
        with llmconf.local_server(s, log_path, command=command) as info:
            out["load_seconds"] = info.get("load_seconds")
            for _ in range(repeat):
                out["results"] += [_row(s, inp) for inp in inputs]
            if info.get("pid"):
                out["memory_mb"] = llmconf.memory_mb(info["pid"])
        errors = [r["error"] for r in out["results"] if r.get("error")]
        if out["results"] and len(errors) == len(out["results"]):  # it started, then answered nothing (died, OOM)
            out.update(status="failed", error=errors[0])
    except (RuntimeError, OSError) as exc:  # would not start, or died (out of memory): next model
        out.update(status="failed", error=str(exc)[-2000:])
    return out


def _host(server: str) -> dict:
    meminfo = Path("/proc/meminfo").read_text()
    ram = int(next(l.split()[1] for l in meminfo.splitlines() if l.startswith("MemTotal"))) // 1024
    cpu = None
    board = Path("/proc/device-tree/model")  # e.g. "Raspberry Pi 3 Model B Rev 1.2"
    if board.exists():
        cpu = board.read_text(errors="replace").strip("\x00\n ")
    if not cpu:
        try:
            info = dict(l.split(":", 1) for l in subprocess.run(["lscpu"], capture_output=True, text=True,
                                                                  timeout=10).stdout.splitlines() if ":" in l)
            cpu = " ".join(v.strip() for k in ("Vendor ID", "Model name") if (v := info.get(k, "")).strip() not in ("", "-"))
        except OSError:
            pass
    cpu = cpu or platform.machine()
    try:
        version = subprocess.run([server, "--version"], capture_output=True, text=True, timeout=10)
        llama = next((l for l in (version.stdout + version.stderr).splitlines() if l.startswith("version")), None)
    except OSError:
        llama = None
    return {"cpu": cpu, "ram_mb": ram, "os": platform.platform(), "llama_cpp": llama}


def run(run_dir: Path, models: list[str], api: bool, repeat: int, fetch=guide.fetch, command_for=None) -> dict:
    cfg = llmconf._config()
    budget = dict(cfg["local"]["budget"])
    inputs = build_inputs(run_dir, budget, fetch)
    host = _host(llmconf._path(cfg["local"]["server"]))
    log = run_dir / "llmbench" / "llm-server.log"
    results = []
    for key in models:
        s = llmconf.settings({**cfg, "provider": "local", "local": {**cfg["local"], "model": key}})
        if cfg["models"][key].get("kali_only") and host["ram_mb"] < SMALL_RAM_MB:
            results.append({"model": key, "provider": "local", "status": "skipped",
                            "error": f"needs more than {host['ram_mb']} MB RAM"})
        elif not command_for and not llmconf.configured(s):
            results.append({"model": key, "provider": "local", "status": "failed", "error": llmconf.not_configured_hint(s)})
        else:
            results.append(bench_model(s, inputs, log, repeat, command_for(s) if command_for else None))
    if api:
        s = llmconf.settings({**cfg, "provider": "api"})  # prompts use the local budget; output limit its own
        results.append(bench_model(s, inputs, log, repeat) if llmconf.configured(s) else
                       {"model": s["model"], "provider": "api", "status": "skipped", "error": llmconf.not_configured_hint(s)})
    out = {"schema_version": SCHEMA_VERSION, "run_id": run_dir.name,
           "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "host": host, "budget": budget,
           "inputs": [{"task": i["task"], "id": i["id"], "prompt_chars": len(i["prompt"])} for i in inputs],
           "models": results}
    path = run_dir / "llmbench" / f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(out, indent=2))
    out["path"] = str(path)
    return out
