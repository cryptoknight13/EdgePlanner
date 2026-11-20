"""Phase 8c — which LLM every step uses: a hosted API (key in .env) or a small local model (llama.cpp).

One `llm:` block in config/settings.yaml picks the provider. Our own call sites read `settings()`;
iEXAM code (in-process and its subprocess scripts) reads the environment that `export_env()` sets.
`local_server()` runs llama-server on 127.0.0.1 only while a stage needs it, so the model's memory is
free while nmap and the planners run.
"""
import json
import os
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from contextlib import contextmanager
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent
KEY_VARS = ("NVIDIA_API_KEY", "OPENAI_API_KEY", "LLM_API_KEY")
HEALTH_TIMEOUT = 120
STOP_TIMEOUT = 10
LOG_TAIL_LINES = 20


def _path(p: str) -> str:
    return str(Path(p) if Path(p).is_absolute() else ROOT / p)


def _config() -> dict:
    with open(ROOT / "config" / "settings.yaml") as f:
        return yaml.safe_load(f).get("llm") or {}


def settings(cfg: dict | None = None) -> dict:
    """The resolved provider: base_url, model, api_key (None for local), budget and local paths."""
    cfg = _config() if cfg is None else cfg
    provider = cfg.get("provider", "api")
    if provider == "api":
        api = cfg["api"]
        return {"provider": "api",
                "base_url": os.environ.get("LLM_BASE_URL") or api["base_url"],
                "model": os.environ.get("LLM_MODEL") or api["model"], "model_key": None,
                "api_key": next((os.environ[k] for k in KEY_VARS if os.environ.get(k)), None),
                "budget": dict(api["budget"]), "no_think": False}
    if provider != "local":
        raise ValueError(f"llm.provider must be api or local, not {provider!r}")
    local, key = cfg["local"], cfg["local"]["model"]
    if key not in cfg.get("models", {}):
        raise ValueError(f"llm.local.model {key!r} is not listed under llm.models")
    m = cfg["models"][key]
    # The local server ignores LLM_BASE_URL on purpose: a leftover hosted URL must never receive scan data.
    return {"provider": "local", "base_url": f"http://127.0.0.1:{local['port']}/v1", "model": key, "model_key": key,
            "api_key": None, "budget": dict(local["budget"]), "no_think": bool(m.get("no_think")),
            "server": _path(local["server"]), "model_file": _path(m["file"]),
            "port": local["port"], "threads": local.get("threads", 4),
            "server_args": [str(a) for a in local.get("server_args", [])]}


def configured(s: dict | None = None) -> bool:
    s = settings() if s is None else s
    if s["provider"] == "api":
        return bool(s["api_key"])
    return Path(s["server"]).is_file() and Path(s["model_file"]).is_file()


def not_configured_hint(s: dict) -> str:
    if s["provider"] == "api":
        return "Set NVIDIA_API_KEY (or OPENAI_API_KEY) in .env, then retry."
    return f"Local LLM not installed: run scripts/fetch_llama.sh and scripts/fetch_model.sh {s['model_key']}."


def extra_body(s: dict) -> dict:
    """Provider-specific request fields: NVIDIA's reasoning bound, or thinking off for local models that have it."""
    if s["provider"] == "api":
        return {"reasoning_effort": "low"}
    return {"chat_template_kwargs": {"enable_thinking": False}} if s["no_think"] else {}


def export_env(s: dict) -> None:
    """Hand the provider to iEXAM code, which reads the environment (subprocesses inherit it).

    api leaves iEXAM's own output limits and request fields untouched, so it behaves exactly as before.
    """
    os.environ["LLM_PROVIDER"] = s["provider"]
    os.environ["LLM_BASE_URL"] = s["base_url"]
    os.environ["LLM_MODEL"] = s["model"]
    if s["provider"] == "local":
        os.environ["LLM_MAX_TOKENS"] = str(s["budget"]["max_tokens"])
        os.environ["LLM_EXTRA_BODY"] = json.dumps(extra_body(s))
        os.environ["LLM_API_KEY"] = "local"  # iEXAM sends this, never the real key, when LLM_PROVIDER is local
        return
    os.environ.pop("LLM_MAX_TOKENS", None)
    os.environ.pop("LLM_EXTRA_BODY", None)
    if os.environ.get("LLM_API_KEY") == "local":
        del os.environ["LLM_API_KEY"]


def exit_on_sigterm() -> None:
    """SIGTERM as a normal exit, so local_server's cleanup runs and no llama-server is left holding memory."""
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))


def _tail(path: Path) -> str:
    try:
        return "\n".join(path.read_text(errors="replace").splitlines()[-LOG_TAIL_LINES:])
    except OSError:
        return ""


def _healthy(port: int) -> bool:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=1) as r:
            return r.status == 200
    except (OSError, urllib.error.URLError):
        return False


def _stop(proc: subprocess.Popen) -> None:
    proc.terminate()
    try:
        proc.wait(STOP_TIMEOUT)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


@contextmanager
def local_server(s: dict, log_path: Path, command: list[str] | None = None):
    """Run llama-server for the duration of the block (no-op for the api provider); always stopped on exit."""
    if s["provider"] != "local":
        yield {}
        return
    cmd = command or [s["server"], "-m", s["model_file"], "--host", "127.0.0.1", "--port", str(s["port"]),
                      "-c", str(s["budget"]["context"]), "-t", str(s["threads"]), *s["server_args"]]
    # A server already on the port (a leftover llama-server, or anything else) must never pass for ours.
    with socket.socket() as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # still fails while anything listens there
        try:
            probe.bind(("127.0.0.1", s["port"]))
        except OSError:
            raise RuntimeError(f"port {s['port']} is in use (perhaps a llama-server left running): "
                               "stop that process or change llm.local.port") from None
    log_path.parent.mkdir(parents=True, exist_ok=True)
    start = time.monotonic()
    with open(log_path, "ab") as log:
        proc = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
    try:
        # Health only counts while our process lives: a stranger on the port must not pass for our model.
        while not _healthy(s["port"]) or proc.poll() is not None:
            if proc.poll() is not None:
                raise RuntimeError(f"llama-server exited ({proc.returncode}):\n{_tail(log_path)}")
            if time.monotonic() - start > HEALTH_TIMEOUT:
                raise RuntimeError(f"llama-server not ready after {HEALTH_TIMEOUT}s:\n{_tail(log_path)}")
            time.sleep(0.5)
        yield {"pid": proc.pid, "load_seconds": round(time.monotonic() - start, 2)}
    finally:
        _stop(proc)


def memory_mb(pid: int) -> dict:
    """Memory of a running process in MB: peak resident (VmHWM), anonymous now, file-backed now (the mapped model).

    File-backed pages can be dropped under pressure; anonymous ones cannot, so `anon` is what a small device must fit.
    """
    names = {"VmHWM": "peak", "RssAnon": "anon", "RssFile": "file"}
    try:
        lines = Path(f"/proc/{pid}/status").read_text().splitlines()
    except OSError:
        return {}
    return {names[k]: round(int(v.split()[0]) / 1024, 1) for k, _, v in (l.partition(":") for l in lines) if k in names}
