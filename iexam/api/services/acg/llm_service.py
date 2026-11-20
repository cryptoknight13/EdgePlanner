"""LLM-backed plan explanation via NVIDIA NIM (OpenAI-compatible endpoint).

Defaults to `nvidia/nemotron-3-ultra-550b-a55b` and streams with reasoning enabled;
both the reasoning trace and the final assistant text are persisted to disk so
repeat fetches don't re-bill the API.
"""
from __future__ import annotations

import json
import logging
import os
import re
import time

from api.core.errors import ApiException, InputValidationError, NotFoundError
from api.services.acg import dataset_service, plan_service
from api.services.acg.pddl_service import curate

logger = logging.getLogger(__name__)

# Upstream LLM may drop the streaming connection mid-response (chunked
# transfer cut off, network blip, model timeout). Retry the whole request
# this many times before surfacing an error to the client.
MAX_STREAM_RETRIES = 2
RETRY_BACKOFF_SECONDS = 1.5


class LLMUpstreamError(ApiException):
    """LLM provider closed the connection or returned a transport error."""

    status_code = 502
    code = "llm_upstream_error"

EXPLANATION_FILE = plan_service.EXPLANATION_FILE

DEFAULT_BASE_URL = "https://integrate.api.nvidia.com/v1"
DEFAULT_MODEL = "nvidia/nemotron-3-ultra-550b-a55b"
MAX_OUTPUT_TOKENS = 16384
# EdgePlanner phase 8c: llmconf.export_env() sets these for the chosen provider (api or local model).
DEFAULT_EXTRA_BODY = {
    # reasoning_effort (low/medium/max) bounds thinking time;
    # "low" keeps a plan explanation to ~1 min instead of 3+.
    "reasoning_effort": "low",
}


def _max_tokens() -> int:
    return int(os.environ.get("LLM_MAX_TOKENS") or MAX_OUTPUT_TOKENS)


def _extra_body() -> dict:
    raw = os.environ.get("LLM_EXTRA_BODY")
    return json.loads(raw) if raw else dict(DEFAULT_EXTRA_BODY)


def _strip_think(text: str) -> str:
    """Small local models can emit a <think> block even with thinking off."""
    return re.sub(r"<think>.*?</think>", "", text, flags=re.S).strip()


class LLMNotConfigured(InputValidationError):
    """API key missing — surfaced to the UI."""

    def __init__(self) -> None:
        super().__init__(
            "LLM API key is not configured on the server",
            details={
                "hint": (
                    "Set NVIDIA_API_KEY (or OPENAI_API_KEY) in .env, then "
                    "restart start.sh and retry."
                ),
            },
        )


def _resolve_credentials() -> tuple[str, str, str]:
    base_url = os.environ.get("LLM_BASE_URL", DEFAULT_BASE_URL)
    model = os.environ.get("LLM_MODEL", DEFAULT_MODEL)
    # EdgePlanner phase 8c: the real key never goes to the local model's server.
    api_key = "local" if os.environ.get("LLM_PROVIDER") == "local" else (
        os.environ.get("NVIDIA_API_KEY")
        or os.environ.get("OPENAI_API_KEY")
        or os.environ.get("LLM_API_KEY")
    )
    if not api_key:
        raise LLMNotConfigured()
    return base_url, model, api_key


def _build_prompt(plan: dict) -> str:
    nodes = dataset_service.read_slot("nodes") or {}
    cves = dataset_service.read_slot("cves") or {}

    # Curated summaries: PDDL object names in the plan steps are the node
    # tokens (e.g. "john-n3"), so tell the model which token is which node.
    tokens = curate.node_tokens(nodes)
    node_lines = [
        f"  - [{tokens[nid]}] {curate.llm_node_summary(nid, a)}"
        for nid, a in nodes.items()
    ]
    used_cves = plan.get("highlights", {}).get("cve_ids", [])
    cve_lines = [f"  - {curate.llm_cve_summary(cid, cves.get(cid, {}))}" for cid in used_cves]

    return (
        "You are a network security analyst. For each plan step below, write "
        "a short paragraph (2-4 sentences) in plain English explaining the "
        "action. Cover: the source node and target node (with their roles or "
        "locations), the CVE exploited (with its vulnerability/capability and "
        "CVSS), what the attacker gains from this step, and how it sets up the "
        "next step. Output ONLY the numbered list of per-action explanations. "
        "Do NOT include a goal summary, an introduction, an overall-risk "
        "paragraph, mitigations, conclusions, or any other commentary.\n\n"
        "Network nodes:\n" + "\n".join(node_lines) + "\n\n"
        "CVEs referenced:\n" + ("\n".join(cve_lines) or "  (none)") + "\n\n"
        "Plan steps (PDDL grounded actions):\n"
        + "\n".join(f"  {i + 1}. {s}" for i, s in enumerate(plan.get("steps", [])))
    )


def _stream_once(client, model: str, prompt: str) -> tuple[str, str]:
    """One streaming attempt. Raises on transport / API errors."""
    completion = client.chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": prompt}],
        temperature=0.2,
        top_p=0.95,
        max_tokens=_max_tokens(),
        extra_body=_extra_body(),
        stream=True,
    )
    text_parts: list[str] = []
    reasoning_parts: list[str] = []
    for chunk in completion:
        if not chunk.choices:
            continue
        delta = chunk.choices[0].delta
        reasoning = getattr(delta, "reasoning_content", None)
        if reasoning:
            reasoning_parts.append(reasoning)
        if delta.content:
            text_parts.append(delta.content)
    return _strip_think("".join(text_parts)), "".join(reasoning_parts).strip()


def _is_transient_stream_error(exc: BaseException) -> bool:
    """True for upstream connection drops / timeouts worth retrying."""
    # Late import: httpx is an openai dependency so always present.
    import httpx

    if isinstance(exc, (httpx.RemoteProtocolError, httpx.ReadTimeout,
                        httpx.ConnectTimeout, httpx.ReadError,
                        httpx.WriteError, httpx.ConnectError,
                        httpx.PoolTimeout)):
        return True
    # openai wraps some of these; check for "incomplete chunked read" and
    # APIConnectionError as a broad fallback.
    try:
        from openai import APIConnectionError, APITimeoutError  # type: ignore
        if isinstance(exc, (APIConnectionError, APITimeoutError)):
            return True
    except ImportError:
        pass
    return "incomplete chunked read" in str(exc).lower()


def _stream_completion(client, model: str, prompt: str) -> tuple[str, str]:
    """Stream a chat completion with retry on upstream transport drops.

    Returns (final_text, reasoning_trace). Raises LLMUpstreamError after
    `MAX_STREAM_RETRIES` consecutive transient failures.
    """
    last_exc: BaseException | None = None
    for attempt in range(MAX_STREAM_RETRIES + 1):
        try:
            return _stream_once(client, model, prompt)
        except Exception as exc:  # noqa: BLE001 — surface or retry below
            if not _is_transient_stream_error(exc):
                raise LLMUpstreamError(
                    f"LLM provider error ({model}): {exc}",
                    details={"cause": exc.__class__.__name__},
                ) from exc
            last_exc = exc
            logger.warning(
                "LLM stream attempt %d/%d failed (%s); retrying in %.1fs",
                attempt + 1,
                MAX_STREAM_RETRIES + 1,
                exc.__class__.__name__,
                RETRY_BACKOFF_SECONDS,
            )
            if attempt < MAX_STREAM_RETRIES:
                time.sleep(RETRY_BACKOFF_SECONDS * (attempt + 1))
    raise LLMUpstreamError(
        "LLM provider closed the connection before the response finished. "
        "This is usually transient — try again.",
        details={"cause": last_exc.__class__.__name__ if last_exc else None,
                 "message": str(last_exc) if last_exc else None},
    ) from last_exc


def generate_explanation(force: bool = False) -> dict:
    plan = plan_service.get_last_plan()
    if plan is None:
        raise NotFoundError("Run the planner first")

    if not force and EXPLANATION_FILE.exists():
        try:
            payload = json.loads(EXPLANATION_FILE.read_text(encoding="utf-8"))
            if payload.get("goal") == plan.get("goal") and payload.get("text"):
                return {
                    "text": payload["text"],
                    "model": payload.get("model"),
                    "cached": True,
                }
        except (json.JSONDecodeError, OSError):
            pass

    base_url, model, api_key = _resolve_credentials()

    try:
        from openai import OpenAI  # type: ignore
    except ImportError as exc:
        raise InputValidationError("openai package not installed") from exc

    client = OpenAI(base_url=base_url, api_key=api_key)
    prompt = _build_prompt(plan)
    text, reasoning = _stream_completion(client, model, prompt)
    if not text:
        raise InputValidationError("LLM returned an empty response")

    EXPLANATION_FILE.parent.mkdir(parents=True, exist_ok=True)
    EXPLANATION_FILE.write_text(
        json.dumps(
            {
                "goal": plan.get("goal"),
                "model": model,
                "text": text,
                "reasoning": reasoning,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return {"text": text, "model": model, "cached": False}


def get_cached_explanation() -> dict | None:
    plan = plan_service.get_last_plan()
    if plan is None or not EXPLANATION_FILE.exists():
        return None
    try:
        payload = json.loads(EXPLANATION_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    if payload.get("goal") != plan.get("goal") or not payload.get("text"):
        return None
    return {"text": payload["text"], "model": payload.get("model"), "cached": True}


def _topk_cache_path(index: int):
    from api.services.acg import topk_service
    return topk_service.EXPLANATIONS_DIR / f"plan_{index}.json"


def _resolve_topk_plan(index: int) -> dict:
    from api.services.acg import topk_service
    topk = topk_service.get_last_topk()
    if topk is None:
        raise NotFoundError("Run Top-K first")
    plans = topk.get("plans") or []
    if index < 0 or index >= len(plans):
        raise NotFoundError(
            f"Plan index {index} out of range", details={"k_returned": len(plans)}
        )
    plan = dict(plans[index])
    # _build_prompt expects top-level goal/cost/step_count/steps/highlights.cve_ids.
    plan.setdefault("goal", topk.get("goal"))
    return plan


def generate_topk_explanation(index: int, force: bool = False) -> dict:
    plan = _resolve_topk_plan(index)
    cache_path = _topk_cache_path(index)

    if not force and cache_path.exists():
        try:
            payload = json.loads(cache_path.read_text(encoding="utf-8"))
            if payload.get("goal") == plan.get("goal") and payload.get("text"):
                return {
                    "text": payload["text"],
                    "model": payload.get("model"),
                    "cached": True,
                }
        except (json.JSONDecodeError, OSError):
            pass

    base_url, model, api_key = _resolve_credentials()

    try:
        from openai import OpenAI  # type: ignore
    except ImportError as exc:
        raise InputValidationError("openai package not installed") from exc

    client = OpenAI(base_url=base_url, api_key=api_key)
    prompt = _build_prompt(plan)
    text, reasoning = _stream_completion(client, model, prompt)
    if not text:
        raise InputValidationError("LLM returned an empty response")

    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(
        json.dumps(
            {
                "goal": plan.get("goal"),
                "index": index,
                "model": model,
                "text": text,
                "reasoning": reasoning,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return {"text": text, "model": model, "cached": False}


def get_cached_topk_explanation(index: int) -> dict | None:
    try:
        plan = _resolve_topk_plan(index)
    except NotFoundError:
        return None
    cache_path = _topk_cache_path(index)
    if not cache_path.exists():
        return None
    try:
        payload = json.loads(cache_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    if payload.get("goal") != plan.get("goal") or not payload.get("text"):
        return None
    return {"text": payload["text"], "model": payload.get("model"), "cached": True}
