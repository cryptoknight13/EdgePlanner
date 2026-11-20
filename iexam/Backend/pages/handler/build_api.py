import json
import os
import time
from openai import OpenAI

LLM_MAX_RETRIES = 3
LLM_RETRY_BACKOFF_SECONDS = 2.0

# Same fallback chain as api/services/acg/llm_service.py:_resolve_credentials.
# NVIDIA_API_KEY wins for backward compat; OPENAI_API_KEY and LLM_API_KEY are
# accepted so a single .env entry works for both the FastAPI service and the
# Backend metric pipelines invoked as subprocesses.
DEFAULT_BASE_URL = "https://integrate.api.nvidia.com/v1"
DEFAULT_EXPLANATION_MODEL = "nvidia/nemotron-3-ultra-550b-a55b"
DEFAULT_OPTIONS_MODEL = "nvidia/nemotron-3-ultra-550b-a55b"


def _resolve_api_key() -> str:
    # EdgePlanner phase 8c: the real key never goes to the local model's server.
    key = "local" if os.environ.get("LLM_PROVIDER") == "local" else (
        os.environ.get("NVIDIA_API_KEY")
        or os.environ.get("OPENAI_API_KEY")
        or os.environ.get("LLM_API_KEY")
    )
    if not key:
        raise RuntimeError(
            "No LLM API key found. Set NVIDIA_API_KEY (or OPENAI_API_KEY / "
            "LLM_API_KEY) in the environment before invoking the metric "
            "pipelines."
        )
    return key


def _resolve_base_url() -> str:
    return os.environ.get("LLM_BASE_URL", DEFAULT_BASE_URL)


def _build_client() -> OpenAI:
    return OpenAI(base_url=_resolve_base_url(), api_key=_resolve_api_key())


def _stream_completion(client, **kwargs):
    """Stream a chat completion with retries on transient connection drops.

    NVIDIA's streaming endpoint occasionally closes the connection mid-response
    ("peer closed connection without sending complete message body"). Treat
    that — and any empty response — as transient and retry a few times.

    Only `delta.content` is returned. `delta.reasoning_content` (raw chain-of-
    thought from Nemotron reasoning models) is intentionally ignored — it
    contains the model's internal scratchpad ("Let's count words…", "Actually
    the precondition is…") and is never appropriate to show users. If
    reasoning is enabled and the model emits no final content, that's a real
    error and surfaces here so the caller can disable thinking or shorten the
    prompt.
    """
    last_err = None
    for attempt in range(1, LLM_MAX_RETRIES + 1):
        try:
            completion = client.chat.completions.create(**kwargs)
            content_parts: list[str] = []
            for chunk in completion:
                if not chunk.choices:
                    continue
                delta = chunk.choices[0].delta
                if delta.content:
                    content_parts.append(delta.content)
            content_text = "".join(content_parts).strip()
            if content_text:
                return content_text
            last_err = RuntimeError("empty stream response")
        except Exception as exc:
            last_err = exc
        if attempt < LLM_MAX_RETRIES:
            time.sleep(LLM_RETRY_BACKOFF_SECONDS * attempt)
    raise last_err if last_err else RuntimeError("LLM stream failed")


def read_message_from_file(file_path):
    with open(file_path, 'r') as file:
        return file.read().strip()


def process_explanation_file(file_path):
    """Generate an explanation for a single 'explanation*' input file.

    Failures are re-raised so the caller's subprocess returns non-zero and the
    UI surfaces the error instead of writing an empty all_explanations.txt.
    """
    if not (os.path.isfile(file_path)
            and os.path.basename(file_path).startswith("explanation")):
        raise FileNotFoundError(
            f"Expected an 'explanation*' file: {file_path}"
        )
    message_content = read_message_from_file(file_path)
    if not message_content:
        raise ValueError(f"File {file_path} is empty.")

    client = _build_client()
    model = os.environ.get("LLM_MODEL", DEFAULT_EXPLANATION_MODEL)
    return _stream_completion(
        client,
        model=model,
        messages=[{"role": "user", "content": message_content}],
        temperature=0.6,
        top_p=0.95,
        max_tokens=int(os.environ.get("LLM_MAX_TOKENS") or 4096),
        frequency_penalty=0,
        presence_penalty=0,
        stream=True,
        # EdgePlanner phase 8c: llmconf.export_env() sets LLM_EXTRA_BODY for the chosen provider.
        extra_body=json.loads(os.environ["LLM_EXTRA_BODY"]) if os.environ.get("LLM_EXTRA_BODY") else {
            "reasoning_effort": "low",
            "chat_template_kwargs": {"enable_thinking": False},
        },
    )


def process_options_file(file_path):
    """Generate option labels for a single 'options*' input file."""
    if not (os.path.isfile(file_path)
            and os.path.basename(file_path).startswith("options")):
        raise FileNotFoundError(
            f"Expected an 'options*' file: {file_path}"
        )
    message_content = read_message_from_file(file_path)
    if not message_content:
        raise ValueError(f"File {file_path} is empty.")

    client = _build_client()
    # Options model is intentionally separate from the explanation model — a
    # smaller / faster model is enough for short labels. LLM_OPTIONS_MODEL
    # overrides; LLM_MODEL is intentionally NOT used here so changing the
    # explanation model doesn't accidentally switch the options model too.
    model = os.environ.get("LLM_OPTIONS_MODEL", DEFAULT_OPTIONS_MODEL)
    return _stream_completion(
        client,
        model=model,
        messages=[{"role": "user", "content": message_content}],
        temperature=0.5,
        top_p=0.95,
        max_tokens=1024,
        stream=True,
        extra_body={
            "reasoning_effort": "low",
            "chat_template_kwargs": {"enable_thinking": False},
        },
    )
