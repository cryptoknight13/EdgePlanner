"""CVE cause / consequence in plain words via an OpenAI-compatible endpoint (NVIDIA API or a local model).

Explanation only: never used for PDDL. Provider, model and batch size come from llmconf (phase 8c).
Batched, and cached per CVE + model in one JSON file.
"""
import json
import re
import time
from pathlib import Path

import requests

import llmconf

SYSTEM = (
    "You explain software vulnerabilities to a home user. For each CVE you get the id, its CWE and NVD "
    "description. Return ONLY a JSON object mapping each CVE id to {\"cause\": ..., \"consequence\": ...}. "
    "cause: the root flaw in the software, one sentence, max 25 words. "
    "consequence: what an attacker can achieve if exploited, one sentence, max 25 words. "
    "Use only the given description. Do not invent versions, products or commits."
)


def configured() -> bool:
    return llmconf.configured(llmconf.settings())


def model() -> str:
    return llmconf.settings()["model"]


def user_prompt(items: list[dict]) -> str:
    return "\n\n".join(f"{i['id']} ({', '.join(i['cwes']) or 'no CWE'}): {i['description']}" for i in items)


def _call(items: list[dict]) -> dict:
    s = llmconf.settings()
    headers = {"Authorization": f"Bearer {s['api_key']}"} if s["api_key"] else {}
    for attempt in range(4):
        resp = requests.post(f"{s['base_url'].rstrip('/')}/chat/completions", timeout=s["budget"]["timeout"],
                             headers=headers,
                             json={"model": s["model"], "temperature": 0, "max_tokens": s["budget"]["max_tokens"],
                                   "messages": [{"role": "system", "content": SYSTEM},
                                                {"role": "user", "content": user_prompt(items)}],
                                   **llmconf.extra_body(s)})
        if resp.status_code not in (429, 500, 502, 503, 504) or attempt == 3:
            break
        time.sleep(15 * 2 ** attempt)  # the hosted endpoint is intermittently overloaded
    resp.raise_for_status()
    return parse(resp.json()["choices"][0]["message"]["content"] or "")


def extract_json(text: str) -> dict:
    """Pull the JSON object out of a reply that may carry <think> blocks or code fences."""
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.S)
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end < start:
        raise ValueError("no JSON object in LLM reply")
    data = json.loads(text[start:end + 1])
    if not isinstance(data, dict):
        raise ValueError("LLM reply is not a JSON object")
    return data


def parse(text: str) -> dict:
    data = extract_json(text)
    return {k.upper(): v for k, v in data.items()
            if isinstance(v, dict) and isinstance(v.get("cause"), str) and isinstance(v.get("consequence"), str)}


def explain(items: list[dict], cache_file: Path, notes: list[str]) -> dict[str, dict]:
    """{cve_id: {cause, consequence, model}} for items [{id, cwes, description}]; cached."""
    cache = json.loads(cache_file.read_text()) if cache_file.exists() else {}
    m = model()
    todo = [i for i in items if f"{i['id']}|{m}" not in cache and i["description"]]
    size = llmconf.settings()["budget"]["cve_batch"]
    batches = [todo[n:n + size] for n in range(0, len(todo), size)]
    while batches:
        batch = batches.pop(0)
        try:
            got = _call(batch)
        except (requests.ConnectionError, requests.Timeout) as exc:
            if llmconf.settings()["provider"] == "local":
                # The local model is gone or thrashing: every further batch would wait out the full timeout.
                notes.append(f"local model stopped responding ({exc}); remaining CVEs not explained")
                break
            if len(batch) > 1:
                batches[:0] = [[i] for i in batch]
            else:
                notes.append(f"LLM failed for {batch[0]['id']}: {exc}")
            continue
        except (requests.RequestException, ValueError, KeyError) as exc:
            if len(batch) > 1:
                # One malformed reply should not cost the whole batch: retry each CVE alone.
                batches[:0] = [[i] for i in batch]
            else:
                notes.append(f"LLM failed for {batch[0]['id']}: {exc}")
            continue
        for i in batch:
            if i["id"] in got:
                cache[f"{i['id']}|{m}"] = {**got[i["id"]], "model": m}
        cache_file.parent.mkdir(parents=True, exist_ok=True)
        cache_file.write_text(json.dumps(cache, indent=1))
    return {i["id"]: cache[f"{i['id']}|{m}"] for i in items if f"{i['id']}|{m}" in cache}
