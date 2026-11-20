"""Phase 8b — fix guides: per mitigation action, how it blocks the attack, steps, and links.

The LLM reads only the evidence pages phase 8 already linked (advisories, fix commits, NVD); no search
engine, and any link it returns that we did not fetch is dropped. Request style and JSON extraction come
from cveinfo/llm.py; provider, model and sizes from llmconf (phase 8c). Guides are cached per action in
mitigation/guide.json; explanation only.
"""
import json
import re
import urllib.request
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path

import requests

import llmconf
from cveinfo import llm

SCHEMA_VERSION = "1.0"
MAX_LINKS = 8
MAX_BYTES = 200_000
MAX_TEXT = 4000
FETCH_TIMEOUT = 10
MAX_STEPS, MAX_STEP, MAX_BLOCKS = 6, 200, 400
MAX_CVES, MAX_CVE_TEXT = 8, 200
WORDS = re.compile(r"[A-Za-z]{3}")

SYSTEM = (
    "You help a home user fix one security problem on a device in their home network. You get the device, "
    "the change to make, the vulnerabilities it removes, and the text of vendor and NVD pages. Return ONLY a "
    'JSON object: {"how_it_blocks": "...", "steps": ["..."], "links": [{"title": "...", "url": "..."}]}. '
    "how_it_blocks: 1-2 plain sentences on how this change stops the attacker. "
    "steps: 3 to 6 short imperative steps the user can follow (where to click, what to download, how to check "
    "the result). links: the most useful of the given SOURCE pages, up to 4, with a short title. "
    "Use only the given facts and pages. Never invent versions, URLs or menu names; if the pages do not say "
    "where a setting is, say to look in the device's web page or the vendor's manual."
)


def action_key(a: dict) -> str:
    return f"{a['node']}|{a['fact']}|{a['token']}"


def unique_actions(target: dict) -> dict[str, dict]:
    """Every distinct action across a goal's options, first occurrence wins."""
    out: dict[str, dict] = {}
    for o in target.get("options", []):
        for a in o["actions"]:
            out.setdefault(action_key(a), a)
    return out


def links_for(a: dict) -> list[str]:
    ev = a.get("evidence", [])
    urls = ([u for e in ev for u in e.get("advisories", [])] + [u for e in ev for u in e.get("fix_commits", [])]
            + [e["nvd"] for e in ev if e.get("nvd")])
    return list(dict.fromkeys(urls))[:MAX_LINKS]


class _Text(HTMLParser):
    def __init__(self):
        super().__init__()
        self.parts: list[str] = []
        self.skip = 0

    def handle_starttag(self, tag, attrs):
        self.skip += tag in ("script", "style")

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self.skip:
            self.skip -= 1

    def handle_data(self, data):
        if not self.skip:
            self.parts.append(data)


def html_to_text(html: str) -> str:
    p = _Text()
    p.feed(html)
    return " ".join(" ".join(p.parts).split())[:MAX_TEXT]


def fetch(url: str) -> tuple[str | None, str | None]:
    """(page text, None) or (None, why not). Never raises."""
    scheme = url.split(":", 1)[0].lower()
    if scheme not in ("http", "https"):
        return None, f"scheme {scheme}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "EdgePlanner/1.0"})
        with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as resp:
            ctype = resp.headers.get_content_type()
            if not ctype.startswith("text/"):
                return None, f"content-type {ctype}"
            body = resp.read(MAX_BYTES)
            return html_to_text(body.decode(resp.headers.get_content_charset() or "utf-8", errors="replace")), None
    except (OSError, ValueError) as exc:
        return None, str(exc)


def _clip(text: str, n: int) -> str:
    """At most n characters, ending at a full sentence when one fits."""
    text = text.strip()
    if len(text) <= n:
        return text
    end = text.rfind(". ", 0, n)
    return text[:end + 1] if end > 0 else text[:n]


def parse_guide(reply: str, allowed: set[str]) -> dict:
    """Checked LLM reply; links limited to the pages we fetched. Raises ValueError on a bad shape."""
    d = llm.extract_json(reply)
    blocks, steps, links = d.get("how_it_blocks"), d.get("steps"), d.get("links", [])
    if not isinstance(blocks, str) or not WORDS.search(blocks):
        raise ValueError("how_it_blocks missing")
    if not isinstance(steps, list) or not all(isinstance(s, str) for s in steps):
        raise ValueError("steps must be a list of strings")
    steps = [s for s in steps if WORDS.search(s)]  # a small model may echo the template ("...")
    if not steps:
        raise ValueError("no usable steps")
    if not isinstance(links, list) or not all(
            isinstance(l, dict) and isinstance(l.get("title"), str) and isinstance(l.get("url"), str) for l in links):
        raise ValueError("links must be a list of {title, url}")
    return {"how_it_blocks": _clip(blocks, MAX_BLOCKS),
            "steps": [_clip(s, MAX_STEP) for s in steps[:MAX_STEPS]],
            "links": [{"title": l["title"], "url": l["url"]} for l in links if l["url"] in allowed]}


def build_prompt(a: dict, node: dict, cves: dict, pages: list[tuple[str, str]]) -> str:
    lines = [f"Device: {node.get('name')} ({node.get('IP')}), type: {node.get('label') or 'unknown'}",
             f"Change to make: {a['text']}"]
    if a.get("installed"):
        lines.append(f"Installed: {', '.join(a['installed'])}")
    if a.get("target_version"):
        lines.append(f"Fixed in: {a['target_version']}")
    if a.get("ports"):
        lines.append(f"Ports: {', '.join(map(str, a['ports']))}")
    lines.append("Vulnerabilities removed:")
    # The most severe few: a long list would not fit a small model's context, and the fix is the same.
    ev = sorted(a.get("evidence", []), key=lambda e: -((cves.get(e["cve"], {}).get("cvss") or {}).get("score") or 0))
    for e in ev[:MAX_CVES]:
        info = cves.get(e["cve"], {})
        lines.append(f"- {e['cve']} (CVSS {(info.get('cvss') or {}).get('score', '?')}): "
                     f"{info.get('description', '')[:MAX_CVE_TEXT]}")
    if len(ev) > MAX_CVES:
        lines.append(f"- and {len(ev) - MAX_CVES} more")
    lines += [f"\nSOURCE {url}:\n{text}" for url, text in pages] or ["\nNo source page could be fetched."]
    return "\n".join(lines)


def ask(prompt: str) -> str:
    """One non-streaming chat request; one retry on a transport error or an overloaded endpoint."""
    s = llmconf.settings()
    headers = {"Authorization": f"Bearer {s['api_key']}"} if s["api_key"] else {}
    for attempt in range(2):
        try:
            resp = requests.post(f"{s['base_url'].rstrip('/')}/chat/completions", timeout=s["budget"]["timeout"],
                                 headers=headers,
                                 json={"model": s["model"], "temperature": 0, "max_tokens": s["budget"]["max_tokens"],
                                       "messages": [{"role": "system", "content": SYSTEM},
                                                    {"role": "user", "content": prompt}], **llmconf.extra_body(s)})
            if resp.status_code in (429, 500, 502, 503, 504) and attempt == 0:
                continue
            resp.raise_for_status()
            return resp.json()["choices"][0]["message"]["content"] or ""
        except requests.RequestException:
            if attempt == 1:
                raise
    raise requests.RequestException("LLM endpoint unavailable")


def _load(path: Path, run_id: str, model: str) -> dict:
    if path.exists():
        return json.loads(path.read_text())
    return {"schema_version": SCHEMA_VERSION, "run_id": run_id, "model": model, "guides": {}, "notes": []}


def _sources(a: dict, fetch, budget: dict) -> tuple[list[dict], list[tuple[str, str]]]:
    """Fetch the action's evidence pages, each and all together within the provider's text budget."""
    sources, pages, room = [], [], budget["pages_total_chars"]
    for url in links_for(a):
        if room <= 0:
            sources.append({"url": url, "status": "skipped", "reason": "page text budget used"})
            continue
        text, reason = fetch(url)
        if text is None:
            sources.append({"url": url, "status": "failed", "reason": reason})
            continue
        text = text[:min(budget["page_chars"], room)]
        room -= len(text)
        sources.append({"url": url, "status": "fetched"})
        pages.append((url, text))
    return sources, pages


def run(run_dir: Path, goal: str, fetch=fetch, ask=ask) -> dict:
    """Write a guide for every action of one goal that has none yet; returns guide.json's content."""
    s = llmconf.settings()
    if not llmconf.configured(s):
        raise ValueError(llmconf.not_configured_hint(s))
    mitigation = json.loads((run_dir / "mitigation" / "mitigation.json").read_text())
    target = next((t for t in mitigation["targets"] if t["goal"] == goal), None)
    if not target or target.get("unreachable") or not target.get("options"):
        raise ValueError(f"no mitigation options for {goal}")
    nodes = json.loads((run_dir / "iexam" / "node-data.json").read_text())
    ci = run_dir / "cveinfo.json"
    cves = json.loads(ci.read_text())["cves"] if ci.exists() else {}
    path = run_dir / "mitigation" / "guide.json"
    out = _load(path, run_dir.name, s["model"])
    for key, a in unique_actions(target).items():
        if key in out["guides"]:
            continue
        sources, pages = _sources(a, fetch, s["budget"])
        try:
            g = parse_guide(ask(build_prompt(a, nodes.get(a["node"], {}), cves, pages)), {u for u, _ in pages})
        except (ValueError, KeyError, requests.RequestException) as exc:
            out["notes"].append(f"guide for {key}: {exc}")
            continue
        out["guides"][key] = {"goal": goal, "model": s["model"], "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                              **g, "sources": sources, "no_sources": not pages}
        path.write_text(json.dumps(out, indent=2))  # after each action: a later hang keeps earlier guides
    path.write_text(json.dumps(out, indent=2))
    return out
