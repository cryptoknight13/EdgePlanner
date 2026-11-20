"""Download fix-commit diffs from GitHub / GitLab to disk (size-capped)."""
from pathlib import Path

import requests

MAX_BYTES = 200_000
UA = {"User-Agent": "EdgePlanner/1.0"}


def patch_url(commit: dict) -> str | None:
    if commit["host"] in ("github.com", "gitlab.com") and commit["sha"]:
        return commit["url"].split("#")[0].rstrip("/") + ".patch"
    return None


def fetch(commit: dict, cve_id: str, out_dir: Path) -> dict:
    """Save the commit's .patch under out_dir; return {path, bytes, truncated, files} or {error}."""
    url = patch_url(commit)
    if url is None:
        return {"error": "not a GitHub/GitLab commit; link only"}
    path = out_dir / f"{cve_id}-{commit['sha'][:12]}.diff"
    if path.exists():
        text = path.read_text(errors="replace")
        return {"path": str(path), "bytes": len(text), "truncated": text.endswith("[truncated]\n"),
                "files": text.count("\ndiff --git ")}
    try:
        with requests.get(url, timeout=30, headers=UA, stream=True) as resp:
            resp.raise_for_status()
            body = b""
            for chunk in resp.iter_content(16384):
                body += chunk
                if len(body) > MAX_BYTES:
                    break
    except requests.RequestException as exc:
        return {"error": str(exc)}
    truncated = len(body) > MAX_BYTES
    text = body[:MAX_BYTES].decode("utf-8", "replace") + ("\n[truncated]\n" if truncated else "")
    out_dir.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return {"path": str(path), "bytes": len(text), "truncated": truncated, "files": text.count("\ndiff --git ")}
