"""EdgePlanner settings: permission to scan the current network, and the API keys in .env.

Permission is per network: it covers the subnets that were in scope when the operator confirmed, and is asked
again when the box is moved to another network. Keys are written to .env (mode 600) and never sent back.
"""
import json
import os
import re
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
CONSENT = ROOT / "data" / "consent.json"
ENV = ROOT / ".env"
KEYS = {"NVD_API_KEY": re.compile(r"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$"),
        "NVIDIA_API_KEY": re.compile(r"^nvapi-[A-Za-z0-9_-]{20,200}$")}


def current_networks() -> list[str]:
    """Subnets Discover would scan right now (same detection as Discover); [] when offline."""
    from discover import scope
    settings = yaml.safe_load((ROOT / "config" / "settings.yaml").read_text())
    try:
        return [str(n) for n in scope(settings, [])[1]]
    except (RuntimeError, ValueError, subprocess.CalledProcessError):
        return []


def consent_status(networks: list[str] | None = None) -> dict:
    networks = current_networks() if networks is None else networks
    try:
        saved = json.loads(CONSENT.read_text())
    except (OSError, ValueError):
        saved = {}
    accepted = saved.get("networks", {})
    return {"ok": bool(networks) and all(n in accepted for n in networks), "networks": networks,
            "accepted_at": [accepted[n] for n in networks if n in accepted]}


def accept_consent() -> dict:
    networks = current_networks()
    if not networks:
        raise ValueError("this box is not on a network yet; connect it first")
    try:
        saved = json.loads(CONSENT.read_text())
    except (OSError, ValueError):
        saved = {}
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    saved.setdefault("networks", {}).update({n: now for n in networks})
    CONSENT.write_text(json.dumps(saved, indent=2))
    return consent_status(networks)


def keys_status() -> dict:
    """Which keys are set; only the last 4 characters are shown."""
    return {k: {"set": bool(os.environ.get(k)), "hint": (os.environ.get(k) or "")[-4:]} for k in KEYS}


def save_keys(values: dict) -> dict:
    """Validate, write to .env (other lines kept, mode 600) and to this process, so the next stage uses them."""
    new = {k: v.strip() for k, v in values.items() if k in KEYS and isinstance(v, str) and v.strip()}
    if not new:
        raise ValueError("enter at least one key")
    for k, v in new.items():
        if not KEYS[k].match(v):
            raise ValueError(f"{k} does not look right; copy the whole key")
    lines = ENV.read_text().splitlines() if ENV.exists() else []
    kept = [ln for ln in lines if ln.partition("=")[0].strip() not in new]
    fd, tmp = tempfile.mkstemp(dir=ROOT, prefix=".env.")
    with os.fdopen(fd, "w") as f:
        f.write("\n".join(kept + [f"{k}={v}" for k, v in new.items()]) + "\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, ENV)
    os.environ.update(new)
    return keys_status()

