"""Phase 2 — Gather: what an outside attacker learns about each discovered host.

One nmap run (-sV -O, top ports, ssl-cert) over every discovered host except this
machine, then per-host banner probes reused from phase 0 (collector.active).
"""
import re
import subprocess
from datetime import datetime, timezone

from collector.active import nmap, onvif, probe_ports
from discover.label import label

SCHEMA_VERSION = "1.1"  # 1.1: label / confidence / evidence relabelled with nmap results
MODEL_TOKEN_RE = re.compile(r"[A-Za-z]*\d[\w-]*")  # tokens like M1014, WRT3200ACM


def nmap_args(top_ports: int) -> list[str]:
    return ["--privileged", "-sV", "-O", "--osscan-guess", "-Pn", "--top-ports", str(top_ports),
            "--script", "ssl-cert"]


def model_tokens(host: dict) -> set[str]:
    """Model identifiers the device announced (UPnP / mDNS), used to spot firmware strings."""
    texts = [d.get(k, "") for d in host["upnp"] for k in ("model_name", "model_number")]
    texts += host["mdns"]["models"]
    return {t.lower() for text in texts for t in MODEL_TOKEN_RE.findall(text or "")}


def identity(host: dict, ports: list[dict], onvif_info: dict) -> dict:
    """make / model / firmware with sources; firmware only from sources that state it."""
    upnp = host["upnp"][0] if host["upnp"] else {}
    answered = onvif_info.get("status") == "answered"
    pick = lambda *pairs: next(((v, s) for v, s in pairs if v), (None, None))
    make, make_src = pick((answered and onvif_info.get("make"), "onvif"),
                          (upnp.get("manufacturer"), "upnp"), (host.get("vendor"), "oui"))
    model, model_src = pick((answered and onvif_info.get("model"), "onvif"),
                            (upnp.get("model_name"), "upnp"),
                            (host["mdns"]["models"][0] if host["mdns"]["models"] else None, "mdns"))

    candidates = []
    if answered and onvif_info.get("firmware"):
        candidates.append({"value": onvif_info["firmware"], "source": "onvif FirmwareVersion"})
    tokens = model_tokens(host)
    for p in ports:
        product = (p["product"] or "").lower()
        if p["version"] and tokens and any(t in product for t in tokens):
            candidates.append({"value": p["version"],
                               "source": f"{p['port']}/{p['service']} banner: {p['product']} {p['version']}"})
    return {
        "make": make, "make_source": make_src, "model": model, "model_source": model_src,
        "firmware": candidates[0]["value"] if candidates else None,
        "firmware_source": candidates[0]["source"] if candidates else None,
        "firmware_candidates": candidates,
    }


def gather(discovered: dict, top_ports: int) -> dict:
    targets = [h for h in discovered["hosts"] if h["role"] != "self"]
    notes: list[str] = []
    try:
        scanned = nmap.parse_hosts(nmap.scan([h["ip"] for h in targets], nmap_args(top_ports)))
    except (OSError, subprocess.CalledProcessError) as exc:
        notes.append(f"nmap failed: {getattr(exc, 'stderr', '') or exc}")
        scanned = {}

    hosts = []
    for h in targets:
        s = scanned.get(h["ip"], {"ports": [], "os": None})
        lab, conf, evidence = label(h, s["ports"], s["os"])
        rtsp_banner, web = probe_ports(h["ip"], s["ports"])
        camera_like = lab == "camera" or rtsp_banner is not None
        onvif_info = onvif.query(h["ip"], web) if camera_like and web else {"status": "not_applicable"}
        host_notes = []
        if not s["ports"]:
            host_notes.append(f"No open TCP ports in the top {top_ports}.")
        if s["os"] is None:
            host_notes.append("nmap made no OS guess (too few open/closed ports to fingerprint).")
        hosts.append({
            "ip": h["ip"], "mac": h["mac"], "vendor": h["vendor"], "role": h["role"],
            "label": lab, "confidence": conf, "evidence": evidence,
            "hostnames": h["hostnames"], "os": s["os"], "ports": s["ports"],
            "rtsp_banner": rtsp_banner, "onvif": onvif_info,
            "upnp": h["upnp"], "mdns_models": h["mdns"]["models"],
            "identity": identity(h, s["ports"], onvif_info),
            "notes": host_notes,
        })
    return {
        "schema_version": SCHEMA_VERSION,
        "run_id": discovered["run_id"],
        "collected_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "nmap_args": nmap_args(top_ports),
        "skipped": [h["ip"] for h in discovered["hosts"] if h["role"] == "self"],
        "hosts": hosts,
        "notes": notes,
    }
