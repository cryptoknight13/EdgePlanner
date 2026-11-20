"""Active collector: scoped probes against one configured target only."""
import subprocess

import requests

from collector import upnp
from collector.active import nmap, onvif, rtsp

RTSP_PORTS = {554, 8554}
WEB_PORTS = {80, 443, 8000, 8080, 8443}


def server_header(url: str) -> str | None:
    try:
        with requests.get(url, timeout=5, verify=False, allow_redirects=False, stream=True) as resp:
            return resp.headers.get("Server")
    except requests.RequestException:
        return None


def probe_ports(ip: str, ports: list[dict]) -> tuple[str | None, list[tuple[str, int]]]:
    """Fill http_server_header on web ports; return (RTSP banner, web endpoints)."""
    tcp = [p for p in ports if p["proto"] == "tcp"]
    rtsp_port = next((p["port"] for p in tcp if p["service"] == "rtsp" or p["port"] in RTSP_PORTS), None)
    banner = rtsp.banner(ip, rtsp_port) if rtsp_port else None
    web = []
    for p in tcp:
        if (p["service"] or "").startswith("http") or p["port"] in WEB_PORTS:
            scheme = "https" if p["tunnel"] == "ssl" or p["service"] == "https" else "http"
            p["http_server_header"] = server_header(f"{scheme}://{ip}:{p['port']}/")
            web.append((scheme, p["port"]))
    return banner, web


def collect(record: dict, nmap_args: list[str]) -> None:
    ip = record["target"]["ip"]
    a = record["active"]

    try:
        a["ports"] = nmap.parse(nmap.scan(ip, nmap_args))
    except (OSError, subprocess.CalledProcessError) as exc:
        record["notes"].append(f"nmap failed: {getattr(exc, 'stderr', '') or exc}")

    a["rtsp_banner"], web = probe_ports(ip, a["ports"])
    a["upnp"] = upnp.msearch(ip)
    record["onvif"] = {**record["onvif"], **onvif.query(ip, web or [("http", 80)])}

    upnp_answered = any(r.get("description") for r in a["upnp"] + record["passive"]["ssdp"])
    if record["onvif"]["status"] != "answered" and not upnp_answered:
        record["notes"].append(
            f"Target answered neither ONVIF (status: {record['onvif']['status']}) nor UPnP; "
            "make, model and firmware not obtained from those sources.")
