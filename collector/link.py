"""Link layer: target MAC from the kernel ARP cache, vendor from the IEEE OUI registry."""
import csv
import socket
import time
from pathlib import Path

import requests


def mac_for(ip: str) -> str | None:
    """Read the target MAC from /proc/net/arp, nudging the cache with one UDP datagram if absent."""
    for attempt in range(2):
        with open("/proc/net/arp") as f:
            for line in f.readlines()[1:]:
                cols = line.split()
                if cols[0] == ip and cols[3] != "00:00:00:00:00:00":
                    return cols[3].lower()
        if attempt == 0:
            # Discard port; the reply does not matter, only the ARP resolution it triggers.
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.sendto(b"", (ip, 9))
            time.sleep(1)
    return None


def ensure_oui_file(path: Path, url: str) -> None:
    """Download the IEEE OUI CSV once."""
    if path.exists():
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    resp = requests.get(url, timeout=60, headers={"User-Agent": "Mozilla/5.0 edge-monitor"})
    resp.raise_for_status()
    path.write_bytes(resp.content)


def oui_vendor(mac: str, path: Path) -> str | None:
    """Stream the OUI CSV and return the organization for the MAC's first 24 bits."""
    prefix = mac.replace(":", "").upper()[:6]
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.reader(f):
            if len(row) > 2 and row[1] == prefix:
                return row[2].strip()
    return None


def collect(record: dict, oui_file: Path, oui_url: str) -> None:
    ip = record["target"]["ip"]
    mac = mac_for(ip)
    record["target"]["mac"] = record["link"]["mac"] = mac
    if mac is None:
        record["notes"].append(f"No ARP entry for {ip}; MAC and OUI vendor unknown.")
        return
    try:
        ensure_oui_file(oui_file, oui_url)
        record["link"]["oui_vendor"] = oui_vendor(mac, oui_file)
    except (OSError, requests.RequestException) as exc:
        record["notes"].append(f"OUI lookup failed: {exc}")
