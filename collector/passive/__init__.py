"""Passive collector: bounded broadcast/multicast capture on the LAN interface.

dumpcap streams the capture to disk (it holds cap_net_raw, so no root is needed);
scapy then reads the pcap packet by packet, so memory stays flat.
"""
import subprocess
from pathlib import Path

from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dns import DNS
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.utils import PcapReader

from collector import upnp

BPF = "arp or udp port 67 or udp port 68 or udp port 5353 or udp port 1900"
DHCP_TYPES = {1: "discover", 3: "request"}
PTR, TXT, A = 12, 16, 1


def start_capture(iface: str, seconds: int, pcap: Path) -> subprocess.Popen:
    return subprocess.Popen(
        ["dumpcap", "-q", "-i", iface, "-a", f"duration:{seconds}", "-F", "pcap", "-f", BPF, "-w", str(pcap)],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
    )


def wait_capture(proc: subprocess.Popen) -> None:
    _, err = proc.communicate()
    if proc.returncode:
        raise subprocess.CalledProcessError(proc.returncode, proc.args, stderr=err)


def capture(iface: str, seconds: int, pcap: Path) -> None:
    wait_capture(start_capture(iface, seconds, pcap))


def _text(value) -> str:
    return value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value)


def _dhcp(pkt) -> dict | None:
    opts = {o[0]: o[1] for o in pkt[DHCP].options if isinstance(o, tuple) and len(o) >= 2}
    kind = DHCP_TYPES.get(opts.get("message-type"))
    if kind is None:
        return None
    prl = opts.get("param_req_list")
    return {
        "message_type": kind,
        "param_req_list": list(prl) if isinstance(prl, (list, bytes)) else prl,
        "vendor_class": _text(opts["vendor_class_id"]) if "vendor_class_id" in opts else None,
        "hostname": _text(opts["hostname"]) if "hostname" in opts else None,
    }


def mdns_records(dns, out: dict) -> None:
    """Fold one mDNS message's answer/additional records into {names, services, txt, hosts}."""
    for rr in list(dns.an or []) + list(dns.ar or []):
        name = _text(rr.rrname)
        out["names"].add(name)
        if rr.type == PTR:
            out["services"].add(f"{name} -> {_text(rr.rdata)}")
        elif rr.type == TXT:
            out["txt"][name] = [_text(t) for t in rr.rdata]
        elif rr.type == A:
            out["hosts"].add(name)


def _blank() -> dict:
    return {"ips": set(), "dhcp": [],
            "mdns": {"names": set(), "services": set(), "txt": {}, "hosts": set()}, "ssdp": {}}


def observe(pcap: Path) -> dict[tuple[str, str | None], dict]:
    """Stream the pcap; return findings per (source MAC, source IP).

    Keyed by IP too because an extender answering with its own MAC for all its clients
    would otherwise mix their announcements. DHCP is keyed (client hardware address, None).
    """
    seen: dict[tuple[str, str | None], dict] = {}
    with PcapReader(str(pcap)) as reader:
        for pkt in reader:
            if UDP not in pkt or Ether not in pkt:
                continue
            if DHCP in pkt:
                entry = _dhcp(pkt)
                f = seen.setdefault((pkt[BOOTP].chaddr[:6].hex(":"), None), _blank())
                if entry and entry not in f["dhcp"]:
                    f["dhcp"].append(entry)
                continue
            if IP not in pkt:
                continue
            udp = pkt[UDP]
            if udp.sport == 5353 and DNS in pkt and pkt[DNS].qr == 1:
                f = seen.setdefault((pkt[Ether].src, pkt[IP].src), _blank())
                f["ips"].add(pkt[IP].src)
                mdns_records(pkt[DNS], f["mdns"])
            elif 1900 in (udp.sport, udp.dport):
                headers = upnp.parse_headers(bytes(udp.payload))
                if headers["start_line"].startswith(("NOTIFY", "HTTP/1.1 200")):
                    f = seen.setdefault((pkt[Ether].src, pkt[IP].src), _blank())
                    f["ips"].add(pkt[IP].src)
                    f["ssdp"].setdefault(headers.get("usn", str(len(f["ssdp"]))), headers)
    return {key: f for key, f in seen.items() if f["dhcp"] or f["mdns"]["names"] or f["ssdp"]}


def parse(pcap: Path, record: dict) -> None:
    """Write passive findings about the record's target into the record."""
    ip, mac = record["target"]["ip"], record["target"]["mac"]
    found = observe(pcap)
    if mac is None:
        mac = next((m for m, src in found if src == ip), None)
        if mac:
            record["target"]["mac"] = record["link"]["mac"] = mac
    f, lease = found.get((mac, ip)), found.get((mac, None))
    if f is None and lease is None:
        return
    f = f or _blank()
    p = record["passive"]
    p["dhcp"] = lease["dhcp"] if lease else []
    p["mdns"] = {"names": sorted(f["mdns"]["names"]), "services": sorted(f["mdns"]["services"]),
                 "txt": f["mdns"]["txt"]}
    p["ssdp"] = upnp.describe(list(f["ssdp"].values()), ip)


def collect(record: dict, iface: str, seconds: int, pcap: Path) -> None:
    record["passive"].update(window_seconds=seconds, pcap=str(pcap))
    try:
        capture(iface, seconds, pcap)
    except (OSError, subprocess.CalledProcessError) as exc:
        detail = getattr(exc, "stderr", "") or exc
        record["notes"].append(f"Passive capture failed: {str(detail).strip()}")
        return
    parse(pcap, record)
    p = record["passive"]
    if not (p["dhcp"] or p["mdns"]["names"] or p["ssdp"]):
        record["notes"].append(f"Passive: target emitted no DHCP, mDNS or SSDP in the {seconds}s window.")
