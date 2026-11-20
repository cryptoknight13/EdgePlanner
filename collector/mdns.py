"""Active mDNS / DNS-SD browse without avahi: one-shot legacy-unicast queries.

Round 1 asks for the list of service types; round 2 asks for instances of each.
Replies come back unicast to our socket, keyed here by source IP.
"""
import socket
import time

from scapy.layers.dns import DNS, DNSQR

from collector.passive import mdns_records

MDNS = ("224.0.0.251", 5353)
SERVICES = "_services._dns-sd._udp.local."


def _blank() -> dict:
    return {"names": set(), "services": set(), "txt": {}, "hosts": set()}


def query(names: list[str], local_ip: str, timeout: float = 2.0) -> dict[str, dict]:
    """Ask PTR questions for `names`; return mDNS records per responding IP."""
    found: dict[str, dict] = {}
    if not names:
        return found
    packet = bytes(DNS(rd=0, qd=[DNSQR(qname=n, qtype="PTR") for n in names]))
    deadline = time.monotonic() + timeout
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(local_ip))
        s.sendto(packet, MDNS)
        while (remaining := deadline - time.monotonic()) > 0:
            s.settimeout(remaining)
            try:
                data, (src, _) = s.recvfrom(9000)
            except socket.timeout:
                break
            try:
                mdns_records(DNS(data), found.setdefault(src, _blank()))
            except Exception:  # malformed reply from a device; skip it, keep browsing
                continue
    return found


def browse(local_ip: str, timeout: float = 2.0) -> dict[str, dict]:
    """Service types, then their instances; merged per IP."""
    found = query([SERVICES], local_ip, timeout)
    types = sorted({s.split(" -> ", 1)[1] for f in found.values() for s in f["services"]
                    if s.startswith(SERVICES)})
    # shortcut: one packet carries all type questions; split if a LAN ever exceeds ~30 types.
    for ip, f in query(types, local_ip, timeout).items():
        g = found.setdefault(ip, _blank())
        g["names"] |= f["names"]
        g["services"] |= f["services"]
        g["hosts"] |= f["hosts"]
        g["txt"].update(f["txt"])
    return found
