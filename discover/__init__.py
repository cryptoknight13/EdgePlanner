"""Phase 1 — Discover: find every live host on the local network and label it.

Scope is found automatically: the interface that carries the default route, and the IPv4 network(s)
that interface is on (its own address and mask). settings `interface` / `subnets` may pin them instead.
Either way only RFC1918 networks no larger than /16 are scanned.

Sources, all run inside one bounded window:
  - nmap ARP sweep (privileged) with reverse DNS, or TCP-connect sweep as fallback
  - kernel ARP cache
  - passive capture (DHCP, mDNS, SSDP)            -> collector.passive
  - one LAN-wide SSDP M-SEARCH and mDNS browse    -> collector.upnp, collector.mdns
"""
import ipaddress
import json
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

from collector import link, mdns, passive, upnp
from discover.label import label, mac_randomized, models_from_txt

SCHEMA_VERSION = "1.1"  # 1.1: uplink, shared_mac, routers[].via
PRIVATE = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
MAX_PREFIX = 16  # refuse sweeps larger than a /16
SSDP_GROUP = "239.255.255.250"


def check_subnets(subnets: list[str]) -> list[ipaddress.IPv4Network]:
    """Only RFC1918 networks no larger than /16 are allowed."""
    nets = []
    for s in subnets:
        net = ipaddress.ip_network(s, strict=False)
        if not any(net.subnet_of(p) for p in PRIVATE):
            raise ValueError(f"{s} is not an RFC1918 range; refusing to scan it")
        if net.prefixlen < MAX_PREFIX:
            raise ValueError(f"{s} is larger than /{MAX_PREFIX}; refusing to scan it")
        nets.append(net)
    return nets


def default_interface(routes: list[dict]) -> str:
    """`ip -j -4 route show default` -> the interface carrying the default route."""
    if not routes:
        raise RuntimeError("no default route: this machine is not on a network")
    return routes[0]["dev"]


def attached_subnets(addr: list[dict]) -> list[str]:
    """`ip -j -4 addr show dev X` -> the networks this machine is directly on (address + prefix)."""
    return sorted({str(ipaddress.ip_interface(f"{a['local']}/{a['prefixlen']}").network)
                   for link_ in addr for a in link_.get("addr_info", []) if a.get("family", "inet") == "inet"})


def _ip_json(*args: str) -> list[dict]:
    return json.loads(subprocess.run(["ip", "-j", "-4", *args], check=True, capture_output=True, text=True).stdout)


def scope(settings: dict, notes: list[str]) -> tuple[str, list[ipaddress.IPv4Network]]:
    """Interface and subnets to scan: detected from this machine, unless pinned in settings."""
    iface = settings.get("interface", "auto")
    if iface in (None, "auto"):
        iface = default_interface(_ip_json("route", "show", "default"))
        notes.append(f"Interface {iface} detected from the default route.")
    subnets = settings.get("subnets", "auto")
    if subnets in (None, "auto", []):
        subnets = attached_subnets(_ip_json("addr", "show", "dev", iface))
        if not subnets:
            raise RuntimeError(f"{iface} has no IPv4 address; cannot tell which network to scan")
        notes.append(f"Subnet {', '.join(subnets)} detected from {iface}'s address.")
    try:
        return iface, check_subnets(subnets)
    except ValueError as exc:
        raise ValueError(f"{exc}. Pin a smaller private subnet under `subnets:` in config/settings.yaml.") from exc


def local_identity(iface: str) -> dict:
    """This machine's IP, MAC and default gateway on the interface."""
    addr = json.loads(subprocess.run(["ip", "-j", "-4", "addr", "show", "dev", iface],
                                     check=True, capture_output=True, text=True).stdout)
    route = json.loads(subprocess.run(["ip", "-j", "-4", "route", "show", "default", "dev", iface],
                                      check=True, capture_output=True, text=True).stdout)
    return {
        "ip": addr[0]["addr_info"][0]["local"],
        "mac": Path(f"/sys/class/net/{iface}/address").read_text().strip().lower(),
        "gateway": route[0]["gateway"] if route else None,
    }


def parse_sweep(xml: str) -> dict[str, dict]:
    """nmap -sn XML -> {ip: {mac, hostnames}} for hosts that are up."""
    hosts = {}
    for h in ET.fromstring(xml).iter("host"):
        status = h.find("status")
        if status is None or status.get("state") != "up":
            continue
        ip = mac = None
        for a in h.findall("address"):
            if a.get("addrtype") == "ipv4":
                ip = a.get("addr")
            elif a.get("addrtype") == "mac":
                mac = a.get("addr").lower()
        names = [n.get("name") for n in h.iter("hostname") if n.get("name")]
        if ip:
            hosts[ip] = {"mac": mac, "hostnames": names}
    return hosts


def sweep(nets: list, notes: list[str]) -> tuple[dict[str, dict], str]:
    """ARP sweep if nmap has raw-socket privilege, otherwise a TCP-connect sweep."""
    targets = [str(n) for n in nets]
    try:
        out = subprocess.run(["nmap", "--privileged", "-sn", "-PR", "-oX", "-", *targets],
                             check=True, capture_output=True, text=True)
        return parse_sweep(out.stdout), "arp-sweep"
    except subprocess.CalledProcessError as exc:
        notes.append(f"Privileged ARP sweep failed ({exc.stderr.strip()[:200]}); "
                     "fell back to unprivileged TCP-connect sweep, which can miss hosts.")
    out = subprocess.run(["nmap", "--unprivileged", "-sn", "-oX", "-", *targets],
                         check=True, capture_output=True, text=True)
    return parse_sweep(out.stdout), "tcp-sweep"


def recheck_cache_only(hosts: dict[str, dict], resweep, notes: list[str]) -> None:
    """Hosts known only from this machine's ARP cache may carry an old MAC (the cache does not say how old):
    ask them again after the listening window; a fresh answer replaces the cached MAC."""
    ips = sorted((ip for ip, h in hosts.items() if h["seen_by"] == ["arp-cache"]), key=ipaddress.ip_address)
    if not ips:
        return
    fresh, method = resweep(ips)
    for ip, s in fresh.items():
        if ip in hosts and s["mac"]:
            if hosts[ip]["mac"] != s["mac"]:
                notes.append(f"{ip}: cached MAC {hosts[ip]['mac']} replaced by {s['mac']} from a fresh reply.")
            hosts[ip]["mac"] = s["mac"]
            _add(hosts[ip], "seen_by", [method])


def arp_cache(iface: str) -> dict[str, str]:
    with open("/proc/net/arp") as f:
        rows = [line.split() for line in f.readlines()[1:]]
    return {r[0]: r[3].lower() for r in rows if r[5] == iface and r[3] != "00:00:00:00:00:00"}


def _host(ip: str) -> dict:
    return {"ip": ip, "mac": None, "mac_randomized": False, "vendor": None, "hostnames": [],
            "role": "device", "is_gateway": False, "uplink": None, "shared_mac": 0, "label": "unknown", "confidence": 0.0, "evidence": [],
            "seen_by": [], "mdns": {"service_types": [], "instances": [], "models": [], "txt": {}},
            "upnp": [], "ssdp_servers": [], "dhcp": []}


def _add(host: dict, key: str, values) -> None:
    host[key] = sorted(set(host[key]) | set(values))


def _merge_mdns(host: dict, f: dict) -> None:
    m = host["mdns"]
    _add(host, "hostnames", (n.rstrip(".") for n in f["hosts"]))
    for s in f["services"]:
        stype, inst = s.split(" -> ", 1)
        if stype.startswith("_services._dns-sd"):
            m["service_types"] = sorted(set(m["service_types"]) | {inst.rstrip(".")})
        else:
            m["instances"] = sorted(set(m["instances"]) | {inst.rstrip(".")})
    m["txt"].update(f["txt"])
    m["models"] = models_from_txt(m["txt"])


def _merge_ssdp(host: dict, headers: list[dict]) -> None:
    _add(host, "ssdp_servers", (h["server"] for h in headers if h.get("server")))
    for h in upnp.describe(headers, host["ip"]):
        d = h.get("description")
        if d and "error" not in d and d not in host["upnp"]:
            host["upnp"].append(d)


def shared_mac_groups(hosts: dict[str, dict], me: dict) -> list[list[str]]:
    """IPs answering with one MAC: an extender that substitutes its own MAC for its clients'.

    Marks each member's `shared_mac` with how many others share it. The gateway's and this
    machine's MACs are not groups.
    """
    gw_mac = (hosts.get(me["gateway"] or "") or {}).get("mac")
    by_mac: dict[str, list[str]] = {}
    for h in hosts.values():
        if h["mac"] and h["mac"] not in (gw_mac, me["mac"]):
            by_mac.setdefault(h["mac"], []).append(h["ip"])
    groups = [sorted(ips, key=ipaddress.ip_address) for ips in by_mac.values() if len(ips) > 1]
    for ips in groups:
        for ip in ips:
            hosts[ip]["shared_mac"] = len(ips) - 1
    return groups


def attach_bridges(hosts: dict[str, dict], groups: list[list[str]], routers: list[dict],
                   gateway: str | None, notes: list[str]) -> None:
    """In each shared-MAC group, the member labelled router is the bridge; the rest get `uplink` to it."""
    for ips in groups:
        bridge = next((ip for ip in ips if hosts[ip]["role"] == "router" or hosts[ip]["label"] == "router"), None)
        if bridge is None:
            notes.append(f"{', '.join(ips)} share MAC {hosts[ips[0]]['mac']}: behind an unidentified bridge.")
            continue
        if hosts[bridge]["role"] != "router":
            hosts[bridge]["role"] = "router"
            routers.append({"ip": bridge, "subnets": [], "upstream": gateway, "via": "mac-bridge"})
        for ip in ips:
            if ip != bridge:
                hosts[ip]["uplink"] = bridge


def discover(settings: dict, oui_file: Path, oui_url: str, run_dir: Path) -> dict:
    notes: list[str] = []
    iface, nets = scope(settings, notes)
    me = local_identity(iface)
    window = settings.get("passive_window_seconds", 45)

    pcap = run_dir / "discover-passive.pcap"
    cap = passive.start_capture(iface, window, pcap)
    swept, method = sweep(nets, notes)
    ssdp = upnp.search(SSDP_GROUP, 3.0, me["ip"])
    mdns_found = mdns.browse(me["ip"])
    try:
        passive.wait_capture(cap)
        observed = passive.observe(pcap)
    except (OSError, subprocess.CalledProcessError) as exc:
        notes.append(f"Passive capture failed: {getattr(exc, 'stderr', '') or exc}")
        observed = {}

    in_scope = lambda ip: any(ipaddress.ip_address(ip) in n for n in nets)
    hosts: dict[str, dict] = {}

    def get(ip: str, source: str) -> dict:
        h = hosts.setdefault(ip, _host(ip))
        _add(h, "seen_by", [source])
        return h

    for ip, s in swept.items():
        h = get(ip, method)
        h["mac"] = h["mac"] or s["mac"]
        _add(h, "hostnames", s["hostnames"])
    for ip, mac in arp_cache(iface).items():
        if in_scope(ip):
            h = get(ip, "arp-cache")
            h["mac"] = h["mac"] or mac
    for ip, f in mdns_found.items():
        if in_scope(ip):
            _merge_mdns(get(ip, "mdns-browse"), f)
    for ip, headers in ssdp.items():
        if in_scope(ip):
            _merge_ssdp(get(ip, "ssdp-search"), headers)
    for (mac, _), f in observed.items():
        ips = [ip for ip in f["ips"] if in_scope(ip)] or [h["ip"] for h in hosts.values() if h["mac"] == mac]
        for ip in ips:
            h = get(ip, "passive")
            h["mac"] = h["mac"] or mac
            _merge_mdns(h, f["mdns"])
            _merge_ssdp(h, list(f["ssdp"].values()))
            h["dhcp"] += [d for d in f["dhcp"] if d not in h["dhcp"]]
            _add(h, "hostnames", (d["hostname"] for d in f["dhcp"] if d.get("hostname")))

    recheck_cache_only(hosts, lambda ips: sweep(ips, notes), notes)

    me_host = get(me["ip"], "self")
    me_host["mac"] = me["mac"]

    link.ensure_oui_file(oui_file, oui_url)
    groups = shared_mac_groups(hosts, me)
    routers = []
    for h in hosts.values():
        h["mac_randomized"] = mac_randomized(h["mac"])
        if h["mac"]:
            h["vendor"] = link.oui_vendor(h["mac"], oui_file)
        if h["ip"] == me["ip"]:
            h["role"] = "self"
        elif h["ip"] == me["gateway"]:
            h["role"], h["is_gateway"] = "router", True
            routers.append({"ip": h["ip"], "subnets": [str(n) for n in nets if ipaddress.ip_address(h["ip"]) in n],
                            "upstream": None, "via": "gateway"})
        elif any("internetgatewaydevice" in (d.get("device_type") or "").lower() for d in h["upnp"]):
            # A second gateway inside our LAN: mesh / cascaded router. Its own subnet is not visible from here.
            h["role"] = "router"
            routers.append({"ip": h["ip"], "subnets": [], "upstream": me["gateway"], "via": "upnp-igd"})
        h["label"], h["confidence"], h["evidence"] = label(h)
    attach_bridges(hosts, groups, routers, me["gateway"], notes)

    if not hosts.get(me["gateway"] or ""):
        notes.append(f"Default gateway {me['gateway']} did not answer discovery.")
    return {
        "schema_version": SCHEMA_VERSION,
        "run_id": run_dir.name,
        "collected_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "interface": iface,
        "subnets": [str(n) for n in nets],
        "attacker": {"id": "n0", "ip": settings.get("attacker_ip", "0.0.0.0"), "location": "external"},
        "self": {"ip": me["ip"], "mac": me["mac"]},
        "routers": routers,
        "hosts": sorted(hosts.values(), key=lambda h: ipaddress.ip_address(h["ip"])),
        "passive_window_seconds": window,
        "pcap": str(pcap),
        "notes": notes,
    }
