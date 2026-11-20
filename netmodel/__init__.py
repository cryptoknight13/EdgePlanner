"""Merge a run's stage files into one network model: nodes, edges and CVEs.

Consumed by the web view (phase 5) and the iEXAM export (phase 6). Works with partial runs:
each stage file that is missing simply contributes nothing.
"""
import json
import re
from pathlib import Path

STAGES = ("discover", "gather", "scan", "cveinfo")


def load_stages(run_dir: Path) -> dict[str, dict]:
    return {s: json.loads((run_dir / f"{s}.json").read_text())
            for s in STAGES if (run_dir / f"{s}.json").exists()}


def _risk(cves: list[dict]) -> float:
    return max((c["cvss"] or 0 for c in cves), default=0.0)


GENERIC_HOSTNAMES = {"linux", "localhost", "android", "openwrt", "espressif", "unknown"}
# nmap products that name only the server software, not the device
SERVER_SOFTWARE = ("lighttpd", "boa", "apache", "nginx", "dnsmasq", "samba", "dropbear", "openssh", "micro_httpd",
                   "mini_httpd", "goahead", "uhttpd", "thttpd", "portable sdk", "busybox", "microsoft", "jetty")
SERVER_SUFFIX = re.compile(r"\s+(?:api\s+)?(?:httpd|http config|http interface|webcam http interface|ftpd|rtspd|"
                           r"sshd|telnetd|upnp|web ?server)$", re.I)
VERSION = re.compile(r"v?\d+(?:\.\d+)+[a-z]?", re.I)
MAKE_NOISE = {"inc", "ltd", "co", "llc", "corp", "corporation", "technologies", "technology", "international",
              "systems", "communications", "ab", "foundation", "electronics", "gmbh", "limited", "company"}
MAKE_CITIES = {"shenzhen", "hangzhou", "guangzhou", "beijing", "shanghai", "dongguan", "xiamen"}
KIND_NAMES = {"router": "router", "switch": "switch", "camera": "camera", "computer": "computer", "phone": "phone",
              "tablet": "tablet", "tv": "TV", "speaker": "speaker", "printer": "printer", "iot": "smart device"}


def short_make(make: str) -> str:
    """"Shenzhen Ogemray Technology Co., Ltd." -> "Ogemray"; "Amazon Technologies Inc." -> "Amazon"."""
    words = [w for w in re.split(r"[\s,]+", make.split(",")[0]) if w]
    while words and words[0].lower() in MAKE_CITIES:
        words.pop(0)
    while len(words) > 1 and words[-1].lower().strip(".") in MAKE_NOISE:
        words.pop()
    return " ".join(words)


def banner_model(ports: list[dict]) -> str | None:
    """A device model named in a service banner ("Wink Hub 2 API httpd" -> "Wink Hub 2"); plain server software is not one."""
    for p in ports:
        product = (p.get("product") or "").strip()
        # digits must belong to a model ("DCS-932L", "Hub 2"), not a version ("alphapd/2.1.6", "1.4.20")
        model_part = " ".join(t for t in product.split() if "/" not in t and not VERSION.fullmatch(t))
        if any(ch.isdigit() for ch in model_part) and not product.lower().startswith(SERVER_SOFTWARE):
            return SERVER_SUFFIX.sub("", product).replace("_", " ").strip() or None
    return None


def display_name(host: dict, ident: dict, ports: list[dict] = (), label: str | None = None) -> str:
    """Announced model, else a specific hostname, else a model from a service banner, else make + device type, else IP."""
    make = (ident.get("make") or "").split(",")[0].strip()
    model = ident.get("model") if ident.get("model_source") in ("onvif", "upnp") else None
    if model:
        return model if not make or model.lower().startswith(make.lower()) else f"{make} {model}"
    names = sorted((n for n in host["hostnames"] if n.removesuffix(".local").lower() not in GENERIC_HOSTNAMES),
                   key=lambda n: (not n.endswith(".local"), -len(n)))
    if names:
        return names[0].removesuffix(".local")
    if banner := banner_model(ports):
        return banner
    if make := short_make(ident.get("make") or host.get("vendor") or ""):
        return f"{make} {KIND_NAMES.get(label, 'device')}"
    return host["ip"]


def attach_unnamed_bridges(hosts: list[dict], nodes: list[dict], gateway: str | None) -> list[dict]:
    """Shared-MAC groups whose bridge Discover could not name (no member looked like a router then): pick it now
    from the best label, Gather's when it ran. Sets the clients' uplink; returns the new router entries."""
    by_ip = {n["ip"]: n for n in nodes}
    groups: dict[str, list[dict]] = {}
    for h in hosts:
        if h.get("shared_mac") and h["ip"] in by_ip:
            groups.setdefault(h["mac"], []).append(by_ip[h["ip"]])
    added = []
    for members in groups.values():
        if any(m["uplink"] or m["kind"] == "router" for m in members):
            continue  # Discover already attached this group
        bridge = next((m for m in members if m["label"] == "router"), None)
        if bridge is None:
            continue
        bridge["kind"] = "router"
        if bridge["name"] == bridge["ip"]:  # its own MAC is hidden behind the translated one: no maker to name it by
            bridge["name"] = f"Extender (.{bridge['ip'].rsplit('.', 1)[-1]})"
        added.append({"ip": bridge["ip"], "subnets": [], "upstream": gateway, "via": "mac-bridge"})
        for m in members:
            if m is not bridge:
                m["uplink"] = bridge["ip"]
    return added


def build(run_dir: Path) -> dict:
    st = load_stages(run_dir)
    if "discover" not in st:
        raise FileNotFoundError(f"{run_dir} has no discover.json")
    d = st["discover"]
    gathered = {h["ip"]: h for h in st.get("gather", {}).get("hosts", [])}
    scanned = {h["ip"]: h for h in st.get("scan", {}).get("hosts", [])}
    info = st.get("cveinfo", {}).get("cves", {})

    nodes = [{"id": "n0", "kind": "attacker", "ip": d["attacker"]["ip"], "name": "Internet attacker",
              "label": "attacker", "cves": [], "risk": 0.0}]
    ids = {}
    for n, h in enumerate(d["hosts"], start=1):
        g, s = gathered.get(h["ip"], {}), scanned.get(h["ip"], {})
        ident = g.get("identity") or {}
        kind = "self" if h["role"] == "self" else ("router" if h["role"] == "router" else "device")
        cve_rows = []
        for c in s.get("cves", []):
            ci = info.get(c["cve_id"], {})
            cve_rows.append({"id": c["cve_id"], "port": c["port"], "vendor": c["vendor"], "product": c["product"],
                             "version": c["version"],
                             "match_type": c["match_type"], "weak": c["weak_match"], "source": c["source"],
                             "cvss": (ci.get("cvss") or {}).get("score") or c["cvss"],
                             "kev": bool((ci.get("exploit") or {}).get("kev")),
                             "public_exploit": bool((ci.get("exploit") or {}).get("public_exploit"))})
        # one row per CVE id: keep the strongest match
        best: dict[str, dict] = {}
        for r in sorted(cve_rows, key=lambda r: (r["weak"], -(r["cvss"] or 0))):
            best.setdefault(r["id"], r)
        cves = sorted(best.values(), key=lambda r: (r["weak"], -(r["cvss"] or 0), r["id"]))
        label = (g if "evidence" in g else h)["label"]
        name = display_name(h, ident, g.get("ports", []), label)
        node = {
            "id": f"n{n}", "kind": kind, "ip": h["ip"], "mac": h["mac"], "vendor": h["vendor"],
            # gather relabels with what nmap found (gather.json 1.1+); older runs keep discover's label
            **{k: (g if "evidence" in g else h)[k] for k in ("label", "confidence", "evidence")},
            "uplink": h.get("uplink"),
            "hostnames": h["hostnames"], "name": name, "identity": ident,
            "os": g.get("os"), "ports": g.get("ports", []), "scanned": bool(g),
            "software": s.get("software", []), "skipped": s.get("skipped", []),
            "cves": cves, "risk": _risk([c for c in cves if not c["weak"]]),
            "kev_count": sum(c["kev"] for c in cves),
            "strong_cve_count": sum(not c["weak"] for c in cves),
        }
        ids[h["ip"]] = node["id"]
        nodes.append(node)

    # Names must stay unique (iEXAM picks goals by name): "Amazon speaker" twice -> "Amazon speaker (.114)".
    counts: dict[str, int] = {}
    for node in nodes:
        counts[node["name"]] = counts.get(node["name"], 0) + 1
    for node in nodes[1:]:
        if counts[node["name"]] > 1:
            node["name"] = f"{node['name']} (.{node['ip'].rsplit('.', 1)[-1]})"

    routers = [r for r in d["routers"] if r["ip"] in ids]
    gateway = next((r for r in routers if r["upstream"] is None), None)
    routers += attach_unnamed_bridges(d["hosts"], nodes, gateway["ip"] if gateway else None)

    edges = []
    if gateway:
        edges.append({"source": "n0", "target": ids[gateway["ip"]], "kind": "wan"})
    for r in routers:
        if r["upstream"] and r["upstream"] in ids:
            edges.append({"source": ids[r["upstream"]], "target": ids[r["ip"]], "kind": "lan"})
    router_ids = {ids[r["ip"]] for r in routers}
    for node in nodes[1:]:
        if node["id"] in router_ids or not gateway:
            continue
        # behind a bridge (shared-MAC extender): the edge comes from the bridge, not the gateway
        parent = ids.get(node["uplink"] or "", ids[gateway["ip"]])
        edges.append({"source": parent, "target": node["id"],
                      "kind": "monitor" if node["kind"] == "self" else "lan"})

    return {"run_id": d["run_id"], "subnets": d["subnets"], "stages": sorted(st),
            "collected_at": {k: v.get("collected_at") for k, v in st.items()},
            "nodes": nodes, "edges": edges, "cves": info,
            "notes": [n for v in st.values() for n in v.get("notes", [])]}
