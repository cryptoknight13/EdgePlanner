"""Rule-based first-guess device type. Every match carries its evidence; no match -> unknown.

Rules are data tables so they can be extended as new devices show up. A trained
classifier may replace or back this up later (operator decision, see phases/README.md).
"""
import re

LABELS = ("router", "switch", "camera", "computer", "phone", "tablet", "tv", "speaker", "printer", "iot", "unknown")

# (regex over the OUI vendor string, label, confidence)
VENDOR_RULES = [
    (r"axis communications|hikvision|dahua|reolink|amcrest|foscam|wyze|hanwha|vivotek|uniview|arlo", "camera", 0.8),
    (r"raspberry pi", "computer", 0.6),
    (r"sonos|bose", "speaker", 0.8),
    (r"roku|vizio|tcl|hisense", "tv", 0.7),
    (r"brother|canon|epson|lexmark|kyocera|xerox", "printer", 0.6),
    (r"espressif|tuya|shelly|lifx|signify|philips lighting|ecobee|nest labs|ring|wemo|tp-link.*kasa|sonoff", "iot", 0.6),
    (r"intel corporate|dell|lenovo|hewlett|micro-star|asustek|vmware", "computer", 0.4),
    (r"amazon technologies", "speaker", 0.5),
    (r"securifi", "router", 0.7),
]

# (regex over a DNS-SD service type, label, confidence)
MDNS_RULES = [
    (r"_axis-video|_onvif|_nvr|_rtsp\b", "camera", 0.85),
    (r"_ipp\b|_ipps\b|_printer|_pdl-datastream|_scanner", "printer", 0.85),
    (r"_sonos", "speaker", 0.7),
    (r"_spotify-connect", "speaker", 0.5),  # phones running Spotify announce it too
    (r"_googlecast|_roku|_androidtvremote", "tv", 0.7),
    (r"_hap\b|_matter|_hue|_shelly|_esphomelib", "iot", 0.75),
    (r"_apple-mobdev2|_rdlink", "phone", 0.6),
    (r"_workstation|_ssh\b|_smb\b|_sftp-ssh|_rfb\b|_companion-link|_device-info", "computer", 0.5),
]

# (regex over Apple-style model ids from TXT records, label, confidence)
MODEL_RULES = [
    (r"^(mac|macbook|imac|macmini|macpro)", "computer", 0.95),
    (r"^iphone", "phone", 0.95),
    (r"^ipad", "tablet", 0.95),
    (r"^appletv", "tv", 0.95),
    (r"^audioaccessory|^homepod", "speaker", 0.95),
]

# (regex over a hostname, label, confidence)
HOSTNAME_RULES = [
    (r"iphone|android|galaxy|pixel|oneplus|redmi", "phone", 0.7),
    (r"ipad|tablet", "tablet", 0.7),
    (r"macbook|imac|desktop|laptop|-pc\b|thinkpad|kali|ubuntu|raspberrypi", "computer", 0.6),
    (r"axis-|ipcam|camera|cam\d", "camera", 0.7),
    (r"printer|^hp[0-9a-f]{6}|^brn|^epson", "printer", 0.7),
    (r"chromecast|roku|appletv|firetv|-tv\b", "tv", 0.7),
    (r"router|gateway|myrouter|almond|extender|repeater|mesh|deco|eero|orbi|velop", "router", 0.6),
    (r"^amazon-|echo|alexa|^google-home|^nest", "speaker", 0.6),
    (r"^wink", "iot", 0.7),
    (r"^ring-|^wyze|^blink", "camera", 0.6),
    (r"^dsh-|^dcs-", "camera", 0.8),  # D-Link camera model names
]

# (regex over UPnP deviceType / modelDescription / modelName, label, confidence)
UPNP_RULES = [
    (r"internetgatewaydevice|wandevice", "router", 0.9),
    (r"network camera|ip camera|digitalsecuritycamera|\bnvr\b", "camera", 0.9),
    (r"mediarenderer|television|\btv\b", "tv", 0.6),
    (r"printer", "printer", 0.85),
    (r"zoneplayer|speaker", "speaker", 0.8),
]

# Gather-time rules (phase 9b): what nmap found on the host itself.
# (regex over nmap product + extrainfo, label, confidence)
PRODUCT_RULES = [
    (r"webcam|network camera|ip camera", "camera", 0.9),
    (r"wink hub", "iot", 0.9),
    (r"^alphapd", "camera", 0.7),  # D-Link / TRENDnet IP-camera web server
    (r"^dnsmasq", "router", 0.5),  # a DNS forwarder off the gateway: extender or second router
]

# (regex over the nmap OS guess, label, confidence)
OS_RULES = [
    (r"apple ios|iphone os", "phone", 0.8),
    (r"mac ?os", "computer", 0.7),
]

# nmap's device type per OS class. One fingerprint can carry several (Cisco IOS: router and
# switch); switch outweighs router because a host that routes for others (gateway, bridge,
# UPnP IGD, DNS forwarder) already has stronger router evidence, and one that does not is a switch.
OS_TYPE_RULES = {
    "switch": ("switch", 0.7), "router": ("router", 0.6), "wap": ("router", 0.6),
    "webcam": ("camera", 0.7), "phone": ("phone", 0.7), "printer": ("printer", 0.7),
}

PORT_RULES = {62078: ("phone", 0.8, "TCP 62078 open (Apple lockdownd: iPhone / iPad)"),
              # Behind a MAC-translating extender there is no OUI vendor; a DNS server still marks the extender.
              53: ("router", 0.5, "DNS server (port 53): router or extender forwarding DNS")}

TXT_MODEL_RE = re.compile(r"^(?:model|am)=(.+)$", re.I)


def _match(rules, text: str, source: str) -> list[tuple[str, float, str]]:
    return [(label, conf, f"{source}: {text}") for pattern, label, conf in rules
            if text and re.search(pattern, text, re.I)]


def mac_randomized(mac: str | None) -> bool:
    """Locally administered bit set: a privacy (random) MAC, typical of phones and laptops."""
    return bool(mac) and int(mac.split(":")[0], 16) & 0x02 == 0x02


def label(host: dict, ports: list[dict] | None = None, os: dict | None = None) -> tuple[str, float, list[str]]:
    """Return (label, confidence, evidence) for one merged host record.

    `ports` and `os` are gather's nmap results; pass them to relabel after gather.
    """
    if host["role"] == "router":
        hits = [("router", 0.95, "default gateway of this LAN" if host.get("is_gateway") else "second router or extender on this LAN")]
    elif host["role"] == "self":
        hits = [("computer", 0.95, "this monitoring machine")]
    else:
        hits = []
    hits += _match(VENDOR_RULES, host.get("vendor") or "", "OUI vendor")
    for svc in host["mdns"]["service_types"]:
        hits += _match(MDNS_RULES, svc, "mDNS service")
    for model in host["mdns"]["models"]:
        hits += _match(MODEL_RULES, model, "mDNS model")
    for name in host["hostnames"]:
        hits += _match(HOSTNAME_RULES, name, "hostname")
    for desc in host["upnp"]:
        for field in ("device_type", "model_description", "model_name"):
            hits += _match(UPNP_RULES, desc.get(field, ""), f"UPnP {field}")
    for p in ports or []:
        hits += _match(PRODUCT_RULES, " ".join(filter(None, (p.get("product"), p.get("extrainfo")))), "nmap product")
        if p.get("port") in PORT_RULES:
            lab, conf, ev = PORT_RULES[p["port"]]
            hits.append((lab, conf, f"open port: {ev}"))
    if os:
        hits += _match(OS_RULES, os.get("name") or "", "nmap OS guess")
        for t in os.get("types", []):
            if t.lower() in OS_TYPE_RULES:
                lab, conf = OS_TYPE_RULES[t.lower()]
                hits.append((lab, conf, f"nmap device type: {t}"))
    # A MAC shared by several IPs belongs to a bridge (extender), so it says nothing about the host itself.
    shared = [f"MAC shared with {host['shared_mac']} other host(s): bridge or behind one"] \
        if host.get("shared_mac") else []
    if not hits and not shared and mac_randomized(host.get("mac")):
        hits.append(("phone", 0.3, "randomized MAC (privacy address: phone or laptop)"))
    if not hits:
        return "unknown", 0.0, shared

    # Sum confidence per label (capped at 0.99); independent signals agreeing raise it.
    score: dict[str, float] = {}
    for lab, conf, _ in hits:
        score[lab] = 1 - (1 - score.get(lab, 0.0)) * (1 - conf)
    best = max(score, key=score.get)
    evidence = list(dict.fromkeys(ev for lab, _, ev in hits if lab == best))
    others = sorted({f"also matched {lab}: {ev}" for lab, _, ev in hits if lab != best})
    return best, round(min(score[best], 0.99), 2), evidence + shared + others


def models_from_txt(txt: dict[str, list[str]]) -> list[str]:
    return sorted({m.group(1) for values in txt.values() for v in values if (m := TXT_MODEL_RE.match(v))})
