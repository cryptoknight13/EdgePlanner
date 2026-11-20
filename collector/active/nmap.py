"""nmap service scans, parsed from nmap's XML output."""
import subprocess
import xml.etree.ElementTree as ET


def scan(targets: str | list[str], args: list[str]) -> str:
    """Run nmap against exactly the given IP(s) and return the XML report."""
    ips = [targets] if isinstance(targets, str) else targets
    return subprocess.run(["nmap", *args, "-oX", "-", *ips],
                          check=True, capture_output=True, text=True).stdout


def _cert_subject(script: ET.Element) -> str | None:
    table = script.find("table[@key='subject']")
    if table is None:
        return None
    return ", ".join(f"{e.get('key')}={e.text}" for e in table.findall("elem"))


def _ports(host: ET.Element) -> list[dict]:
    """One entry per open port of one <host>."""
    ports = []
    for port in host.iter("port"):
        state = port.find("state")
        if state is None or state.get("state") != "open":
            continue
        svc = port.find("service")
        get = (lambda k: svc.get(k)) if svc is not None else (lambda k: None)
        entry = {
            "port": int(port.get("portid")), "proto": port.get("protocol"),
            "service": get("name"), "tunnel": get("tunnel"), "product": get("product"),
            "version": get("version"), "extrainfo": get("extrainfo"),
            "cpes": [c.text for c in svc.findall("cpe")] if svc is not None else [],
            "http_server_header": None, "tls_cert_subject": None,
        }
        for script in port.iter("script"):
            if script.get("id") == "ssl-cert":
                entry["tls_cert_subject"] = _cert_subject(script)
        ports.append(entry)
    return ports


def _os(host: ET.Element) -> dict | None:
    """Best OS match with its accuracy, CPEs and nmap device types, or None if nmap made no guess."""
    m = host.find("os/osmatch")
    if m is None:
        return None
    return {"name": m.get("name"), "accuracy": int(m.get("accuracy", 0)),
            "cpes": sorted({c.text for c in m.iter("cpe")}),
            "types": list(dict.fromkeys(c.get("type") for c in m.iter("osclass") if c.get("type")))}


def parse_hosts(xml: str) -> dict[str, dict]:
    """{ip: {ports, os}} for every scanned host in the report."""
    out = {}
    for i, host in enumerate(ET.fromstring(xml).iter("host")):
        addr = host.find("address[@addrtype='ipv4']")
        out[addr.get("addr") if addr is not None else f"host{i}"] = {"ports": _ports(host), "os": _os(host)}
    return out


def parse(xml: str) -> list[dict]:
    """Open ports of every host in the report, flattened (single-target use)."""
    return [p for h in parse_hosts(xml).values() for p in h["ports"]]
