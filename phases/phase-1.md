# Phase 1 — Discover

Read `CLAUDE.md` and `phases/README.md` first. Build only discovery. Runs on Kali against the live LAN.

## Goal

One command finds every live device on the configured subnets and gives each a first-guess label (what kind of device it is), with no prior knowledge of IPs.

```
python run.py discover
```

writes `runs/<run-id>/discover.json` and prints a table.

## Scope

In scope:
- `config/settings.yaml`: interface and subnets, `auto` by default (detected from the default route and the interface address; may be pinned), attacker IP (`0.0.0.0`).
- Host discovery on those subnets: ARP sweep (nmap `-sn -PR`), plus the kernel ARP cache, plus a bounded passive listen (DHCP, mDNS, SSDP; reuse `collector/passive`).
- Per host: IP, MAC, OUI vendor (reuse `collector/link.py`), reverse-DNS / mDNS / DHCP hostname, whether it is the gateway, whether it is this machine.
- Router detection: the default gateway is the router. A host that is also a gateway for another subnet is a second router (mesh case).
- First-guess label per host: `router`, `camera`, `computer`, `phone`, `tv`, `speaker`, `printer`, `iot`, `unknown`, with a `confidence` and the `evidence` that led to it. Rules only, from OUI vendor, hostnames, mDNS service types, SSDP device types. No trained model yet.

Out of scope: port scans and service versions (phase 2), CVEs (phase 3+), ML classifier.

## Rules

- Never scan outside the detected (or pinned) subnets. Refuse non-RFC1918 ranges and anything larger than /16.
- Raw-socket nmap (ARP ping) needs privilege. Use `nmap --privileged` with file capabilities granted once by the operator:
  `sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $(which nmap)`.
  If missing, fall back to unprivileged TCP-connect discovery and say so in the output.
- Reuse phase 0 code (`collector/link.py`, `collector/passive`, `collector/upnp.py`); do not duplicate it.

## Output schema (`discover.json`)

```json
{
  "schema_version": "1.0",
  "run_id": "20261013T220000Z",
  "subnets": ["192.168.1.0/24"],
  "self": {"ip": "...", "mac": "..."},
  "routers": [{"ip": "192.168.1.1", "subnets": ["192.168.1.0/24"], "upstream": null}],
  "hosts": [
    {"ip": "192.168.1.183", "mac": "00:40:8c:f0:9f:da", "vendor": "Axis Communications AB",
     "hostnames": ["axis-00408cf09fda"], "role": "device",
     "label": "camera", "confidence": 0.9, "evidence": ["OUI Axis", "SSDP AXIS M1014"],
     "seen_by": ["arp-sweep", "passive-ssdp"]}
  ],
  "notes": []
}
```

## Gate

From Kali, `python run.py discover`:
- finds the router, the camera, the Pi and Kali itself, plus any other device on the LAN;
- labels the router `router` and the camera `camera`;
- every host has an `evidence` list; unknowns are `unknown`, not guessed;
- finishes in under 2 minutes for a /24.

Stop at the gate. Report the host table and which devices could not be labelled.
