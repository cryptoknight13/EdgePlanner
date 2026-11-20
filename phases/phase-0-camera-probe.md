# Phase 1 — Collection pipeline against the camera, on Kali

Read `CLAUDE.md` first. This phase builds the sensing half of the BAT subset and nothing else. It runs on Kali, pointed at the real router and camera. The resolver and CVE steps are stubbed so the pipeline runs end to end, but no identification method is chosen yet.

## Goal of this phase

From Kali, run one command against the camera's IP and produce a single JSON evidence record that contains the device's observable signature. This proves the collection contract works before any resolver, planner, or Pi deployment.

## Scope

In scope:
- Repo scaffold and config.
- Evidence record schema.
- Passive collector — broadcast and multicast capture on the LAN interface.
- Active collector — nmap service scan, ONVIF and UPnP query, HTTP and RTSP banner grab, scoped to configured targets.
- Resolver and CVE interfaces with pass-through stubs.
- Orchestrator that runs active components per config and writes the record.

Out of scope this phase: resolver method, CVE data source, PDDL, planner, Pi deployment, unicast flow capture.

## Build steps

### 1. Environment check (Kali)

- Confirm Python 3.11+, `pip`, and a virtualenv. Create `.venv` and use it.
- Confirm these system tools exist, install if missing: `nmap`, `tcpdump`, `avahi-utils` (for `avahi-browse`), `iproute2`.
- Confirm Python libs and pin them in `requirements.txt`: `scapy`, `python-nmap` (or call the `nmap` binary directly), `onvif-zeep`, `pyyaml`, `requests`. For each, confirm an ARM wheel exists or the package is pure Python. Flag any that do not before proceeding.
- Identify the LAN interface Kali uses to reach the router and record it. Do not hardcode it. Put it in `config/targets.yaml`.

### 2. Scaffold

- Create the directory tree from `CLAUDE.md`.
- `config/targets.yaml`: the LAN interface, the router IP, and the camera IP with a label. Ask the operator for the camera IP if it is not known.
- `config/components.yaml`: mark `passive`, `active`, `resolver`, `cve` active. Leave `planner` inactive.

### 3. Evidence record schema (`collector/schema.py`)

Define one structure that every component reads and writes. At minimum:

- `target`: IP, MAC, label.
- `collected_at`: timestamp.
- `link`: MAC, OUI vendor string (from the IEEE OUI file, downloaded once).
- `passive`: DHCP fingerprint (option 55 list, vendor class, hostname), mDNS names and services, SSDP device type and model.
- `active`: open ports, service and version per port, HTTP server header, TLS cert subject, RTSP banner.
- `onvif`: make, model, firmware, serial if the device answers.
- `resolved`: left empty by the stub, filled by a future resolver.
- `cves`: left empty by the stub, filled by a future CVE step.

Keep it JSON-serializable. Version the schema with a field.

### 4. Passive collector (`collector/passive/`)

- Capture on the configured interface for a bounded window (default 60 seconds, configurable).
- Parse DHCP Discover and Request for option 55, vendor class (option 60), and hostname (option 12).
- Collect mDNS or DNS-SD service announcements. `avahi-browse -art` is acceptable as a first pass, or parse UDP 5353 with scapy.
- Collect SSDP or UPnP announcements on UDP 1900 and fetch the device description XML for type, model, manufacturer.
- Write findings into the evidence record. Stream to disk, do not hold the whole capture in memory.

### 5. Active collector (`collector/active/`)

- Scope every action to the configured targets. No subnet-wide scanning.
- Run `nmap -sV` against the camera for open ports and service and version detection. Capture HTTP server headers and TLS cert subject where present.
- Query ONVIF `GetDeviceInformation` against the camera. On a camera this usually returns make, model, firmware, and serial directly. Handle the no-answer case cleanly.
- Grab the RTSP banner if an RTSP port is open.
- Merge findings into the same evidence record.

### 6. Resolver and CVE stubs

- `resolver/`: an interface with one function that takes an evidence record and returns it with `resolved` populated. The Phase 1 stub copies through ONVIF and SSDP make, model, and firmware strings into `resolved` without any database or model. This is a pass-through, not identification. Mark it clearly as a stub.
- `cve/`: an interface with one function that takes a record and returns it with `cves` populated. The Phase 1 stub returns an empty list and a note that no source is wired. Do not fetch or invent CVEs.

### 7. Orchestrator (`run.py`)

- Read `config/components.yaml` and `config/targets.yaml`.
- Run active components in order: passive, active, resolver, cve.
- Write one timestamped JSON evidence record per target to `output/`.
- Print a short human-readable summary to stdout: target, MAC and OUI vendor, open ports, and any make, model, firmware found.

## Phase 1 gate

The phase is met when, from Kali, this holds:

```
python run.py --target camera
```

produces an `output/<timestamp>-camera.json` evidence record that contains:

- The camera's MAC and resolved OUI vendor.
- Its open ports with service and version strings.
- Make, model, and firmware **if** the camera answers ONVIF or UPnP. If it answers neither, the record says so plainly and the passive and nmap fields are still populated.

The resolver and CVE fields exist and are empty by stub. The pipeline runs end to end with no errors.

Stop at the gate. Report what the record contains and what the camera did and did not reveal. Do not start Phase 2.

## Report back

- The evidence record for the camera.
- Which signals the camera exposed and which it withheld. This determines whether lookup alone will identify future devices or whether a traffic vantage is needed.
- Any dependency that lacked an ARM wheel, so the Pi step is not a surprise.
