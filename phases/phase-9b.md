# Phase 9b — Bridge clusters and IoT fingerprinting

Read `CLAUDE.md` and `phases/README.md` first. Touches discover (phase 1), gather (phase 2), the network model behind the page (phases 5/9) and the iEXAM export (phase 6). Built and validated on Kali against the live network, before the Pi (phase 10).

## Goal

1. **Clusters.** Devices that reach the LAN through a Wi-Fi extender or second router in bridge mode are shown, and exported, behind that extender instead of directly on the gateway.
2. **Fingerprinting.** Every device gets the most specific type its own answers support. Gather's evidence (nmap service products, OS guess) feeds the label, not only discover's.

Agentless as always: nothing here logs in to the router, the extender or a device.

## Evidence from the live network (run `20261021T225655Z`, gather `20261021T224559Z`)

| IP | MAC | Hostname | Gather says | Label today | Should be |
|---|---|---|---|---|---|
| .129 | e6:71:85:62:4b:e0 | Almond3 | dnsmasq on 53, Linux 2.6/3.x | phone 0.3 | router (extender), upstream .1 |
| .186 | e6:71:85:62:4b:e0 | amazon-2b6ac75c8 | (not scanned) | phone 0.3 | speaker (Echo/Alexa), behind .129 |
| .196 | e6:71:85:62:4b:e0 | – | port 62078, Apple iOS 15 | phone 0.3 | phone (iPhone), behind .129 |
| .120 / .145 | Flextronics | – | "Wink Hub 2 API httpd" | unknown | iot (Wink Hub 2) |
| .147 | Cisco | – | Cisco switch/router IOS 12.x | unknown | switch (nmap device types router + switch; it routes for no one) |
| .165 | D-Link | – | "D-Link DCS-932L webcam http interface" | unknown | camera |

The Almond answers ARP for its Wi-Fi clients with its own (locally administered) MAC. So **one MAC on several IPs = a bridge and its clients.** The `phone` label for all three comes only from the randomized-MAC fallback in `discover/label.py`, which fires on the Almond's shared MAC.

## 1. Clusters (discover)

After hosts are merged, in `discover/__init__.py`:

- Group in-scope hosts by MAC. A group with 2+ IPs whose MAC is not the gateway's or this machine's is a **shared-MAC group**.
- The **bridge** is the member identified as a router: `role == "router"` already, or a hostname / UPnP / vendor router rule match (add `almond`, `extender`, `repeater`, `mesh`, `deco`, `eero`, `orbi`, `velop` to `HOSTNAME_RULES` → router). Every other member gets `"uplink": <bridge ip>`.
- The bridge gets `role = "router"` and an entry in `routers` with `"upstream": <gateway ip>`, `"subnets": []`, `"via": "mac-bridge"` (vs `"upnp-igd"` for the existing UPnP rule, `"gateway"` for the default gateway).
- No member identifiable as the bridge → no `uplink` is set; add a note: `"<ips> share MAC <mac>: behind an unidentified bridge"`. No synthetic node.
- Shared-MAC members skip the randomized-MAC → phone fallback (the MAC is the bridge's, not theirs). Evidence line instead: `"MAC shared with <n> other hosts (behind bridge <ip>)"`.
- Hosts with no shared MAC: `"uplink": null` (= the gateway). Schema version bump.

Known limits (state them in the page's notes, do not work around them):
- Router Wi-Fi vs router Ethernet is not distinguishable from the wire without router login. Not attempted.
- An extender that forwards client MACs unchanged (WDS / 4-address) leaves no shared MAC; its clients show on the gateway.
- A device behind a NAT-mode second router is still invisible (README, "Router2 visibility").

## 2. Network model and export

- `netmodel/__init__.py`: a device with `uplink` gets its `lan` edge from the bridge node, not the gateway. Bridge → gateway edge already comes from `routers[].upstream`.
- Lateral edges (`export.lateral_edges`) are unchanged: a bridge in this mode keeps one LAN segment, so a compromised device behind the Almond can still reach devices on the gateway.
- `export/`: no new code expected; `connectivity-edge.json` follows the model edges. Check iEXAM's consistency check still passes and the attack graph now runs `n0 → gateway → Almond → Alexa/iPhone`.
- Page: the graph shows the cluster under the Almond node; the node panel shows "Connected via Almond3 (.129)" for its clients.

## 3. Fingerprinting

Rules stay data tables in `discover/label.py` (no trained classifier in this phase; that is still the README's open decision).

**Discover-time, new rules:**
- Hostnames: `^amazon-|echo|alexa` → speaker; `^wink` → iot; `almond|…` → router (above); `^google-home|nest` → speaker; `^ring-|^wyze|^blink` → camera.
- Vendor: `flextronics` alone stays unknown (too generic); `amazon technologies` → speaker 0.5; `securifi` → router.

**Gather-time relabel (new):** gather already knows nmap service products and OS. In `gather/__init__.py`, after nmap, re-run `label()` with two more inputs and write `label`, `confidence`, `evidence` into `gather.json`:
- `PRODUCT_RULES` over nmap product/extrainfo: `webcam|network camera|ip camera` → camera 0.9; `wink hub` → iot 0.9; `alphapd` (D-Link camera httpd, seen on .160) → camera 0.7; `dnsmasq` → router 0.5.
- `OS_RULES` over nmap OS name: `apple ios|iphone os` → phone 0.8; `mac os` → computer 0.7. `OS_TYPE_RULES` over nmap osclass device types: switch 0.7, router/WAP → router 0.6, webcam, phone, printer. Switch outweighs router: a host that routes for others already has stronger router evidence.
- Port hints: TCP 62078 (Apple lockdownd) → phone 0.8.

`netmodel` takes label/confidence/evidence from gather when present, else discover. Evidence lines say which stage they came from.

**DHCP fingerprints:** `dhcp` was empty in the last run because devices only send DHCP when they renew a lease, which is rare within a 45 s window. Not chased in this phase. If a lease is seen, option 12 (hostname) is already used; options 55/60 are recorded but not matched.

## Tests

- `tests/test_discover.py`: three hosts sharing a MAC with one hostname `Almond3` → Almond becomes router with upstream gateway, other two get `uplink`, none labelled `phone` from the randomized-MAC rule. Shared MAC with no identifiable bridge → no uplink, one note. Same MAC as gateway → not a group.
- `tests/test_discover.py` `Labels`: each new rule table, one positive case each; the six rows of the evidence table above give the expected label.
- `tests/test_web.py` (where the network model is already tested): device with `uplink` gets its edge from the bridge, not the gateway.
- `tests/test_export.py` still passes; the exported edges include gateway → bridge → client.

## Gate

On a fresh run of the live network (Discover → Gather → … → Plan):
1. The Almond (.129) is a router node under the gateway; the Alexa (.186) and the iPhone (.196, when it answers) hang under it in the page graph and in `connectivity-edge.json`.
2. The six hosts in the evidence table carry the "Should be" label, each with evidence naming its source.
3. iEXAM's consistency check passes, and `connectivity-edge.json` has gateway → Almond. Almond clients only appear there when they have a kept CVE (export drops CVE-free nodes); then Plan's path to them runs through the Almond.
4. All tests pass with `.venv/bin/python -m unittest discover -s tests -t .`.

Stop and report.
