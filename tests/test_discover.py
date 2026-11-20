"""Discovery self-checks: scope guard, sweep parser, labelling rules."""
import unittest
from unittest import mock

import discover
from discover import _host, attached_subnets, check_subnets, default_interface, parse_sweep
from discover.label import LABELS, label, mac_randomized, models_from_txt

SWEEP = """<nmaprun>
<host><status state="up"/><address addr="192.168.1.183" addrtype="ipv4"/>
<address addr="00:40:8C:F0:9F:DA" addrtype="mac"/><hostnames><hostname name="axis-cam"/></hostnames></host>
<host><status state="down"/><address addr="192.168.1.9" addrtype="ipv4"/></host>
<host><status state="up"/><address addr="192.168.1.192" addrtype="ipv4"/></host>
</nmaprun>"""


def host(**kw) -> dict:
    h = _host("192.168.1.50")
    for k, v in kw.items():
        if k in ("service_types", "models"):
            h["mdns"][k] = v
        else:
            h[k] = v
    return h


class Scope(unittest.TestCase):
    def test_refuses_public_and_huge(self):
        with self.assertRaises(ValueError):
            check_subnets(["8.8.8.0/24"])
        with self.assertRaises(ValueError):
            check_subnets(["10.0.0.0/8"])
        self.assertEqual(str(check_subnets(["192.168.1.7/24"])[0]), "192.168.1.0/24")


# Shapes of `ip -j -4 route show default` and `ip -j -4 addr show dev eth0`.
ROUTES = [{"dst": "default", "gateway": "192.168.1.1", "dev": "eth0", "protocol": "dhcp"}]
ADDR = [{"ifname": "eth0", "addr_info": [{"family": "inet", "local": "192.168.1.170", "prefixlen": 24}]}]


class AutoScope(unittest.TestCase):
    def test_parsers(self):
        self.assertEqual(default_interface(ROUTES), "eth0")
        self.assertEqual(attached_subnets(ADDR), ["192.168.1.0/24"])
        with self.assertRaises(RuntimeError):
            default_interface([])

    def fake_ip(self, addr):
        return lambda *args: ROUTES if args[0] == "route" else addr

    def test_detects_interface_and_subnet(self):
        notes = []
        with mock.patch.object(discover, "_ip_json", self.fake_ip(ADDR)):
            iface, nets = discover.scope({"interface": "auto", "subnets": "auto"}, notes)
        self.assertEqual((iface, [str(n) for n in nets]), ("eth0", ["192.168.1.0/24"]))
        self.assertEqual(len(notes), 2)

    def test_pinned_settings_win(self):
        with mock.patch.object(discover, "_ip_json", side_effect=AssertionError("must not probe")):
            iface, nets = discover.scope({"interface": "wlan0", "subnets": ["10.1.2.0/24"]}, [])
        self.assertEqual((iface, [str(n) for n in nets]), ("wlan0", ["10.1.2.0/24"]))

    def test_refuses_a_detected_network_that_is_too_big_or_missing(self):
        big = [{"ifname": "eth0", "addr_info": [{"family": "inet", "local": "10.4.5.6", "prefixlen": 8}]}]
        with mock.patch.object(discover, "_ip_json", self.fake_ip(big)), self.assertRaises(ValueError) as ctx:
            discover.scope({}, [])
        self.assertIn("Pin a smaller private subnet", str(ctx.exception))
        with mock.patch.object(discover, "_ip_json", self.fake_ip([{"ifname": "eth0", "addr_info": []}])), \
                self.assertRaises(RuntimeError):
            discover.scope({}, [])


class Sweep(unittest.TestCase):
    def test_up_hosts_only(self):
        hosts = parse_sweep(SWEEP)
        self.assertEqual(sorted(hosts), ["192.168.1.183", "192.168.1.192"])
        self.assertEqual(hosts["192.168.1.183"], {"mac": "00:40:8c:f0:9f:da", "hostnames": ["axis-cam"]})
        self.assertIsNone(hosts["192.168.1.192"]["mac"])


class Bridges(unittest.TestCase):
    ME = {"ip": "192.168.1.170", "mac": "00:0c:29:f2:e2:0f", "gateway": "192.168.1.1"}

    def hosts(self, almond_name: str) -> dict:
        hs = {ip: _host(ip) for ip in ("192.168.1.1", "192.168.1.129", "192.168.1.186", "192.168.1.196")}
        hs["192.168.1.1"].update(mac="c4:41:1e:38:02:90", role="router")
        for ip in ("192.168.1.129", "192.168.1.186", "192.168.1.196"):
            hs[ip]["mac"] = "e6:71:85:62:4b:e0"
        hs["192.168.1.129"]["hostnames"] = [almond_name]
        return hs

    def test_cache_only_host_gets_its_fresh_mac(self):
        # .114 slept through the sweep; the cache still had its pre-extender MAC. It answers the recheck.
        hs = self.hosts("almond")
        hs["192.168.1.114"] = _host("192.168.1.114")
        hs["192.168.1.114"].update(mac="f0:81:73:7f:37:e0", seen_by=["arp-cache"])
        hs["192.168.1.186"]["seen_by"] = ["arp-sweep"]
        asked, notes = [], []

        def resweep(ips):
            asked.extend(ips)
            return {"192.168.1.114": {"mac": "e6:71:85:62:4b:e0", "hostnames": []}}, "arp-sweep"
        discover.recheck_cache_only(hs, resweep, notes)
        self.assertEqual(asked, ["192.168.1.114"])  # only the cache-only host is asked again
        self.assertEqual(hs["192.168.1.114"]["mac"], "e6:71:85:62:4b:e0")
        self.assertEqual(hs["192.168.1.114"]["seen_by"], ["arp-cache", "arp-sweep"])
        self.assertIn("192.168.1.114", discover.shared_mac_groups(hs, self.ME)[0])
        self.assertEqual(len(notes), 1)

    def attach(self, hs: dict) -> tuple[list, list]:
        routers, notes = [], []
        groups = discover.shared_mac_groups(hs, self.ME)
        for h in hs.values():
            h["label"] = label(h)[0]
        discover.attach_bridges(hs, groups, routers, "192.168.1.1", notes)
        return routers, notes

    def test_named_bridge_gets_its_clients(self):
        hs = self.hosts("Almond3")
        routers, notes = self.attach(hs)
        self.assertEqual(routers, [{"ip": "192.168.1.129", "subnets": [], "upstream": "192.168.1.1", "via": "mac-bridge"}])
        self.assertEqual([hs[ip]["uplink"] for ip in sorted(hs)], [None, None, "192.168.1.129", "192.168.1.129"])
        self.assertEqual((hs["192.168.1.186"]["shared_mac"], notes), (2, []))

    def test_unidentified_bridge_is_a_note_only(self):
        hs = self.hosts("box")
        routers, notes = self.attach(hs)
        self.assertEqual((routers, len(notes)), ([], 1))
        self.assertTrue(all(h["uplink"] is None for h in hs.values()))

    def test_gateway_mac_is_not_a_group(self):
        hs = self.hosts("Almond3")
        hs["192.168.1.2"] = _host("192.168.1.2")
        hs["192.168.1.2"]["mac"] = "c4:41:1e:38:02:90"
        self.attach(hs)
        self.assertEqual(hs["192.168.1.2"]["shared_mac"], 0)


class Labels(unittest.TestCase):
    def test_camera_signals_agree(self):
        lab, conf, ev = label(host(vendor="Axis Communications AB", service_types=["_axis-video._tcp.local"]))
        self.assertEqual(lab, "camera")
        self.assertGreater(conf, 0.9)
        self.assertEqual(len(ev), 2)

    def test_gateway_is_router(self):
        self.assertEqual(label(host(role="router", is_gateway=True, vendor="Belkin"))[0], "router")

    def test_apple_model_beats_weak_signals(self):
        lab, _, ev = label(host(models=["Mac15,13"], service_types=["_apple-mobdev2._tcp.local"]))
        self.assertEqual(lab, "computer")
        self.assertTrue(any(e.startswith("also matched phone") for e in ev))

    def test_randomized_mac_only(self):
        self.assertEqual(label(host(mac="b2:87:9d:55:6c:e7"))[:2], ("phone", 0.3))

    def test_nothing_is_unknown(self):
        self.assertEqual(label(host(mac="00:11:22:33:44:55")), ("unknown", 0.0, []))

    def test_shared_mac_is_not_a_phone(self):
        lab, _, ev = label(host(mac="e6:71:85:62:4b:e0", shared_mac=2))
        self.assertEqual(lab, "unknown")
        self.assertIn("MAC shared with 2", ev[0])

    def test_labels_have_page_names(self):
        import re
        from pathlib import Path
        js = Path(__file__).resolve().parent.parent.joinpath("web/static/app.js").read_text()
        names = re.search(r"const KIND_NAMES = \{(.*?)\};", js, re.S).group(1)
        for lab in LABELS:
            self.assertIn(f"{lab}:", names)

    def test_live_network_examples(self):
        """The phase 9b evidence table: discover hints plus gather's nmap results."""
        cisco_os = {"name": "Cisco 500, 2000-series switch; or 2500-series router (IOS 12.1 - 12.2)",
                    "types": ["router", "switch"]}
        cases = [
            (host(hostnames=["Almond3"], shared_mac=2), [{"port": 53, "product": "dnsmasq"}], None, "router"),
            # 2026-10-24: the Almond behind its own translated MAC, no name, DNS software not identified
            (host(shared_mac=3), [{"port": 53, "product": None}, {"port": 80, "product": "lighttpd"}],
             {"name": "Linux 2.6.32 - 3.10"}, "router"),
            (host(hostnames=["amazon-2b6ac75c8"], shared_mac=2), [], None, "speaker"),
            (host(shared_mac=2), [{"port": 62078}], {"name": "Apple iOS 15.0 - 15.6"}, "phone"),
            (host(vendor="Flextronics International"), [{"port": 80, "product": "Wink Hub 2 API httpd"}], None, "iot"),
            (host(vendor="Cisco Systems, Inc"), [], cisco_os, "switch"),  # not routing for anyone
            (host(role="router"), [], cisco_os, "router"),  # same fingerprint on a host that routes
            (host(vendor="D-Link International"),
             [{"port": 80, "product": "D-Link DCS-932L_A1 webcam http interface"}], None, "camera"),
            (host(mac="b2:c5:54:3b:a9:87"), [{"port": 8088, "product": "alphapd/2.1.6"}], None, "camera"),
            (host(hostnames=["DSH-C310-A987.local"], service_types=["_hap._tcp.local"]), [], None, "camera"),
            (host(hostnames=["iPhone"], service_types=["_spotify-connect._tcp.local"]), [], None, "phone"),
        ]
        for h, ports, os, want in cases:
            self.assertEqual(label(h, ports, os)[0], want, h)

    def test_helpers(self):
        self.assertTrue(mac_randomized("b2:87:9d:55:6c:e7"))
        self.assertFalse(mac_randomized("00:40:8c:f0:9f:da"))
        self.assertEqual(models_from_txt({"x": ["model=Mac15,13", "foo=1"], "y": ["am=iPhone14,2"]}),
                         ["Mac15,13", "iPhone14,2"])


if __name__ == "__main__":
    unittest.main()
