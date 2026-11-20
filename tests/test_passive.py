"""Passive parser on a synthetic pcap (the live camera was silent in its window)."""
import tempfile
import unittest
from pathlib import Path

from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dns import DNS, DNSRR
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

from collector import passive
from collector.schema import new_record

MAC, IPADDR = "00:40:8c:f0:9f:da", "192.168.1.183"


def packets():
    dhcp = (Ether(src=MAC, dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0", dst="255.255.255.255")
            / UDP(sport=68, dport=67) / BOOTP(chaddr=bytes.fromhex(MAC.replace(":", "")))
            / DHCP(options=[("message-type", "discover"), ("param_req_list", [1, 3, 6]),
                            ("vendor_class_id", b"AXIS"), ("hostname", b"axis-cam"), "end"]))
    mdns = (Ether(src=MAC) / IP(src=IPADDR, dst="224.0.0.251") / UDP(sport=5353, dport=5353)
            / DNS(qr=1, aa=1, an=[DNSRR(rrname="_http._tcp.local.", type="PTR", rdata="cam._http._tcp.local."),
                                  DNSRR(rrname="cam._http._tcp.local.", type="TXT", rdata=[b"model=M1014"])]))
    notify = (Ether(src=MAC) / IP(src=IPADDR, dst="239.255.255.250") / UDP(sport=1900, dport=1900)
              / b"NOTIFY * HTTP/1.1\r\nLOCATION: http://10.9.9.9/d.xml\r\nUSN: uuid:x\r\n\r\n")
    other = Ether() / IP(src="192.168.1.50", dst="224.0.0.251") / UDP(sport=5353, dport=5353) / DNS()
    return [dhcp, mdns, notify, other]


class Passive(unittest.TestCase):
    def test_parse(self):
        with tempfile.TemporaryDirectory() as d:
            pcap = Path(d) / "t.pcap"
            wrpcap(str(pcap), packets())
            rec = new_record("camera", IPADDR)
            rec["target"]["mac"] = MAC
            passive.parse(pcap, rec)
        p = rec["passive"]
        self.assertEqual(p["dhcp"], [{"message_type": "discover", "param_req_list": [1, 3, 6],
                                      "vendor_class": "AXIS", "hostname": "axis-cam"}])
        self.assertIn("_http._tcp.local. -> cam._http._tcp.local.", p["mdns"]["services"])
        self.assertEqual(p["mdns"]["txt"]["cam._http._tcp.local."], ["model=M1014"])
        self.assertEqual(len(p["ssdp"]), 1)
        self.assertIn("not on the target", p["ssdp"][0]["description"]["error"])

    def test_shared_mac_keeps_clients_apart(self):
        """An extender answers with one MAC for all its clients; each IP keeps its own announcements."""
        bridge = "e6:71:85:62:4b:e0"
        mdns = lambda ip, name: (Ether(src=bridge) / IP(src=ip, dst="224.0.0.251") / UDP(sport=5353, dport=5353)
                                 / DNS(qr=1, aa=1, an=[DNSRR(rrname=name, type="A", rdata=ip)]))
        with tempfile.TemporaryDirectory() as d:
            pcap = Path(d) / "t.pcap"
            wrpcap(str(pcap), [mdns("192.168.1.196", "iPhone.local."), mdns("192.168.1.114", "echo.local.")])
            found = passive.observe(pcap)
        self.assertEqual(set(found), {(bridge, "192.168.1.196"), (bridge, "192.168.1.114")})
        self.assertEqual(found[(bridge, "192.168.1.114")]["ips"], {"192.168.1.114"})


if __name__ == "__main__":
    unittest.main()
