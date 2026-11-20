"""Gather self-checks: multi-host nmap parse with OS, identity and firmware candidates."""
import unittest

from collector.active import nmap
from discover import _host
from gather import identity

XML = """<nmaprun>
<host><address addr="192.168.1.183" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="21"><state state="open"/>
<service name="ftp" product="Axis M1014 Fixed Network Camera ftpd" version="5.40.5.2"><cpe>cpe:/h:axis:m1014_fixed_network_camera</cpe></service></port>
</ports><os><osmatch name="Linux 2.6.19 - 2.6.36" accuracy="100"><osclass type="webcam"><cpe>cpe:/o:linux:linux_kernel:2.6</cpe></osclass></osmatch></os></host>
<host><address addr="192.168.1.50" addrtype="ipv4"/><ports/></host>
</nmaprun>"""


def camera() -> dict:
    h = _host("192.168.1.183")
    h["vendor"] = "Axis Communications AB"
    h["upnp"] = [{"manufacturer": "AXIS", "model_name": "AXIS M1014", "model_number": "M1014"}]
    return h


class Gather(unittest.TestCase):
    def test_parse_hosts(self):
        hosts = nmap.parse_hosts(XML)
        cam = hosts["192.168.1.183"]
        self.assertEqual(cam["ports"][0]["cpes"], ["cpe:/h:axis:m1014_fixed_network_camera"])
        self.assertEqual(cam["os"], {"name": "Linux 2.6.19 - 2.6.36", "accuracy": 100,
                                     "cpes": ["cpe:/o:linux:linux_kernel:2.6"], "types": ["webcam"]})
        self.assertEqual(hosts["192.168.1.50"], {"ports": [], "os": None})

    def test_identity_firmware_from_model_banner(self):
        ports = nmap.parse_hosts(XML)["192.168.1.183"]["ports"]
        i = identity(camera(), ports, {"status": "auth_required"})
        self.assertEqual((i["make"], i["make_source"], i["model"]), ("AXIS", "upnp", "AXIS M1014"))
        self.assertEqual(i["firmware"], "5.40.5.2")
        self.assertIn("21/ftp", i["firmware_source"])

    def test_onvif_wins_when_answered(self):
        i = identity(camera(), [], {"status": "answered", "make": "Axis", "model": "M1014", "firmware": "5.51"})
        self.assertEqual((i["make_source"], i["firmware"]), ("onvif", "5.51"))

    def test_unrelated_banner_is_not_firmware(self):
        ports = [{"port": 22, "service": "ssh", "product": "OpenSSH", "version": "9.2"}]
        self.assertIsNone(identity(camera(), ports, {"status": "no_answer"})["firmware"])


if __name__ == "__main__":
    unittest.main()
