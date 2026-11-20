"""Parser self-checks on fixed inputs. Run: .venv/bin/python -m unittest discover tests"""
import unittest

from collector import upnp
from collector.active import nmap, onvif

NMAP_XML = """<nmaprun><host><ports>
<port protocol="tcp" portid="21"><state state="open"/><service name="ftp" product="Axis ftpd" version="5.40.5.2"/></port>
<port protocol="tcp" portid="23"><state state="closed"/></port>
<port protocol="tcp" portid="443"><state state="open"/><service name="http" tunnel="ssl"/>
<script id="ssl-cert" output="x"><table key="subject"><elem key="commonName">cam</elem><elem key="organizationName">AXIS</elem></table></script></port>
</ports></host></nmaprun>"""

UPNP_XML = b"""<root xmlns="urn:schemas-upnp-org:device-1-0"><device>
<deviceType>urn:schemas-upnp-org:device:Basic:1</deviceType><manufacturer>AXIS</manufacturer>
<modelName>AXIS M1014</modelName><serialNumber>00408CF09FDA</serialNumber>
<deviceList><device><modelName>child</modelName></device></deviceList></device></root>"""

ONVIF_XML = b"""<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
 xmlns:tds="http://www.onvif.org/ver10/device/wsdl"><s:Body><tds:GetDeviceInformationResponse>
<tds:Manufacturer>AXIS</tds:Manufacturer><tds:Model>M1014</tds:Model>
<tds:FirmwareVersion>5.40.5.2</tds:FirmwareVersion><tds:SerialNumber>00408CF09FDA</tds:SerialNumber>
</tds:GetDeviceInformationResponse></s:Body></s:Envelope>"""


class Parsers(unittest.TestCase):
    def test_nmap_open_ports_only(self):
        ports = nmap.parse(NMAP_XML)
        self.assertEqual([p["port"] for p in ports], [21, 443])
        self.assertEqual(ports[0]["version"], "5.40.5.2")
        self.assertEqual(ports[1]["tunnel"], "ssl")
        self.assertEqual(ports[1]["tls_cert_subject"], "commonName=cam, organizationName=AXIS")

    def test_upnp_root_device_not_child(self):
        d = upnp.parse_description(UPNP_XML)
        self.assertEqual(d["model_name"], "AXIS M1014")
        self.assertEqual(d["serial"], "00408CF09FDA")

    def test_upnp_refuses_off_target_location(self):
        self.assertIn("error", upnp.fetch_description("http://10.0.0.9/desc.xml", "192.168.1.183"))

    def test_ssdp_headers(self):
        h = upnp.parse_headers(b"NOTIFY * HTTP/1.1\r\nLOCATION: http://a:1/x.xml\r\nUSN: uuid:1\r\n\r\n")
        self.assertEqual(h["start_line"], "NOTIFY * HTTP/1.1")
        self.assertEqual(h["location"], "http://a:1/x.xml")

    def test_onvif_device_information(self):
        d = onvif.parse(ONVIF_XML)
        self.assertEqual((d["make"], d["model"], d["firmware"], d["hardware_id"]),
                         ("AXIS", "M1014", "5.40.5.2", None))


if __name__ == "__main__":
    unittest.main()
