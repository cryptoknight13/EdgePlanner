"""Scan self-checks: version ordering, NVD cpeMatch evaluation, software list, nuclei parse."""
import json
import unittest
from pathlib import Path

from scan import nuclei
from scan.software import first_token, firmware_product, software_list
from scan.version import cmp, match, match_cve


def entry(criteria: str, **bounds) -> dict:
    return {"vulnerable": True, "criteria": criteria, **bounds}


class Versions(unittest.TestCase):
    def test_ordering(self):
        self.assertEqual(cmp("1.4", "1.4.0"), 0)
        self.assertLess(cmp("1.4", "1.4p1"), 0)
        self.assertLess(cmp("2.78rc1", "2.78"), 0)
        self.assertLess(cmp("1.0.2", "1.0.2k"), 0)
        self.assertLess(cmp("1.0.2k", "1.0.3"), 0)
        self.assertLess(cmp("9.9", "10.0p2"), 0)
        self.assertLess(cmp("5.40.5.2", "5.51.5"), 0)


class Match(unittest.TestCase):
    def test_exact_with_update(self):
        e = entry("cpe:2.3:a:openbsd:openssh:9.3:p1:*:*:*:*:*:*")
        self.assertEqual(match(e, "openbsd", "openssh", "9.3p1"), "exact")
        self.assertIsNone(match(e, "openbsd", "openssh", "9.3p2"))

    def test_ranges(self):
        e = entry("cpe:2.3:a:thekelleys:dnsmasq:*:*:*:*:*:*:*:*", versionEndExcluding="2.83")
        self.assertEqual(match(e, "thekelleys", "dnsmasq", "2.78"), "range")
        self.assertIsNone(match(e, "thekelleys", "dnsmasq", "2.83"))
        e = entry("cpe:2.3:a:x:y:*:*:*:*:*:*:*:*", versionStartIncluding="1.2", versionEndIncluding="1.4")
        self.assertEqual(match(e, "x", "y", "1.4"), "range")
        self.assertIsNone(match(e, "x", "y", "1.1"))

    def test_weak_and_other(self):
        self.assertEqual(match(entry("cpe:2.3:a:x:y:*:*:*:*:*:*:*:*"), "x", "y", "1"), "all-versions")
        self.assertEqual(match(entry("cpe:2.3:a:x:y:-:*:*:*:*:*:*:*"), "x", "y", "1"), "unversioned")
        self.assertIsNone(match(entry("cpe:2.3:a:x:z:*:*:*:*:*:*:*:*"), "x", "y", "1"))
        self.assertIsNone(match({**entry("cpe:2.3:a:x:y:*:*:*:*:*:*:*:*"), "vulnerable": False}, "x", "y", "1"))

    def test_strongest_wins(self):
        cve = {"configurations": [{"nodes": [{"cpeMatch": [
            entry("cpe:2.3:a:x:y:-:*:*:*:*:*:*:*"), entry("cpe:2.3:a:x:y:1.0:*:*:*:*:*:*:*")]}]}]}
        self.assertEqual(match_cve(cve, "x", "y", "1.0"), "exact")


class Software(unittest.TestCase):
    def test_items_and_skips(self):
        host = {"ports": [
            {"port": 53, "service": "domain", "product": "dnsmasq", "version": "2.78",
             "cpes": ["cpe:/a:thekelleys:dnsmasq:2.78"]},
            {"port": 445, "service": "netbios-ssn", "product": "Samba smbd", "version": "3.X - 4.X",
             "cpes": ["cpe:/a:samba:samba"]},
            {"port": 49153, "service": "upnp", "product": "Portable SDK for UPnP devices", "version": "1.6.19",
             "cpes": ["cpe:/o:linux:linux_kernel:3.10.70"]},
            {"port": 80, "service": "http", "product": "Boa httpd", "version": "", "cpes": ["cpe:/a:boa:boa"]},
        ], "identity": {"make": "Linksys, LLC", "model": "WRT3200ACM", "firmware": None}}
        items, skipped = software_list(host, {"linux_kernel"}, Path("/nonexistent"))
        found = {(i["vendor"], i["product"], i["version"]) for i in items}
        self.assertEqual(found, {("thekelleys", "dnsmasq", "2.78"), ("libupnp_project", "libupnp", "1.6.19")})
        reasons = {s["product"]: s["reason"] for s in skipped}
        self.assertIn("3.X", reasons["samba:samba"])
        self.assertIn("OS kernel", reasons["linux:linux_kernel"])
        self.assertEqual(reasons["linksys:wrt3200acm_firmware"], "firmware version unknown")
        self.assertEqual(sum(s["product"] == "boa:boa" for s in skipped), 1)

    def test_helpers(self):
        self.assertEqual(first_token("10.0p2 Debian 7+deb13u4"), "10.0p2")
        self.assertIsNone(first_token(""))
        self.assertEqual(firmware_product({"make": "AXIS", "model": "AXIS M1014"}), ("axis", "m1014_firmware"))


class Nuclei(unittest.TestCase):
    def test_parse_version_extract(self):
        line = json.dumps({"template-id": "CVE-2026-4480", "ip": "192.168.1.1", "port": "445",
                           "matched-at": "192.168.1.1:445", "extracted-results": ["3.0.37"],
                           "info": {"name": "Samba", "severity": "critical", "tags": ["cve", "passive"],
                                    "classification": {"cve-id": ["cve-2026-4480"]},
                                    "metadata": {"vendor": "samba", "product": "samba"}}})
        f = nuclei.parse(line)[0]
        self.assertEqual((f["cve_ids"], f["port"], f["vendor"], f["extracted_version"]),
                         (["CVE-2026-4480"], 445, "samba", "3.0.37"))


if __name__ == "__main__":
    unittest.main()
