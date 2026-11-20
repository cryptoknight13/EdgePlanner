"""iEXAM export self-checks on a synthetic run (same fixture as the web tests)."""
import json
import tempfile
import unittest
from pathlib import Path

from export import export, keep_reason, product_name
from tests.test_web import write_run


def add_cveinfo(run_dir: Path) -> None:
    (run_dir / "cveinfo.json").write_text(json.dumps({"cves": {
        "CVE-1": {"cvss": {"score": 10.0, "attack_vector": "NETWORK", "vector": "AV:N"}, "cwes": ["CWE-121"],
                  "explanation": {"cause": "Stack overflow.", "consequence": "Code execution.", "model": "m"},
                  "fixed": {"nvd": [{"version": "1.6.18", "kind": "fixed_in"}]}, "exploit": {"kev": None}},
        "CVE-2": {"cvss": {"score": 5.0, "attack_vector": "LOCAL"}},
    }, "notes": []}))


class Export(unittest.TestCase):
    def test_files(self):
        with tempfile.TemporaryDirectory() as t:
            d = write_run(Path(t))
            add_cveinfo(d)
            f = export(d, "0.0.0.0", {})
        nodes, mf = f["node-data"], f["manifest"]
        # Router has no CVE in the fixture, so only the attacker and the camera remain.
        self.assertEqual(sorted(nodes), ["n0", "n1"])
        self.assertEqual(nodes["n0"]["name"], "Attacker")
        self.assertEqual(nodes["n1"]["IP"], "192.168.1.183")
        self.assertEqual(f["cve-in-node"], {"n1": ["CVE-1"]})
        self.assertEqual(f["connectivity-edge"], {})
        rec = f["cve-data"]["CVE-1"]
        self.assertEqual((rec["installed_version"], rec["cvss_score"], rec["fixed_in"]), ("libupnp", 10.0, ["1.6.18"]))
        self.assertEqual(rec["driver"], "port 49152 service")
        self.assertEqual(rec["vulnerability"], "Stack overflow.")
        self.assertNotIn("cause", rec)  # LLM text never becomes a PDDL fact
        self.assertIn("gateway router has no kept CVE", mf["notes"][0])
        reasons = {x["ip"]: x["reason"] for x in mf["excluded_nodes"]}
        self.assertEqual(reasons, {"192.168.1.1": "no known CVE", "192.168.1.192": "this monitoring machine"})

    def test_filters(self):
        row = {"weak": False, "cvss": 5.0, "public_exploit": False}
        self.assertIsNone(keep_reason(row, {"cvss": {"attack_vector": "ADJACENT_NETWORK"}}, {}))
        self.assertIn("local", keep_reason(row, {"cvss": {"attack_vector": "LOCAL"}}, {}))
        self.assertIn("weak", keep_reason({**row, "weak": True}, {}, {}))
        self.assertIsNone(keep_reason({**row, "weak": True}, {}, {"include_weak": True}))
        self.assertIn("min_cvss", keep_reason(row, {}, {"min_cvss": 7}))
        self.assertIn("exploit", keep_reason(row, {}, {"require_public_exploit": True}))

    def test_product_name(self):
        self.assertEqual(product_name({"vendor": "axis", "product": "m1014_firmware"}), "axis m1014 firmware")
        self.assertEqual(product_name({"vendor": "thekelleys", "product": "dnsmasq"}), "dnsmasq")


if __name__ == "__main__":
    unittest.main()
