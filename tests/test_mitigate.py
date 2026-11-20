"""Phase 8 mitigation: grouping, option parsing, action mapping, fact removal; iEXAM example end to end."""
import importlib.util
import shutil
import tempfile
import unittest
from pathlib import Path

import attackplan
import mitigate

EXAMPLE = attackplan.IEXAM / "input_data" / "test-network-simple"
PLANNERS = (attackplan.IEXAM / "Backend" / "downward" / "builds" / "release" / "bin" / "downward").exists()
# Metric 1 scripts run under sys.executable and import openai (the project venv has it).
OPENAI = importlib.util.find_spec("openai") is not None

NODES = {"n1": {"name": "router", "IP": "192.168.1.1"}}
CVES = {
    "CVE-A": {"installed_version": "samba", "driver": "netbios-ssn service", "versions": ["samba 3.0.37"], "ports": [139]},
    "CVE-B": {"installed_version": "samba", "driver": "netbios-ssn service", "versions": ["samba 3.0.37"], "ports": [139]},
    "CVE-C": {"installed_version": "dnsmasq", "driver": "domain service", "versions": ["dnsmasq 2.78"], "ports": [53]},
}
CIN = {"n1": ["CVE-A", "CVE-B", "CVE-C"]}
INFO = {
    "CVE-A": {"fixed": {"nvd": [{"kind": "fixed_in", "version": "4.9.0"}]},
              "affects": [{"ip": "192.168.1.1", "port": 139, "product": "samba", "version": "3.0.37"}],
              "patches": [{"url": "https://x/commit/1", "for_our_product": True}]},
    "CVE-B": {"fixed": {"nvd": [{"kind": "fixed_in", "version": "4.10.2"}, {"kind": "fixed_in", "version": "3.6.1"}]}},
}


class Units(unittest.TestCase):
    def test_group_keeps_one_cve_per_product_and_service(self):
        self.assertEqual(mitigate.group_cves(CIN, CVES), {"n1": ["CVE-A", "CVE-C"]})

    def test_parse_option(self):
        raw = "{'has-initial-state-has-n3-driver-1-dot-1 upnp-service', 'has-initial-state-has-n3-system-2-dot-1 axis-m1014-firmware'}"
        self.assertEqual(mitigate.parse_option(raw),
                         [("n3", "driver", "upnp-service"), ("n3", "system", "axis-m1014-firmware")])
        self.assertEqual(mitigate.parse_option("not a set"), [])

    def test_upgrade_targets_highest_fix_across_group(self):
        a = mitigate.action("n1", "system", "samba", NODES, CIN, CVES, INFO)
        self.assertEqual(a["type"], "upgrade")
        self.assertEqual(a["cves_fixed"], 2)
        self.assertEqual(a["target_version"], "4.10.2")  # numeric, not lexical: 4.10.2 > 4.9.0
        self.assertEqual(a["installed"], ["samba 3.0.37"])
        self.assertIn("from samba 3.0.37 to 4.10.2 or later", a["text"])
        self.assertEqual(a["evidence"][0]["fix_commits"], ["https://x/commit/1"])

    def test_upgrade_without_fix_says_so(self):
        a = mitigate.action("n1", "system", "dnsmasq", NODES, CIN, CVES, {})
        self.assertIsNone(a["target_version"])
        self.assertIn("no fixed version is published", a["text"])

    def test_close_service(self):
        a = mitigate.action("n1", "driver", "domain-service", NODES, CIN, CVES, {})
        self.assertEqual((a["type"], a["ports"]), ("close", [53]))
        self.assertEqual(a["text"], "Close or firewall domain service (port 53) on router (192.168.1.1)")

    def test_without_removes_every_matching_fact_only_on_that_node(self):
        problem = ("(has-n1-system-1-dot-1 samba)\n(has-n1-system-2-dot-1 samba)\n"
                   "(has-n12-system-1-dot-1 samba)\n(has-n1-driver-1-dot-1 netbios-ssn-service)\n")
        self.assertEqual(mitigate._without(problem, [("n1", "system", "samba")]),
                         "(has-n12-system-1-dot-1 samba)\n(has-n1-driver-1-dot-1 netbios-ssn-service)\n")


class GoalLookup(unittest.TestCase):
    """Device names with dots or symbols: the PDDL holds curate.pddl_token(name), the lookup must find it."""

    def test_names_with_dots_and_symbols(self):
        from api.services.acg import plan_service
        from api.services.acg.pddl_service import curate
        names = ["Amazon speaker (.114)", "alphapd/2.1.6", "AXIS M1014", "Wink Hub 2 (.120)"]
        goal = "(:goal (and " + " ".join(f"(exploited-system attacker1 {curate.pddl_token(n)})" for n in names) + "))"
        problem = f"(define (problem p) (:domain d) (:init) {goal})"
        for n in names:
            out = plan_service._replace_goal_block(problem, n)
            self.assertIn(curate.pddl_token(n), out[out.index("(:goal"):], n)
            self.assertEqual(out.count("exploited-system"), 1, n)  # only that goal remains


@unittest.skipUnless(PLANNERS and OPENAI, "needs built planners and the project venv")
class Example(unittest.TestCase):
    def test_simple_network(self):
        with tempfile.TemporaryDirectory() as t:
            run_dir = Path(t) / "20260101T000000Z"
            shutil.copytree(EXAMPLE, run_dir / "iexam")
            result = mitigate.run(run_dir, ["Admin Server"])
        opts = result["targets"][0]["options"]
        self.assertTrue(opts)
        for o in opts:
            self.assertTrue(o["blocks_all_plans"])
            self.assertTrue(o["actions"])
            self.assertTrue(all(a["node_name"] == "Admin Server" for a in o["actions"]))


if __name__ == "__main__":
    unittest.main()
