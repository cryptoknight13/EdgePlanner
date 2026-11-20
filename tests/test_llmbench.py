"""Phase 8c benchmark: fixed inputs from one run, per-model timings/validity, failures recorded, no secrets."""
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import attackplan
import llmbench
import llmconf
from tests.test_guide import A1, A2, write_run
from tests.test_llmconf import CFG, fake_cmd, free_port

LOCAL_BUDGET = {"context": 4096, "max_tokens": 512, "page_chars": 1500, "pages_total_chars": 6000,
                "cve_batch": 2, "timeout": 600}
EXAMPLE = attackplan.IEXAM / "input_data" / "test-network-simple"


def bench_run(root: Path) -> Path:
    run = write_run(root)
    shutil.rmtree(run / "iexam")
    shutil.copytree(EXAMPLE, run / "iexam")
    node = next(iter(json.loads((run / "iexam" / "node-data.json").read_text())))
    for a in (A1, A2):
        a["node"] = node
    mit = json.loads((run / "mitigation" / "mitigation.json").read_text())
    for o in mit["targets"][0]["options"]:
        for a in o["actions"]:
            a["node"] = node
    (run / "mitigation" / "mitigation.json").write_text(json.dumps(mit))
    (run / "cveinfo.json").write_text(json.dumps({"cves": {
        f"CVE-{n}": {"cwes": ["CWE-79"], "description": f"flaw {n}", "cvss": {"score": 5.0}} for n in range(5)}}))
    (run / "plans").mkdir()
    (run / "plans" / "plans.json").write_text(json.dumps({"targets": [
        {"goal": "nobody"}, {"goal": "camera", "optimal": {"steps": ["(exploit n0 n1 cve-1)"], "highlights": {"cve_ids": []}}}]}))
    return run


class Bench(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.run_dir = bench_run(Path(tmp.name))
        self.log = Path(tmp.name) / "llm-server.log"
        self.port = free_port()
        self.cfg = {**CFG, "local": {**CFG["local"], "port": self.port, "budget": LOCAL_BUDGET},
                    "api": {**CFG["api"], "base_url": f"http://127.0.0.1:{self.port}/v1"}}
        self.inputs = [{"task": "guide", "id": "n1|system|x", "system": "s", "prompt": "p", "allowed": []},
                       {"task": "cve", "id": "CVE-0,CVE-1", "system": "s", "prompt": "p", "ids": ["CVE-0", "CVE-1"]},
                       {"task": "plan", "id": "camera", "system": None, "prompt": "p"}]

    def test_inputs_use_local_budget_and_cache_pages(self):
        calls = []

        def fetch(url):
            calls.append(url)
            return "x" * 4000, None

        inputs = llmbench.build_inputs(self.run_dir, LOCAL_BUDGET, fetch=fetch)
        self.assertEqual([i["task"] for i in inputs], ["cve", "cve", "plan", "guide", "guide"])
        self.assertEqual(inputs[0]["ids"], ["CVE-0", "CVE-1"])  # batches of cve_batch, first 4 by id
        self.assertEqual(inputs[2]["id"], "camera")  # first goal that has an optimal plan
        self.assertIn("(exploit n0 n1 cve-1)", inputs[2]["prompt"])
        texts = [b.split(":\n", 1)[1].strip() for b in inputs[3]["prompt"].split("\nSOURCE ")[1:]]
        self.assertTrue(texts and all(len(t) <= 1500 for t in texts))
        first = len(calls)
        llmbench.build_inputs(self.run_dir, LOCAL_BUDGET, fetch=fetch)
        self.assertEqual(len(calls), first)  # pages.json reused

    def test_score_is_strict_about_echoes(self):
        three = json.dumps({"how_it_blocks": "Upgrading removes the flaw.", "steps": ["Open it.", "Upload it.", "Check it."],
                            "links": []})
        two = json.dumps({"how_it_blocks": "Upgrading removes the flaw.", "steps": ["Open it.", "Upload it."], "links": []})
        g = {"allowed": []}
        self.assertEqual((llmbench.score("guide", three, g), llmbench.score("guide", two, g)), (True, False))
        steps = "1. (attacker-has-access-to-router router attacker1)\n2. (attacker-exploit-cve-1-to-compromise-cam cam router)"
        prose = steps + "\nThe attacker first reaches the router from the internet, then uses the UPnP flaw on the camera " \
                        "to run its own code there and take it over completely."
        self.assertEqual((llmbench.score("plan", steps, {}), llmbench.score("plan", prose, {})), (False, True))

    def test_api_keeps_its_own_output_limit(self):
        cfg = {**self.cfg, "api": {**self.cfg["api"], "budget": {"max_tokens": 4096, "timeout": 120}}}
        seen = []
        with mock.patch.object(llmbench.llmconf, "_config", return_value=cfg), \
                mock.patch.dict(os.environ, {"NVIDIA_API_KEY": "k"}), \
                mock.patch.object(llmbench, "bench_model", side_effect=lambda s, *a, **k: seen.append(s) or {"model": "x"}):
            llmbench.run(self.run_dir, [], api=True, repeat=1, fetch=lambda u: ("page", None))
        self.assertEqual((seen[0]["budget"]["max_tokens"], seen[0]["budget"]["timeout"]), (4096, 120))

    def test_host_names_the_cpu(self):
        self.assertNotIn(llmbench._host("/nope")["cpu"], (None, "", "-"))

    def test_bench_model_records_timings_validity_and_stops_server(self):
        s = llmconf.settings(self.cfg)
        r = llmbench.bench_model(s, self.inputs, self.log, repeat=1, command=fake_cmd(self.port))
        self.assertEqual(r["status"], "ok")
        by = {x["task"]: x for x in r["results"]}
        self.assertEqual((by["guide"]["prompt_tokens"], by["guide"]["output_tps"], by["guide"]["valid"]), (100, 5.0, True))
        self.assertFalse(by["cve"]["valid"])  # a guide JSON is not a CVE map
        self.assertTrue(by["plan"]["valid"])  # non-empty text
        self.assertGreater(r["memory_mb"]["peak"], 1)
        self.assertGreater(r["load_seconds"], 0)
        self.assertEqual(llmconf._healthy(self.port), False)  # stopped

    def test_model_that_dies_mid_bench_is_failed(self):
        s = llmconf.settings(self.cfg)
        with mock.patch.object(llmbench, "_chat", side_effect=llmbench.requests.ConnectionError("connection refused")):
            r = llmbench.bench_model(s, self.inputs, self.log, repeat=1, command=fake_cmd(self.port))
        self.assertEqual(r["status"], "failed")
        self.assertIn("connection refused", r["error"])

    def test_dead_model_is_recorded_and_bench_continues(self):
        port = self.port

        def command_for(s):
            return fake_cmd(port, "--die") if s["model"] == "qwen3-0.6b" else fake_cmd(port)

        cfg = {**self.cfg, "models": {**CFG["models"], "gemma3-270m": {"file": "/nope/g.gguf"}}}
        with mock.patch.object(llmbench.llmconf, "_config", return_value=cfg):
            out = llmbench.run(self.run_dir, ["qwen3-0.6b", "gemma3-270m"], api=False, repeat=1,
                               fetch=lambda u: ("page", None), command_for=command_for)
        self.assertEqual([m["status"] for m in out["models"]], ["failed", "ok"])
        self.assertIn("out of memory", out["models"][0]["error"])
        saved = sorted((self.run_dir / "llmbench").glob("*Z.json"))
        self.assertEqual(len(saved), 1)
        self.assertEqual(json.loads(saved[0].read_text())["schema_version"], "1.0")
        self.assertEqual(out["budget"], LOCAL_BUDGET)
        self.assertIn("ram_mb", out["host"])

    def test_api_baseline_uses_local_budget_and_record_has_no_secret(self):
        # The fake server stands in for the API too; the key must reach the header, never the record.
        import subprocess
        import sys
        proc = subprocess.Popen(fake_cmd(self.port), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(proc.wait)
        self.addCleanup(proc.terminate)
        import time
        while not llmconf._healthy(self.port):
            time.sleep(0.1)
        with mock.patch.object(llmbench.llmconf, "_config", return_value=self.cfg), \
                mock.patch.dict(os.environ, {"NVIDIA_API_KEY": "sekrit"}):
            out = llmbench.run(self.run_dir, [], api=True, repeat=1, fetch=lambda u: ("page", None))
        api = out["models"][0]
        self.assertEqual((api["provider"], api["status"]), ("api", "ok"))
        self.assertTrue(all(r["output_tps"] is None for r in api["results"]))  # usage only for the API
        self.assertNotIn("sekrit", json.dumps(out))
        self.assertNotIn("sekrit", "".join(p.read_text() for p in (self.run_dir / "llmbench").glob("*.json")))


if __name__ == "__main__":
    unittest.main()
