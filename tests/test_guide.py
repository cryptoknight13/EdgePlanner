"""Phase 8b fix guides: action keys, links, page text, fetch limits, LLM reply checks, run caching."""
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from mitigate import guide

A1 = {"node": "n2", "fact": "system", "token": "axis-fw", "text": "Upgrade AXIS firmware on cam (192.168.1.183)",
      "installed": ["axis 5.40"], "target_version": "5.51", "evidence": [
          {"cve": "CVE-1", "nvd": "https://nvd/1", "advisories": ["https://axis/adv"], "fix_commits": []},
          {"cve": "CVE-2", "nvd": "https://nvd/2", "advisories": ["https://axis/adv"], "fix_commits": ["https://git/c1"]}]}
A2 = {"node": "n2", "fact": "driver", "token": "upnp", "text": "Close or firewall upnp service on cam",
      "ports": [49153], "evidence": [{"cve": "CVE-3", "nvd": "https://nvd/3", "advisories": [], "fix_commits": []}]}
GOOD = json.dumps({"how_it_blocks": "Blocks the attack.", "steps": ["Open the page."], "links": [{"title": "Axis", "url": "https://axis/adv"}]})


class FakeResp(io.BytesIO):
    def __init__(self, body: bytes, ctype: str):
        super().__init__(body)
        self.headers = mock.Mock(get_content_type=lambda: ctype, get_content_charset=lambda: "utf-8")
        self.reads = []

    def read(self, n=-1):
        self.reads.append(n)
        return super().read(n)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class Helpers(unittest.TestCase):
    def test_unique_actions_dedupes_across_options(self):
        t = {"options": [{"actions": [A1]}, {"actions": [A1, A2]}]}
        self.assertEqual(list(guide.unique_actions(t)), ["n2|system|axis-fw", "n2|driver|upnp"])

    def test_links_order_dedupe_cap(self):
        self.assertEqual(guide.links_for(A1), ["https://axis/adv", "https://git/c1", "https://nvd/1", "https://nvd/2"])
        many = {"evidence": [{"nvd": f"https://nvd/{i}", "advisories": [], "fix_commits": []} for i in range(12)]}
        self.assertEqual(len(guide.links_for(many)), 8)

    def test_html_to_text(self):
        t = guide.html_to_text("<html><style>x{}</style><script>bad()</script><h1>Fix</h1>  <p>Upgrade\n to 5.51</p></html>")
        self.assertEqual(t, "Fix Upgrade to 5.51")
        self.assertEqual(len(guide.html_to_text("<p>" + "a " * 5000 + "</p>")), 4000)

    def test_fetch_rejects_non_http(self):
        self.assertEqual(guide.fetch("file:///etc/passwd"), (None, "scheme file"))

    def test_fetch_rejects_non_text(self):
        with mock.patch.object(guide.urllib.request, "urlopen", return_value=FakeResp(b"%PDF", "application/pdf")):
            self.assertEqual(guide.fetch("https://x/a.pdf"), (None, "content-type application/pdf"))

    def test_fetch_reads_at_most_200kb(self):
        resp = FakeResp(b"<p>" + b"a" * 300_000 + b"</p>", "text/html")
        with mock.patch.object(guide.urllib.request, "urlopen", return_value=resp):
            text, reason = guide.fetch("https://x/big")
        self.assertEqual((reason, resp.reads), (None, [200_000]))
        self.assertEqual(len(text), 4000)

    def test_fetch_network_error_is_a_reason(self):
        with mock.patch.object(guide.urllib.request, "urlopen", side_effect=OSError("timed out")):
            self.assertEqual(guide.fetch("https://x/"), (None, "timed out"))

    def test_parse_guide_filters_links_and_caps(self):
        reply = ('Sure! <think>hmm</think>```json\n{"how_it_blocks": "Blocks it.", "steps": ["Open it."], "links": ['
                 '{"title": "Axis", "url": "https://axis/adv"}, {"title": "Made up", "url": "https://evil/x"},'
                 '{"title": "Redirected", "url": "https://axis/adv?r=1"}]}```')
        g = guide.parse_guide(reply, {"https://axis/adv"})
        self.assertEqual(g["links"], [{"title": "Axis", "url": "https://axis/adv"}])
        long = '{"how_it_blocks": "' + "b" * 900 + '", "steps": ' + json.dumps(["s" * 300] * 9) + ', "links": []}'
        g = guide.parse_guide(long, set())
        self.assertEqual((len(g["how_it_blocks"]), len(g["steps"]), len(g["steps"][0])), (400, 6, 200))

    def test_parse_guide_clips_at_a_sentence(self):
        reply = json.dumps({"how_it_blocks": "First sentence. " + "word " * 100, "steps": ["Open it."], "links": []})
        self.assertEqual(guide.parse_guide(reply, set())["how_it_blocks"], "First sentence.")

    def test_parse_guide_rejects_bad_shape(self):
        for bad in ("no json here", '{"how_it_blocks": "x", "steps": "one string", "links": []}',
                    '{"how_it_blocks": "x", "steps": ["a"], "links": ["https://axis/adv"]}',
                    '{"steps": ["a"], "links": []}', '{"how_it_blocks": "x", "steps": [], "links": []}'):
            with self.assertRaises(ValueError, msg=bad):
                guide.parse_guide(bad, {"https://axis/adv"})


def write_run(root: Path) -> Path:
    run = root / "20261020T000000Z"
    (run / "mitigation").mkdir(parents=True)
    (run / "iexam").mkdir()
    (run / "mitigation" / "mitigation.json").write_text(json.dumps({"targets": [
        {"goal": "camera", "unreachable": False, "options": [{"actions": [A1]}, {"actions": [A1, A2]}]},
        {"goal": "router", "unreachable": True, "options": []}]}))
    (run / "iexam" / "node-data.json").write_text(json.dumps({"n2": {"name": "cam", "IP": "192.168.1.183", "label": "camera"}}))
    (run / "cveinfo.json").write_text(json.dumps({"cves": {"CVE-1": {"cvss": {"score": 9.8}, "description": "overflow"}}}))
    return run


class Run(unittest.TestCase):
    def setUp(self):
        env = mock.patch.dict(os.environ, {"NVIDIA_API_KEY": "test"})
        env.start()
        self.addCleanup(env.stop)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.run_dir = write_run(Path(tmp.name))

    def test_run_writes_one_guide_per_unique_action_and_skips_cached(self):
        calls = []

        def ask(prompt):
            calls.append(prompt)
            return GOOD

        def fetch(url):
            return ("page text", None) if "axis" in url else (None, "HTTP 404")

        out = guide.run(self.run_dir, "camera", fetch=fetch, ask=ask)
        self.assertEqual(len(calls), 2)
        g = out["guides"]["n2|system|axis-fw"]
        self.assertEqual((g["goal"], g["links"], g["no_sources"]), ("camera", [{"title": "Axis", "url": "https://axis/adv"}], False))
        self.assertIn({"url": "https://nvd/1", "status": "failed", "reason": "HTTP 404"}, g["sources"])
        self.assertIn({"url": "https://axis/adv", "status": "fetched"}, g["sources"])
        self.assertTrue(out["guides"]["n2|driver|upnp"]["no_sources"])
        self.assertEqual(out["guides"]["n2|driver|upnp"]["links"], [])  # nothing fetched, so no link survives
        guide.run(self.run_dir, "camera", fetch=fetch, ask=ask)
        self.assertEqual(len(calls), 2)  # cached
        saved = json.loads((self.run_dir / "mitigation" / "guide.json").read_text())
        self.assertEqual(saved["guides"].keys(), out["guides"].keys())
        self.assertNotIn("test", json.dumps(saved))  # the key never reaches the file

    def test_run_bad_reply_records_note_and_continues(self):
        replies = iter(["not json", GOOD])
        out = guide.run(self.run_dir, "camera", fetch=lambda u: ("t", None), ask=lambda p: next(replies))
        self.assertEqual(list(out["guides"]), ["n2|driver|upnp"])
        self.assertTrue(any("n2|system|axis-fw" in n for n in out["notes"]))

    def test_run_unknown_or_unreachable_goal(self):
        for goal in ("nope", "router"):
            with self.assertRaises(ValueError):
                guide.run(self.run_dir, goal, fetch=lambda u: ("t", None), ask=lambda p: GOOD)

    def test_run_without_key(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(ValueError, "NVIDIA_API_KEY"):
                guide.run(self.run_dir, "camera", fetch=lambda u: ("t", None), ask=lambda p: GOOD)

    def test_local_budget_caps_page_text(self):
        prompts = []
        budget = {"max_tokens": 512, "page_chars": 1500, "pages_total_chars": 6000, "timeout": 600}
        many = {**A1, "evidence": [{"cve": f"CVE-{i}", "nvd": f"https://nvd/{i}", "advisories": [], "fix_commits": []}
                                   for i in range(8)]}
        mit = self.run_dir / "mitigation" / "mitigation.json"
        mit.write_text(json.dumps({"targets": [{"goal": "camera", "unreachable": False, "options": [{"actions": [many]}]}]}))
        local = {"provider": "local", "budget": budget, "model": "m", "no_think": False}
        with mock.patch.object(guide.llmconf, "settings", return_value=local), \
                mock.patch.object(guide.llmconf, "configured", return_value=True):
            guide.run(self.run_dir, "camera", fetch=lambda u: ("<p>" + "x" * 4000 + "</p>", None),
                      ask=lambda p: prompts.append(p) or GOOD)
        blocks = prompts[0].split("\nSOURCE ")[1:]
        texts = [b.split(":\n", 1)[1].strip() for b in blocks]
        self.assertTrue(all(len(t) <= 1500 for t in texts))
        self.assertLessEqual(sum(map(len, texts)), 6000)
        self.assertEqual(len(texts), 4)  # 4 x 1500 fills the 6000 total

    def test_prompt_lists_at_most_8_cves_highest_cvss_first(self):
        ev = [{"cve": f"CVE-{i}", "nvd": "", "advisories": [], "fix_commits": []} for i in range(30)]
        cves = {f"CVE-{i}": {"cvss": {"score": i % 10}, "description": "d" * 1000} for i in range(30)}
        p = guide.build_prompt({**A1, "evidence": ev}, {"name": "cam"}, cves, [])
        listed = [l for l in p.splitlines() if l.startswith("- CVE-")]
        self.assertEqual(len(listed), 8)
        scores = [int(l.split("CVSS ")[1].split(")")[0]) for l in listed]
        self.assertEqual(scores, [9, 9, 9, 8, 8, 8, 7, 7])
        self.assertIn("and 22 more", p)
        self.assertLess(len(p), 8 * 260 + 600)

    def test_parse_guide_rejects_placeholder_echo(self):
        echo = '{"how_it_blocks": "...", "steps": ["..."], "links": [{"title": "...", "url": "..."}]}'
        with self.assertRaises(ValueError):
            guide.parse_guide(echo, set())

    def test_prompt_has_device_versions_cves_and_pages(self):
        p = guide.build_prompt(A1, {"name": "cam", "IP": "192.168.1.183", "label": "camera"},
                               {"CVE-1": {"cvss": {"score": 9.8}, "description": "overflow"}},
                               [("https://axis/adv", "Upgrade to 5.51")])
        for s in ("cam", "192.168.1.183", "camera", "axis 5.40", "5.51", "CVE-1", "overflow",
                  "https://axis/adv", "Upgrade to 5.51", A1["text"]):
            self.assertIn(s, p)


if __name__ == "__main__":
    unittest.main()
