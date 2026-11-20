"""CVE info self-checks: NVD facts, fixed versions, OSV fixes, patch commits, LLM reply parsing."""
import unittest

from cveinfo import facts, llm, patches

NVD = {
    "id": "CVE-2020-25681", "published": "2021-01-20T17:15:00", "vulnStatus": "Analyzed",
    "descriptions": [{"lang": "en", "value": "A heap-based buffer overflow in dnsmasq."}],
    "metrics": {"cvssMetricV31": [{"type": "Primary", "exploitabilityScore": 2.2, "impactScore": 5.9,
                                   "cvssData": {"version": "3.1", "baseScore": 8.1, "baseSeverity": "HIGH",
                                                "vectorString": "CVSS:3.1/AV:N/AC:H", "attackVector": "NETWORK"}}]},
    "weaknesses": [{"description": [{"value": "CWE-122"}, {"value": "NVD-CWE-noinfo"}]}],
    "references": [{"url": "https://github.com/lighttpd/lighttpd1.4/commit/32120d5b8b32", "tags": ["Patch"]},
                   {"url": "https://bugzilla.redhat.com/show_bug.cgi?id=1", "tags": ["Patch"]}],
    "configurations": [{"nodes": [{"cpeMatch": [
        {"vulnerable": True, "criteria": "cpe:2.3:a:thekelleys:dnsmasq:*:*:*:*:*:*:*:*", "versionEndExcluding": "2.83"},
        {"vulnerable": True, "criteria": "cpe:2.3:a:other:thing:*:*:*:*:*:*:*:*", "versionEndIncluding": "9"}]}]}],
}
OSV = {"id": "CVE-2016-6255", "aliases": ["GHSA-x"],
       "references": [{"type": "FIX", "url": "https://example.org/fix"}],
       "affected": [{"package": {"name": "pupnp", "ecosystem": "GIT"},
                     "ranges": [{"type": "GIT", "repo": "https://github.com/pupnp/pupnp.git",
                                 "events": [{"introduced": "0"}, {"fixed": "be0a01bdb833"}]}]}]}


class Facts(unittest.TestCase):
    def test_nvd_facts(self):
        f = facts.nvd_facts(NVD)
        self.assertEqual((f["cvss"]["score"], f["cvss"]["attack_vector"], f["cwes"]), (8.1, "NETWORK", ["CWE-122"]))
        self.assertEqual(f["description"], "A heap-based buffer overflow in dnsmasq.")

    def test_fixed_in_only_our_product(self):
        self.assertEqual(facts.fixed_in(NVD, "thekelleys", "dnsmasq"),
                         [{"version": "2.83", "kind": "fixed_in", "source": "nvd"}])

    def test_osv_and_commits(self):
        o = facts.osv_facts(OSV)
        self.assertEqual(o["fixes"][0]["fixed"], "be0a01bdb833")
        commits = facts.patch_commits(facts.nvd_facts(NVD)["references"] + o["references"], o["fixes"])
        urls = {c["url"] for c in commits}
        self.assertIn("https://github.com/pupnp/pupnp/commit/be0a01bdb833", urls)
        self.assertIn("https://github.com/lighttpd/lighttpd1.4/commit/32120d5b8b32", urls)
        self.assertNotIn("https://bugzilla.redhat.com/show_bug.cgi?id=1", urls)
        self.assertEqual(patches.patch_url(next(c for c in commits if "pupnp" in c["url"])),
                         "https://github.com/pupnp/pupnp/commit/be0a01bdb833.patch")

    def test_product_tokens(self):
        self.assertEqual(facts.product_tokens(["libupnp", "m1014_firmware"]), {"libupnp", "upnp", "m1014"})
        self.assertEqual(facts.osv_facts(None)["fixes"], [])


LOCAL = {"provider": "local", "base_url": "http://127.0.0.1:8091/v1", "model": "qwen3-0.6b", "model_key": "qwen3-0.6b",
         "api_key": None, "no_think": True, "budget": {"max_tokens": 512, "cve_batch": 2, "timeout": 600}}


class LLMProvider(unittest.TestCase):
    def test_batch_size_and_extra_body_follow_the_provider(self):
        import tempfile
        from pathlib import Path
        from unittest import mock
        posts = []

        def post(url, json=None, **kw):
            posts.append((url, json, kw))
            ids = [line.split(" ")[0] for line in json["messages"][1]["content"].split("\n\n")]
            reply = {i: {"cause": "c", "consequence": "q"} for i in ids}
            return mock.Mock(status_code=200, json=lambda: {"choices": [{"message": {"content": __import__("json").dumps(reply)}}]},
                             raise_for_status=lambda: None)

        items = [{"id": f"CVE-{n}", "cwes": [], "description": "d"} for n in range(5)]
        with tempfile.TemporaryDirectory() as t, mock.patch.object(llm.llmconf, "settings", return_value=LOCAL), \
                mock.patch.object(llm.requests, "post", side_effect=post):
            out = llm.explain(items, Path(t) / "cache.json", [])
        self.assertEqual(len(out), 5)
        self.assertEqual(len(posts), 3)
        url, body, kw = posts[0]
        self.assertTrue(url.startswith("http://127.0.0.1:8091/v1"))
        self.assertEqual((body["model"], body["max_tokens"], body["chat_template_kwargs"], kw["timeout"]),
                         ("qwen3-0.6b", 512, {"enable_thinking": False}, 600))
        self.assertNotIn("Authorization", kw.get("headers", {}))

    def test_unresponsive_local_model_stops_the_batch_loop(self):
        import tempfile
        from pathlib import Path
        from unittest import mock
        calls = []

        def post(*a, **kw):
            calls.append(1)
            raise llm.requests.Timeout("read timed out")

        items = [{"id": f"CVE-{n}", "cwes": [], "description": "d"} for n in range(6)]
        notes = []
        with tempfile.TemporaryDirectory() as t, mock_settings(LOCAL), mock.patch.object(llm.requests, "post", side_effect=post):
            self.assertEqual(llm.explain(items, Path(t) / "cache.json", notes), {})
        self.assertEqual(len(calls), 1)  # not 6 more per-CVE timeouts
        self.assertTrue(any("local model stopped responding" in n for n in notes))

    def test_cache_is_per_model(self):
        with mock_settings(LOCAL):
            self.assertEqual(llm.model(), "qwen3-0.6b")


def mock_settings(s):
    from unittest import mock
    return mock.patch.object(llm.llmconf, "settings", return_value=s)


class LLMParse(unittest.TestCase):
    def test_parse_with_think_and_fence(self):
        reply = ('<think>reasoning</think>```json\n{"cve-2020-25681": {"cause": "Heap overflow.", '
                 '"consequence": "Remote code execution."}, "CVE-1": {"cause": 3}}\n```')
        self.assertEqual(llm.parse(reply), {"CVE-2020-25681": {"cause": "Heap overflow.",
                                                               "consequence": "Remote code execution."}})

    def test_parse_rejects_non_json(self):
        with self.assertRaises(ValueError):
            llm.parse("sorry, I cannot help")


if __name__ == "__main__":
    unittest.main()
