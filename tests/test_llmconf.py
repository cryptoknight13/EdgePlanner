"""Phase 8c: LLM provider resolution, extra request fields, env export for iEXAM, local server lifecycle."""
import json
import os
import socket
import sys
import tempfile
import time
import unittest
import urllib.request
from pathlib import Path
from unittest import mock

import llmconf

CFG = {"provider": "local",
       "api": {"base_url": "https://nv/v1", "model": "big", "budget": {"max_tokens": 4096, "cve_batch": 8, "timeout": 120}},
       "local": {"server": "/nope/llama-server", "model": "qwen3-0.6b", "port": 8091, "threads": 4,
                 "budget": {"context": 4096, "max_tokens": 512, "cve_batch": 2}},
       "models": {"qwen3-0.6b": {"file": "/nope/q.gguf", "no_think": True}, "gemma3-270m": {"file": "/nope/g.gguf"}}}
API = {**CFG, "provider": "api"}


class Resolve(unittest.TestCase):
    def test_local_ignores_env_base_url(self):
        with mock.patch.dict(os.environ, {"LLM_BASE_URL": "https://integrate.api.nvidia.com/v1", "LLM_MODEL": "x",
                                          "NVIDIA_API_KEY": "k"}):
            s = llmconf.settings(CFG)
        self.assertEqual((s["provider"], s["base_url"], s["model"], s["api_key"], s["budget"]["cve_batch"]),
                         ("local", "http://127.0.0.1:8091/v1", "qwen3-0.6b", None, 2))

    def test_api_env_overrides_and_key(self):
        with mock.patch.dict(os.environ, {"LLM_BASE_URL": "https://other/v1", "NVIDIA_API_KEY": "k"}, clear=True):
            s = llmconf.settings(API)
            self.assertEqual((s["base_url"], s["model"], s["api_key"], s["budget"]["cve_batch"]),
                             ("https://other/v1", "big", "k", 8))
            self.assertTrue(llmconf.configured(s))
        with mock.patch.dict(os.environ, {"NVIDIA_API_KEY": ""}, clear=True):
            s = llmconf.settings(API)
            self.assertFalse(llmconf.configured(s))
            self.assertIn("NVIDIA_API_KEY", llmconf.not_configured_hint(s))

    def test_local_configured_needs_server_and_model_files(self):
        s = llmconf.settings(CFG)
        self.assertFalse(llmconf.configured(s))
        self.assertIn("fetch_model.sh qwen3-0.6b", llmconf.not_configured_hint(s))
        with tempfile.TemporaryDirectory() as t:
            server, model = Path(t) / "llama-server", Path(t) / "q.gguf"
            server.write_text(""), model.write_text("")
            cfg = {**CFG, "local": {**CFG["local"], "server": str(server)},
                   "models": {**CFG["models"], "qwen3-0.6b": {"file": str(model)}}}
            self.assertTrue(llmconf.configured(llmconf.settings(cfg)))

    def test_relative_paths_are_under_the_project(self):
        cfg = {**CFG, "local": {**CFG["local"], "server": "tools/x"}, "models": {"qwen3-0.6b": {"file": "models/q.gguf"}}}
        s = llmconf.settings(cfg)
        self.assertEqual((s["server"], s["model_file"]), (str(llmconf.ROOT / "tools/x"), str(llmconf.ROOT / "models/q.gguf")))

    def test_server_args_from_settings(self):
        cfg = {**CFG, "local": {**CFG["local"], "server_args": ["-np", 1, "-nr"]}}
        self.assertEqual(llmconf.settings(cfg)["server_args"], ["-np", "1", "-nr"])
        self.assertEqual(llmconf.settings(CFG)["server_args"], [])

    def test_extra_body(self):
        self.assertEqual(llmconf.extra_body(llmconf.settings(CFG)), {"chat_template_kwargs": {"enable_thinking": False}})
        other = {**CFG, "local": {**CFG["local"], "model": "gemma3-270m"}}
        self.assertEqual(llmconf.extra_body(llmconf.settings(other)), {})
        self.assertEqual(llmconf.extra_body(llmconf.settings(API)), {"reasoning_effort": "low"})

    def test_export_env_local(self):
        with mock.patch.dict(os.environ, {"LLM_BASE_URL": "https://integrate.api.nvidia.com/v1"}):
            llmconf.export_env(llmconf.settings(CFG))
            self.assertEqual((os.environ["LLM_BASE_URL"], os.environ["LLM_MODEL"], os.environ["LLM_API_KEY"],
                              os.environ["LLM_MAX_TOKENS"], json.loads(os.environ["LLM_EXTRA_BODY"])),
                             ("http://127.0.0.1:8091/v1", "qwen3-0.6b", "local", "512",
                              {"chat_template_kwargs": {"enable_thinking": False}}))

    def test_export_env_api_keeps_key_out_of_new_vars(self):
        with mock.patch.dict(os.environ, {"NVIDIA_API_KEY": "sekrit"}, clear=True):
            llmconf.export_env(llmconf.settings(API))
            self.assertEqual(os.environ["LLM_BASE_URL"], "https://nv/v1")
            self.assertNotIn("LLM_API_KEY", os.environ)
            self.assertNotIn("LLM_MAX_TOKENS", os.environ)  # iEXAM keeps its own limits (16384 / 4096), as before

    def test_export_env_api_after_local_restores_api(self):
        with mock.patch.dict(os.environ, {"NVIDIA_API_KEY": "sekrit"}, clear=True):
            llmconf.export_env(llmconf.settings(CFG))
            llmconf.export_env(llmconf.settings(API))
            self.assertEqual(os.environ["LLM_PROVIDER"], "api")
            self.assertNotIn("LLM_MAX_TOKENS", os.environ)
            self.assertNotIn("LLM_API_KEY", os.environ)

    def test_unknown_provider_or_model(self):
        for bad in ({**CFG, "provider": "cloud"}, {**CFG, "local": {**CFG["local"], "model": "nope"}}):
            with self.assertRaises(ValueError):
                llmconf.settings(bad)

    def test_project_settings_default_to_api(self):
        self.assertEqual(llmconf.settings()["provider"], "api")


class IexamEnv(unittest.TestCase):
    def test_iexam_reads_exported_env(self):
        import attackplan  # noqa: F401  puts iexam/ on sys.path
        from api.services.acg import llm_service
        with mock.patch.dict(os.environ, {}):
            llmconf.export_env(llmconf.settings(CFG))
            self.assertEqual((llm_service._max_tokens(), llm_service._extra_body()),
                             (512, {"chat_template_kwargs": {"enable_thinking": False}}))
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual((llm_service._max_tokens(), llm_service._extra_body()), (16384, {"reasoning_effort": "low"}))

    def test_local_mode_never_sends_the_real_key(self):
        import importlib.util
        import attackplan  # noqa: F401
        from api.services.acg import llm_service
        spec = importlib.util.spec_from_file_location("build_api", attackplan.IEXAM / "Backend/pages/handler/build_api.py")
        build_api = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(build_api)
        with mock.patch.dict(os.environ, {"NVIDIA_API_KEY": "sekrit"}):
            llmconf.export_env(llmconf.settings(CFG))
            self.assertEqual(llm_service._resolve_credentials()[2], "local")
            self.assertEqual(build_api._resolve_api_key(), "local")
            llmconf.export_env(llmconf.settings(API))
            self.assertEqual((llm_service._resolve_credentials()[2], build_api._resolve_api_key()), ("sekrit", "sekrit"))

    def test_think_block_stripped_from_plan_text(self):
        import attackplan  # noqa: F401
        from api.services.acg import llm_service
        self.assertEqual(llm_service._strip_think("<think>x\ny</think>\n1. Step one"), "1. Step one")


FAKE = Path(__file__).resolve().parent / "fake_llama_server.py"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def fake_cmd(port: int, *extra: str) -> list[str]:
    return [sys.executable, str(FAKE), "--port", str(port), *extra]


def alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


class Server(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.log = Path(tmp.name) / "llm-server.log"
        self.port = free_port()
        self.local = llmconf.settings({**CFG, "local": {**CFG["local"], "port": self.port}})

    def test_starts_waits_for_health_and_stops(self):
        with llmconf.local_server(self.local, self.log, command=fake_cmd(self.port)) as info:
            self.assertEqual(urllib.request.urlopen(f"http://127.0.0.1:{self.port}/health").status, 200)
            pid = info["pid"]
            self.assertGreater(info["load_seconds"], 0.4)  # waited through the 503s
            m = llmconf.memory_mb(pid)
            self.assertGreater(m["peak"], 1)
            self.assertGreaterEqual(m["peak"], m["anon"])
        self.assertFalse(alive(pid))

    def test_failure_reports_log_tail(self):
        with self.assertRaisesRegex(RuntimeError, "fake server died: out of memory"):
            with llmconf.local_server(self.local, self.log, command=fake_cmd(self.port, "--die")):
                pass

    def test_stops_on_exception(self):
        with self.assertRaises(KeyError):
            with llmconf.local_server(self.local, self.log, command=fake_cmd(self.port)) as info:
                pid = info["pid"]
                raise KeyError("boom")
        self.assertFalse(alive(pid))

    def test_port_taken_by_someone_else(self):
        other = socket.socket()
        other.bind(("127.0.0.1", self.port))
        other.listen()
        self.addCleanup(other.close)
        t = time.monotonic()
        with self.assertRaises(RuntimeError):
            with llmconf.local_server(self.local, self.log, command=fake_cmd(self.port)):
                pass
        self.assertLess(time.monotonic() - t, 30)

    def test_healthy_stranger_on_the_port_is_refused(self):
        import subprocess as sp
        stranger = sp.Popen(fake_cmd(self.port), stdout=sp.DEVNULL, stderr=sp.DEVNULL)
        self.addCleanup(stranger.wait)
        self.addCleanup(stranger.terminate)
        while not llmconf._healthy(self.port):
            time.sleep(0.1)
        with self.assertRaisesRegex(RuntimeError, f"port {self.port} is in use"):
            with llmconf.local_server(self.local, self.log, command=fake_cmd(self.port)):
                self.fail("used a server we did not start")

    def test_sigterm_stops_the_server(self):
        import signal
        import subprocess as sp
        cfg = Path(self.log).with_name("cfg.json")
        cfg.write_text(json.dumps({**CFG, "local": {**CFG["local"], "port": self.port}}))
        code = ("import json, sys, time, llmconf\nfrom pathlib import Path\n"
                "llmconf.exit_on_sigterm()\n"
                f"s = llmconf.settings(json.loads(Path({str(cfg)!r}).read_text()))\n"
                f"with llmconf.local_server(s, Path({str(self.log)!r}), command={fake_cmd(self.port)!r}) as i:\n"
                "    print(i['pid'], flush=True)\n    time.sleep(60)\n")
        parent = sp.Popen([sys.executable, "-c", code], stdout=sp.PIPE, text=True, cwd=str(llmconf.ROOT))
        child = int(parent.stdout.readline())
        parent.send_signal(signal.SIGTERM)
        parent.wait(20)
        deadline = time.monotonic() + 15
        while alive(child) and time.monotonic() < deadline:
            time.sleep(0.2)
        self.assertFalse(alive(child))

    def test_api_is_a_no_op(self):
        with llmconf.local_server(llmconf.settings(API), self.log) as info:
            self.assertEqual(info, {})


if __name__ == "__main__":
    unittest.main()
