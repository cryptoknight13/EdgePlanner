"""Network model, web server and pipeline runner self-checks on a synthetic run."""
import base64
import http.client
import json
import os
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

from discover import _host
from netmodel import build, display_name
from unittest import mock

from web import network, setup
from web.jobs import Busy, Pipeline, steps_for
from web.server import make_handler

RUN = "20261013T225721Z"


def write_run(root: Path) -> Path:
    d = root / RUN
    d.mkdir()
    router, cam, me = _host("192.168.1.1"), _host("192.168.1.183"), _host("192.168.1.192")
    router.update(role="router", label="router", hostnames=["myrouter.local"])
    cam.update(label="camera", hostnames=["axis-cam"])
    me.update(role="self", label="computer", hostnames=["kali"])
    (d / "discover.json").write_text(json.dumps({
        "run_id": RUN, "subnets": ["192.168.1.0/24"], "attacker": {"ip": "0.0.0.0"},
        "routers": [{"ip": "192.168.1.1", "subnets": ["192.168.1.0/24"], "upstream": None}],
        "hosts": [router, cam, me], "notes": []}))
    (d / "gather.json").write_text(json.dumps({"hosts": [
        {"ip": "192.168.1.183", "os": None, "ports": [],
         "identity": {"make": "AXIS", "model": "AXIS M1014", "model_source": "upnp"}}], "notes": []}))
    (d / "scan.json").write_text(json.dumps({"hosts": [{"ip": "192.168.1.183", "software": [], "skipped": [], "cves": [
        {"cve_id": "CVE-1", "port": 49152, "vendor": "libupnp_project", "product": "libupnp", "version": "1.4.1", "match_type": "range",
         "weak_match": False, "source": "nvd-cpe", "cvss": 10.0},
        {"cve_id": "CVE-1", "port": 49152, "vendor": "libupnp_project", "product": "libupnp", "version": "1.4.1", "match_type": "unversioned",
         "weak_match": True, "source": "nvd-cpe", "cvss": 10.0},
        {"cve_id": "CVE-2", "port": None, "vendor": "v", "product": "x", "version": "1", "match_type": "all-versions",
         "weak_match": True, "source": "nvd-cpe", "cvss": 5.0}]}], "notes": []}))
    return d


class Model(unittest.TestCase):
    def test_build(self):
        with tempfile.TemporaryDirectory() as t:
            m = build(write_run(Path(t)))
        by_ip = {n["ip"]: n for n in m["nodes"]}
        cam = by_ip["192.168.1.183"]
        self.assertEqual(cam["name"], "AXIS M1014")
        self.assertEqual([c["id"] for c in cam["cves"]], ["CVE-1", "CVE-2"])  # one row per CVE, strongest first
        self.assertFalse(cam["cves"][0]["weak"])
        self.assertEqual((cam["risk"], cam["strong_cve_count"]), (10.0, 1))
        edges = {(e["source"], e["target"], e["kind"]) for e in m["edges"]}
        r, c, s = by_ip["192.168.1.1"]["id"], cam["id"], by_ip["192.168.1.192"]["id"]
        self.assertEqual(edges, {("n0", r, "wan"), (r, c, "lan"), (r, s, "monitor")})
        self.assertEqual(m["stages"], ["discover", "gather", "scan"])

    def test_bridge_clients_hang_off_the_bridge(self):
        router, almond, alexa = _host("192.168.1.1"), _host("192.168.1.129"), _host("192.168.1.186")
        router.update(role="router", is_gateway=True, label="router")
        almond.update(role="router", label="router")
        alexa.update(uplink="192.168.1.129", label="speaker")
        with tempfile.TemporaryDirectory() as t:
            d = Path(t) / RUN
            d.mkdir()
            (d / "discover.json").write_text(json.dumps({
                "run_id": RUN, "subnets": ["192.168.1.0/24"], "attacker": {"ip": "0.0.0.0"},
                "routers": [{"ip": "192.168.1.1", "subnets": [], "upstream": None},
                            {"ip": "192.168.1.129", "subnets": [], "upstream": "192.168.1.1"}],
                "hosts": [router, almond, alexa], "notes": []}))
            (d / "gather.json").write_text(json.dumps({"hosts": [  # gather's relabel wins over discover's
                {"ip": "192.168.1.186", "os": None, "ports": [], "identity": {},
                 "label": "iot", "confidence": 0.9, "evidence": ["nmap product: x"]}], "notes": []}))
            m = build(d)
        by_ip = {n["ip"]: n for n in m["nodes"]}
        r, a, x = (by_ip[ip]["id"] for ip in ("192.168.1.1", "192.168.1.129", "192.168.1.186"))
        self.assertEqual({(e["source"], e["target"]) for e in m["edges"]}, {("n0", r), (r, a), (a, x)})
        self.assertEqual((by_ip["192.168.1.186"]["label"], by_ip["192.168.1.186"]["uplink"]), ("iot", "192.168.1.129"))

    def test_display_name(self):
        h = {"hostnames": ["Mac", "Rakeshs-MacBook-Air.local"], "ip": "192.168.1.140"}
        self.assertEqual(display_name(h, {"model": "Mac15,13", "model_source": "mdns"}), "Rakeshs-MacBook-Air")
        self.assertEqual(display_name(h, {"make": "Linksys, LLC", "model": "WRT3200ACM", "model_source": "upnp"}),
                         "Linksys WRT3200ACM")
        self.assertEqual(display_name({"hostnames": [], "ip": "10.0.0.9"}, {}), "10.0.0.9")

    def test_bridge_named_after_gather_gets_its_clients(self):
        from netmodel import attach_unnamed_bridges
        mat = "e6:71:85:62:4b:e0"  # the extender's translated MAC, shared by it and its clients
        hosts = [{"ip": ip, "mac": mat, "shared_mac": 3} for ip in ("192.168.1.114", "192.168.1.129", "192.168.1.177", "192.168.1.186")]
        hosts.append({"ip": "192.168.1.183", "mac": "00:40:8c:f0:9f:da", "shared_mac": 0})
        node = lambda ip, label: {"ip": ip, "label": label, "kind": "device", "uplink": None, "name": ip}
        nodes = [node("192.168.1.114", "speaker"), node("192.168.1.129", "unknown"), node("192.168.1.177", "phone"),
                 node("192.168.1.186", "speaker"), node("192.168.1.183", "camera")]
        self.assertEqual(attach_unnamed_bridges(hosts, nodes, "192.168.1.1"), [])  # Discover only: no member is a router
        nodes[1]["label"] = "router"  # Gather found DNS + a web server on .129
        added = attach_unnamed_bridges(hosts, nodes, "192.168.1.1")
        self.assertEqual(added, [{"ip": "192.168.1.129", "subnets": [], "upstream": "192.168.1.1", "via": "mac-bridge"}])
        self.assertEqual([n["uplink"] for n in nodes], ["192.168.1.129", None, "192.168.1.129", "192.168.1.129", None])
        self.assertEqual((nodes[1]["kind"], nodes[1]["name"]), ("router", "Extender (.129)"))
        self.assertEqual(attach_unnamed_bridges(hosts, nodes, "192.168.1.1"), [])  # already attached: no second router

    def test_display_name_without_model_or_hostname(self):
        bare = {"hostnames": [], "ip": "192.168.1.120"}
        wink = [{"product": "lighttpd 1.4"}, {"product": "Wink Hub 2 API httpd"}]
        self.assertEqual(display_name(bare, {"make": "Flextronics International"}, wink, "iot"), "Wink Hub 2")
        self.assertEqual(display_name(bare, {}, [{"product": "D-Link DCS-932L_A1 webcam http interface"}]), "D-Link DCS-932L A1")
        boa = [{"product": "Boa httpd 0.94"}, {"product": "Dropbear sshd 2019.78"}]  # server software is not a model
        self.assertEqual(display_name(bare, {}, [{"product": "alphapd/2.1.6"}, {"product": "lighttpd 1.4.20"}], "camera"),
                         "192.168.1.120")  # versions are not models
        self.assertEqual(display_name(bare, {"make": "Amazon Technologies Inc."}, boa, "speaker"), "Amazon speaker")
        self.assertEqual(display_name({"hostnames": ["linux.local"], "ip": "x"}, {"make": "Amazon Technologies Inc."},
                                      [], "speaker"), "Amazon speaker")  # generic hostname skipped
        self.assertEqual(display_name(bare, {"make": "Shenzhen Ogemray Technology Co., Ltd."}, [], "unknown"), "Ogemray device")
        self.assertEqual(display_name(bare, {"make": "Cisco Systems, Inc"}, [], "switch"), "Cisco switch")
        self.assertEqual(display_name(bare, {"make": "Securifi Ltd"}, [], "router"), "Securifi router")
        self.assertEqual(display_name({"hostnames": [], "ip": "1.2.3.4", "vendor": "Axis Communications AB"}, {}, [], "camera"),
                         "Axis camera")


class Server(unittest.TestCase):
    def test_routes_and_guards(self):
        with tempfile.TemporaryDirectory() as t:
            write_run(Path(t))
            srv = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(Path(t), hostnames=("edgeplanner.local",)))
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            base = f"http://127.0.0.1:{srv.server_address[1]}"
            try:
                runs = json.load(urllib.request.urlopen(base + "/api/runs"))
                self.assertEqual(runs[0]["id"], RUN)
                named = urllib.request.Request(base + "/api/runs", headers={"Host": "EdgePlanner.local"})
                self.assertEqual(json.load(urllib.request.urlopen(named))[0]["id"], RUN)
                model = json.load(urllib.request.urlopen(f"{base}/api/runs/{RUN}/model"))
                self.assertEqual(len(model["nodes"]), 4)
                self.assertIn(b"EdgePlanner", urllib.request.urlopen(base + "/").read())
                for bad in ("/static/../run.py", "/static/%2e%2e/run.py", "/api/runs/..%2f/model", "/api/runs/x/model",
                            f"/api/runs/{RUN}/plans"):
                    with self.assertRaises(urllib.error.HTTPError) as ctx:
                        urllib.request.urlopen(base + bad)
                    self.assertEqual(ctx.exception.code, 404, bad)
                (Path(t) / RUN / "plans").mkdir()
                (Path(t) / RUN / "plans" / "plans.json").write_text('{"targets": []}')
                self.assertEqual(json.load(urllib.request.urlopen(f"{base}/api/runs/{RUN}/plans")), {"targets": []})
                with self.assertRaises(urllib.error.HTTPError) as ctx:
                    urllib.request.urlopen(f"{base}/api/runs/{RUN}/guide")
                self.assertEqual(ctx.exception.code, 404)
                (Path(t) / RUN / "mitigation").mkdir()
                (Path(t) / RUN / "mitigation" / "guide.json").write_text('{"guides": {}}')
                self.assertEqual(json.load(urllib.request.urlopen(f"{base}/api/runs/{RUN}/guide")), {"guides": {}})
                (Path(t) / RUN / "plans" / "NetDomain.pddl").write_text("(define (domain x))")
                self.assertEqual(urllib.request.urlopen(f"{base}/api/runs/{RUN}/pddl/NetDomain").read(), b"(define (domain x))")
                for bad in (f"/api/runs/{RUN}/pddl/plans", f"/api/runs/{RUN}/pddl/NetProblem", f"/api/runs/{RUN}/pddl/..%2fplans"):
                    with self.assertRaises(urllib.error.HTTPError) as ctx:
                        urllib.request.urlopen(base + bad)
                    self.assertEqual(ctx.exception.code, 404, bad)
                self.assertEqual(json.load(urllib.request.urlopen(base + "/api/job")), {"state": "idle"})
                c = http.client.HTTPConnection("127.0.0.1", srv.server_address[1])
                c.request("GET", "/api/runs", headers={"Host": "evil.example:8080"})
                r = c.getresponse()  # a rebound name only gets a bodiless redirect to the IP
                self.assertEqual((r.status, r.getheader("Location"), r.read()),
                                 (302, f"http://127.0.0.1:{srv.server_address[1]}/", b""))
                c.close()
            finally:
                srv.shutdown()
                srv.server_close()

    def test_pipeline_post_guards(self):
        with tempfile.TemporaryDirectory() as t:
            write_run(Path(t))
            started = []

            class Fake(Pipeline):
                def start(self, run_id, stage, goal=None, k=None):
                    started.append((run_id, stage))
                    return {"state": "running"}

            srv = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(Path(t), Fake(Path(t))))
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            host = f"127.0.0.1:{srv.server_address[1]}"

            def post(body, origin=f"http://{host}", ctype="application/json"):
                req = urllib.request.Request(f"http://{host}/api/pipeline", data=json.dumps(body).encode(),
                                             headers={"Content-Type": ctype, "Origin": origin}, method="POST")
                try:
                    return urllib.request.urlopen(req).status
                except urllib.error.HTTPError as exc:
                    return exc.code
            try:
                self.assertEqual(post({"run": RUN, "stage": "plan"}), 202)
                self.assertEqual(post({"run": RUN, "stage": "plan"}, origin="http://evil.example"), 403)
                self.assertEqual(post({"run": RUN, "stage": "plan"}, ctype="text/plain"), 403)
                self.assertEqual(post({"run": "../etc", "stage": "plan"}), 400)
                self.assertEqual(started, [(RUN, "plan")])
            finally:
                srv.shutdown()
                srv.server_close()

    def test_login_and_scan_permission(self):
        with tempfile.TemporaryDirectory() as t:
            write_run(Path(t))
            started = []

            class Fake(Pipeline):
                def start(self, run_id, stage, goal=None, k=None):
                    started.append(stage)
                    return {"state": "running"}

            allowed = []
            srv = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(Path(t), Fake(Path(t)), credentials=("u", "p"),
                                                                     consent_ok=lambda: bool(allowed)))
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            host = f"127.0.0.1:{srv.server_address[1]}"
            good = "Basic " + base64.b64encode(b"u:p").decode()

            def call(path, auth=None, body=None):
                headers = {"Authorization": auth} if auth else {}
                if body is not None:
                    headers.update({"Content-Type": "application/json", "Origin": f"http://{host}"})
                req = urllib.request.Request(f"http://{host}{path}", headers=headers,
                                             data=None if body is None else json.dumps(body).encode())
                try:
                    return urllib.request.urlopen(req).status
                except urllib.error.HTTPError as exc:
                    return exc.code
            try:
                self.assertEqual(call("/"), 401)
                self.assertEqual(call("/api/runs", "Basic " + base64.b64encode(b"u:wrong").decode()), 401)
                self.assertEqual(call("/api/runs", good), 200)
                self.assertEqual(call("/api/pipeline", body={"run": None, "stage": "discover"}), 401)
                self.assertEqual(call("/api/pipeline", good, {"run": None, "stage": "discover"}), 400)
                allowed.append(True)
                self.assertEqual(call("/api/pipeline", good, {"run": None, "stage": "discover"}), 202)
                self.assertEqual(started, ["discover"])
            finally:
                srv.shutdown()
                srv.server_close()


class Setup(unittest.TestCase):
    def test_consent_is_per_network(self):
        with tempfile.TemporaryDirectory() as t, mock.patch.object(setup, "CONSENT", Path(t) / "consent.json"), \
                mock.patch.object(setup, "current_networks", return_value=["192.168.1.0/24"]):
            self.assertFalse(setup.consent_status()["ok"])
            self.assertTrue(setup.accept_consent()["ok"])
            self.assertFalse(setup.consent_status(["10.0.0.0/24"])["ok"])  # moved to another network: ask again
            self.assertFalse(setup.consent_status([])["ok"])               # offline

    def test_save_keys_keeps_other_lines_and_hides_values(self):
        nvd, nv = "0123abcd-0000-1111-2222-333344445555", "nvapi-" + "x" * 30 + "WXYZ"
        with tempfile.TemporaryDirectory() as t, mock.patch.object(setup, "ENV", Path(t) / ".env"), \
                mock.patch.object(setup, "ROOT", Path(t)), mock.patch.dict(os.environ, {}, clear=False):
            (Path(t) / ".env").write_text("EDGEPLANNER_USER=u\nNVD_API_KEY=old\n")
            with self.assertRaises(ValueError):
                setup.save_keys({"NVIDIA_API_KEY": "sk-not-nvidia"})
            status = setup.save_keys({"NVD_API_KEY": nvd, "NVIDIA_API_KEY": nv, "OTHER": "ignored"})
            self.assertEqual(status["NVIDIA_API_KEY"], {"set": True, "hint": "WXYZ"})
            text = (Path(t) / ".env").read_text()
            self.assertEqual(text, f"EDGEPLANNER_USER=u\nNVD_API_KEY={nvd}\nNVIDIA_API_KEY={nv}\n")
            self.assertEqual((Path(t) / ".env").stat().st_mode & 0o777, 0o600)
            self.assertNotIn(nv, json.dumps(status))


class Runner(unittest.TestCase):
    @staticmethod
    def fake(step, run_id):
        # Prints its argv; the export step fails.
        return [sys.executable, "-c", "import sys; print('ran', *sys.argv[1:]); sys.exit(sys.argv[1] == 'export')", *step]

    def wait(self, p):
        for _ in range(200):
            s = p.snapshot()
            if s["state"] != "running":
                return s
            time.sleep(0.05)
        self.fail("pipeline did not finish")

    def test_runs_exactly_one_stage(self):
        with tempfile.TemporaryDirectory() as t:
            write_run(Path(t))  # has discover, gather, scan.json (no cveinfo yet)
            p = Pipeline(Path(t), self.fake)
            p.start(RUN, "gather")
            s = self.wait(p)
            self.assertEqual((s["state"], s["stages"], s["done"]), ("done", ["gather"], ["gather"]))
            self.assertIn("ran gather", s["log_tail"])
            self.assertNotIn("ran scan", s["log_tail"])

    def test_scan_your_network_resumes_with_the_cve_lookup(self):
        with tempfile.TemporaryDirectory() as t:
            run = write_run(Path(t))
            p = Pipeline(Path(t), self.fake)
            self.assertEqual(steps_for(run, "scan"), [["cveinfo"]])  # scan.json is there already
            p.start(RUN, "scan")
            s = self.wait(p)
            self.assertEqual((s["state"], s["steps"]), ("done", ["cveinfo"]))
            self.assertNotIn("ran scan", s["log_tail"])
            (run / "cveinfo.json").write_text("{}")
            self.assertEqual(steps_for(run, "scan"), [["scan"], ["cveinfo"]])  # a re-run does both

    def test_plan_prepares_the_iexam_files_first_and_stops_on_failure(self):
        with tempfile.TemporaryDirectory() as t:
            run = write_run(Path(t))
            (run / "cveinfo.json").write_text("{}")
            p = Pipeline(Path(t), self.fake)
            p.start(RUN, "plan")
            s = self.wait(p)
            self.assertEqual((s["state"], s["current"], s["step"], s["done"]), ("failed", "plan", "export", []))
            self.assertIn("ran export", s["log_tail"])
            self.assertNotIn("ran plan", s["log_tail"])

    def test_planning_actions_need_a_goal_from_the_attack_model(self):
        with tempfile.TemporaryDirectory() as t:
            run = write_run(Path(t))
            (run / "cveinfo.json").write_text("{}")
            p = Pipeline(Path(t), self.fake)
            with self.assertRaises(ValueError):
                p.start(RUN, "optimal", goal="AXIS M1014")  # Start Planning has not run
            (run / "plans").mkdir()
            (run / "plans" / "plans.json").write_text(json.dumps({"targets": [{"goal": "AXIS M1014"}]}))
            for goal, k in (("Router; rm -rf /", None), ("AXIS M1014", 0), ("AXIS M1014", 11), ("AXIS M1014", "3")):
                with self.assertRaises(ValueError):
                    p.start(RUN, "topk" if k is not None else "optimal", goal=goal, k=k)
            p.start(RUN, "topk", goal="AXIS M1014", k=3)
            s = self.wait(p)
            self.assertEqual((s["state"], s["stages"], s["goal"]), ("done", ["topk"], "AXIS M1014"))
            self.assertIn("ran plan --target AXIS M1014 --topk 3\n", s["log_tail"])

    def test_guide_action_needs_mitigation_for_the_goal(self):
        with tempfile.TemporaryDirectory() as t:
            run = write_run(Path(t))
            (run / "plans").mkdir()
            (run / "plans" / "plans.json").write_text(json.dumps({"targets": [{"goal": "AXIS M1014"}]}))
            p = Pipeline(Path(t), self.fake)
            with self.assertRaisesRegex(ValueError, "Mitigate"):
                p.start(RUN, "guide", goal="AXIS M1014")  # Mitigate has not run
            (run / "mitigation").mkdir()
            m = run / "mitigation" / "mitigation.json"
            m.write_text(json.dumps({"targets": [{"goal": "AXIS M1014", "unreachable": True, "options": []}]}))
            with self.assertRaisesRegex(ValueError, "Mitigate"):
                p.start(RUN, "guide", goal="AXIS M1014")
            m.write_text(json.dumps({"targets": [{"goal": "AXIS M1014", "unreachable": False, "options": [{"actions": []}]}]}))
            p.start(RUN, "guide", goal="AXIS M1014")
            s = self.wait(p)
            self.assertEqual((s["state"], s["stages"]), ("done", ["guide"]))
            self.assertIn("ran guide --target AXIS M1014\n", s["log_tail"])

    def test_rejects_bad_requests_and_concurrent_jobs(self):
        with tempfile.TemporaryDirectory() as t:
            write_run(Path(t))
            p = Pipeline(Path(t), lambda s, r: [sys.executable, "-c", "import time; time.sleep(0.5)"])
            for run_id, stage in ((RUN, "discover"), (None, "plan"), (RUN, "nope"), ("20990101T000000Z", "plan"),
                                  (RUN, "plan"), (RUN, "export"), (RUN, "cveinfo")):  # plan needs Scan Your Network done
                with self.assertRaises(ValueError):
                    p.start(run_id, stage)
            p.start(RUN, "scan")
            with self.assertRaises(Busy):
                p.start(RUN, "gather")
            self.wait(p)
            new = p.start(None, "discover")["run"]
            self.wait(p)
            self.assertTrue((Path(t) / new / "pipeline.log").exists())

if __name__ == "__main__":
    unittest.main()


class NetworkPage(unittest.TestCase):
    def test_nmcli_rows_unescape(self):
        self.assertEqual(network.rows("My\\:Net:72:WPA2\nback\\\\slash:40:\n"),
                         [["My:Net", "72", "WPA2"], ["back\\slash", "40", ""]])
        nets = network.parse_wifi(network.rows("Home:40:WPA2\nHome:80:WPA2\nEdgePlanner-Setup:99:WPA2\n:50:\nCafe:30:--\n"))
        self.assertEqual(nets, [{"ssid": "Home", "signal": 80, "secured": True},
                                {"ssid": "Cafe", "signal": 30, "secured": False}])

    def test_only_setup_wifi_addresses_get_the_network_page(self):
        with mock.patch.object(network, "WIFI_HELPER", Path(sys.executable)):  # any file that exists
            self.assertTrue(network.on_setup_wifi("10.42.0.1"))
            self.assertFalse(network.on_setup_wifi("192.168.1.115"))
        with mock.patch.object(network, "WIFI_HELPER", Path("/nonexistent")):
            self.assertFalse(network.on_setup_wifi("10.42.0.1"))  # not the box (no helper installed)

    def test_setup_wifi_serves_only_the_form_and_connects(self):
        with tempfile.TemporaryDirectory() as t:
            write_run(Path(t))
            scan = Path(t) / "scan.txt"
            scan.write_text("Home:80:WPA2\n<b>evil</b>:40:WPA2\n")
            calls = []
            with mock.patch.object(network, "on_setup_wifi", return_value=True), \
                    mock.patch.object(network, "WIFI_SCAN", scan), mock.patch.object(network, "WIFI_RESULT", Path(t) / "none"), \
                    mock.patch.object(network, "connect", side_effect=lambda s, p: calls.append((s, p))):
                srv = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(Path(t), credentials=("u", "p")))
                threading.Thread(target=srv.serve_forever, daemon=True).start()
                host = f"127.0.0.1:{srv.server_address[1]}"
                try:
                    for path in ("/", "/api/runs", "/hotspot-detect.html"):  # no login, never the app or its data
                        page = urllib.request.urlopen(f"http://{host}{path}").read().decode()
                        self.assertIn("Network setup", page)
                        self.assertNotIn(RUN, page)
                    self.assertIn('<option value="Home">', page)
                    self.assertIn("&lt;b&gt;evil&lt;/b&gt;", page)
                    form = urllib.parse.urlencode({"ssid": "Home", "password": "secret123"}).encode()
                    req = urllib.request.Request(f"http://{host}/", data=form, headers={
                        "Origin": f"http://{host}", "Content-Type": "application/x-www-form-urlencoded"})
                    self.assertIn("Connecting to <b>Home</b>", urllib.request.urlopen(req).read().decode())
                    self.assertEqual(calls, [("Home", "secret123")])
                    req.headers["Origin"] = "http://evil.example"
                    urllib.request.urlopen(req).read()
                    self.assertEqual(len(calls), 1)  # cross-origin form refused
                finally:
                    srv.shutdown()
                    srv.server_close()
