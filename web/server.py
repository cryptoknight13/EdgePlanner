"""Minimal web server (stdlib only, runs on the Pi without Node):

  GET /                       the single page
  GET /static/<file>          page assets
  GET /api/runs               runs and which stages each has
  GET /api/runs/<id>/model    merged network model for one run
  GET /api/runs/<id>/plans    phase 7 plans.json
  GET /api/runs/<id>/mitigation  phase 8 mitigation.json
  GET /api/runs/<id>/guide       phase 8b guide.json
  GET /api/runs/<id>/pddl/<name>  phase 7 PDDL (NetDomain, NetProblem, newNetProblem) as text
  GET /api/job                pipeline job status and log tail
  POST /api/pipeline          {"run": id or null, "stage": stage}: run that one stage (discover = new run);
                              {"run": id, "stage": "optimal" | "topk", "goal": name, "k": n}: plan one goal
  GET /api/setup              scan permission for the current network, which API keys are set
  POST /api/setup/consent     {"accept": true}: permission to scan the current network
  POST /api/setup/keys        {"NVD_API_KEY": k, "NVIDIA_API_KEY": k}: save to .env

Every request needs the login (HTTP Basic) when credentials are given; serve() always gives them.
On the box's setup Wi-Fi only the separate network setup page is served (web/network.py), with no login.
"""
import base64
import hmac
import ipaddress
import json
import mimetypes
import re
import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable
from urllib.parse import parse_qs

from netmodel import build
from web import network, setup
from web.jobs import Busy, Pipeline, done_stages

STATIC = Path(__file__).resolve().parent / "static"
RUN_ID_RE = re.compile(r"^\d{8}T\d{6}Z$")
RESULTS = {"plans": "plans/plans.json", "mitigation": "mitigation/mitigation.json", "guide": "mitigation/guide.json"}
PDDL = ("NetDomain", "NetProblem", "newNetProblem")
MAX_BODY = 1024


def make_handler(runs_dir: Path, pipeline: Pipeline | None = None, hostnames: tuple[str, ...] = (),
                 credentials: tuple[str, str] | None = None, consent_ok: Callable[[], bool] = lambda: True):
    pipeline = pipeline or Pipeline(runs_dir)
    allowed = {"localhost", *(h.lower() for h in hostnames)}
    expected = credentials and "Basic " + base64.b64encode(":".join(credentials).encode()).decode()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):  # keep the console quiet
            pass

        def _send(self, code: int, body: bytes, ctype: str) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, obj, code: int = 200) -> None:
            self._send(code, json.dumps(obj).encode(), "application/json")

        def _host_ok(self) -> bool:
            """Host must be an IP literal, localhost or a configured name: a rebound DNS name never reaches the API."""
            host = (self.headers.get("Host") or "").rsplit(":", 1)[0].strip("[]")
            try:
                ipaddress.ip_address(host)
                return True
            except ValueError:
                return host.lower().rstrip(".") in allowed

        def _authorized(self) -> bool:
            if not expected or hmac.compare_digest(self.headers.get("Authorization") or "", expected):
                return True
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="EdgePlanner", charset="UTF-8"')
            self.send_header("Content-Length", "0")
            self.end_headers()
            return False

        def _to_own_address(self) -> None:
            """Unknown name: send it to this box's IP. A redirect carries no data, so a rebound name reads nothing."""
            ip, port = self.connection.getsockname()[:2]
            self.send_response(302)
            self.send_header("Location", f"http://{ip}{'' if port == 80 else f':{port}'}/")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def _setup_wifi(self) -> bool:
            return network.on_setup_wifi(self.connection.getsockname()[0])

        def _network_page(self, body: bytes) -> None:
            self._send(200, body, "text/html; charset=utf-8")

        def _network_post(self) -> None:
            """Connect form on the setup Wi-Fi: same-origin form posts only."""
            length = int(self.headers.get("Content-Length") or 0)
            if (self.headers.get("Origin") != f"http://{self.headers.get('Host')}"
                    or self.headers.get_content_type() != "application/x-www-form-urlencoded" or not 0 < length <= MAX_BODY):
                return self._network_page(network.form_page("Please use the form on this page."))
            form = parse_qs(self.rfile.read(length).decode("utf-8", "replace"), keep_blank_values=True)
            ssid, password = form.get("ssid", [""])[0], form.get("password", [""])[0]
            try:
                network.connect(ssid, password)
            except (ValueError, OSError, subprocess.TimeoutExpired) as exc:
                return self._network_page(network.form_page(str(exc)))
            self._network_page(network.connecting_page(ssid))

        def do_GET(self) -> None:
            if self._setup_wifi():  # any address a laptop opens here lands on the network setup page
                return self._network_page(network.form_page())
            if not self._host_ok():
                return self._to_own_address()
            if not self._authorized():
                return
            path = self.path.split("?", 1)[0]
            if path == "/api/setup":
                return self._json({"consent": setup.consent_status(), "keys": setup.keys_status()})
            if path == "/":
                return self._file(STATIC / "index.html")
            if path.startswith("/static/"):
                target = (STATIC / path[len("/static/"):]).resolve()
                if STATIC in target.parents and target.is_file():
                    return self._file(target)
                return self._json({"error": "not found"}, 404)
            if path == "/api/runs":
                runs = [{"id": d.name, "stages": done_stages(d)}
                        for d in sorted(runs_dir.glob("*"), reverse=True) if RUN_ID_RE.match(d.name)]
                return self._json([r for r in runs if "discover" in r["stages"]])
            if path == "/api/job":
                return self._json(pipeline.snapshot())
            m = re.fullmatch(r"/api/runs/([^/]+)/pddl/([A-Za-z]+)", path)
            if m and RUN_ID_RE.match(m.group(1)) and m.group(2) in PDDL:
                f = runs_dir / m.group(1) / "plans" / f"{m.group(2)}.pddl"
                if f.is_file():
                    return self._send(200, f.read_bytes(), "text/plain; charset=utf-8")
                return self._json({"error": "no PDDL in this run"}, 404)
            m = re.fullmatch(r"/api/runs/([^/]+)/(model|plans|mitigation|guide)", path)
            if m and RUN_ID_RE.match(m.group(1)) and (runs_dir / m.group(1)).is_dir():
                d = runs_dir / m.group(1)
                if m.group(2) != "model":
                    f = d / RESULTS[m.group(2)]
                    return self._file(f) if f.is_file() else self._json({"error": f"no {m.group(2)} in this run"}, 404)
                try:
                    return self._json(build(d))
                except (FileNotFoundError, KeyError, json.JSONDecodeError) as exc:
                    return self._json({"error": f"run {m.group(1)} is incomplete: {exc}"}, 422)
            return self._json({"error": "not found"}, 404)

        def do_POST(self) -> None:
            if self._setup_wifi():
                return self._network_post()
            if not self._host_ok():
                return self._json({"error": "use the IP address or localhost"}, 403)
            if not self._authorized():
                return
            path = self.path.split("?", 1)[0]
            if path != "/api/pipeline" and not path.startswith("/api/setup/"):
                return self._json({"error": "not found"}, 404)
            # Every POST is a side effect: same-origin JSON only, so another site cannot trigger it.
            if (self.headers.get("Origin") != f"http://{self.headers.get('Host')}"
                    or self.headers.get_content_type() != "application/json"):
                return self._json({"error": "cross-origin or non-JSON request refused"}, 403)
            length = int(self.headers.get("Content-Length") or 0)
            if not 0 < length <= MAX_BODY:
                return self._json({"error": "bad request body"}, 400)
            try:
                body = json.loads(self.rfile.read(length))
                if path == "/api/setup/consent":
                    if body.get("accept") is not True:
                        raise ValueError("tick the box to confirm")
                    return self._json(setup.accept_consent())
                if path == "/api/setup/keys":
                    return self._json(setup.save_keys(body))
                if path != "/api/pipeline":
                    return self._json({"error": "not found"}, 404)
                run_id, stage, goal, k = body.get("run"), body.get("stage"), body.get("goal"), body.get("k")
                if stage == "discover" and not consent_ok():
                    raise ValueError("confirm on the Setup page that you may scan this network first")
                if run_id is not None and not (isinstance(run_id, str) and RUN_ID_RE.match(run_id)):
                    raise ValueError("bad run id")
                if goal is not None and not (isinstance(goal, str) and 0 < len(goal) <= 200):
                    raise ValueError("bad goal")
                return self._json(pipeline.start(run_id, stage, goal, k), 202)
            except Busy as exc:
                return self._json({"error": str(exc)}, 409)
            except (ValueError, AttributeError, TypeError) as exc:
                return self._json({"error": str(exc)}, 400)

        def _file(self, path: Path) -> None:
            ctype = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
            self._send(200, path.read_bytes(), ctype + ("; charset=utf-8" if ctype.startswith("text") else ""))

    return Handler


def serve(runs_dir: Path, host: str, port: int, hostnames: tuple[str, ...], credentials: tuple[str, str]) -> None:
    server = ThreadingHTTPServer((host, port), make_handler(runs_dir, hostnames=hostnames, credentials=credentials,
                                                            consent_ok=lambda: setup.consent_status()["ok"]))
    print(f"EdgePlanner web view on http://{host}:{port}/  (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
