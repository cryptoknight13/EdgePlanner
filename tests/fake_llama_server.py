"""Stand-in for llama-server in tests: /health (503 while 'loading', then 200) and a fixed chat reply with timings."""
import argparse
import json
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

REPLY = json.dumps({"how_it_blocks": "Blocks it.", "steps": ["Open the page.", "Upload the file.", "Check the version."],
                    "links": []})


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--die", action="store_true")
    ap.add_argument("--reply", default=REPLY)
    a, _ = ap.parse_known_args()
    if a.die:
        print("fake server died: out of memory", flush=True)
        sys.exit(1)
    ready = time.monotonic() + 0.5

    class H(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            print("request", self.command, self.path, flush=True)

        def _json(self, code, obj):
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path == "/health":
                return self._json(200 if time.monotonic() > ready else 503, {"status": "ok"})
            self._json(404, {})

        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length") or 0))
            self._json(200, {"choices": [{"message": {"content": a.reply}}],
                             "usage": {"prompt_tokens": 100, "completion_tokens": 20},
                             "timings": {"prompt_n": 100, "prompt_per_second": 50.0,
                                         "predicted_n": 20, "predicted_per_second": 5.0}})

    HTTPServer(("127.0.0.1", a.port), H).serve_forever()


if __name__ == "__main__":
    main()
