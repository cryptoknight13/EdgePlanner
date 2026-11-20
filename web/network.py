"""Network setup page: a plain, separate page served only on the box's setup Wi-Fi (config: box.setup_wifi).

No script and no login (the setup Wi-Fi's password is the lock): pick a Wi-Fi, type its password, Connect.
The root helper the installer adds (scripts/install_box.sh) does the switch in the background.
"""
import html
import ipaddress
import subprocess
from functools import cache
from pathlib import Path

import yaml

SETTINGS = Path(__file__).resolve().parent.parent / "config" / "settings.yaml"
WIFI_HELPER = Path("/usr/local/sbin/edgeplanner-wifi")
WIFI_SCAN = Path("/run/edgeplanner/wifi-scan.txt")  # taken before the setup Wi-Fi starts (radio busy after)
WIFI_RESULT = Path("/run/edgeplanner/wifi-result.txt")


@cache
def settings() -> dict:
    """Setup Wi-Fi name, address range and wait, and the name the page is reached by, from config/settings.yaml."""
    s = yaml.safe_load(SETTINGS.read_text())
    names = s.get("web", {}).get("hostnames") or []
    return {**s["box"]["setup_wifi"], "page": next((n for n in names if n.endswith(".local")), names[0] if names else None)}


def on_setup_wifi(local_ip: str) -> bool:
    """True when the request reached the box on its setup Wi-Fi address."""
    return WIFI_HELPER.exists() and ipaddress.ip_address(local_ip) in ipaddress.ip_network(settings()["subnet"])


def rows(text: str) -> list[list[str]]:
    """`nmcli -t` output -> fields per line (nmcli escapes ':' and '\\' inside values with a backslash)."""
    out = []
    for ln in text.splitlines():
        if ln:
            ln = ln.replace("\\\\", "\0").replace("\\:", "\1")
            out.append([f.replace("\1", ":").replace("\0", "\\") for f in ln.split(":")])
    return out


def parse_wifi(table: list[list[str]]) -> list[dict]:
    """Strongest entry per network name, strongest first; hidden networks and the setup Wi-Fi left out."""
    best: dict[str, dict] = {}
    for ssid, signal, security in (r[:3] for r in table if len(r) >= 3):
        if ssid and ssid != settings()["ssid"] and int(signal or 0) > best.get(ssid, {}).get("signal", -1):
            best[ssid] = {"ssid": ssid, "signal": int(signal or 0), "secured": bool(security.strip(" -"))}
    return sorted(best.values(), key=lambda n: -n["signal"])


def connect(ssid: str, password: str) -> None:
    """Hand the network to the root helper; it switches in the background (the setup Wi-Fi then turns off)."""
    if not (1 <= len(ssid.encode()) <= 32 and "\n" not in ssid):
        raise ValueError("Pick a Wi-Fi network.")
    if "\n" in password or not (password == "" or 8 <= len(password) <= 63):
        raise ValueError("A Wi-Fi password is 8 to 63 characters.")
    proc = subprocess.run(["sudo", "-n", str(WIFI_HELPER)], input=f"{ssid}\n{password}\n",
                          capture_output=True, text=True, timeout=20)
    if proc.returncode != 0:
        raise ValueError(proc.stderr.strip() or "The box could not start the switch.")


STYLE = """body{margin:0;padding:48px 16px;font:16px/1.5 system-ui,sans-serif;background:#0f172a;color:#e2e8f0}
main{max-width:28rem;margin:auto;background:#1e293b;border:1px solid #334155;border-radius:12px;padding:28px}
h1{margin:0 0 4px;font-size:1.3rem}h1 b{color:#22d3ee}p{color:#94a3b8;margin:0 0 20px}
label{display:block;font-size:.85rem;font-weight:600;margin:0 0 6px}
select,input{box-sizing:border-box;width:100%;font:inherit;color:#e2e8f0;background:#0f172a;border:1px solid #475569;
border-radius:8px;min-height:44px;padding:0 12px;margin:0 0 18px}
button{font:inherit;font-weight:600;background:#22d3ee;color:#0f172a;border:0;border-radius:8px;min-height:44px;
padding:0 24px;cursor:pointer}.bad{color:#fca5a5}code{color:#fff}"""


def _page(body: str) -> bytes:
    return (f'<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" '
            f'content="width=device-width, initial-scale=1"><title>EdgePlanner network setup</title>'
            f"<style>{STYLE}</style></head><body><main><h1>Edge<b>Planner</b> · Network setup</h1>{body}"
            f"</main></body></html>").encode()


def form_page(error: str | None = None) -> bytes:
    nets = parse_wifi(rows(WIFI_SCAN.read_text())) if WIFI_SCAN.exists() else []
    last = WIFI_RESULT.read_text().strip() if WIFI_RESULT.exists() else ""
    problem = error or (last if last.startswith("could not") else "")
    options = "".join(f'<option value="{html.escape(n["ssid"])}">{html.escape(n["ssid"])}</option>' for n in nets)
    return _page(f"""<p>Connect this box to your network. With a network cable plugged into your router you do not need this page.</p>
{f'<p class="bad" role="alert">{html.escape(problem)}</p>' if problem else ""}
<form method="post" action="/">
<label for="ssid">Wi-Fi network</label>
<select id="ssid" name="ssid" required>{options or '<option value="">No networks found</option>'}</select>
<label for="password">Password</label>
<input id="password" name="password" type="password" autocomplete="off">
<button type="submit">Connect</button>
</form>""")


def connecting_page(ssid: str) -> bytes:
    s, cfg = html.escape(ssid), settings()
    where = f"http://{cfg['page']}" if cfg["page"] else "this box's address on that network"
    return _page(f"""<p>Connecting to <b>{s}</b>. This setup Wi-Fi turns off now.</p>
<p>Join your laptop to <b>{s}</b>, then open <code>{html.escape(where)}</code>.</p>
<p>If the box does not appear within two minutes, the password was probably wrong: join {html.escape(cfg['ssid'])} again
and this page will say what went wrong.</p>""")
