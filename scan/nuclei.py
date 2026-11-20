"""nuclei CVE templates, detection only. Ported idea from BATs agent/bat_agent/scanner.py."""
import json
import re
import subprocess
from pathlib import Path

EXCLUDED_TAGS = "intrusive,dos,fuzz,bruteforce,brute-force"
VERSION_RE = re.compile(r"^\d+(\.\d+)+[a-z0-9.\-]*$", re.I)


def targets(hosts: list[dict]) -> tuple[list[str], list[str]]:
    """(web URLs, host:port for every other open TCP port)."""
    web, net = [], []
    for h in hosts:
        for p in h["ports"]:
            if p["proto"] != "tcp":
                continue
            svc = p["service"] or ""
            if svc.startswith("http") or svc == "https":
                scheme = "https" if p["tunnel"] == "ssl" or svc == "https" else "http"
                web.append(f"{scheme}://{h['ip']}:{p['port']}")
            else:
                net.append(f"{h['ip']}:{p['port']}")
    return web, net


def run(target_list: list[str], out_file: Path, template_args: list[str], rate_limit: int = 50) -> list[dict]:
    """Run nuclei with the given template selection; return parsed findings (JSONL kept on disk)."""
    if not target_list:
        return []
    list_file = out_file.with_suffix(".targets")
    list_file.write_text("\n".join(target_list) + "\n")
    subprocess.run(["nuclei", "-l", str(list_file), *template_args, "-etags", EXCLUDED_TAGS,
                    "-rl", str(rate_limit), "-timeout", "5", "-silent", "-jsonl", "-o", str(out_file),
                    "-disable-update-check"], check=True, capture_output=True, text=True)
    return parse(out_file.read_text() if out_file.exists() else "")


# fast: the ~100 CVE templates for non-HTTP services (javascript/tcp); ~3.5 min on Kali for 10 ports.
#   Web software is covered by NVD version matching instead. Measured: -as on 4 web ports took 27 min
#   and found only tech detections, so it is not used.
# full: every CVE template against every port (~11 min for 4 web ports on Kali).
MODES = {
    "fast": [("net", ["-tags", "cve", "-type", "javascript,tcp"])],
    "full": [("all", ["-tags", "cve"])],
}


def scan_hosts(hosts: list[dict], run_dir: Path, mode: str = "fast") -> list[dict]:
    web, net = targets(hosts)
    lists = {"web": web, "net": net, "all": web + net}
    findings = []
    for name, args in MODES[mode]:
        findings += run(lists[name], run_dir / f"nuclei-{name}.jsonl", args)
    return findings


def parse(jsonl: str) -> list[dict]:
    findings = []
    for line in jsonl.splitlines():
        if not line.strip():
            continue
        r = json.loads(line)
        info = r.get("info", {})
        cves = (info.get("classification") or {}).get("cve-id") or []
        meta = info.get("metadata") or {}
        extracted = [v for v in r.get("extracted-results") or [] if VERSION_RE.match(v)]
        findings.append({
            "template": r.get("template-id"), "name": info.get("name"), "severity": info.get("severity"),
            "tags": info.get("tags") or [],
            "cve_ids": [c.upper() for c in cves], "ip": r.get("ip") or r.get("host"),
            "port": int(r["port"]) if str(r.get("port", "")).isdigit() else None,
            "matched_at": r.get("matched-at"),
            # A version the template read from the service, with the NVD product it names.
            "vendor": meta.get("vendor"), "product": meta.get("product"),
            "extracted_version": extracted[0] if extracted else None,
        })
    return findings
