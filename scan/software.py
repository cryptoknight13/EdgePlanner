"""Turn a gathered host into a list of (vendor, product, version) to look up in NVD.

Every candidate that cannot be looked up precisely is kept in `skipped` with the reason.
"""
import re
from pathlib import Path

from scan import nvd

CLEAN_VERSION_RE = re.compile(r"^[\w][\w.\-+]*$")
FUZZY_RE = re.compile(r"(^|[.\-])x($|[.\-])", re.I)  # nmap ranges like "3.X - 4.X"

# nmap product string (regex) -> NVD (part, vendor, product), for products nmap names without a usable CPE.
PRODUCT_MAP = [
    (r"portable sdk for upnp devices", ("a", "libupnp_project", "libupnp")),
    (r"^lighttpd", ("a", "lighttpd", "lighttpd")),
    (r"^dnsmasq", ("a", "thekelleys", "dnsmasq")),
    (r"^boa httpd", ("a", "boa", "boa")),
    (r"^mini_httpd", ("a", "acme", "mini_httpd")),
    (r"^miniupnpd", ("a", "miniupnp_project", "miniupnpd")),
    (r"^openssh", ("a", "openbsd", "openssh")),
    (r"^dropbear", ("a", "dropbear_ssh_project", "dropbear_ssh")),
    (r"^busybox", ("a", "busybox", "busybox")),
]


def first_token(version: str | None) -> str | None:
    """'10.0p2 Debian 7+deb13u4' -> '10.0p2'; empty -> None."""
    return version.split()[0] if version and version.split() else None


def _cpe22(cpe: str) -> tuple[str, str, str, str | None] | None:
    """'cpe:/a:vendor:product[:version]' -> (part, vendor, product, version|None)."""
    if not cpe.startswith("cpe:/"):
        return None
    f = cpe[5:].split(":")
    if len(f) < 3 or not f[1] or not f[2]:
        return None
    return f[0], f[1], f[2], (f[3] if len(f) > 3 and f[3] else None)


def _vendor_token(make: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (make or "").lower().split(",")[0].split()[0]) if make else ""


def firmware_product(identity: dict) -> tuple[str, str] | None:
    """(vendor, '<model>_firmware') following NVD's naming for device firmware."""
    vendor = _vendor_token(identity.get("make") or "")
    model = (identity.get("model") or "").lower()
    if not vendor or not model:
        return None
    model = re.sub(rf"^{re.escape(vendor)}\s+", "", model)
    model = re.sub(r"[^a-z0-9]+", "_", model).strip("_")
    return (vendor, f"{model}_firmware") if model else None


def software_list(host: dict, exclude: set[str], cache_dir: Path) -> tuple[list[dict], list[dict]]:
    items: dict[tuple, dict] = {}
    skipped: list[dict] = []

    def add(port: dict | None, part: str, vendor: str, product: str, version: str | None, source: str) -> None:
        where = f"{port['port']}/{port['service']}" if port else "device"
        label = f"{vendor}:{product}"
        if part == "h":
            return skipped.append({"where": where, "product": label, "reason": "hardware CPE, no software version"})
        if product in exclude:
            return skipped.append({"where": where, "product": label, "reason": "excluded product (OS kernel)"})
        if not version or not CLEAN_VERSION_RE.match(version) or FUZZY_RE.search(version):
            entry = {"where": where, "product": label, "reason": f"no single clean version ({version or 'none'})"}
            return None if entry in skipped else skipped.append(entry)
        k = (vendor, product, version, where)
        items.setdefault(k, {"port": port["port"] if port else None, "service": port["service"] if port else None,
                             "part": part, "vendor": vendor, "product": product, "version": version,
                             "source": source})

    for p in host["ports"]:
        for cpe in p.get("cpes", []):
            parsed = _cpe22(cpe)
            if parsed:
                part, vendor, product, ver = parsed
                add(p, part, vendor, product, ver or first_token(p["version"]), f"nmap cpe {cpe}")
        for pattern, (part, vendor, product) in PRODUCT_MAP:
            if re.search(pattern, p["product"] or "", re.I):
                add(p, part, vendor, product, first_token(p["version"]),
                    f"product map: {p['product']}")

    ident = host["identity"]
    fw = firmware_product(ident)
    if fw and ident.get("firmware"):
        vendor, product = fw
        if nvd.product_exists("o", vendor, product, cache_dir):
            add(None, "o", vendor, product, ident["firmware"], f"firmware ({ident['firmware_source']})")
        else:
            skipped.append({"where": "device", "product": f"{vendor}:{product}",
                            "reason": "NVD CPE dictionary has no such firmware product"})
    elif fw:
        skipped.append({"where": "device", "product": f"{fw[0]}:{fw[1]}", "reason": "firmware version unknown"})
    return list(items.values()), skipped
