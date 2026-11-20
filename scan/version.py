"""Version comparison and NVD cpeMatch evaluation."""
import re

TOKEN_RE = re.compile(r"\d+|[a-z]+")


PRE_RELEASE = {"alpha", "a", "beta", "b", "rc", "pre", "dev"}
ZERO = (2, 0)


def key(version: str) -> list:
    """'10.0p2' -> [(2,10), (2,0), (3,'p'), (2,2)].
    Pre-release words sort below the release, patch letters (p1, OpenSSL 'k') above it."""
    out = []
    for t in TOKEN_RE.findall(version.lower()):
        if t.isdigit():
            out.append((2, int(t)))
        else:
            out.append((0, t) if t in PRE_RELEASE else (3, t))
    return out


def cmp(a: str, b: str) -> int:
    ka, kb = key(a), key(b)
    # Pad with zeros so 1.4 == 1.4.0.
    n = max(len(ka), len(kb))
    ka += [ZERO] * (n - len(ka))
    kb += [ZERO] * (n - len(kb))
    return (ka > kb) - (ka < kb)


def split_cpe(cpe23: str) -> tuple[str, str, str, str]:
    """'cpe:2.3:a:vendor:product:version:update:...' -> (part, vendor, product, version).
    A concrete update is folded into the version: 9.3 + p1 -> 9.3p1."""
    f = cpe23.split(":")
    version = f[5]
    if version not in ("*", "-") and len(f) > 6 and f[6] not in ("*", "-", ""):
        version += f[6]
    return f[2], f[3], f[4], version


def match(entry: dict, vendor: str, product: str, version: str) -> str | None:
    """Match one NVD cpeMatch entry against our product/version. Returns the match type or None."""
    if not entry.get("vulnerable"):
        return None
    _, v, p, ver = split_cpe(entry["criteria"])
    if (v, p) != (vendor, product):
        return None
    bounds = {k: entry[k] for k in ("versionStartIncluding", "versionStartExcluding",
                                    "versionEndIncluding", "versionEndExcluding") if k in entry}
    if ver not in ("*", "-"):
        return "exact" if cmp(ver, version) == 0 else None
    if ver == "-":
        return "unversioned"
    if not bounds:
        return "all-versions"
    ok = True
    if "versionStartIncluding" in bounds:
        ok &= cmp(version, bounds["versionStartIncluding"]) >= 0
    if "versionStartExcluding" in bounds:
        ok &= cmp(version, bounds["versionStartExcluding"]) > 0
    if "versionEndIncluding" in bounds:
        ok &= cmp(version, bounds["versionEndIncluding"]) <= 0
    if "versionEndExcluding" in bounds:
        ok &= cmp(version, bounds["versionEndExcluding"]) < 0
    return "range" if ok else None


STRENGTH = ["unversioned", "all-versions", "range", "exact"]


def match_cve(cve: dict, vendor: str, product: str, version: str) -> str | None:
    """Strongest match type across all configurations of an NVD CVE record, or None."""
    best = None
    for conf in cve.get("configurations", []):
        for node in conf.get("nodes", []):
            for entry in node.get("cpeMatch", []):
                m = match(entry, vendor, product, version)
                if m and (best is None or STRENGTH.index(m) > STRENGTH.index(best)):
                    best = m
    return best
