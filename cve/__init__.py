"""CVE interface: evidence record in, record with `cves` populated out.

STUB (Phase 1). No vulnerability source is wired; returns an empty list.
"""


def lookup(record: dict) -> dict:
    record["cves"] = []
    record["notes"].append("CVE step is a stub: no vulnerability source is wired.")
    return record
