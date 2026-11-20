"""Resolver interface: evidence record in, record with `resolved` populated out.

STUB (Phase 1). No identification method is chosen. This copies the make, model and
firmware strings the device itself reported over ONVIF or UPnP into `resolved`.
It does not consult a database or a model and must not be read as an identification.
"""


def resolve(record: dict) -> dict:
    onvif = record["onvif"]
    descs = [r["description"] for r in record["active"]["upnp"] + record["passive"]["ssdp"]
             if r.get("description") and "error" not in r["description"]]
    upnp = descs[0] if descs else {}
    record["resolved"] = {
        "method": "stub-passthrough",
        "make": onvif.get("make") or upnp.get("manufacturer"),
        "model": onvif.get("model") or upnp.get("model_name"),
        "firmware": onvif.get("firmware"),
        "sources": [s for s, ok in (("onvif", onvif.get("status") == "answered"), ("upnp", bool(upnp))) if ok],
    }
    return record
