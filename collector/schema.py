"""Evidence record: the contract every component reads and writes.

Bump SCHEMA_VERSION on any change to the structure below.
"""
from datetime import datetime, timezone

SCHEMA_VERSION = "1.0"


def new_record(label: str, ip: str) -> dict:
    """Return an empty, JSON-serializable evidence record for one target."""
    return {
        "schema_version": SCHEMA_VERSION,
        "target": {"ip": ip, "mac": None, "label": label},
        "collected_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "link": {"mac": None, "oui_vendor": None},
        "passive": {
            "window_seconds": None,
            "pcap": None,
            "dhcp": [],  # [{message_type, param_req_list, vendor_class, hostname}]
            "mdns": {"names": [], "services": [], "txt": {}},
            "ssdp": [],  # [{headers..., description: {...}}]
        },
        "active": {
            "ports": [],  # [{port, proto, service, product, version, extrainfo, http_server_header, tls_cert_subject}]
            "rtsp_banner": None,
            "upnp": [],  # unicast M-SEARCH responses, same shape as passive.ssdp
        },
        "onvif": {"status": "not_run", "endpoint": None,
                  "make": None, "model": None, "firmware": None, "serial": None, "hardware_id": None},
        "resolved": {},
        "cves": [],
        "notes": [],
    }
