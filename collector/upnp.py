"""SSDP/UPnP helpers shared by the passive (NOTIFY) and active (M-SEARCH) collectors."""
import socket
import time
import xml.etree.ElementTree as ET
from urllib.parse import urlparse

import requests

DESC_FIELDS = {
    "deviceType": "device_type", "manufacturer": "manufacturer", "modelName": "model_name",
    "modelNumber": "model_number", "modelDescription": "model_description",
    "friendlyName": "friendly_name", "serialNumber": "serial", "UDN": "udn",
}

MSEARCH = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    'MAN: "ssdp:discover"\r\n'
    "MX: 1\r\n"
    "ST: ssdp:all\r\n\r\n"
).encode()


def parse_headers(payload: bytes) -> dict:
    """Parse an SSDP datagram into {start_line, lower-cased headers}."""
    lines = payload.decode("utf-8", "replace").split("\r\n")
    headers = {"start_line": lines[0]}
    for line in lines[1:]:
        key, sep, value = line.partition(":")
        if sep:
            headers[key.strip().lower()] = value.strip()
    return headers


def parse_description(xml: bytes) -> dict:
    """Extract the root device's identity fields from a UPnP description document."""
    root = ET.fromstring(xml)
    device = next((el for el in root.iter() if el.tag.rsplit("}", 1)[-1] == "device"), None)
    if device is None:
        return {"error": "no <device> element"}
    out = {}
    for child in device:
        name = child.tag.rsplit("}", 1)[-1]
        if name in DESC_FIELDS:
            out[DESC_FIELDS[name]] = (child.text or "").strip()
    return out


def fetch_description(location: str, target_ip: str) -> dict:
    """Fetch a description document, but only from the target itself (scope rule)."""
    if urlparse(location).hostname != target_ip:
        return {"error": f"location {location} is not on the target; not fetched"}
    try:
        resp = requests.get(location, timeout=5)
        resp.raise_for_status()
        return parse_description(resp.content)
    except (requests.RequestException, ET.ParseError) as exc:
        return {"error": str(exc)}


def describe(responses: list[dict], target_ip: str) -> list[dict]:
    """Attach a description to each SSDP response, fetching each LOCATION once."""
    cache: dict[str, dict] = {}
    for headers in responses:
        location = headers.get("location")
        if location:
            if location not in cache:
                cache[location] = fetch_description(location, target_ip)
            headers["description"] = cache[location]
    return responses


def search(dest: str, timeout: float = 3.0, local_ip: str | None = None) -> dict[str, list[dict]]:
    """Send one M-SEARCH to dest (a host, or 239.255.255.250 for the whole LAN);
    return replies per source IP, deduplicated by USN. Descriptions are not fetched."""
    seen: dict[str, dict[str, dict]] = {}
    deadline = time.monotonic() + timeout
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        if local_ip:
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(local_ip))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        s.sendto(MSEARCH, (dest, 1900))
        while (remaining := deadline - time.monotonic()) > 0:
            s.settimeout(remaining)
            try:
                data, (src, _) = s.recvfrom(65535)
            except socket.timeout:
                break
            headers = parse_headers(data)
            per_host = seen.setdefault(src, {})
            per_host.setdefault(headers.get("usn", str(len(per_host))), headers)
    return {src: list(per_host.values()) for src, per_host in seen.items()}


def msearch(target_ip: str, timeout: float = 3.0) -> list[dict]:
    """Send one unicast M-SEARCH to the target and collect its described replies."""
    return describe(search(target_ip, timeout).get(target_ip, []), target_ip)
