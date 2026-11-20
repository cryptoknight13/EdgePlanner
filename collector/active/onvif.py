"""ONVIF GetDeviceInformation over plain SOAP. Unauthenticated: no credentials are assumed."""
import xml.etree.ElementTree as ET

import requests
import urllib3

# Camera certs are self-signed; we read what the device says, we do not trust it.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TDS = "{http://www.onvif.org/ver10/device/wsdl}"
REQUEST = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body>'
    '<GetDeviceInformation xmlns="http://www.onvif.org/ver10/device/wsdl"/>'
    "</s:Body></s:Envelope>"
)
FIELDS = {"Manufacturer": "make", "Model": "model", "FirmwareVersion": "firmware",
          "SerialNumber": "serial", "HardwareId": "hardware_id"}


def parse(xml: bytes) -> dict:
    root = ET.fromstring(xml)
    return {key: (el.text or "").strip() if (el := root.find(f".//{TDS}{tag}")) is not None else None
            for tag, key in FIELDS.items()}


def query(ip: str, endpoints: list[tuple[str, int]]) -> dict:
    """Try each (scheme, port) web endpoint; return the onvif section of the record."""
    result: dict = {"status": "no_answer", "endpoint": None}
    for scheme, port in endpoints:
        url = f"{scheme}://{ip}:{port}/onvif/device_service"
        try:
            resp = requests.post(url, data=REQUEST, timeout=5, verify=False,
                                 headers={"Content-Type": "application/soap+xml; charset=utf-8"})
        except requests.RequestException:
            continue
        if resp.status_code == 401 or b"NotAuthorized" in resp.content:
            result.update(status="auth_required", endpoint=url)
            continue
        if resp.ok and b"GetDeviceInformationResponse" in resp.content:
            try:
                return {"status": "answered", "endpoint": url, **parse(resp.content)}
            except ET.ParseError:
                continue
    return result
