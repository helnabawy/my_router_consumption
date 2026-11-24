"""Whole-house total from the router's standard UPnP counters (if UPnP is on).

Most home routers answer the UPnP "Internet Gateway Device" queries
GetTotalBytesReceived / GetTotalBytesSent. That gives the TOTAL traffic of
the internet connection (never per device), which is exactly what the quota
tracker needs. No password is required and nothing on the router is changed.

Limits: the counters are 32-bit on most routers (they wrap every 4 GB; the
accounting code handles that), reset when the router reboots, and some
firmware returns 0 or leaves UPnP switched off.
"""
from __future__ import annotations

import logging
import re
import socket
import time
import xml.etree.ElementTree as ET
from urllib.parse import urljoin, urlparse

import httpx

from ..netutil import default_gateway
from .base import Collector, CollectorError, CounterObs, Snapshot

log = logging.getLogger("we.upnp")

SSDP_ADDR = ("239.255.255.250", 1900)
SERVICE = "urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1"
SEARCH_TARGETS = (SERVICE, "urn:schemas-upnp-org:device:InternetGatewayDevice:1", "upnp:rootdevice")


def ssdp_locations(timeout: float = 3.0) -> list[str]:
    """Ask the local network which UPnP devices exist; return their description URLs."""
    found: list[str] = []
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.settimeout(0.5)
    try:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        for st in SEARCH_TARGETS:
            msg = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
                   f'MAN: "ssdp:discover"\r\nMX: 2\r\nST: {st}\r\n\r\n')
            try:
                s.sendto(msg.encode(), SSDP_ADDR)
            except OSError:
                pass
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data, _ = s.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            m = re.search(rb"(?im)^location:\s*(\S+)", data)
            if m:
                url = m.group(1).decode(errors="replace")
                if url not in found:
                    found.append(url)
    finally:
        s.close()
    return found


def find_control_url(description_xml: str, base_url: str) -> str | None:
    """Locate the WANCommonInterfaceConfig control URL inside a device description."""
    root = ET.fromstring(description_xml)
    url_base = None
    for el in root.iter():
        if el.tag.endswith("}URLBase") or el.tag == "URLBase":
            url_base = (el.text or "").strip() or None
    for svc in root.iter():
        if not svc.tag.endswith("service"):
            continue
        fields = {c.tag.split("}")[-1]: (c.text or "").strip() for c in svc}
        if "WANCommonInterfaceConfig" in fields.get("serviceType", ""):
            return urljoin(url_base or base_url, fields.get("controlURL", ""))
    return None


def soap_value(control_url: str, action: str, timeout: float = 5.0) -> int:
    body = ('<?xml version="1.0"?>'
            '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
            's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>'
            f'<u:{action} xmlns:u="{SERVICE}"/></s:Body></s:Envelope>')
    r = httpx.post(control_url, content=body, timeout=timeout, headers={
        "Content-Type": 'text/xml; charset="utf-8"',
        "SOAPAction": f'"{SERVICE}#{action}"',
    })
    r.raise_for_status()
    m = re.search(r"<New\w+>\s*(\d+)\s*</New\w+>", r.text)
    if not m:
        raise CollectorError(f"router gave no value for {action}")
    return int(m.group(1))


class UpnpCollector(Collector):
    name = "upnp"
    priority = 5

    def __init__(self, interval: float = 30, gateway: str | None = None):
        super().__init__()
        self.interval = interval
        self.gateway_hint = gateway
        self.control_url: str | None = None
        self._next_discovery = 0.0

    def _discover(self) -> None:
        gateway = self.gateway_hint or default_gateway()
        for loc in ssdp_locations():
            # Only trust the router itself, not a TV or printer that also speaks UPnP.
            if gateway and urlparse(loc).hostname != gateway:
                continue
            try:
                xml = httpx.get(loc, timeout=5).text
                url = find_control_url(xml, loc)
            except (httpx.HTTPError, ET.ParseError):
                continue
            if url:
                self.control_url = url
                log.info("UPnP total counters found at %s", url)
                return
        raise CollectorError("router does not answer UPnP (it may be switched off in the router settings)")

    def collect(self) -> Snapshot:
        if not self.control_url:
            if time.time() < self._next_discovery:
                raise CollectorError("UPnP not available on this router (will retry later)")
            self._next_discovery = time.time() + 600     # don't spam the network
            self._discover()
        try:
            rx = soap_value(self.control_url, "GetTotalBytesReceived")
            tx = soap_value(self.control_url, "GetTotalBytesSent")
        except httpx.HTTPError as e:
            self.control_url = None
            raise CollectorError(f"UPnP query failed: {e}") from e
        if rx == 0 and tx == 0:
            self.note = "router answers UPnP but reports 0 bytes (firmware does not count)"
            raise CollectorError(self.note)
        self.capabilities = {"wan_total": True}
        snap = Snapshot(source=self.name)
        snap.counters.append(CounterObs(key="total:wan", rx=rx, tx=tx))
        return snap
