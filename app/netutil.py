"""Small network helpers shared by the collectors (no root needed)."""
from __future__ import annotations

import ipaddress
import re
import socket
import subprocess
import sys
from dataclasses import dataclass
from functools import lru_cache

import psutil

_MAC_RE = re.compile(r"^[0-9a-f]{1,2}([:-][0-9a-f]{1,2}){5}$", re.I)


def normalize_mac(mac: str | None) -> str | None:
    """'A:B:C:D:E:F' / 'AA-BB-..' / 'aabb.ccdd.eeff' -> 'aa:bb:cc:dd:ee:ff' (None if invalid)."""
    if not mac:
        return None
    mac = mac.strip().lower()
    if re.fullmatch(r"[0-9a-f]{12}", mac):
        mac = ":".join(mac[i:i + 2] for i in range(0, 12, 2))
    elif re.fullmatch(r"[0-9a-f]{4}(\.[0-9a-f]{4}){2}", mac):
        raw = mac.replace(".", "")
        mac = ":".join(raw[i:i + 2] for i in range(0, 12, 2))
    if not _MAC_RE.match(mac):
        return None
    mac = ":".join(part.zfill(2) for part in re.split(r"[:-]", mac))
    if mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
        return None
    return mac


def is_multicast_mac(mac: str) -> bool:
    return bool(int(mac[:2], 16) & 0x01)


def is_randomized_mac(mac: str) -> bool:
    """Phones use 'private' (locally administered) MAC addresses that hide the vendor."""
    return bool(int(mac[:2], 16) & 0x02)


@lru_cache(maxsize=4096)
def vendor_for(mac: str) -> str:
    """Manufacturer from the MAC prefix (IEEE OUI registry bundled with `netaddr`)."""
    if is_randomized_mac(mac):
        return "Private (randomized) address"
    try:
        from netaddr import EUI
        return EUI(mac).oui.registration().org
    except Exception:
        return "Unknown"


@dataclass
class LocalNet:
    interface: str
    ip: str
    netmask: str
    mac: str | None
    gateway: str | None

    @property
    def network(self) -> ipaddress.IPv4Network:
        return ipaddress.ip_network(f"{self.ip}/{self.netmask}", strict=False)


def default_gateway() -> str | None:
    """IP address of the router this computer uses."""
    try:
        if sys.platform == "darwin":
            out = subprocess.run(["/sbin/route", "-n", "get", "default"],
                                 capture_output=True, text=True, timeout=5).stdout
            m = re.search(r"gateway:\s*(\d+\.\d+\.\d+\.\d+)", out)
        else:
            out = subprocess.run(["ip", "route", "show", "default"],
                                 capture_output=True, text=True, timeout=5).stdout
            m = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", out)
        return m.group(1) if m else None
    except (OSError, subprocess.SubprocessError):
        return None


def _outbound_ip(target: str) -> str | None:
    """Which local IP would be used to reach `target` (no packet is sent)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((target, 9))
        return s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()


def local_network(prefer_gateway: str | None = None) -> LocalNet | None:
    """The interface, IP, netmask and MAC this computer uses to reach the router."""
    gateway = prefer_gateway or default_gateway()
    ip = _outbound_ip(gateway or "192.0.2.1")
    if not ip:
        return None
    for name, addrs in psutil.net_if_addrs().items():
        v4 = next((a for a in addrs if a.family == socket.AF_INET and a.address == ip), None)
        if not v4:
            continue
        link = next((a for a in addrs if a.family == psutil.AF_LINK), None)
        return LocalNet(name, ip, v4.netmask or "255.255.255.0",
                        normalize_mac(link.address) if link else None, gateway)
    return None


def interface_mac(name: str) -> str | None:
    for a in psutil.net_if_addrs().get(name, []):
        if a.family == psutil.AF_LINK:
            return normalize_mac(a.address)
    return None
