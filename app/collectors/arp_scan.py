"""Device discovery that works with ANY router, without admin access or root.

How it works (this is ordinary traffic, not ARP spoofing):
  1. Send one tiny UDP datagram to every address in the home subnet. To send
     it, the operating system must first ask "who has 192.168.1.x?" (a normal
     ARP request). Every powered-on device answers that question.
  2. Read the operating system's ARP table (`arp -an`) to get IP -> MAC pairs.

Limit: the OS keeps ARP entries for up to ~20 minutes, so a device that left
can still look online for a while. When the router collector works, it is
used as the authority for online/offline instead.
"""
from __future__ import annotations

import ipaddress
import logging
import re
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, wait

from ..netutil import is_multicast_mac, local_network, normalize_mac
from .base import Collector, CollectorError, DeviceObs, Snapshot

log = logging.getLogger("we.arp")

# macOS:  ? (192.168.1.7) at a4:83:e7:1:2:3 on en0 ifscope [ethernet]
# Linux:  ? (192.168.1.7) at a4:83:e7:01:02:03 [ether] on eth0
_ARP_LINE = re.compile(r"\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-fA-F:]+)\b.*? on (\S+)")
# Linux `ip neigh`: 192.168.1.7 dev eth0 lladdr a4:83:e7:01:02:03 REACHABLE
_NEIGH_LINE = re.compile(r"^(\d+\.\d+\.\d+\.\d+) dev (\S+) lladdr ([0-9a-fA-F:]+) (\w+)")

MAX_HOSTS = 1024           # never sweep more than a /22
HOSTNAME_TTL = 6 * 3600


def parse_arp_table(text: str, interface: str | None = None) -> dict[str, str]:
    """Parse `arp -an` output into {ip: mac}. Incomplete entries are skipped."""
    found: dict[str, str] = {}
    for line in text.splitlines():
        m = _ARP_LINE.search(line)
        if not m:
            continue
        ip, mac, iface = m.group(1), normalize_mac(m.group(2)), m.group(3)
        if not mac or is_multicast_mac(mac):
            continue
        if interface and iface != interface:
            continue
        found[ip] = mac
    return found


def parse_ip_neigh(text: str, interface: str | None = None) -> dict[str, str]:
    found: dict[str, str] = {}
    for line in text.splitlines():
        m = _NEIGH_LINE.match(line.strip())
        if not m or m.group(4) in ("FAILED", "INCOMPLETE"):
            continue
        mac = normalize_mac(m.group(3))
        if mac and not is_multicast_mac(mac) and (not interface or m.group(2) == interface):
            found[m.group(1)] = mac
    return found


def read_arp_table(interface: str | None = None) -> dict[str, str]:
    for cmd, parser in ((["arp", "-an"], parse_arp_table),
                        (["ip", "neigh", "show"], parse_ip_neigh)):
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        except (OSError, subprocess.SubprocessError):
            continue
        if out.returncode == 0:
            return parser(out.stdout, interface)
    raise CollectorError("could not read the ARP table (`arp -an` failed)")


class ArpScanCollector(Collector):
    name = "arp_scan"
    priority = 0

    def __init__(self, interval: float = 60, gateway: str | None = None):
        super().__init__()
        self.interval = interval
        self.gateway_hint = gateway
        self._names: dict[str, tuple[float, str | None]] = {}   # ip -> (looked up at, hostname)
        self._pool = ThreadPoolExecutor(max_workers=8, thread_name_prefix="rdns")

    def _poke(self, net) -> None:
        """Make the OS resolve every address on the subnet (one tiny datagram each)."""
        hosts = list(net.network.hosts())
        if len(hosts) > MAX_HOSTS:   # huge subnet: only the /24 around us
            hosts = list(ipaddress.ip_network(f"{net.ip}/24", strict=False).hosts())
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setblocking(False)
        try:
            for i, host in enumerate(hosts):
                if str(host) == net.ip:
                    continue
                try:
                    s.sendto(b"\x00", (str(host), 33434))
                except OSError:
                    pass                 # e.g. ARP queue full: next scan will catch it
                if i % 32 == 31:
                    time.sleep(0.02)     # spread ~254 packets over ~0.2 s
        finally:
            s.close()

    def _hostnames(self, ips: list[str]) -> dict[str, str | None]:
        """Best-effort reverse DNS (the router often knows DHCP hostnames)."""
        now = time.time()
        todo = [ip for ip in ips
                if ip not in self._names or now - self._names[ip][0] > HOSTNAME_TTL]

        def lookup(ip: str) -> tuple[str, str | None]:
            try:
                name = socket.gethostbyaddr(ip)[0]
                return ip, None if name == ip else name.split(".")[0]
            except OSError:
                return ip, None

        futures = [self._pool.submit(lookup, ip) for ip in todo[:32]]
        done, _ = wait(futures, timeout=8)
        for f in done:
            ip, name = f.result()
            self._names[ip] = (now, name)
        return {ip: self._names[ip][1] for ip in ips if ip in self._names}

    def collect(self) -> Snapshot:
        net = local_network(self.gateway_hint)
        if net is None:
            raise CollectorError("this computer is not connected to a network")
        self._poke(net)
        time.sleep(1.5)                  # give devices a moment to answer
        table = read_arp_table(net.interface)
        table = {ip: mac for ip, mac in table.items() if _in_net(ip, net)}
        names = self._hostnames(list(table))
        snap = Snapshot(source=self.name)
        for ip, mac in table.items():
            snap.devices.append(DeviceObs(mac=mac, ip=ip, hostname=names.get(ip),
                                          is_gateway=(ip == net.gateway)))
        if net.mac:                       # the ARP table never lists ourselves
            snap.devices.append(DeviceObs(mac=net.mac, ip=net.ip,
                                          hostname=socket.gethostname().split(".")[0],
                                          is_self=True))
        self.capabilities = {"devices": len(snap.devices), "subnet": str(net.network)}
        return snap

    def close(self) -> None:
        self._pool.shutdown(wait=False, cancel_futures=True)


def _in_net(ip: str, net) -> bool:
    try:
        return ipaddress.ip_address(ip) in net.network
    except ValueError:
        return False
