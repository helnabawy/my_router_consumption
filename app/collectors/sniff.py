"""Gateway mode: exact per-device usage when this Mac shares its internet.

When macOS "Internet Sharing" is on (System Settings > General > Sharing),
the Mac becomes a small router: it is plugged into the WE router by cable and
your devices join the Mac's own Wi-Fi network. Every byte those devices use
then passes through the Mac's `bridge100` interface, where we can simply
COUNT it per MAC address. Nothing is intercepted, redirected or spoofed: the
devices chose this Mac as their access point.

We count with `tcpdump`, which only reads packet headers (first 96 bytes) and
writes nothing to disk. tcpdump needs root; see README "Gateway mode" for the
one-line sudoers rule that allows exactly this command and nothing else.

EXPERIMENTAL: this collector was developed against tcpdump's documented output
format but could not be exercised on a real Internet Sharing setup. Verify it
with the testing checklist before trusting its numbers.
"""
from __future__ import annotations

import logging
import re
import shutil
import subprocess
import threading
import time

import psutil

from ..netutil import interface_mac, is_multicast_mac, local_network, normalize_mac
from .base import Collector, CollectorError, CounterObs, DeviceObs, Snapshot

log = logging.getLogger("we.sniff")

# 1732480000.123456 aa:bb:cc:dd:ee:ff > 11:22:33:44:55:66, IPv4, length 1514: 192.168.2.3.50 > ...
_FRAME = re.compile(
    r"^\S+ ([0-9a-f:]{11,17}) > ([0-9a-f:]{11,17}), (?:ethertype )?(IPv4|IPv6)\b.*?length (\d+)")
_IPV4_SRC = re.compile(r"length \d+: (\d+\.\d+\.\d+\.\d+)[. ]")


def parse_frame(line: str) -> tuple[str, str, int, str | None] | None:
    """One tcpdump line -> (src_mac, dst_mac, frame_bytes, src_ipv4) or None."""
    m = _FRAME.match(line)
    if not m:
        return None
    src, dst = normalize_mac(m.group(1)), normalize_mac(m.group(2))
    if not src or not dst:
        return None
    ip = _IPV4_SRC.search(line) if m.group(3) == "IPv4" else None
    return src, dst, int(m.group(4)), ip.group(1) if ip else None


class SniffCollector(Collector):
    name = "sniff"
    interval = 10
    priority = 30          # most trustworthy per-device source

    def __init__(self, interface: str = "bridge100", use_sudo: bool = True):
        super().__init__()
        self.interface = interface
        self.use_sudo = use_sudo
        self._proc: subprocess.Popen | None = None
        self._lock = threading.Lock()
        self._bytes: dict[str, list[int]] = {}        # mac -> [download, upload]
        self._ips: dict[str, str] = {}
        self._last_frame: dict[str, float] = {}
        self._gw_mac: str | None = None
        self._err_tail: list[str] = []
        # For the Mac's own usage: uplink bytes minus what was forwarded to clients.
        self._own = [0, 0]
        self._prev_io: tuple[int, int, int, int] | None = None

    # ---- tcpdump process ------------------------------------------------
    def _start(self) -> None:
        if self.interface not in psutil.net_if_addrs():
            raise CollectorError(
                f"interface {self.interface} does not exist. Turn on Internet Sharing "
                "(System Settings > General > Sharing) or fix collectors.sniff.interface")
        tcpdump = shutil.which("tcpdump") or "/usr/sbin/tcpdump"
        cmd = [tcpdump, "-i", self.interface, "-e", "-n", "-q", "-l", "-tt", "-s", "96",
               "ip or ip6"]
        if self.use_sudo:
            cmd = ["/usr/bin/sudo", "-n", *cmd]     # -n: never ask for a password
        self._gw_mac = interface_mac(self.interface)
        self._proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                      text=True, bufsize=1)
        threading.Thread(target=self._read, args=(self._proc,), daemon=True).start()
        threading.Thread(target=self._read_err, args=(self._proc,), daemon=True).start()
        log.info("counting traffic on %s (gateway MAC %s)", self.interface, self._gw_mac)

    def _read(self, proc: subprocess.Popen) -> None:
        for line in proc.stdout:              # one line per packet
            frame = parse_frame(line)
            if frame:
                self._count(*frame)

    def _read_err(self, proc: subprocess.Popen) -> None:
        for line in proc.stderr:
            self._err_tail = (self._err_tail + [line.strip()])[-5:]

    def _count(self, src: str, dst: str, size: int, src_ip: str | None) -> None:
        gw = self._gw_mac
        with self._lock:
            if dst == gw and not is_multicast_mac(src):        # device -> internet
                self._bytes.setdefault(src, [0, 0])[1] += size
                self._last_frame[src] = time.time()
                if src_ip:
                    self._ips[src] = src_ip
            elif src == gw and not is_multicast_mac(dst):      # internet -> device
                self._bytes.setdefault(dst, [0, 0])[0] += size
            # device <-> device traffic never touches the internet: ignored

    # ---- collector API --------------------------------------------------
    def _own_usage(self) -> None:
        """This Mac's own traffic = uplink interface minus what it forwarded."""
        net = local_network()
        io = psutil.net_io_counters(pernic=True)
        if not net or net.interface not in io or self.interface not in io:
            return
        up, br = io[net.interface], io[self.interface]
        cur = (up.bytes_recv, up.bytes_sent, br.bytes_recv, br.bytes_sent)
        if self._prev_io:
            d = [max(0, c - p) for c, p in zip(cur, self._prev_io)]
            self._own[0] += max(0, d[0] - d[3])   # downloaded - sent on to clients
            self._own[1] += max(0, d[1] - d[2])   # uploaded - received from clients
        self._prev_io = cur
        if net.mac:
            self._self = (net.mac, net.ip)

    def collect(self) -> Snapshot:
        if self._proc is None or self._proc.poll() is not None:
            if self._proc is not None:
                detail = "; ".join(self._err_tail) or f"exit code {self._proc.returncode}"
                self._proc = None
                raise CollectorError(f"tcpdump stopped: {detail}")
            self._start()
            time.sleep(1.0)
            if self._proc.poll() is not None:
                detail = "; ".join(self._err_tail) or "permission denied?"
                self._proc = None
                raise CollectorError(f"tcpdump could not start: {detail} (see README > Gateway mode)")
        self._self = None
        self._own_usage()
        snap = Snapshot(source=self.name, authoritative_presence=False)
        now = time.time()
        with self._lock:
            for mac, (rx, tx) in self._bytes.items():
                snap.counters.append(CounterObs(key=mac, rx=rx, tx=tx))
                snap.devices.append(DeviceObs(
                    mac=mac, ip=self._ips.get(mac), conn_type="wifi",
                    segment="Mac Internet Sharing",
                    online=now - self._last_frame.get(mac, 0) < 120))
        if self._self:
            mac, ip = self._self
            snap.counters.append(CounterObs(key=mac, rx=self._own[0], tx=self._own[1]))
            snap.devices.append(DeviceObs(mac=mac, ip=ip, is_self=True))
        self.capabilities = {"per_device": True, "clients": len(self._bytes)}
        return snap

    def close(self) -> None:
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
