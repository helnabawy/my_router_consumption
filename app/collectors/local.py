"""Exact usage of the computer running this app (interface byte counters).

This is the one device we can always measure precisely, with no router
support at all. It counts everything on the network interface, so large
transfers to other devices at home (AirDrop, a NAS) are included too.
"""
from __future__ import annotations

import socket

import psutil

from ..netutil import local_network
from .base import Collector, CollectorError, CounterObs, DeviceObs, Snapshot


class LocalCollector(Collector):
    name = "local"
    interval = 10
    priority = 10

    def __init__(self, gateway: str | None = None):
        super().__init__()
        self.gateway_hint = gateway

    def collect(self) -> Snapshot:
        net = local_network(self.gateway_hint)
        if net is None or not net.mac:
            raise CollectorError("no active network interface")
        io = psutil.net_io_counters(pernic=True).get(net.interface)
        if io is None:
            raise CollectorError(f"no counters for interface {net.interface}")
        snap = Snapshot(source=self.name)
        snap.devices.append(DeviceObs(mac=net.mac, ip=net.ip, is_self=True,
                                      hostname=socket.gethostname().split(".")[0]))
        snap.counters.append(CounterObs(key=net.mac, rx=io.bytes_recv, tx=io.bytes_sent))
        self.capabilities = {"interface": net.interface}
        return snap
