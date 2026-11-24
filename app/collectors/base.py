"""Common types for data collectors.

A collector looks at ONE data source (the router's admin pages, this
computer's ARP table, ...) and returns a Snapshot: which devices it saw and
whatever cumulative byte counters it could read. The poller (app/poller.py)
merges the snapshots, so adding a new source later (for example an OpenWrt
router running nlbwmon) only means writing one more small class.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field


@dataclass
class DeviceObs:
    mac: str
    ip: str | None = None
    hostname: str | None = None
    conn_type: str | None = None      # 'wifi' | 'lan'
    segment: str | None = None        # e.g. 'LAN2' or 'Wi-Fi: HomeNet (5G)'
    online: bool = True
    is_gateway: bool = False
    is_self: bool = False


@dataclass
class CounterObs:
    """A cumulative byte counter.

    key   device MAC, 'seg:<name>' (router port / Wi-Fi network) or 'total:wan'
    rx    bytes downloaded BY the device / segment / house (cumulative)
    tx    bytes uploaded (cumulative)
    """
    key: str
    rx: int
    tx: int
    label: str | None = None          # display name for segments


@dataclass
class Snapshot:
    source: str
    ts: float = field(default_factory=time.time)
    devices: list[DeviceObs] = field(default_factory=list)
    counters: list[CounterObs] = field(default_factory=list)
    # True when the source knows exactly who is connected right now (the
    # router does; an ARP cache can be up to ~20 minutes stale).
    authoritative_presence: bool = False


class CollectorError(Exception):
    """Expected failure (router unreachable, wrong password, ...)."""


class Collector:
    name = "base"
    interval = 60.0          # minimum seconds between runs
    timeout = 45.0
    # Higher wins when two sources report bytes for the same device.
    priority = 0

    def __init__(self) -> None:
        self.capabilities: dict = {}
        self.note: str | None = None      # human-readable hint shown on the dashboard

    def collect(self) -> Snapshot:        # runs in a worker thread
        raise NotImplementedError

    def close(self) -> None:
        pass
