"""Simulated household, for trying the dashboard before pointing it at a real network.

Start with `./run.sh --demo`. Demo numbers live in data/demo.sqlite and never
mix with real measurements.
"""
from __future__ import annotations

import math
import random
import time

from .base import Collector, CounterObs, DeviceObs, Snapshot

# mac, hostname, connection, segment, [typical Mbit/s when active], active hours (local), duty
DEMO_DEVICES = [
    ("3c:22:fb:10:20:30", "MacBook-Air", "wifi", "Wi-Fi: Home (5G)", 1.0, range(9, 24), 0.5),
    ("f4:5c:89:aa:01:02", "Living-Room-TV", "wifi", "Wi-Fi: Home (5G)", 3.0, range(18, 24), 0.7),
    ("00:d9:d1:12:34:56", "PS5", "lan", "LAN2", 12.0, range(1, 5), 0.25),
    ("a6:3b:11:22:33:44", "iPhone", "wifi", "Wi-Fi: Home (2.4G)", 0.4, range(7, 24), 0.4),
    ("52:9c:de:ad:be:ef", "Galaxy-A54", "wifi", "Wi-Fi: Home (2.4G)", 0.8, range(10, 26), 0.5),
    ("b8:27:eb:00:11:22", "raspberrypi", "lan", "LAN1", 0.02, range(0, 24), 1.0),
    ("d8:0d:17:5a:5b:5c", "Desktop-PC", "lan", "LAN3", 1.5, range(14, 23), 0.4),
    ("7a:10:c4:99:88:77", None, "wifi", "Wi-Fi: Home (2.4G)", 1.2, range(22, 30), 0.6),
]

DEMO_SCALE = 0.4      # tuned so the simulated house uses roughly 9-10 GB a day


def demo_rate(spec, local_hour: float, rng: random.Random) -> tuple[float, float]:
    """(download, upload) bytes per second for a simulated device at a time of day."""
    _, _, _, _, mbps, hours, duty = spec
    h = int(local_hour)
    active = h in hours or (h + 24) in hours
    if not active or rng.random() > duty:
        return 500.0 * rng.random(), 200.0 * rng.random()        # idle chatter
    wobble = 0.6 + 0.8 * rng.random() + 0.2 * math.sin(local_hour)
    down = mbps * DEMO_SCALE * 1_000_000 / 8 * wobble
    return down, down * (0.04 + 0.05 * rng.random())


class DemoCollector(Collector):
    name = "demo"
    interval = 5
    priority = 20

    def __init__(self, tz):
        super().__init__()
        self.tz = tz
        self.rng = random.Random(7)
        self.counters = {d[0]: [0.0, 0.0] for d in DEMO_DEVICES}
        self.last = time.time()
        self.note = "DEMO MODE: these devices and numbers are simulated."

    def collect(self) -> Snapshot:
        from datetime import datetime
        now = time.time()
        dt = now - self.last
        self.last = now
        local = datetime.fromtimestamp(now, self.tz)
        hour = local.hour + local.minute / 60
        snap = Snapshot(source=self.name, authoritative_presence=True)
        total = [0.0, 0.0]
        for i, spec in enumerate(DEMO_DEVICES):
            mac, name, conn, seg, *_ = spec
            down, up = demo_rate(spec, hour, self.rng)
            c = self.counters[mac]
            c[0] += down * dt
            c[1] += up * dt
            total[0] += c[0]
            total[1] += c[1]
            online = (int(hour) in spec[5]) or (int(hour) + 24 in spec[5])
            snap.devices.append(DeviceObs(mac=mac, ip=f"192.168.1.{10 + i}", hostname=name,
                                          conn_type=conn, segment=seg, online=online))
            snap.counters.append(CounterObs(key=mac, rx=int(c[0]), tx=int(c[1])))
        snap.counters.append(CounterObs(key="total:wan", rx=int(total[0]), tx=int(total[1])))
        self.capabilities = {"per_device": True, "wan_total": True}
        return snap
