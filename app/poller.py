"""The background loop: run collectors, merge what they saw, store usage.

Every `poll_seconds` the poller:
  1. runs each collector that is due (in worker threads, with a timeout)
  2. updates the device list (and raises "new device" alerts)
  3. converts cumulative counters to deltas and adds them to hourly buckets
  4. works out the whole-house total from the best available source
  5. records who was online, updates live speeds, evaluates alert rules
"""
from __future__ import annotations

import asyncio
import logging
import re
import time
from collections import deque

from .accounting import counter_delta, split_by_hour
from .alerts import AlertEngine
from .collectors.base import Collector, CollectorError, Snapshot
from .db import Database
from .netutil import is_randomized_mac, vendor_for

log = logging.getLogger("we.poller")

TOTAL_KEY = "total"
FRESH = 300          # a source is "active" if it produced data in the last 5 minutes
# Which source provides the whole-house total, best first.
TOTAL_PRIORITY = ("wan:router", "wan:demo", "wan:upnp", "sum:sniff", "sum:segments")


class Poller:
    def __init__(self, cfg, db: Database, collectors: list[Collector], alerts: AlertEngine):
        self.cfg = cfg
        self.db = db
        self.collectors = collectors
        self.alerts = alerts
        self.tick = float(cfg.get("poll_seconds", 15))
        self.status: dict[str, dict] = {
            c.name: {"ok": None, "error": None, "last_ok": None, "last_run": None,
                     "capabilities": {}, "note": None, "paused_until": 0}
            for c in collectors
        }
        self._next_run = {c.name: 0.0 for c in collectors}
        self._fail_count = {c.name: 0 for c in collectors}
        # key -> (source, last time that source reported bytes for the key)
        self._key_source: dict[str, tuple[str, float]] = {}
        self._priority = {c.name: c.priority for c in collectors}
        self._covered_until: dict[str, float] = {}
        self._total_seen: dict[str, float] = {}       # total candidate -> last seen
        self.total_source: str | None = None
        self.live: dict[str, tuple[float, float, float]] = {}   # key -> (ts, down_bps, up_bps)
        self.live_total: deque = deque(maxlen=int(1200 / self.tick) + 5)
        self.last_cycle: float | None = None
        self._last_presence_ts: float | None = None
        self._stop = asyncio.Event()

    # ------------------------------------------------------------------
    async def run(self) -> None:
        log.info("poller started with collectors: %s", ", ".join(c.name for c in self.collectors))
        while not self._stop.is_set():
            started = time.time()
            try:
                await self.cycle()
            except Exception:                      # never let the loop die
                log.exception("poll cycle failed")
            delay = max(1.0, self.tick - (time.time() - started))
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=delay)
            except asyncio.TimeoutError:
                pass

    def stop(self) -> None:
        self._stop.set()
        for c in self.collectors:
            try:
                c.close()
            except Exception:
                pass

    def pause(self, name: str, minutes: float) -> None:
        """Stop polling one collector for a while (e.g. to use the router admin page)."""
        if name in self.status:
            self.status[name]["paused_until"] = time.time() + minutes * 60

    # ------------------------------------------------------------------
    async def _run_collector(self, c: Collector) -> Snapshot | None:
        st = self.status[c.name]
        st["last_run"] = time.time()
        try:
            snap = await asyncio.wait_for(asyncio.to_thread(c.collect), timeout=c.timeout)
            st.update(ok=True, error=None, last_ok=time.time())
            self._fail_count[c.name] = 0
            return snap
        except CollectorError as e:
            st.update(ok=False, error=str(e))
        except asyncio.TimeoutError:
            st.update(ok=False, error=f"timed out after {c.timeout:.0f}s")
        except Exception as e:
            log.exception("collector %s crashed", c.name)
            st.update(ok=False, error=f"{type(e).__name__}: {e}")
        finally:
            st["capabilities"] = dict(c.capabilities)
            st["note"] = c.note
        # Back off after repeated failures (max 10 min) so we never hammer the
        # router -- repeated bad logins can lock its admin page.
        self._fail_count[c.name] += 1
        backoff = min(600.0, c.interval * 2 ** min(self._fail_count[c.name], 5))
        self._next_run[c.name] = time.time() + backoff
        return None

    async def cycle(self) -> None:
        now = time.time()
        due = [c for c in self.collectors
               if now >= self._next_run[c.name] and now >= self.status[c.name]["paused_until"]]
        for c in due:
            self._next_run[c.name] = now + c.interval - 0.5
        snaps = [s for s in await asyncio.gather(*(self._run_collector(c) for c in due)) if s]
        self.process(snaps)

    # ------------------------------------------------------------------
    def process(self, snaps: list[Snapshot], now: float | None = None) -> None:
        """Merge snapshots into the database (synchronous; also used by tests)."""
        now = now or time.time()
        online: set[str] = set()
        with self.db.transaction():
            authoritative = any(s.authoritative_presence for s in snaps)
            for snap in snaps:
                self._merge_devices(snap, authoritative, online, int(now))
            deltas = self._counter_deltas(snaps)
            self._store_usage(deltas, now)
            self._store_presence(online, now)
        self.last_cycle = now
        try:
            self.alerts.evaluate(self, now)
        except Exception:
            log.exception("alert evaluation failed")

    def _merge_devices(self, snap: Snapshot, authoritative: bool, online: set[str], now: int) -> None:
        for d in snap.devices:
            # An ARP cache can be stale; if the router told us who is really
            # connected in this cycle, believe the router about online status.
            trust_presence = d.online and (
                snap.authoritative_presence or not authoritative or d.is_self
                or snap.source in ("sniff", "local"))
            fields = {"ip": d.ip, "hostname": d.hostname, "conn_type": d.conn_type,
                      "segment": d.segment}
            if d.is_gateway:
                fields["is_gateway"] = 1
            if d.is_self:
                fields["is_self"] = 1
            existing = self.db.get_device(d.mac)
            if existing is None:
                fields["vendor"] = vendor_for(d.mac)
                fields["randomized"] = int(is_randomized_mac(d.mac))
                if d.is_gateway or d.is_self:
                    fields["known"] = 1
            is_new = self.db.upsert_device(d.mac, fields, trust_presence, snap.source, now)
            if trust_presence:
                online.add(d.mac)
            if is_new:
                self.alerts.new_device(self.db.get_device(d.mac), now)

    def _counter_deltas(self, snaps: list[Snapshot]) -> dict[str, dict[str, tuple]]:
        """{source: {key: (rx_delta, tx_delta, t_prev, t_now)}}"""
        out: dict[str, dict[str, tuple]] = {}
        for snap in snaps:
            for c in snap.counters:
                if c.key.startswith("seg:"):
                    self.db.upsert_device(c.key, {"kind": "segment", "hostname": c.label or c.key[4:],
                                                  "known": 1}, True, snap.source, int(snap.ts))
                prev = self.db.get_counter(snap.source, c.key)
                self.db.set_counter(snap.source, c.key, c.rx, c.tx, snap.ts)
                if prev is None:
                    continue          # first reading is only a baseline
                elapsed = snap.ts - prev["ts"]
                if elapsed <= 0:
                    continue
                # Both directions going backwards together means a restart
                # (router reboot), not a 32-bit wrap.
                restarted = c.rx < prev["rx"] and c.tx < prev["tx"]
                rx = counter_delta(prev["rx"], c.rx, elapsed, reset=restarted)
                tx = counter_delta(prev["tx"], c.tx, elapsed, reset=restarted)
                out.setdefault(snap.source, {})[c.key] = (rx, tx, prev["ts"], snap.ts)
        self._attribute_sole_members(out)
        return out

    def _attribute_sole_members(self, deltas: dict[str, dict[str, tuple]]) -> None:
        """A LAN port or Wi-Fi network with exactly ONE device on it is, in
        effect, a per-device counter: credit that device with the segment's bytes.

        "Exactly one" means one device seen on that port/SSID in the last 7 days,
        so a visitor joining the same Wi-Fi network stops the attribution rather
        than silently polluting it.
        """
        week_ago = int(time.time()) - 7 * 86400
        for items in deltas.values():
            extra: dict[str, tuple] = {}
            for key, d in items.items():
                if not key.startswith("seg:"):
                    continue
                seg = self.db.get_device(key)
                label = re.sub(r" \((2\.4G|5G)\)$", "", (seg or {}).get("hostname") or "")
                if not label:
                    continue
                members = self.db.query(
                    "SELECT key FROM devices WHERE kind='device' AND is_gateway=0 "
                    "AND segment=? AND last_seen>=?", (label, week_ago))
                if len(members) != 1 or members[0]["key"] in items:
                    continue
                mac, old = members[0]["key"], extra.get(members[0]["key"])
                extra[mac] = d if old is None else (
                    old[0] + d[0], old[1] + d[1], min(old[2], d[2]), max(old[3], d[3]))
            items.update(extra)

    def _add(self, key: str, rx: int, tx: int, t0: float, t1: float, source: str) -> None:
        """Add usage for (t0, t1], skipping any part of that window already counted."""
        covered = self._covered_until.get(key, 0.0)
        if covered >= t1:
            return
        if covered > t0:                       # another source already counted the start
            scale = (t1 - covered) / (t1 - t0)
            rx, tx, t0 = int(rx * scale), int(tx * scale), covered
        self._covered_until[key] = t1
        span = t1 - t0
        if span <= FRESH:
            self.live[key] = (t1, rx * 8 / span, tx * 8 / span)
            self.alerts.record(key, rx + tx, t1)
        for hour, r in split_by_hour(rx, t0, t1):
            self.db.add_usage(hour, key, r, 0, source)
        for hour, t in split_by_hour(tx, t0, t1):
            self.db.add_usage(hour, key, 0, t, source)

    def _store_usage(self, deltas: dict[str, dict[str, tuple]], now: float) -> None:
        candidates: dict[str, tuple] = {}       # total candidate -> (rx, tx, t0, t1)

        # Most trustworthy source first, so it claims each device before a
        # weaker source can.
        ordered = sorted(deltas.items(), key=lambda kv: -self._priority.get(kv[0], 0))
        for source, items in ordered:
            sums = {"dev": [0, 0, now, 0.0], "seg": [0, 0, now, 0.0]}
            for key, (rx, tx, t0, t1) in items.items():
                if key == "total:wan":
                    candidates[f"wan:{source}"] = (rx, tx, t0, t1)
                    continue
                bucket = sums["seg" if key.startswith("seg:") else "dev"]
                bucket[0] += rx
                bucket[1] += tx
                bucket[2] = min(bucket[2], t0)
                bucket[3] = max(bucket[3], t1)
                # Per key, keep only the most trustworthy source that is alive.
                best = self._key_source.get(key)
                mine = self._priority.get(source, 0)
                if best and best[0] != source and now - best[1] < FRESH \
                        and self._priority.get(best[0], 0) > mine:
                    continue
                self._key_source[key] = (source, now)
                self._add(key, rx, tx, t0, t1, source)
            if source == "sniff" and sums["dev"][3]:
                candidates["sum:sniff"] = tuple(sums["dev"])
            if sums["seg"][3]:
                candidates["sum:segments"] = tuple(sums["seg"])

        for name in candidates:
            self._total_seen[name] = now
        active = [n for n in TOTAL_PRIORITY if now - self._total_seen.get(n, 0) < FRESH]
        if not active:
            self.total_source = None
            return
        self.total_source = active[0]
        if active[0] in candidates:
            rx, tx, t0, t1 = candidates[active[0]]
            self._add(TOTAL_KEY, rx, tx, t0, t1, active[0])
            down, up = self.live.get(TOTAL_KEY, (0, 0, 0))[1:]
            self.live_total.append((int(now), down, up))

    def _store_presence(self, online: set[str], now: float) -> None:
        last = self._last_presence_ts
        self._last_presence_ts = now
        if last is None:
            return
        seconds = min(now - last, self.tick * 4)
        hour = int(now // 3600) * 3600
        self.db.add_presence(hour, "__up__", seconds)
        # Devices seen recently count as present even in cycles where the
        # (slower) discovery collectors did not run.
        cutoff = int(now) - int(self.cfg.get("offline_after_seconds", 150))
        for row in self.db.query(
                "SELECT key FROM devices WHERE kind='device' AND last_seen>=?", (cutoff,)):
            self.db.add_presence(hour, row["key"], seconds)

    # ------------------------------------------------------------------
    def speed(self, key: str, now: float | None = None) -> tuple[float, float] | None:
        """Current (download, upload) in bits/s, or None if not measured recently."""
        entry = self.live.get(key)
        if not entry or (now or time.time()) - entry[0] > max(90.0, self.tick * 4):
            return None
        return entry[1], entry[2]
