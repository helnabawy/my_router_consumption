"""Alert rules and notifications.

Rules (all thresholds are editable on the dashboard):
  new_device   an unknown MAC address joined the network
  daily_limit  a measured device went over its daily limit
  spike        a device or the whole house used more than N GB in one hour
  night        heavy usage between 01:00 and 06:00 (updates, cloud backups)
  quota        80 / 90 / 100 % of the monthly quota, or on course to run out early

Every alert has a `dedupe` key, so the same condition never notifies twice.
"""
from __future__ import annotations

import logging
import subprocess
import sys
import threading
import time
from collections import deque
from datetime import datetime, timedelta

from .quota import GB, MB

log = logging.getLogger("we.alerts")

INVENTORY_GRACE = 600     # first 10 minutes after the very first start: no "new device" spam

SETTING_DEFAULTS = {
    "quota_gb": 250,
    "cycle_start_day": 1,
    "default_daily_limit_gb": 0,
    "spike_gb_per_hour": 3,
    "night_gb": 2,
    "notify_macos": True,
}


def display_name(dev: dict | None, key: str | None = None) -> str:
    if not dev:
        return "Whole house" if key == "total" else (key or "?")
    if dev.get("custom_name") or dev.get("hostname"):
        return dev.get("custom_name") or dev["hostname"]
    # No name known: describe it by maker plus the end of its MAC address.
    vendor = dev.get("vendor")
    if not vendor or vendor == "Unknown" or dev.get("randomized"):
        return f"Unnamed device ({dev['key'][-5:]})"
    return f"{vendor.split(',')[0].split(' ')[0]} device ({dev['key'][-5:]})"


def fmt_bytes(n: float) -> str:
    return f"{n / GB:.2f} GB" if n >= GB else f"{n / MB:.0f} MB"


class AlertEngine:
    def __init__(self, cfg, db, tz, usage_fn=None):
        self.cfg = cfg
        self.db = db
        self.tz = tz
        self._usage_fn = usage_fn          # callable returning the quota summary
        self._window: dict[str, deque] = {}       # key -> deque[(ts, bytes)] for the last hour
        self._last_slow = 0.0
        if self.db.get_setting("first_start") is None:
            self.db.set_setting("first_start", int(time.time()))

    # ---- settings ------------------------------------------------------
    def setting(self, name: str):
        fallback = {
            "quota_gb": self.cfg.get("quota.monthly_gb"),
            "cycle_start_day": self.cfg.get("quota.cycle_start_day"),
            "default_daily_limit_gb": self.cfg.get("alerts.default_daily_limit_gb"),
            "spike_gb_per_hour": self.cfg.get("alerts.spike_gb_per_hour"),
            "night_gb": self.cfg.get("alerts.night_gb"),
            "notify_macos": self.cfg.get("alerts.macos_notifications"),
        }.get(name)
        if fallback is None:
            fallback = SETTING_DEFAULTS.get(name)
        return self.db.get_setting(name, fallback)

    def all_settings(self) -> dict:
        return {name: self.setting(name) for name in SETTING_DEFAULTS}

    # ---- raising -------------------------------------------------------
    def raise_alert(self, type_: str, severity: str, message: str, key: str | None = None,
                    dedupe: str | None = None, ts: float | None = None) -> bool:
        is_new = self.db.add_alert(type_, severity, message, key, dedupe, int(ts or time.time()))
        if is_new:
            log.warning("ALERT [%s] %s", type_, message)
            threading.Thread(target=self._notify, args=(type_, message), daemon=True).start()
        return is_new

    def _notify(self, type_: str, message: str) -> None:
        title = {"new_device": "New device on your Wi-Fi", "daily_limit": "Daily limit reached",
                 "spike": "Usage spike", "night": "Overnight usage",
                 "quota": "Internet quota"}.get(type_, "WE Monitor")
        if sys.platform == "darwin" and self.setting("notify_macos"):
            # Text is passed as arguments, never pasted into the script: device
            # hostnames come from the network and must not be able to inject code.
            script = ('on run argv\n'
                      'display notification (item 1 of argv) with title "WE Monitor" '
                      'subtitle (item 2 of argv)\nend run')
            try:
                subprocess.run(["/usr/bin/osascript", "-e", script, message[:240], title],
                               capture_output=True, timeout=10)
            except (OSError, subprocess.SubprocessError):
                pass
        tg = self.cfg.telegram
        if tg:
            try:
                import httpx
                httpx.post(f"https://api.telegram.org/bot{tg[0]}/sendMessage",
                           json={"chat_id": tg[1], "text": f"{title}\n{message}"}, timeout=10)
            except Exception:
                log.info("telegram notification failed")

    # ---- rules ---------------------------------------------------------
    def new_device(self, dev: dict, now: float) -> None:
        if dev is None or dev["kind"] != "device" or dev["is_self"] or dev["is_gateway"]:
            return
        first_start = self.db.get_setting("first_start", int(now))
        if now - first_start < INVENTORY_GRACE:
            self.raise_alert(
                "new_device", "info",
                "First scan: review the device list and mark the devices you recognise as "
                "trusted. Anything you cannot identify may be someone using your Wi-Fi.",
                dedupe="inventory", ts=now)
            return
        who = display_name(dev)
        extra = " It uses a private (randomized) MAC, typical for phones." if dev["randomized"] else ""
        self.raise_alert(
            "new_device", "warning",
            f"New device joined: {who} ({dev['key']}, {dev.get('ip') or 'no IP yet'}, "
            f"{dev.get('vendor') or 'unknown vendor'}).{extra} If you do not recognise it, "
            "change your Wi-Fi password.",
            key=dev["key"], dedupe=f"new:{dev['key']}", ts=now)

    def evaluate(self, poller, now: float) -> None:
        self._spikes(now)
        if now - self._last_slow >= 60:       # the remaining rules need database queries
            self._last_slow = now
            local = datetime.fromtimestamp(now, self.tz)
            self._daily_limits(local)
            self._night(local)
            self._quota(local)

    def record(self, key: str, nbytes: int, ts: float) -> None:
        """Called by the poller for every usage delta; feeds the 1-hour spike window."""
        if key.startswith("seg:") or nbytes <= 0:
            return
        self._window.setdefault(key, deque()).append((ts, nbytes))

    def _spikes(self, now: float) -> None:
        limit = float(self.setting("spike_gb_per_hour") or 0) * GB
        for key, window in self._window.items():
            while window and now - window[0][0] > 3600:
                window.popleft()
            used = sum(b for _, b in window)
            if limit > 0 and used >= limit:
                dev = self.db.get_device(key)
                self.raise_alert(
                    "spike", "warning",
                    f"{display_name(dev, key)} used {fmt_bytes(used)} in the last hour.",
                    key=key, dedupe=f"spike:{key}:{int(now // 10800)}", ts=now)

    def _daily_limits(self, local: datetime) -> None:
        default_mb = float(self.setting("default_daily_limit_gb") or 0) * 1024
        start = int(local.replace(hour=0, minute=0, second=0, microsecond=0).timestamp())
        usage = self.db.usage_totals(start, start + 2 * 86400)
        for dev in self.db.list_devices("device"):
            limit_mb = dev["daily_limit_mb"] or default_mb
            u = usage.get(dev["key"])
            if not limit_mb or not u:
                continue
            used = (u["rx"] or 0) + (u["tx"] or 0)
            if used >= limit_mb * MB:
                self.raise_alert(
                    "daily_limit", "warning",
                    f"{display_name(dev)} has used {fmt_bytes(used)} today "
                    f"(limit {fmt_bytes(limit_mb * MB)}).",
                    key=dev["key"], dedupe=f"daily:{dev['key']}:{local.date()}")

    def _night(self, local: datetime) -> None:
        limit = float(self.setting("night_gb") or 0) * GB
        h0, h1 = self.cfg.get("alerts.night_hours", [1, 6])
        if limit <= 0 or not (h1 <= local.hour < h1 + 3):
            return
        day = local.replace(hour=0, minute=0, second=0, microsecond=0)
        start, end = int((day + timedelta(hours=h0)).timestamp()), int((day + timedelta(hours=h1)).timestamp())
        usage = self.db.usage_totals(start, end)
        total = usage.get("total")
        devices = {k: v for k, v in usage.items() if k != "total" and not k.startswith("seg:")}
        total_bytes = (total["rx"] + total["tx"]) if total else sum(v["rx"] + v["tx"] for v in devices.values())
        if total_bytes < limit:
            return
        msg = f"{fmt_bytes(total_bytes)} was used overnight ({h0:02d}:00-{h1:02d}:00)."
        if devices:
            top_key, top = max(devices.items(), key=lambda kv: kv[1]["rx"] + kv[1]["tx"])
            msg += (f" Biggest measured device: {display_name(self.db.get_device(top_key), top_key)} "
                    f"({fmt_bytes(top['rx'] + top['tx'])}).")
        msg += " Check for automatic updates and cloud backups."
        self.raise_alert("night", "warning", msg, dedupe=f"night:{local.date()}")

    def _quota(self, local: datetime) -> None:
        if not self._usage_fn:
            return
        q = self._usage_fn(local)
        if not q or not q.get("has_data"):
            return
        cycle = q["cycle_start_ts"]
        for pct in sorted(self.cfg.get("alerts.quota_thresholds", [80, 90, 100]), reverse=True):
            if q["percent"] >= pct:
                sev = "critical" if pct >= 100 else "serious" if pct >= 90 else "warning"
                self.raise_alert(
                    "quota", sev,
                    f"{q['used_gb']:.1f} GB of {q['quota_gb']:.0f} GB used ({pct}% reached), "
                    f"{q['days_left']:.0f} days left in the billing cycle.",
                    dedupe=f"quota:{cycle}:{pct}")
                return
        if q.get("runout_ts") and q["days_elapsed"] >= 3 and \
                q["cycle_end_ts"] - q["runout_ts"] > 2 * 86400:
            when = datetime.fromtimestamp(q["runout_ts"], self.tz).strftime("%a %d %b")
            self.raise_alert(
                "quota", "warning",
                f"At the current pace ({q['daily_avg_gb']:.1f} GB/day) the quota runs out on {when}. "
                f"To last the cycle, stay under {q['safe_daily_gb']:.1f} GB/day.",
                dedupe=f"proj:{cycle}")
