"""Read-side queries shared by the API, the alert rules and the reports."""
from __future__ import annotations

from datetime import datetime, timedelta

from .alerts import display_name
from .quota import GB, cycle_bounds, quota_summary
from .timeutil import bucket_label, bucket_start, day_start, hour_floor, next_bucket

TOTAL = "total"


def _sum(u: dict | None) -> int:
    return ((u["rx"] or 0) + (u["tx"] or 0)) if u else 0


def is_device_key(key: str) -> bool:
    return key != TOTAL and not key.startswith("seg:")


# ---------------------------------------------------------------- quota
def usage_since(db, key: str, since_ts: int, until_ts: int) -> int:
    """Bytes for `key` in [since_ts, until_ts), pro-rating the first (partial) hour."""
    first_hour = hour_floor(since_ts)
    rows = db.usage_rows(first_hour, until_ts, [key])
    total = 0.0
    for r in rows:
        b = r["rx"] + r["tx"]
        if r["hour"] == first_hour:
            b *= 1 - (since_ts - first_hour) / 3600
        total += b
    return int(total)


def quota_status(db, settings: dict, tz, now: datetime | None = None) -> dict:
    """Quota card: used vs quota, pace, projected run-out and how we know."""
    now = now or datetime.now(tz)
    start, end = cycle_bounds(now, int(settings["cycle_start_day"]))
    s_ts, n_ts = int(start.timestamp()), int(now.timestamp()) + 1

    totals = db.usage_totals(s_ts, n_ts)
    has_total = TOTAL in totals
    measured_devices = sum(_sum(v) for k, v in totals.items() if is_device_key(k))
    readings = db.query("SELECT * FROM we_readings WHERE ts>=? AND ts<=? ORDER BY ts DESC LIMIT 1",
                        (s_ts, n_ts))
    reading = readings[0] if readings else None
    first_hour = db.first_usage_hour(TOTAL)
    tracked_from = max(s_ts, first_hour) if first_hour else None

    basis, partial = "none", False
    if reading:
        used = reading["used_gb"] * GB
        if has_total:
            used += usage_since(db, TOTAL, reading["ts"], n_ts)
            basis = "we_reading_plus_measured"
        else:
            basis = "we_reading_only"
    elif has_total:
        used = _sum(totals[TOTAL])
        basis = "measured_total"
        partial = bool(tracked_from and tracked_from > s_ts + 3600)
    else:
        used = measured_devices
        basis = "measured_devices_only" if measured_devices else "none"
        partial = True

    q = quota_summary(used, float(settings["quota_gb"]), start, end, now)
    if partial:
        # We only saw part of the cycle: the pace is real, the total is a lower bound.
        days = max((n_ts - (tracked_from or n_ts)) / 86400, 1 / 24)
        q["daily_avg_gb"] = used / GB / days if tracked_from else 0
        q["runout"] = q["runout_ts"] = None
        q["projected_total_gb"] = None
    last_day = end - timedelta(days=1)
    q.update(
        cycle_label=f"{start:%-d %b} to {last_day:%-d %b}",
        runout_label=(datetime.fromtimestamp(q["runout_ts"], tz).strftime("%a %-d %b")
                      if q.get("runout_ts") else None),
        basis=basis, partial=partial, has_data=basis != "none",
        tracked_from_ts=tracked_from,
        measured_devices_gb=measured_devices / GB,
        last_reading=reading,
    )
    return q


# ---------------------------------------------------------------- devices
def device_table(db, poller, start: int, end: int, tz, offline_after: int,
                 now: datetime | None = None) -> list[dict]:
    now = now or datetime.now(tz)
    n_ts = int(now.timestamp())
    today = int(day_start(now).timestamp())
    usage = db.usage_totals(start, end)
    usage_today = db.usage_totals(today, n_ts + 1)
    out = []
    for d in db.list_devices():
        key = d["key"]
        u, t = usage.get(key), usage_today.get(key)
        speed = poller.speed(key, n_ts) if poller else None
        out.append({
            **d,
            "name": display_name(d),
            "online": bool(d["last_seen"] and n_ts - d["last_seen"] <= offline_after),
            "measured": u is not None or t is not None or speed is not None,
            "rx": u["rx"] if u else None, "tx": u["tx"] if u else None,
            "today_rx": t["rx"] if t else None, "today_tx": t["tx"] if t else None,
            "down_bps": speed[0] if speed else None, "up_bps": speed[1] if speed else None,
            "usage_source": (u or t or {}).get("source"),
        })
    out.sort(key=lambda r: (-((r["rx"] or 0) + (r["tx"] or 0)), not r["online"], r["name"].lower()))
    return out


def top_consumers(db, start: int, end: int, kind: str = "device") -> dict:
    usage = db.usage_totals(start, end)
    devices = {d["key"]: d for d in db.list_devices()}
    want_seg = kind == "segment"
    items = []
    for key, u in usage.items():
        if key == TOTAL or key.startswith("seg:") != want_seg:
            continue
        items.append({"key": key, "name": display_name(devices.get(key), key),
                      "rx": u["rx"] or 0, "tx": u["tx"] or 0})
    items.sort(key=lambda r: -(r["rx"] + r["tx"]))
    total = _sum(usage.get(TOTAL)) if TOTAL in usage else None
    attributed = sum(i["rx"] + i["tx"] for i in items)
    return {
        "items": items,
        "total": total,
        "attributed": attributed,
        "unattributed": max(total - attributed, 0) if total is not None else None,
    }


# ---------------------------------------------------------------- history
def history(db, start: int, end: int, bucket: str, tz, kind: str = "device",
            key: str | None = None, top_n: int = 7) -> dict:
    """Time series for the stacked chart.

    key=None  -> one series per top device (or segment) plus "Other / not attributed"
    key=<key> -> download and upload of a single device / the total
    """
    rows = db.usage_rows(start, end)
    # Bucket boundaries in local time.
    buckets = []
    cursor = bucket_start(start, bucket, tz)
    limit = datetime.fromtimestamp(end - 1, tz)
    while cursor <= limit and len(buckets) < 1000:
        buckets.append(cursor)
        cursor = next_bucket(cursor, bucket)
    index = {int(b.timestamp()): i for i, b in enumerate(buckets)}
    n = len(buckets)

    def slot(hour: int) -> int | None:
        return index.get(int(bucket_start(hour, bucket, tz).timestamp()))

    labels = [bucket_label(b, bucket) for b in buckets]
    starts = [int(b.timestamp()) for b in buckets]
    devices = {d["key"]: d for d in db.list_devices()}

    if key:
        down, up = [0] * n, [0] * n
        for r in rows:
            i = slot(r["hour"])
            if r["key"] == key and i is not None:
                down[i] += r["rx"]
                up[i] += r["tx"]
        return {"bucket": bucket, "labels": labels, "starts": starts, "mode": "direction",
                "series": [{"key": "down", "name": "Download", "values": down},
                           {"key": "up", "name": "Upload", "values": up}]}

    want_seg = kind == "segment"
    per_key: dict[str, list[int]] = {}
    total = [0] * n
    has_total = False
    for r in rows:
        i = slot(r["hour"])
        if i is None:
            continue
        b = r["rx"] + r["tx"]
        if r["key"] == TOTAL:
            total[i] += b
            has_total = True
        elif r["key"].startswith("seg:") == want_seg:
            per_key.setdefault(r["key"], [0] * n)[i] += b
    ranked = sorted(per_key, key=lambda k: -sum(per_key[k]))
    series = [{"key": k, "name": display_name(devices.get(k), k), "values": per_key[k]}
              for k in ranked[:top_n]]
    shown = [sum(vals) for vals in zip(*(s["values"] for s in series))] if series else [0] * n
    rest = [sum(vals) for vals in zip(*(per_key[k] for k in ranked[top_n:]))] \
        if ranked[top_n:] else [0] * n
    if has_total:      # everything the total saw that the top devices do not explain
        other = [max(t - s, 0) for t, s in zip(total, shown)]
        other_name = "Other / not attributed"
    else:
        other, other_name = rest, "Other devices"
    if any(other):
        series.append({"key": "other", "name": other_name, "values": other})
    return {"bucket": bucket, "labels": labels, "starts": starts, "mode": "breakdown",
            "series": series, "total": total if has_total else None}


def heatmap(db, tz, days: int = 14, key: str = TOTAL, now: datetime | None = None) -> dict:
    """date x hour-of-day matrix of bytes (rows oldest -> newest)."""
    now = now or datetime.now(tz)
    first_day = day_start(now) - timedelta(days=days - 1)
    start, end = int(first_day.timestamp()), int(now.timestamp()) + 1
    keys = [key]
    effective = key
    if key == TOTAL and not db.usage_rows(start, end, [TOTAL]):
        # No whole-house counter: fall back to the sum of measured devices.
        keys = [d["key"] for d in db.list_devices("device")]
        effective = "measured_devices"
    dates = [(first_day + timedelta(days=i)).date() for i in range(days)]
    index = {d: i for i, d in enumerate(dates)}
    matrix = [[0] * 24 for _ in dates]
    for r in db.usage_rows(start, end, keys):
        local = datetime.fromtimestamp(r["hour"], tz)
        i = index.get(local.date())
        if i is not None:
            matrix[i][local.hour] += r["rx"] + r["tx"]
    return {"key": effective, "dates": [d.isoformat() for d in dates],
            "labels": [d.strftime("%a %d %b") for d in dates], "matrix": matrix,
            "max": max((max(row) for row in matrix), default=0)}


# ---------------------------------------------------------------- suspects
def presence_correlation(db, start: int, end: int) -> list[dict]:
    """For devices we cannot measure: how much of the house's traffic flowed while
    each device was online. This is circumstantial evidence, NOT a measurement.

    lift > 1 means the house uses more data than average while this device is online.
    """
    presence = db.query("SELECT hour,key,seconds FROM presence_hourly WHERE hour>=? AND hour<?",
                        (start, end))
    up = {r["hour"]: r["seconds"] for r in presence if r["key"] == "__up__"}
    total = {r["hour"]: r["rx"] + r["tx"] for r in db.usage_rows(start, end, [TOTAL])}
    total_bytes = sum(b for h, b in total.items() if h in up)
    up_seconds = sum(up.values())
    if not total_bytes or not up_seconds:
        return []
    acc: dict[str, list[float]] = {}
    for r in presence:
        if r["key"] == "__up__" or r["hour"] not in up or up[r["hour"]] <= 0:
            continue
        frac = min(r["seconds"] / up[r["hour"]], 1.0)
        a = acc.setdefault(r["key"], [0.0, 0.0])
        a[0] += r["seconds"]
        a[1] += total.get(r["hour"], 0) * frac
    devices = {d["key"]: d for d in db.list_devices("device")}
    out = []
    for key, (seconds, nbytes) in acc.items():
        dev = devices.get(key)
        if not dev or dev["is_gateway"]:
            continue
        time_share = min(seconds / up_seconds, 1.0)
        usage_share = nbytes / total_bytes
        out.append({"key": key, "name": display_name(dev), "online_hours": seconds / 3600,
                    "time_share": time_share, "usage_while_online": int(nbytes),
                    "usage_share": usage_share,
                    "lift": usage_share / time_share if time_share else 0})
    out.sort(key=lambda r: -r["lift"])
    return out


def reading_comparison(db, tz) -> list[dict]:
    """Compare consecutive WE readings with what the app measured in between."""
    rows = db.query("SELECT * FROM we_readings ORDER BY ts")
    out = []
    for prev, cur in zip([None] + rows[:-1], rows):
        item = {**cur, "we_delta_gb": None, "app_delta_gb": None, "diff_pct": None}
        if prev and cur["used_gb"] >= prev["used_gb"]:
            we = cur["used_gb"] - prev["used_gb"]
            has_total = bool(db.usage_rows(hour_floor(prev["ts"]), cur["ts"] + 1, [TOTAL]))
            item["we_delta_gb"] = we
            if has_total:
                app = (usage_since(db, TOTAL, prev["ts"], cur["ts"] + 3600)
                       - usage_since(db, TOTAL, cur["ts"], cur["ts"] + 3600)) / GB
                item["app_delta_gb"] = app
                item["diff_pct"] = (app - we) / we * 100 if we > 0.05 else None
        out.append(item)
    return list(reversed(out))
