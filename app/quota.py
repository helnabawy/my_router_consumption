"""Billing-cycle and quota maths (pure functions, easy to test)."""
from __future__ import annotations

import calendar
from datetime import datetime, timedelta

GB = 1024 ** 3   # WE counts 1 GB = 1024 MB
MB = 1024 ** 2


def _clamped(year: int, month: int, day: int, tz) -> datetime:
    """Midnight on `day` of the month, clamped to the month's length (31 -> 28/30)."""
    last = calendar.monthrange(year, month)[1]
    return datetime(year, month, min(day, last), tzinfo=tz)


def cycle_bounds(now: datetime, start_day: int) -> tuple[datetime, datetime]:
    """Start (inclusive) and end (exclusive) of the billing cycle containing `now`."""
    start_day = max(1, min(31, int(start_day)))
    start = _clamped(now.year, now.month, start_day, now.tzinfo)
    if start > now:
        y, m = (now.year - 1, 12) if now.month == 1 else (now.year, now.month - 1)
        start = _clamped(y, m, start_day, now.tzinfo)
    y, m = (start.year + 1, 1) if start.month == 12 else (start.year, start.month + 1)
    end = _clamped(y, m, start_day, now.tzinfo)
    return start, end


def previous_cycle(now: datetime, start_day: int) -> tuple[datetime, datetime]:
    start, _ = cycle_bounds(now, start_day)
    return cycle_bounds(start - timedelta(days=1), start_day)


def quota_summary(used_bytes: float, quota_gb: float, start: datetime,
                  end: datetime, now: datetime) -> dict:
    """Everything the quota card shows."""
    quota_bytes = quota_gb * GB
    elapsed_days = max((now - start).total_seconds() / 86400, 1 / 24)
    days_left = max((end - now).total_seconds() / 86400, 0)
    daily_avg = used_bytes / elapsed_days
    remaining = max(quota_bytes - used_bytes, 0)

    runout = None
    if used_bytes >= quota_bytes:
        runout = now
    elif daily_avg > 0:
        candidate = now + timedelta(days=remaining / daily_avg)
        # Only meaningful if it lands inside this cycle.
        runout = candidate if candidate < end else None

    return {
        "quota_gb": quota_gb,
        "used_gb": used_bytes / GB,
        "remaining_gb": remaining / GB,
        "percent": (used_bytes / quota_bytes * 100) if quota_bytes else 0,
        "cycle_start": start.isoformat(),
        "cycle_end": end.isoformat(),
        "cycle_start_ts": int(start.timestamp()),
        "cycle_end_ts": int(end.timestamp()),
        "days_elapsed": elapsed_days,
        "days_left": days_left,
        "daily_avg_gb": daily_avg / GB,
        "safe_daily_gb": (remaining / GB / days_left) if days_left > 0 else 0,
        "projected_total_gb": daily_avg * ((end - start).total_seconds() / 86400) / GB,
        "runout": runout.isoformat() if runout else None,
        "runout_ts": int(runout.timestamp()) if runout else None,
    }
