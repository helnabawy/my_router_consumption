"""Local-time helpers. Usage is stored in UTC hours and shown in your timezone."""
from __future__ import annotations

from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

from .quota import cycle_bounds, previous_cycle

HOUR = 3600


def get_tz(name: str | None):
    try:
        return ZoneInfo(name) if name else datetime.now().astimezone().tzinfo
    except Exception:
        return datetime.now().astimezone().tzinfo


def hour_floor(ts: float) -> int:
    return int(ts // HOUR) * HOUR


def day_start(dt: datetime) -> datetime:
    return dt.replace(hour=0, minute=0, second=0, microsecond=0)


def resolve_range(name: str, now: datetime, cycle_day: int) -> tuple[int, int, str]:
    """Named range -> (start_ts, end_ts, label). End is exclusive."""
    today = day_start(now)
    end = int(now.timestamp()) + 1
    if name == "today":
        return int(today.timestamp()), end, "Today"
    if name == "yesterday":
        return int((today - timedelta(days=1)).timestamp()), int(today.timestamp()), "Yesterday"
    if name == "7d":
        return int((today - timedelta(days=6)).timestamp()), end, "Last 7 days"
    if name == "30d":
        return int((today - timedelta(days=29)).timestamp()), end, "Last 30 days"
    if name == "prev_cycle":
        s, e = previous_cycle(now, cycle_day)
        return int(s.timestamp()), int(e.timestamp()), "Previous billing cycle"
    s, _ = cycle_bounds(now, cycle_day)
    return int(s.timestamp()), end, "This billing cycle"


def bucket_start(ts: int, bucket: str, tz) -> datetime:
    dt = datetime.fromtimestamp(ts, tz)
    if bucket == "hour":
        return dt.replace(minute=0, second=0, microsecond=0)
    if bucket == "month":
        return dt.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    return day_start(dt)


def next_bucket(dt: datetime, bucket: str) -> datetime:
    if bucket == "hour":
        # Go through UTC so daylight-saving changes cannot skip or repeat an hour.
        return datetime.fromtimestamp(dt.timestamp() + HOUR, dt.tzinfo)
    if bucket == "month":
        y, m = (dt.year + 1, 1) if dt.month == 12 else (dt.year, dt.month + 1)
        return dt.replace(year=y, month=m)
    return day_start(dt + timedelta(days=1))


def bucket_label(dt: datetime, bucket: str) -> str:
    if bucket == "hour":
        return dt.strftime("%d %b %H:00")
    if bucket == "month":
        return dt.strftime("%b %Y")
    return dt.strftime("%a %d %b")
