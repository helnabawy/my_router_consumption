"""Turning raw cumulative byte counters into trustworthy usage numbers.

Routers and network interfaces report *cumulative* counters ("4,812,113,002
bytes since boot"). Usage is the difference between two readings, but three
things go wrong in practice:

  * the counter resets to zero (router reboot, Wi-Fi client re-associates)
  * a 32-bit counter wraps around at 4 GB
  * a reading is garbage (firmware glitch)

`counter_delta` handles all three, and `split_by_hour` spreads a delta across
the clock hours it covers so hourly/daily totals stay honest even after the
app was stopped for a while.
"""
from __future__ import annotations

WRAP_32 = 2 ** 32
HOUR = 3600


def counter_delta(prev: int | None, cur: int, elapsed: float,
                  max_bps: float = 2_000_000_000, reset: bool = False) -> int:
    """Bytes transferred between two cumulative readings.

    prev     previous reading (None on the very first observation)
    cur      current reading
    elapsed  seconds between the two readings
    max_bps  fastest link we consider physically possible; anything implying
             a higher rate is treated as a glitch and counted as 0.
    reset    the caller knows the counter restarted from zero (for example
             download AND upload both went backwards, which a reboot does and
             a 32-bit wrap almost never does), so do not treat it as a wrap.
    """
    if prev is None or cur is None or cur < 0:
        return 0
    plausible = max(1.0, elapsed) * max_bps / 8
    if cur >= prev:
        d = cur - prev
        return d if d <= plausible else 0
    # The counter went backwards: either a 32-bit wrap or a reset.
    wrapped = cur + WRAP_32 - prev
    if not reset and prev < WRAP_32 and prev > WRAP_32 // 2 and wrapped <= plausible:
        return wrapped
    # Reset to zero: everything on the counter now happened since the reset.
    return cur if cur <= plausible else 0


def split_by_hour(amount: int, t0: float, t1: float) -> list[tuple[int, int]]:
    """Spread `amount` bytes evenly over (t0, t1] and return [(hour_start, bytes)].

    The parts always add up to exactly `amount`.
    """
    if amount <= 0:
        return []
    if t1 <= t0:
        return [(int(t1 // HOUR) * HOUR, amount)]
    parts: list[tuple[int, int]] = []
    span = t1 - t0
    cursor = t0
    assigned = 0
    while cursor < t1:
        hour = int(cursor // HOUR) * HOUR
        seg_end = min(t1, hour + HOUR)
        share = int(amount * (seg_end - cursor) / span)
        parts.append((hour, share))
        assigned += share
        cursor = seg_end
    # Give rounding leftovers to the most recent hour.
    hour, share = parts[-1]
    parts[-1] = (hour, share + amount - assigned)
    return [(h, b) for h, b in parts if b > 0]
