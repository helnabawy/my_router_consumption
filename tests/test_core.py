"""Unit tests for the parts where a bug would silently produce wrong GB figures.

Run:  .venv/bin/python -m pytest -q
"""
from datetime import datetime
from zoneinfo import ZoneInfo

from app.accounting import WRAP_32, counter_delta, split_by_hour
from app.collectors.arp_scan import parse_arp_table, parse_ip_neigh
from app.collectors.sniff import parse_frame
from app.collectors.upnp import find_control_url
from app.netutil import is_randomized_mac, normalize_mac, vendor_for
from app.quota import GB, cycle_bounds, previous_cycle, quota_summary

CAIRO = ZoneInfo("Africa/Cairo")


# ---------------------------------------------------------------- counters
def test_delta_normal_and_first_reading():
    assert counter_delta(None, 5000, 30) == 0            # first reading is only a baseline
    assert counter_delta(1000, 6000, 30) == 5000


def test_delta_counter_reset_counts_bytes_since_reset():
    # Router rebooted: counter fell from 3 GB to 20 MB.
    assert counter_delta(3 * GB, 20 * 1024 ** 2, 60, reset=True) == 20 * 1024 ** 2
    # A small counter going backwards can only be a reset, never a wrap.
    assert counter_delta(500 * 1024 ** 2, 20 * 1024 ** 2, 60) == 20 * 1024 ** 2


def test_delta_32bit_wrap():
    prev = WRAP_32 - 1_000_000
    assert counter_delta(prev, 4_000_000, 30) == 5_000_000


def test_delta_rejects_impossible_jump():
    # 500 GB in 10 seconds is a firmware glitch, not usage.
    assert counter_delta(0, 500 * GB, 10) == 0


def test_split_by_hour_is_exact_and_proportional():
    t0 = 1_700_000_000 - (1_700_000_000 % 3600) + 3000      # 50 minutes into an hour
    parts = split_by_hour(1_000_000, t0, t0 + 1200)          # 10 min before, 10 min after
    assert sum(b for _, b in parts) == 1_000_000
    assert len(parts) == 2 and abs(parts[0][1] - parts[1][1]) <= 1


def test_split_by_hour_long_gap():
    parts = split_by_hour(7_200_001, 0, 7200)
    assert [h for h, _ in parts] == [0, 3600]
    assert sum(b for _, b in parts) == 7_200_001


# ---------------------------------------------------------------- quota
def test_cycle_bounds_mid_month():
    s, e = cycle_bounds(datetime(2026, 11, 24, 15, tzinfo=CAIRO), 10)
    assert (s.month, s.day, e.month, e.day) == (11, 10, 12, 10)


def test_cycle_bounds_before_start_day_and_year_wrap():
    s, e = cycle_bounds(datetime(2026, 1, 5, tzinfo=CAIRO), 10)
    assert (s.year, s.month, s.day) == (2025, 12, 10) and (e.year, e.month) == (2026, 1)


def test_cycle_day_31_clamps_to_short_months():
    s, e = cycle_bounds(datetime(2026, 2, 28, 12, tzinfo=CAIRO), 31)
    assert (s.month, s.day) == (2, 28) and (e.month, e.day) == (3, 31)
    ps, pe = previous_cycle(datetime(2026, 2, 28, 12, tzinfo=CAIRO), 31)
    assert (ps.month, ps.day) == (1, 31) and pe == s


def test_quota_runs_out_early():
    start, end = datetime(2026, 11, 1, tzinfo=CAIRO), datetime(2026, 12, 1, tzinfo=CAIRO)
    q = quota_summary(250 * GB * 0.9, 250, start, end, datetime(2026, 11, 14, tzinfo=CAIRO))
    assert round(q["daily_avg_gb"], 1) == 17.3
    assert q["runout"] is not None and q["runout"].startswith("2026-11-15")
    assert round(q["safe_daily_gb"], 2) == round(25 / 17, 2)


def test_quota_lasts_the_cycle():
    start, end = datetime(2026, 11, 1, tzinfo=CAIRO), datetime(2026, 12, 1, tzinfo=CAIRO)
    q = quota_summary(50 * GB, 250, start, end, datetime(2026, 11, 16, tzinfo=CAIRO))
    assert q["runout"] is None and round(q["projected_total_gb"]) == 100


# ---------------------------------------------------------------- parsers
MACOS_ARP = """\
? (192.168.1.1) at 34:e8:94:a:b:c on en0 ifscope [ethernet]
? (192.168.1.7) at a4:83:e7:1:2:3 on en0 ifscope [ethernet]
? (192.168.1.9) at (incomplete) on en0 ifscope [ethernet]
? (192.168.1.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]
? (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]
? (10.8.0.1) at 0:11:22:33:44:55 on utun3 ifscope [ethernet]
"""


def test_parse_macos_arp_table():
    table = parse_arp_table(MACOS_ARP, "en0")
    assert table == {"192.168.1.1": "34:e8:94:0a:0b:0c", "192.168.1.7": "a4:83:e7:01:02:03"}


def test_parse_linux_neigh():
    text = ("192.168.1.7 dev eth0 lladdr a4:83:e7:01:02:03 REACHABLE\n"
            "192.168.1.8 dev eth0  FAILED\n192.168.1.9 dev eth0 lladdr 00:11:22:33:44:55 STALE\n")
    assert set(parse_ip_neigh(text)) == {"192.168.1.7", "192.168.1.9"}


def test_mac_helpers():
    assert normalize_mac("A4-83-E7-1-2-3") == "a4:83:e7:01:02:03"
    assert normalize_mac("a483.e701.0203") == "a4:83:e7:01:02:03"
    assert normalize_mac("(incomplete)") is None and normalize_mac("ff:ff:ff:ff:ff:ff") is None
    assert is_randomized_mac("a6:3b:11:22:33:44") and not is_randomized_mac("a4:83:e7:01:02:03")
    assert "Apple" in vendor_for("f4:5c:89:aa:01:02")
    assert "randomized" in vendor_for("a6:3b:11:22:33:44")


def test_parse_tcpdump_frames():
    quiet = ("1732480000.123456 aa:bb:cc:dd:ee:ff > 11:22:33:44:55:66, IPv4, length 1514: "
             "192.168.2.3.50123 > 142.250.1.1.443: tcp 1448")
    assert parse_frame(quiet) == ("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66", 1514, "192.168.2.3")
    verbose = ("1732480000.2 11:22:33:44:55:66 > aa:bb:cc:dd:ee:ff, ethertype IPv6 (0x86dd), "
               "length 86: 2a00::1.443 > fe80::2.50000: tcp 0")
    assert parse_frame(verbose) == ("11:22:33:44:55:66", "aa:bb:cc:dd:ee:ff", 86, None)
    assert parse_frame("tcpdump: listening on bridge100") is None


def test_upnp_control_url():
    xml = """<?xml version="1.0"?><root xmlns="urn:schemas-upnp-org:device-1-0">
      <device><deviceList><device><serviceList><service>
        <serviceType>urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1</serviceType>
        <controlURL>/upnp/control/WANCommonIFC1</controlURL>
      </service></serviceList></device></deviceList></device></root>"""
    assert find_control_url(xml, "http://192.168.1.1:52869/gatedesc.xml") == \
        "http://192.168.1.1:52869/upnp/control/WANCommonIFC1"
