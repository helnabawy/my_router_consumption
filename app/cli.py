"""Command-line helpers.

  python -m app.cli set-password    store the router password in the macOS Keychain
  python -m app.cli scan            list devices found on the network right now
  python -m app.cli probe-router    show what YOUR router firmware exposes (writes a report)
  python -m app.cli check           test every data source once and explain the result
  python -m app.cli seed-demo       fill the demo database with 5 weeks of fake history
"""
from __future__ import annotations

import argparse
import json
import random
import subprocess
import sys
import time
from datetime import datetime, timedelta

from .config import BASE_DIR, KEYCHAIN_ACCOUNT, KEYCHAIN_SERVICE, load_config
from .timeutil import get_tz


def cmd_set_password(args) -> int:
    if sys.platform != "darwin":
        print("The Keychain is macOS-only. Put WE_ROUTER_PASSWORD=... in the .env file instead\n"
              "and run: chmod 600 .env")
        return 1
    print("Enter the router ADMIN password (the one for the router's web page, not the Wi-Fi\n"
          "password). macOS asks for it twice and stores it in your login Keychain, not in a file.")
    # A trailing -w makes `security` prompt for the password itself, so it never
    # appears in a command line or in this program's memory. -U updates an existing item.
    r = subprocess.run(["/usr/bin/security", "add-generic-password", "-U",
                        "-s", KEYCHAIN_SERVICE, "-a", KEYCHAIN_ACCOUNT, "-w"])
    print("Saved to Keychain." if r.returncode == 0 else "Keychain refused the password.")
    return r.returncode


def cmd_scan(args) -> int:
    from .collectors.arp_scan import ArpScanCollector
    from .netutil import vendor_for
    c = ArpScanCollector()
    snap = c.collect()
    c.close()
    print(f"{'IP':<16}{'MAC':<19}{'Hostname':<24}Vendor")
    for d in sorted(snap.devices, key=lambda d: tuple(int(x) for x in (d.ip or '0.0.0.0').split('.'))):
        tag = " (this computer)" if d.is_self else " (router)" if d.is_gateway else ""
        print(f"{d.ip or '':<16}{d.mac:<19}{(d.hostname or '-'):<24}{vendor_for(d.mac)}{tag}")
    print(f"\n{len(snap.devices)} devices on {c.capabilities.get('subnet')}")
    return 0


def cmd_probe_router(args) -> int:
    from .collectors.zte import ZteClient, probe_report
    cfg = load_config()
    pw = cfg.router_password
    if not pw:
        print("No router password found. Run:  python -m app.cli set-password")
        return 1
    client = ZteClient(cfg.get("router.url"), cfg.get("router.username"), pw)
    report = probe_report(client, crawl=not args.quick)
    out = BASE_DIR / "data" / "router-probe.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(report["summary"])
    print(f"\nFull report (password and Wi-Fi keys removed): {out}")
    return 0 if report["login_ok"] else 2


def cmd_check(args) -> int:
    from .main import build_collectors
    cfg = load_config()
    tz = get_tz(cfg.get("timezone"))
    ok = True
    for c in build_collectors(cfg, tz):
        print(f"\n== {c.name} ==")
        try:
            snap = c.collect()
            if c.name in ("sniff",):
                time.sleep(3)
                snap = c.collect()
            print(f"  OK: {len(snap.devices)} devices, {len(snap.counters)} byte counters")
            for k, v in c.capabilities.items():
                print(f"  {k}: {v}")
            for ctr in snap.counters[:12]:
                print(f"    {ctr.key:<28} down={ctr.rx:>15,}  up={ctr.tx:>15,}  {ctr.label or ''}")
        except Exception as e:
            ok = False
            print(f"  NOT WORKING: {e}")
        finally:
            c.close()
    return 0 if ok else 2


def cmd_seed_demo(args) -> int:
    """Backfill the demo database so the charts have something to show."""
    import os
    os.environ["WE_MONITOR_MODE"] = "demo"
    from .collectors.demo import DEMO_DEVICES, demo_rate
    from .db import Database
    from .netutil import is_randomized_mac, vendor_for
    cfg = load_config()
    tz = get_tz(cfg.get("timezone"))
    db = Database(cfg.db_path)
    rng = random.Random(42)
    now = datetime.now(tz)
    start = (now - timedelta(days=args.days)).replace(minute=0, second=0, microsecond=0)
    with db.transaction():
        for table in ("usage_hourly", "presence_hourly", "devices", "counters", "alerts"):
            db.execute(f"DELETE FROM {table}")
        db.set_setting("first_start", int(start.timestamp()))
        for i, spec in enumerate(DEMO_DEVICES):
            mac, name, conn, seg, *_ = spec
            db.upsert_device(mac, {"ip": f"192.168.1.{10 + i}", "hostname": name, "conn_type": conn,
                                   "segment": seg, "vendor": vendor_for(mac),
                                   "randomized": int(is_randomized_mac(mac)),
                                   "known": int(name is not None)},
                             True, "demo", int(start.timestamp()))
        t = start
        while t < now.replace(minute=0, second=0, microsecond=0):
            hour = int(t.timestamp())
            total = [0, 0]
            db.add_presence(hour, "__up__", 3600)
            for spec in DEMO_DEVICES:
                rx = tx = 0.0
                for _ in range(12):                       # 5-minute slices
                    d, u = demo_rate(spec, t.hour + 0.5, rng)
                    rx += d * 300
                    tx += u * 300
                if (t.hour in spec[5]) or (t.hour + 24 in spec[5]):
                    db.add_presence(hour, spec[0], 3600)
                db.add_usage(hour, spec[0], int(rx), int(tx), "demo")
                total[0] += int(rx)
                total[1] += int(tx)
            db.add_usage(hour, "total", total[0], total[1], "wan:demo")
            t += timedelta(hours=1)
    db.close()
    print(f"Demo history written to {cfg.db_path}. Start the dashboard with:  ./run.sh --demo")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m app.cli", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("set-password").set_defaults(fn=cmd_set_password)
    sub.add_parser("scan").set_defaults(fn=cmd_scan)
    pr = sub.add_parser("probe-router")
    pr.add_argument("--quick", action="store_true", help="only the known pages, no menu crawl")
    pr.set_defaults(fn=cmd_probe_router)
    sub.add_parser("check").set_defaults(fn=cmd_check)
    sd = sub.add_parser("seed-demo")
    sd.add_argument("--days", type=int, default=35)
    sd.set_defaults(fn=cmd_seed_demo)
    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
