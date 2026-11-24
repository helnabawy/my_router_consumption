"""CSV and PDF exports (evidence you can attach to a complaint with WE)."""
from __future__ import annotations

import csv
import io
from datetime import datetime
from pathlib import Path

from . import stats
from .quota import GB, MB

FONT_CANDIDATES = [          # Unicode fonts so Arabic device names print correctly
    "/System/Library/Fonts/Supplemental/Arial Unicode.ttf",
    "/Library/Fonts/Arial Unicode.ttf",
    "/System/Library/Fonts/Supplemental/Arial.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
]


def _gb(n: float | None) -> str:
    return "" if n is None else f"{n / GB:.3f}"


def _csv(rows: list[list]) -> bytes:
    buf = io.StringIO()
    csv.writer(buf).writerows(rows)
    return buf.getvalue().encode("utf-8-sig")      # BOM so Excel opens Arabic names correctly


def usage_csv(db, tz, start: int, end: int, bucket: str = "day") -> bytes:
    """One row per device per hour/day: the raw material behind every chart."""
    devices = {d["key"]: d for d in db.list_devices()}
    agg: dict[tuple, list[int]] = {}
    for r in db.usage_rows(start, end):
        local = datetime.fromtimestamp(r["hour"], tz)
        period = local.strftime("%Y-%m-%d %H:00" if bucket == "hour" else "%Y-%m-%d")
        a = agg.setdefault((period, r["key"]), [0, 0])
        a[0] += r["rx"]
        a[1] += r["tx"]
    rows = [["period", "device", "type", "mac_or_id", "ip", "vendor",
             "download_gb", "upload_gb", "total_gb", "download_bytes", "upload_bytes"]]
    for (period, key), (rx, tx) in sorted(agg.items()):
        d = devices.get(key)
        kind = "whole house" if key == "total" else (d["kind"] if d else "device")
        rows.append([period, stats.display_name(d, key), kind, key,
                     (d or {}).get("ip") or "", (d or {}).get("vendor") or "",
                     _gb(rx), _gb(tx), _gb(rx + tx), rx, tx])
    return _csv(rows)


def devices_csv(db, tz) -> bytes:
    rows = [["name", "hostname", "mac", "ip", "vendor", "connection", "port_or_wifi",
             "trusted", "private_mac", "first_seen", "last_seen"]]
    fmt = lambda ts: datetime.fromtimestamp(ts, tz).strftime("%Y-%m-%d %H:%M") if ts else ""
    for d in db.list_devices("device"):
        rows.append([stats.display_name(d), d["hostname"] or "", d["key"], d["ip"] or "",
                     d["vendor"] or "", d["conn_type"] or "", d["segment"] or "",
                     "yes" if d["known"] else "no", "yes" if d["randomized"] else "no",
                     fmt(d["first_seen"]), fmt(d["last_seen"])])
    return _csv(rows)


def report_pdf(db, tz, settings: dict, start: int, end: int, label: str) -> bytes:
    from fpdf import FPDF

    now = datetime.now(tz)
    quota = stats.quota_status(db, settings, tz, now)
    top = stats.top_consumers(db, start, end)
    daily = stats.history(db, start, end, "day", tz, key="total")
    readings = stats.reading_comparison(db, tz)
    alerts = db.query("SELECT * FROM alerts WHERE ts>=? AND ts<? ORDER BY ts", (start, end))

    pdf = FPDF(format="A4")
    pdf.set_auto_page_break(True, margin=15)
    font, unicode_ok = "Helvetica", False
    for path in FONT_CANDIDATES:
        if Path(path).exists():
            try:
                pdf.add_font("uni", "", path)
                pdf.add_font("uni", "B", path)
                font, unicode_ok = "uni", True
                try:
                    pdf.set_text_shaping(True)     # joins Arabic letters (needs uharfbuzz)
                except Exception:
                    pass
                break
            except Exception:
                continue

    def clean(text) -> str:
        text = str(text)
        return text if unicode_ok else text.encode("latin-1", "replace").decode("latin-1")

    def heading(text: str) -> None:
        pdf.ln(3)
        pdf.set_font(font, "B", 12)
        pdf.cell(0, 8, clean(text), new_x="LMARGIN", new_y="NEXT")
        pdf.set_font(font, "", 9)

    def table(header: list[str], rows: list[list], widths: list[int]) -> None:
        pdf.set_font(font, "B", 9)
        pdf.set_fill_color(235, 235, 232)
        for h, w in zip(header, widths):
            pdf.cell(w, 7, clean(h), border=1, fill=True)
        pdf.ln()
        pdf.set_font(font, "", 9)
        for row in rows:
            for value, w in zip(row, widths):
                text = clean(value)
                while text and pdf.get_string_width(text) > w - 2:
                    text = text[:-1]
                pdf.cell(w, 6, text, border=1)
            pdf.ln()

    def para(text: str) -> None:
        pdf.multi_cell(0, 5, clean(text), new_x="LMARGIN", new_y="NEXT")

    pdf.add_page()
    pdf.set_font(font, "B", 16)
    pdf.cell(0, 10, "Home internet usage report", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font(font, "", 9)
    period = (f"{datetime.fromtimestamp(start, tz):%d %b %Y} to "
              f"{datetime.fromtimestamp(min(end, int(now.timestamp())), tz):%d %b %Y %H:%M}")
    para(f"Period: {label} ({period}).  Generated {now:%d %b %Y %H:%M} ({tz}).")

    heading("Quota")
    basis = {
        "we_reading_plus_measured": "WE figure entered by the subscriber plus traffic measured since",
        "we_reading_only": "WE figure entered by the subscriber (no local total counter)",
        "measured_total": "router total counter read by this software",
        "measured_devices_only": "sum of individually measured devices only (incomplete)",
        "none": "no data yet",
    }[quota["basis"]]
    para(f"Used this billing cycle: {quota['used_gb']:.2f} GB of {quota['quota_gb']:.0f} GB "
         f"({quota['percent']:.0f}%).  Basis: {basis}.")
    para(f"Billing cycle: {quota['cycle_label']}.  "
         f"Average {quota['daily_avg_gb']:.2f} GB/day.")
    if quota["partial"]:
        para("Note: monitoring started after the cycle began, so the locally measured total "
             "is a lower bound.")

    heading("Usage per device (measured)")
    if top["items"]:
        total = top["total"] or top["attributed"] or 1
        rows = [[i["name"], i["key"], _gb(i["rx"]), _gb(i["tx"]), _gb(i["rx"] + i["tx"]),
                 f"{(i['rx'] + i['tx']) / total * 100:.1f}%"] for i in top["items"][:25]]
        table(["Device", "MAC address", "Down GB", "Up GB", "Total GB", "Share"], rows,
              [52, 38, 24, 24, 26, 20])
        if top["total"] is not None:
            para(f"Whole-house total in the period: {_gb(top['total'])} GB.  Not attributed to "
                 f"a measured device: {_gb(top['unattributed'])} GB.")
    else:
        para("No per-device measurements exist for this period.")

    heading("Daily totals (whole house)")
    rows = [[lab, _gb(d), _gb(u), _gb(d + u)]
            for lab, d, u in zip(daily["labels"], *(s["values"] for s in daily["series"])) if d + u]
    if rows:
        table(["Day", "Download GB", "Upload GB", "Total GB"], rows, [50, 40, 40, 40])
    else:
        para("No whole-house counter was available in this period.")

    heading("Comparison with WE's own figures")
    rows = [[f"{datetime.fromtimestamp(r['ts'], tz):%d %b %Y %H:%M}", f"{r['used_gb']:.2f}",
             "" if r["we_delta_gb"] is None else f"{r['we_delta_gb']:.2f}",
             "" if r["app_delta_gb"] is None else f"{r['app_delta_gb']:.2f}",
             "" if r["diff_pct"] is None else f"{r['diff_pct']:+.1f}%", r["note"] or ""]
            for r in readings[:20]]
    if rows:
        table(["When", "WE says used GB", "WE change", "Measured here", "Difference", "Note"],
              rows, [34, 30, 24, 28, 24, 44])
    else:
        para("No WE readings were entered. Add the figure shown in the My WE app from the "
             "dashboard to build this comparison.")

    heading("Alerts in this period")
    if alerts:
        for a in alerts[-40:]:
            para(f"{datetime.fromtimestamp(a['ts'], tz):%d %b %H:%M}  [{a['type']}]  {a['message']}")
    else:
        para("None.")

    heading("How these numbers were obtained")
    para("Figures come from byte counters read at regular intervals (router interface counters, "
         "and/or the network interface of the monitoring computer) and stored in hourly totals. "
         "1 GB = 1024 MB. Upload and download are both counted. Counters measure traffic inside "
         "the home network, so small differences from the provider's accounting (protocol "
         "overhead, timing of readings) are expected.")
    return bytes(pdf.output())
