"""FastAPI application: JSON API + the static dashboard.

Run with:  python -m app            (or ./run.sh)
Then open: http://localhost:8000
"""
from __future__ import annotations

import asyncio
import logging
import time
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import reports, stats
from .alerts import AlertEngine
from .collectors.base import Collector
from .config import Config, load_config
from .db import Database
from .poller import Poller
from .timeutil import get_tz, resolve_range

log = logging.getLogger("we.app")
STATIC = Path(__file__).parent / "static"
RANGES = {"today", "yesterday", "7d", "30d", "cycle", "prev_cycle"}


def build_collectors(cfg: Config, tz) -> list[Collector]:
    """Choose the data sources from config.yaml."""
    if cfg.demo:
        from .collectors.demo import DemoCollector
        return [DemoCollector(tz)]
    out: list[Collector] = []
    if cfg.get("router.type") == "zte":
        from .collectors.zte import ZteCollector
        out.append(ZteCollector(
            url=cfg.get("router.url"), username=cfg.get("router.username"),
            password_fn=lambda: cfg.router_password,
            interval=float(cfg.get("router.poll_seconds", 60)),
            swap_directions=bool(cfg.get("router.swap_directions")),
            extra_tags=cfg.get("router.extra_tags") or []))
    if cfg.get("collectors.arp_scan.enabled"):
        from .collectors.arp_scan import ArpScanCollector
        out.append(ArpScanCollector(float(cfg.get("collectors.arp_scan.poll_seconds", 60))))
    if cfg.get("collectors.sniff.enabled"):
        from .collectors.sniff import SniffCollector
        out.append(SniffCollector(cfg.get("collectors.sniff.interface", "bridge100"),
                                  bool(cfg.get("collectors.sniff.use_sudo", True))))
    elif cfg.get("collectors.local.enabled"):
        from .collectors.local import LocalCollector
        out.append(LocalCollector())
    if cfg.get("collectors.upnp.enabled"):
        from .collectors.upnp import UpnpCollector
        out.append(UpnpCollector(float(cfg.get("collectors.upnp.poll_seconds", 30))))
    return out


class DeviceEdit(BaseModel):
    custom_name: str | None = Field(default=None, max_length=60)
    known: bool | None = None
    daily_limit_mb: int | None = Field(default=None, ge=0, le=10_000_000)


class SettingsEdit(BaseModel):
    quota_gb: float | None = Field(default=None, gt=0, le=100_000)
    cycle_start_day: int | None = Field(default=None, ge=1, le=31)
    default_daily_limit_gb: float | None = Field(default=None, ge=0, le=10_000)
    spike_gb_per_hour: float | None = Field(default=None, ge=0, le=10_000)
    night_gb: float | None = Field(default=None, ge=0, le=10_000)
    notify_macos: bool | None = None


class ReadingIn(BaseModel):
    used_gb: float = Field(ge=0, le=100_000)
    note: str | None = Field(default=None, max_length=120)
    ts: int | None = None


class PauseIn(BaseModel):
    minutes: float = Field(default=15, ge=0, le=240)


def create_app(cfg: Config | None = None, collectors: list[Collector] | None = None,
               start_poller: bool = True) -> FastAPI:
    cfg = cfg or load_config()
    tz = get_tz(cfg.get("timezone"))
    db = Database(cfg.db_path)
    alerts = AlertEngine(cfg, db, tz)
    alerts._usage_fn = lambda now: stats.quota_status(db, alerts.all_settings(), tz, now)
    poller = Poller(cfg, db, collectors if collectors is not None else build_collectors(cfg, tz), alerts)
    offline_after = int(cfg.get("offline_after_seconds", 150))

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        task = asyncio.create_task(poller.run()) if start_poller else None
        yield
        poller.stop()
        if task:
            task.cancel()
        db.close()

    app = FastAPI(title="WE Monitor", lifespan=lifespan, docs_url="/api/docs", redoc_url=None)
    app.state.db, app.state.poller, app.state.cfg = db, poller, cfg

    allowed_hosts = {"localhost", "127.0.0.1", "[::1]", str(cfg.get("server.host"))}

    @app.middleware("http")
    async def local_only_guard(request: Request, call_next):
        # The dashboard has no login, so make sure other web pages cannot drive it:
        #  * Host check stops DNS-rebinding tricks
        #  * a custom header on writes stops cross-site form posts (CSRF)
        host = (request.headers.get("host") or "").rsplit(":", 1)[0]
        if host not in allowed_hosts and cfg.get("server.host") != "0.0.0.0":
            return JSONResponse({"detail": "unexpected Host header"}, status_code=400)
        if request.method not in ("GET", "HEAD", "OPTIONS") and \
                request.headers.get("x-requested-with") != "we-monitor":
            return JSONResponse({"detail": "missing X-Requested-With header"}, status_code=403)
        response = await call_next(request)
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    def now_local() -> datetime:
        return datetime.now(tz)

    def rng(name: str) -> tuple[int, int, str]:
        if name not in RANGES:
            raise HTTPException(400, f"range must be one of {sorted(RANGES)}")
        return resolve_range(name, now_local(), int(alerts.setting("cycle_start_day")))

    # ------------------------------------------------------------ status
    @app.get("/api/status")
    def status():
        now = time.time()
        devices = db.list_devices("device")
        totals = db.usage_totals(int(now) - 86400, int(now) + 1)
        measured = [d["key"] for d in devices if d["key"] in totals]
        return {
            "now": int(now), "timezone": str(tz), "demo": cfg.demo,
            "last_cycle": poller.last_cycle,
            "collectors": poller.status,
            "total_source": poller.total_source,
            "has_segments": bool(db.list_devices("segment")),
            "devices": len(devices),
            "online": sum(1 for d in devices if d["last_seen"] and now - d["last_seen"] <= offline_after),
            "measured_devices": len(measured),
            "unacked_alerts": db.query("SELECT COUNT(*) AS n FROM alerts WHERE acked=0")[0]["n"],
        }

    @app.post("/api/collectors/{name}/pause")
    def pause(name: str, body: PauseIn):
        if name not in poller.status:
            raise HTTPException(404, "unknown collector")
        poller.pause(name, body.minutes)
        return {"paused_until": poller.status[name]["paused_until"]}

    # ------------------------------------------------------------ quota
    @app.get("/api/quota")
    def quota():
        return stats.quota_status(db, alerts.all_settings(), tz, now_local())

    @app.get("/api/settings")
    def get_settings():
        return alerts.all_settings()

    @app.put("/api/settings")
    def put_settings(body: SettingsEdit):
        for name, value in body.model_dump(exclude_none=True).items():
            db.set_setting(name, value)
        return alerts.all_settings()

    @app.get("/api/readings")
    def readings():
        return stats.reading_comparison(db, tz)

    @app.post("/api/readings")
    def add_reading(body: ReadingIn):
        ts = body.ts or int(time.time())
        if ts > time.time() + 300:
            raise HTTPException(400, "reading time is in the future")
        db.execute("INSERT INTO we_readings(ts,used_gb,note) VALUES(?,?,?)",
                   (ts, body.used_gb, body.note))
        return stats.reading_comparison(db, tz)

    @app.delete("/api/readings/{reading_id}")
    def delete_reading(reading_id: int):
        db.execute("DELETE FROM we_readings WHERE id=?", (reading_id,))
        return {"ok": True}

    # ------------------------------------------------------------ devices
    @app.get("/api/devices")
    def devices(range: str = "cycle"):
        start, end, label = rng(range)
        return {"range": label,
                "devices": stats.device_table(db, poller, start, end, tz, offline_after, now_local())}

    @app.patch("/api/devices/{key}")
    def edit_device(key: str, body: DeviceEdit):
        changes = body.model_dump(exclude_unset=True)
        if "custom_name" in changes:
            changes["custom_name"] = (changes["custom_name"] or "").strip() or None
        if "known" in changes:
            changes["known"] = int(bool(changes["known"]))
        if "daily_limit_mb" in changes and not changes["daily_limit_mb"]:
            changes["daily_limit_mb"] = None
        if not db.get_device(key):
            raise HTTPException(404, "unknown device")
        db.edit_device(key, changes)
        return db.get_device(key)

    @app.delete("/api/devices/{key}")
    def forget_device(key: str):
        db.delete_device(key)
        return {"ok": True}

    # ------------------------------------------------------------ usage
    @app.get("/api/live")
    def live():
        now = time.time()
        speeds = {}
        for key in list(poller.live):
            s = poller.speed(key, now)
            if s:
                speeds[key] = {"down_bps": s[0], "up_bps": s[1]}
        return {"now": int(now), "tick": poller.tick, "total_source": poller.total_source,
                "total": list(poller.live_total), "speeds": speeds}

    @app.get("/api/usage/top")
    def top(range: str = "cycle", kind: str = "device"):
        start, end, label = rng(range)
        return {"range": label, **stats.top_consumers(db, start, end, kind)}

    @app.get("/api/usage/history")
    def usage_history(range: str = "cycle", bucket: str = "auto", kind: str = "device",
                      key: str | None = None):
        start, end, label = rng(range)
        if bucket == "auto":
            bucket = "hour" if range in ("today", "yesterday") else "day"
        if bucket not in ("hour", "day", "month"):
            raise HTTPException(400, "bucket must be hour, day or month")
        if bucket == "hour" and end - start > 8 * 86400:
            bucket = "day"
        return {"range": label, **stats.history(db, start, end, bucket, tz, kind, key)}

    @app.get("/api/usage/monthly")
    def usage_monthly(key: str = "total"):
        end = int(time.time()) + 1
        h = stats.history(db, end - 400 * 86400, end, "month", tz, key=key)
        # Drop the empty months before the first recorded usage.
        sums = [sum(s["values"][i] for s in h["series"]) for i in range(len(h["labels"]))]
        first = next((i for i, v in enumerate(sums) if v), max(len(sums) - 1, 0))
        h["labels"], h["starts"] = h["labels"][first:], h["starts"][first:]
        for s in h["series"]:
            s["values"] = s["values"][first:]
        return h

    @app.get("/api/usage/heatmap")
    def usage_heatmap(days: int = 14, key: str = "total"):
        return stats.heatmap(db, tz, max(1, min(days, 62)), key, now_local())

    @app.get("/api/usage/suspects")
    def suspects(range: str = "cycle"):
        start, end, label = rng(range)
        return {"range": label, "items": stats.presence_correlation(db, start, end)}

    # ------------------------------------------------------------ alerts
    @app.get("/api/alerts")
    def list_alerts(limit: int = 100):
        return db.query("SELECT * FROM alerts ORDER BY ts DESC, id DESC LIMIT ?",
                        (max(1, min(limit, 500)),))

    @app.post("/api/alerts/{alert_id}/ack")
    def ack(alert_id: int):
        db.execute("UPDATE alerts SET acked=1 WHERE id=?", (alert_id,))
        return {"ok": True}

    @app.post("/api/alerts/ack-all")
    def ack_all():
        db.execute("UPDATE alerts SET acked=1")
        return {"ok": True}

    # ------------------------------------------------------------ export
    def download(data: bytes, media: str, name: str) -> Response:
        return Response(data, media_type=media,
                        headers={"Content-Disposition": f'attachment; filename="{name}"'})

    @app.get("/api/export/usage.csv")
    def export_usage(range: str = "cycle", bucket: str = "day"):
        start, end, _ = rng(range)
        return download(reports.usage_csv(db, tz, start, end, bucket), "text/csv",
                        f"we-usage-{range}-{bucket}-{now_local():%Y%m%d}.csv")

    @app.get("/api/export/devices.csv")
    def export_devices():
        return download(reports.devices_csv(db, tz), "text/csv",
                        f"we-devices-{now_local():%Y%m%d}.csv")

    @app.get("/api/export/report.pdf")
    def export_pdf(range: str = "cycle"):
        start, end, label = rng(range)
        data = reports.report_pdf(db, tz, alerts.all_settings(), start, end, label)
        return download(data, "application/pdf", f"we-usage-report-{now_local():%Y%m%d}.pdf")

    # ------------------------------------------------------------ dashboard
    @app.get("/")
    def index():
        return FileResponse(STATIC / "index.html", headers={"Cache-Control": "no-cache"})

    app.mount("/static", StaticFiles(directory=STATIC), name="static")
    return app


def main() -> None:
    import uvicorn

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)
    cfg = load_config()
    app = create_app(cfg)
    host, port = cfg.get("server.host", "127.0.0.1"), int(cfg.get("server.port", 8000))
    log.info("dashboard: http://localhost:%s  (mode: %s, database: %s)", port, cfg.get("mode"), cfg.db_path)
    uvicorn.run(app, host=host, port=port, log_level="warning")


if __name__ == "__main__":
    main()
