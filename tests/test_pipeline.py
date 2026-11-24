"""End-to-end tests: snapshots -> database -> API, plus a simulated ZTE router."""
import hashlib
import re
import time

import httpx
import pytest
from fastapi.testclient import TestClient

from app.collectors.base import Collector, CollectorError, CounterObs, DeviceObs, Snapshot
from app.collectors.zte import ZteAuthError, ZteClient, ZteCollector, interpret, parse_response
from app.config import DEFAULTS, Config, _deep_merge
from app.main import create_app
from app.quota import GB, MB

W = {"X-Requested-With": "we-monitor"}
PHONE, TV, MAC = "a4:83:e7:01:02:03", "f4:5c:89:aa:01:02", "3c:22:fb:10:20:30"


@pytest.fixture
def app(tmp_path):
    cfg = Config(_deep_merge(DEFAULTS, {"database": str(tmp_path / "t.sqlite"),
                                        "alerts": {"macos_notifications": False}}))
    application = create_app(cfg, collectors=[], start_poller=False)
    for c in ("router", "local", "sniff", "upnp"):
        application.state.poller._priority[c] = {"router": 20, "local": 10, "sniff": 30, "upnp": 5}[c]
    return application


def snap(source, ts, devices=(), counters=(), authoritative=False):
    return Snapshot(source=source, ts=ts, devices=list(devices), counters=list(counters),
                    authoritative_presence=authoritative)


def usage(app, key):
    rows = app.state.db.query("SELECT SUM(rx) rx, SUM(tx) tx FROM usage_hourly WHERE key=?", (key,))
    return rows[0]["rx"] or 0, rows[0]["tx"] or 0


def test_counters_become_usage_and_survive_reset(app):
    p, t = app.state.poller, time.time() - 300
    p.process([snap("router", t, counters=[CounterObs("total:wan", 1000 * MB, 100 * MB)])], t)
    assert usage(app, "total") == (0, 0)                      # baseline only
    p.process([snap("router", t + 60, counters=[CounterObs("total:wan", 1200 * MB, 110 * MB)])], t + 60)
    assert usage(app, "total") == (200 * MB, 10 * MB)
    # Router reboots: counter restarts near zero. Only the new bytes count.
    p.process([snap("router", t + 120, counters=[CounterObs("total:wan", 5 * MB, 1 * MB)])], t + 120)
    assert usage(app, "total") == (205 * MB, 11 * MB)
    assert p.total_source == "wan:router"


def test_better_source_wins_and_no_double_count(app):
    p, t = app.state.poller, time.time() - 300
    for i, (local_rx, sniff_rx) in enumerate([(0, 0), (100 * MB, 90 * MB), (200 * MB, 180 * MB)]):
        ts = t + 60 * i
        p.process([snap("local", ts, counters=[CounterObs(MAC, local_rx, 0)]),
                   snap("sniff", ts, counters=[CounterObs(MAC, sniff_rx, 0)])], ts)
    assert usage(app, MAC)[0] == 180 * MB                      # sniff (priority 30) only


def test_source_handover_does_not_recount_the_gap(app):
    p, t = app.state.poller, time.time() - 1000
    p.process([snap("upnp", t, counters=[CounterObs("total:wan", 0, 0)])], t)
    p.process([snap("upnp", t + 60, counters=[CounterObs("total:wan", 60 * MB, 0)])], t + 60)
    # UPnP stops answering for a while; the port/Wi-Fi sum takes over ...
    seg = lambda v: [CounterObs("seg:lan:1", v, 0, label="LAN1")]
    p.process([snap("router", t + 60, counters=seg(0))], t + 60)
    p.process([snap("router", t + 420, counters=seg(360 * MB))], t + 420)
    assert usage(app, "total")[0] == 420 * MB
    # ... then UPnP returns with a delta that spans the whole gap: only the
    # part after the last counted moment may be added.
    p.process([snap("upnp", t + 480, counters=[CounterObs("total:wan", 480 * MB, 0)])], t + 480)
    assert usage(app, "total")[0] == pytest.approx(480 * MB, rel=0.01)


def test_sole_device_on_a_port_gets_the_port_bytes(app):
    p, t = app.state.poller, time.time() - 300
    devs = [DeviceObs(TV, "192.168.1.11", "TV", "lan", "LAN2"),
            DeviceObs(PHONE, "192.168.1.12", "Phone", "wifi", "Wi-Fi: Home"),
            DeviceObs(MAC, "192.168.1.10", "Mac", "wifi", "Wi-Fi: Home")]
    ctr = lambda lan, wifi: [CounterObs("seg:lan:2", lan, 0, label="LAN2"),
                             CounterObs("seg:wifi:1", wifi, 0, label="Wi-Fi: Home (2.4G)")]
    p.process([snap("router", t, devs, ctr(0, 0), True)], t)
    p.process([snap("router", t + 60, devs, ctr(300 * MB, 500 * MB), True)], t + 60)
    assert usage(app, TV)[0] == 300 * MB        # alone on LAN2 -> measured
    assert usage(app, PHONE)[0] == 0            # shares the Wi-Fi network -> not attributable
    assert usage(app, "total")[0] == 800 * MB and p.total_source == "sum:segments"


def test_router_presence_beats_stale_arp_cache(app):
    p, db, now = app.state.poller, app.state.db, time.time()
    p.process([snap("arp_scan", now - 400, [DeviceObs(PHONE, "192.168.1.12")])], now - 400)
    assert db.get_device(PHONE)["last_seen"] == int(now - 400)
    # ARP still lists the phone, but the router says only the TV is connected.
    p.process([snap("arp_scan", now, [DeviceObs(PHONE, "192.168.1.12")]),
               snap("router", now, [DeviceObs(TV, "192.168.1.11", "TV")], authoritative=True)], now)
    assert db.get_device(PHONE)["last_seen"] == int(now - 400)
    assert db.get_device(TV)["last_seen"] == int(now)


def test_alerts_new_device_limit_and_spike(app):
    p, db, now = app.state.poller, app.state.db, time.time()
    db.set_setting("first_start", int(now) - 7200)             # inventory period is over
    p.process([snap("router", now - 120, [DeviceObs(PHONE, "192.168.1.12", "evil<script>")],
                    [CounterObs(PHONE, 0, 0)], True)], now - 120)
    db.edit_device(PHONE, {"daily_limit_mb": 1024})
    p.alerts._last_slow = 0
    p.process([snap("router", now - 60, [DeviceObs(PHONE)], [CounterObs(PHONE, 4 * GB, 0)], True)], now - 60)
    types = {a["type"] for a in db.query("SELECT type FROM alerts")}
    assert {"new_device", "daily_limit", "spike"} <= types
    n = len(db.query("SELECT 1 FROM alerts"))
    p.alerts._last_slow = 0
    p.process([snap("router", now, [DeviceObs(PHONE)], [CounterObs(PHONE, 4 * GB + 1, 0)], True)], now)
    assert len(db.query("SELECT 1 FROM alerts")) == n          # no duplicates


def test_api_roundtrip_and_exports(app):
    p, t = app.state.poller, time.time() - 100
    devs = [DeviceObs(TV, "192.168.1.11", "TV", "lan", "LAN2")]
    for i, v in enumerate([0, 2 * GB]):
        p.process([snap("router", t + 60 * i, devs, [CounterObs(TV, v, v // 20),
                                                     CounterObs("total:wan", v, v // 20)], True)], t + 60 * i)
    with TestClient(app, base_url="http://localhost") as c:
        assert c.get("/").status_code == 200
        q = c.get("/api/quota").json()
        assert q["basis"] == "measured_total" and q["used_gb"] == pytest.approx(2.1, abs=0.01)
        d = c.get("/api/devices?range=today").json()["devices"][0]
        assert d["name"] == "TV" and d["today_rx"] == 2 * GB and d["online"]
        # Writes need the custom header (CSRF guard) ...
        assert c.patch(f"/api/devices/{TV}", json={"custom_name": "x"}).status_code == 403
        r = c.patch(f"/api/devices/{TV}", json={"custom_name": "تلفزيون الصالة", "known": True}, headers=W)
        assert r.json()["custom_name"] == "تلفزيون الصالة"
        # ... and a foreign Host header is refused (DNS rebinding guard).
        assert c.get("/api/status", headers={"Host": "evil.example"}).status_code == 400
        assert c.put("/api/settings", json={"quota_gb": 140, "cycle_start_day": 5}, headers=W).json()["quota_gb"] == 140
        # A WE reading re-bases the quota figure.
        c.post("/api/readings", json={"used_gb": 100}, headers=W)
        assert c.get("/api/quota").json()["basis"] == "we_reading_plus_measured"
        top = c.get("/api/usage/top?range=today").json()
        assert top["items"][0]["name"] == "تلفزيون الصالة" and top["unattributed"] == 0
        assert sum(c.get("/api/usage/history?range=today").json()["series"][0]["values"]) == int(2.1 * GB)
        assert c.get("/api/usage/heatmap").json()["max"] > 0
        csv = c.get("/api/export/usage.csv?range=today").content.decode("utf-8-sig")
        assert "تلفزيون الصالة" in csv and "whole house" in csv
        assert c.get("/api/export/devices.csv").status_code == 200
        pdf = c.get("/api/export/report.pdf?range=cycle")
        assert pdf.status_code == 200 and pdf.content[:5] == b"%PDF-"


def test_failing_collector_backs_off_and_reports(app):
    import asyncio

    class Broken(Collector):
        name, interval = "router", 60

        def collect(self):
            raise CollectorError("wrong password")

    p = app.state.poller
    c = Broken()
    p.collectors, p.status["router"] = [c], {"ok": None, "error": None, "paused_until": 0}
    p._next_run["router"], p._fail_count["router"] = 0.0, 0
    asyncio.run(p.cycle())
    assert p.status["router"]["ok"] is False and "wrong password" in p.status["router"]["error"]
    assert p._next_run["router"] > time.time() + 90            # no hammering the router


# ---------------------------------------------------------------- simulated ZTE router
LAN_XML = """<ajax_response_xml_root><IF_ERRORPARAM>SUCC</IF_ERRORPARAM><IF_ERRORTYPE>SUCC</IF_ERRORTYPE>
<IF_ERRORSTR>SUCC</IF_ERRORSTR><IF_ERRORID>0</IF_ERRORID><OBJ_ACCESSDEV_ID>
<Instance><ParaName>_InstID</ParaName><ParaValue>DEV.DEVINFO1</ParaValue><ParaName>HostName</ParaName><ParaValue>Living&#32;Room&#32;TV</ParaValue>
<ParaName>MACAddress</ParaName><ParaValue>F4:5C:89:AA:01:02</ParaValue><ParaName>IPAddress</ParaName><ParaValue>192.168.1.11</ParaValue>
<ParaName>AliasName</ParaName><ParaValue>LAN2</ParaValue></Instance></OBJ_ACCESSDEV_ID></ajax_response_xml_root>"""
SSID_XML = """<ajax_response_xml_root><IF_ERRORSTR>SUCC</IF_ERRORSTR><OBJ_ACCESSDEV_ID>
<Instance><ParaName>HostName</ParaName><ParaValue>iPhone</ParaValue><ParaName>MACAddress</ParaName><ParaValue>a4:83:e7:01:02:03</ParaValue>
<ParaName>IPAddress</ParaName><ParaValue>192.168.1.12</ParaValue><ParaName>AliasName</ParaName><ParaValue>HomeNet</ParaValue></Instance>
</OBJ_ACCESSDEV_ID></ajax_response_xml_root>"""
ETH_XML = """<ajax_response_xml_root><IF_ERRORSTR>SUCC</IF_ERRORSTR><OBJ_ETH_ID>
<Instance><ParaName>_InstID</ParaName><ParaValue>DEV.ETH.IF1</ParaValue><ParaName>AliasName</ParaName><ParaValue>LAN1</ParaValue>
<ParaName>MACAddress</ParaName><ParaValue>34:e8:94:0a:0b:0c</ParaValue><ParaName>BytesReceived</ParaName><ParaValue>0</ParaValue><ParaName>BytesSent</ParaName><ParaValue>0</ParaValue></Instance>
<Instance><ParaName>_InstID</ParaName><ParaValue>DEV.ETH.IF2</ParaValue><ParaName>AliasName</ParaName><ParaValue>LAN2</ParaValue>
<ParaName>MACAddress</ParaName><ParaValue>34:e8:94:0a:0b:0c</ParaValue><ParaName>BytesReceived</ParaName><ParaValue>1000</ParaValue><ParaName>BytesSent</ParaName><ParaValue>90000</ParaValue></Instance>
</OBJ_ETH_ID></ajax_response_xml_root>"""
WLAN_XML = """<ajax_response_xml_root><IF_ERRORSTR>SUCC</IF_ERRORSTR>
<OBJ_WLANAP_ID><Instance><ParaName>_InstID</ParaName><ParaValue>DEV.WIFI.AP1</ParaValue><ParaName>ESSID</ParaName><ParaValue>HomeNet</ParaValue><ParaName>KeyPassphrase</ParaName><ParaValue>s3cret</ParaValue></Instance></OBJ_WLANAP_ID>
<OBJ_WLANCONFIGDRV_ID><Instance><ParaName>_InstID</ParaName><ParaValue>DEV.WIFI.AP1</ParaValue><ParaName>RealRF</ParaName><ParaValue>2.4GHz</ParaValue>
<ParaName>TotalBytesSent</ParaName><ParaValue>700000</ParaValue><ParaName>TotalBytesReceived</ParaName><ParaValue>50000</ParaValue></Instance></OBJ_WLANCONFIGDRV_ID>
</ajax_response_xml_root>"""
TIMEOUT_XML = "<ajax_response_xml_root><IF_ERRORSTR>SessionTimeout</IF_ERRORSTR></ajax_response_xml_root>"
PAGES = {"accessdev_landevs_lua.lua": LAN_XML, "accessdev_ssiddev_lua.lua": SSID_XML,
         "eth_lanstatus_lua.lua": ETH_XML, "wlan_status_lua.lua": WLAN_XML}


class FakeZte:
    """Behaves like the modern ZTE web UI: salted login, view-before-data, sessions."""

    def __init__(self, password="Secret123"):
        self.password, self.salt, self.session, self.view = password, "68877896", False, None
        self.logins = self.failed = 0
        self.busy = False

    def __call__(self, request: httpx.Request) -> httpx.Response:
        q = dict(request.url.params)
        typ, tag = q.get("_type"), q.get("_tag")
        if typ == "loginData" and tag == "login_entry" and request.method == "GET":
            return httpx.Response(200, json={"lockingTime": 0, "loginErrMsg": "", "sess_token": "tok"})
        if tag == "login_token":
            return httpx.Response(200, text=f"<ajax_response_xml_root>{self.salt}</ajax_response_xml_root>")
        if tag == "login_entry":
            form = dict(p.split("=") for p in request.content.decode().split("&"))
            good = hashlib.sha256((self.password + self.salt).encode()).hexdigest()
            if self.busy:
                return httpx.Response(200, json={"login_need_refresh": False, "loginErrType": "e_exceed_max_user_preempt"})
            if form["Password"] == good and form["_sessionTOKEN"] == "tok":
                self.session, self.logins = True, self.logins + 1
                return httpx.Response(200, json={"login_need_refresh": True})
            self.failed += 1
            return httpx.Response(200, json={"login_need_refresh": False, "loginErrType": "e_passwd_error"})
        if tag == "logout_entry":
            self.session = False
            return httpx.Response(200, json={})
        if typ == "menuView":
            self.view = tag
            body = " ".join(f"'/?_type=menuData&_tag={t}'" for t in PAGES) if tag == "localNetStatus" else ""
            return httpx.Response(200, text=f"<html>{body}</html>")
        if typ == "menuData":
            ok = self.session and self.view == "localNetStatus" and tag in PAGES
            return httpx.Response(200, text=PAGES[tag] if ok else TIMEOUT_XML)
        return httpx.Response(200, text="<html></html>")


def make_collector(fake, password="Secret123"):
    c = ZteCollector("http://192.168.1.1", "admin", lambda: password)
    c.client = ZteClient("http://192.168.1.1", "admin", password)
    c.client.http = httpx.Client(transport=httpx.MockTransport(fake))
    return c


def test_zte_collector_reads_devices_and_counters():
    fake = FakeZte()
    c = make_collector(fake)
    s = c.collect()
    by_mac = {d.mac: d for d in s.devices}
    assert by_mac[TV].hostname == "Living Room TV" and by_mac[TV].segment == "LAN2" and by_mac[TV].conn_type == "lan"
    assert by_mac[PHONE].segment == "Wi-Fi: HomeNet" and by_mac[PHONE].conn_type == "wifi"
    ctr = {x.label: x for x in s.counters}
    assert set(ctr) == {"LAN2", "Wi-Fi: HomeNet (2.4G)"}        # idle LAN1 is skipped
    assert (ctr["LAN2"].rx, ctr["LAN2"].tx) == (90000, 1000)   # router "sent" = device download
    assert s.authoritative_presence and c.capabilities["per_device"] is False
    # Second poll reuses the session and the discovered pages: no new login.
    c.collect()
    assert fake.logins == 1
    # Session expires on the router: exactly one transparent re-login.
    fake.session = False
    assert len(c.collect().devices) == 2 and fake.logins == 2


def test_zte_wrong_password_is_tried_once_only():
    fake = FakeZte()
    c = make_collector(fake, password="wrong")
    for _ in range(3):
        with pytest.raises(ZteAuthError):
            c.collect()
    assert fake.failed == 1                                    # never locks the admin page


def test_zte_does_not_kick_out_a_logged_in_admin():
    fake = FakeZte()
    fake.busy = True
    c = make_collector(fake)
    with pytest.raises(CollectorError, match="one admin at a time"):
        c.collect()


def test_zte_parsers():
    nodes = parse_response('{"OBJ_X":{"Instance":[{"path":"DEV.HOST.1","parameters":{"PhysAddress":"A4:83:E7:01:02:03","IPAddress":"192.168.1.5"}}]},"IF_ERRORSTR":"SUCC"}')
    devs, _ = interpret("localNetStatus", "x_lua.lua", nodes)
    assert devs[0].mac == PHONE
    wan = parse_response("<ajax_response_xml_root><IF_ERRORSTR>SUCC</IF_ERRORSTR><ID_WAN_COMFIG><Instance>"
                         "<ParaName>RxBytes</ParaName><ParaValue>5000</ParaValue><ParaName>TxBytes</ParaName><ParaValue>300</ParaValue>"
                         "</Instance></ID_WAN_COMFIG></ajax_response_xml_root>")
    _, ctrs = interpret("ethWanStatus", "wan_internetstatus_lua.lua", wan)
    assert (ctrs[0].key, ctrs[0].rx, ctrs[0].tx) == ("total:wan", 5000, 300)


def test_probe_report_hides_secrets():
    from app.collectors.zte import probe_report
    client = ZteClient("http://192.168.1.1", "admin", "Secret123")
    client.http = httpx.Client(transport=httpx.MockTransport(FakeZte()))
    report = probe_report(client, crawl=False)
    text = str(report)
    assert report["login_ok"] and "s3cret" not in text and "Secret123" not in text
    assert re.search(r"Per-port / per-Wi-Fi bytes:\s+YES", report["summary"])
