"""ZTE home gateway collector (modern web UI: H188A, H288A, F670L V9, F680, F6640...).

What ZTE firmware exposes (established from open-source clients for sibling
models; no public source documents a WE-branded unit, so the first run on
YOUR router is the real test -- use `python -m app.cli probe-router`):

  * connected devices: MAC, IP, hostname, which LAN port / Wi-Fi network  -> yes
  * bytes per LAN PORT and per Wi-Fi NETWORK (SSID)                       -> yes
  * bytes for the WAN (whole house)                                      -> some firmware
  * bytes per individual DEVICE                                          -> NO

So this collector gives an authoritative device list plus per-port / per-SSID
counters. A port or SSID that has exactly one device on it is, in effect, a
per-device counter (see README "Getting per-device numbers without hardware").

Protocol: read-only GET requests after a normal admin login
  GET  /?_type=loginData&_tag=login_entry      -> session token (JSON)
  GET  /?_type=loginData&_tag=login_token      -> one-time salt (XML)
  POST /?_type=loginData&_tag=login_entry      -> Password = sha256(password + salt)
  GET  /?_type=menuView&_tag=<page>            -> must precede the data request
  GET  /?_type=menuData&_tag=<x>_lua.lua       -> XML: <Instance><ParaName/><ParaValue/>...
Nothing on the router is ever changed; no settings POST is ever sent.

Older ZTE firmware (pages named getpage.gch / getpage.lua, e.g. H108N, old
H168N) uses a different protocol and is NOT supported here; the app then falls
back to the ARP scan + UPnP collectors.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
import time
import xml.etree.ElementTree as ET
from typing import Callable

import httpx

from ..netutil import normalize_mac
from .base import Collector, CollectorError, CounterObs, DeviceObs, Snapshot

log = logging.getLogger("we.zte")

# Status pages to look at, and the data tags known from sibling models.
# The tags a page really offers are discovered from the page itself.
VIEWS: dict[str, list[str]] = {
    "localNetStatus": ["accessdev_landevs_lua.lua", "accessdev_ssiddev_lua.lua",
                       "wlan_client_stat_lua.lua", "eth_lanstatus_lua.lua",
                       "status_lan_info_lua.lua", "wlan_status_lua.lua"],
    "homePage": ["accessdev_homepage_lua.lua&InstNum=1000"],
    "ethWanStatus": ["wan_internetstatus_lua.lua&TypeUplink=2&pageType=1",
                     "wan_internet_lua.lua&TypeUplink=2&pageType=1"],
    "dslWanStatus": ["wan_internetstatus_lua.lua&TypeUplink=1&pageType=1",
                     "dsl_interface_status_lua.lua"],
    "ethSfpWanStatus": ["eth_sfp_interface_status_lua.lua"],
}
INTERESTING = re.compile(r"accessdev|client|lanstatus|lan_info|wlan_status|wan_internet|interface_status", re.I)
NEVER = re.compile(r"reboot|reset|restore|upgrade|logout|factory|delete|password|passwd", re.I)
TAG_IN_PAGE = re.compile(r"_tag=([A-Za-z0-9_.]+_lua\.lua)")
SECRET_FIELD = re.compile(r"pass|psk|key|secret|wep|pin|token|sn$|serial", re.I)

# Byte-counter field names, from the ROUTER's point of view.
SENT_FIELDS = ("BytesSent", "TotalBytesSent", "OutBytes", "TxBytes")
RECV_FIELDS = ("BytesReceived", "TotalBytesReceived", "InBytes", "RxBytes")
REDISCOVER_SECONDS = 6 * 3600


class ZteAuthError(CollectorError):
    """Wrong password or admin page locked: do not retry automatically."""


class SessionExpired(Exception):
    pass


def parse_response(text: str) -> dict[str, list[dict[str, str]]]:
    """Router answer -> {object name: [ {field: value}, ... ]}.

    Handles the classic XML form and the JSON form used by newer firmware.
    """
    text = text.strip()
    if text.startswith("{"):
        try:
            data = json.loads(text)
        except ValueError as e:
            raise CollectorError(f"unreadable router answer: {e}") from e
        _check_error(str(data.get("IF_ERRORSTR", "SUCC")))
        out: dict[str, list[dict[str, str]]] = {}
        for node, value in data.items():
            if isinstance(value, dict) and isinstance(value.get("Instance"), list):
                out[node] = [{"_InstID": str(i.get("path", "")),
                              **{k: str(v) for k, v in (i.get("parameters") or {}).items()}}
                             for i in value["Instance"] if isinstance(i, dict)]
        return out
    try:
        root = ET.fromstring(text)
    except ET.ParseError as e:
        raise CollectorError(f"unreadable router answer: {e}") from e
    err = root.findtext("IF_ERRORSTR")
    if err is not None:
        _check_error(err)
    out = {}
    for node in root.iter():
        instances = node.findall("Instance")
        if not instances:
            continue
        rows = []
        for inst in instances:
            row, name = {}, None
            for el in inst:                 # ParaName / ParaValue are sibling pairs
                if el.tag == "ParaName":
                    name = el.text or ""
                elif el.tag == "ParaValue" and name is not None:
                    row[name] = el.text or ""
                    name = None
            rows.append(row)
        out.setdefault(node.tag, []).extend(rows)
    return out


def _check_error(err: str) -> None:
    if err.strip().upper() in ("SUCC", "SUCCESS", "OK", ""):
        return
    if "timeout" in err.lower() or "session" in err.lower():
        raise SessionExpired(err)
    raise CollectorError(f"router said: {err}")


class ZteClient:
    def __init__(self, url: str, username: str, password: str, timeout: float = 12,
                 takeover: bool = False):
        self.base = url.rstrip("/")
        self.username, self.password, self.takeover = username, password, takeover
        # verify=False: routers use self-signed certificates on https.
        self.http = httpx.Client(timeout=timeout, verify=False, follow_redirects=True, headers={
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
                          "(KHTML, like Gecko) Version/17.0 Safari/605.1.15",
            "X-Requested-With": "XMLHttpRequest",
            "Referer": self.base + "/",
        })
        self.logged_in = False

    def _url(self, query: str) -> str:
        return f"{self.base}/?{query}"

    def _request(self, method: str, query: str, **kw) -> httpx.Response:
        try:
            return self.http.request(method, self._url(query) if query else self.base + "/", **kw)
        except httpx.HTTPError as e:
            raise CollectorError(f"cannot reach the router at {self.base} ({type(e).__name__})") from e

    def login(self) -> None:
        self.logged_in = False
        r = self._request("GET", "_type=loginData&_tag=login_entry")
        try:
            entry = r.json()
        except ValueError:
            raise CollectorError(
                "this router does not use the modern ZTE web interface (older firmware). "
                "The router collector cannot read it; device discovery still works via ARP scan.")
        if entry.get("lockingTime"):
            raise ZteAuthError(f"router admin page is locked ({entry.get('loginErrMsg') or 'too many wrong passwords'}); "
                               "wait until it unlocks, then restart the app")
        salt_xml = self._request("GET", f"_type=loginData&_tag=login_token&_={int(time.time() * 1000)}").text
        m = re.search(r"<ajax_response_xml_root>\s*([^<\s]+)\s*</ajax_response_xml_root>", salt_xml)
        if not m:
            raise CollectorError("router did not return a login token")
        digest = hashlib.sha256((self.password + m.group(1)).encode()).hexdigest()
        r = self._request("POST", "_type=loginData&_tag=login_entry", data={
            "action": "login", "Username": self.username, "Password": digest,
            "_sessionTOKEN": entry.get("sess_token", "")})
        try:
            result = r.json()
        except ValueError:
            raise CollectorError("unexpected answer to the login request")
        if not result.get("login_need_refresh"):
            err = f"{result.get('loginErrType') or ''} {result.get('loginErrMsg') or ''}".strip()
            if "preempt" in err or "max_user" in err:
                if not self.takeover:
                    raise CollectorError(
                        "someone is logged in to the router admin page (the router allows one "
                        "admin at a time). Log out there, or press 'Pause router polling' "
                        "before you use the admin page.")
                self._preempt()
            else:
                raise ZteAuthError(f"router rejected the login ({err or 'wrong password?'}). "
                                   "Fix the password with `python -m app.cli set-password` and restart.")
        self._request("GET", "")          # some firmware needs the page reload before data
        self.logged_in = True

    def _preempt(self) -> None:
        page = self._request("GET", "").text
        m = re.search(r'name="preempt_sessid"\s+value="([^"]*)"', page)
        r = self._request("POST", "_type=loginData&_tag=login_preempt",
                          data={"preempt_sessid": m.group(1) if m else "0", "action": "preempt"})
        try:
            ok = r.json().get("login_need_refresh")
        except ValueError:
            ok = False
        if not ok:
            raise CollectorError("could not take over the router admin session")

    def view(self, tag: str) -> str:
        return self._request("GET", f"_type=menuView&_tag={tag}&Menu3Location=0&_={int(time.time() * 1000)}").text

    def data(self, tag: str) -> dict[str, list[dict[str, str]]]:
        r = self._request("GET", f"_type=menuData&_tag={tag}&_={int(time.time() * 1000)}")
        return parse_response(r.text)

    def logout(self) -> None:
        if not self.logged_in:
            return
        try:
            self.http.post(self._url("_type=loginData&_tag=logout_entry"), data={"IF_LogOff": "1"})
        except httpx.HTTPError:
            pass
        self.logged_in = False

    def close(self) -> None:
        self.logout()
        self.http.close()


# ---------------------------------------------------------------- interpretation
def _num(row: dict, names: tuple[str, ...]) -> int | None:
    for n in names:
        v = row.get(n)
        if v is not None and re.fullmatch(r"\d+", v.strip()):
            return int(v)
    return None


def interpret(view: str, tag: str, nodes: dict[str, list[dict]], swap: bool = False
              ) -> tuple[list[DeviceObs], list[CounterObs]]:
    """Turn one router answer into devices and counters, by field names (not model)."""
    devices: list[DeviceObs] = []
    counters: list[CounterObs] = []
    is_wan = bool(re.search(r"wan|internet", view, re.I))
    # Wi-Fi network names: instance id -> SSID
    ssids = {r.get("_InstID", ""): r.get("ESSID") for r in nodes.get("OBJ_WLANAP_ID", []) if r.get("ESSID")}
    wan_best: tuple[int, int] | None = None

    for node, rows in nodes.items():
        for idx, row in enumerate(rows):
            sent, recv = _num(row, SENT_FIELDS), _num(row, RECV_FIELDS)
            mac = normalize_mac(row.get("MACAddress") or row.get("PhysAddress"))
            if sent is not None and recv is not None and mac and "IPAddress" in row:
                # Per-client counters (rare; not seen on WE firmware so far).
                rx, tx = (recv, sent) if swap else (sent, recv)
                counters.append(CounterObs(key=mac, rx=rx, tx=tx))
                devices.append(DeviceObs(mac=mac, ip=(row.get("IPAddress") or "").strip() or None,
                                         hostname=(row.get("HostName") or "").strip() or None))
            elif sent is not None and recv is not None:
                if is_wan:
                    # WAN side: received = download. Keep the busiest connection.
                    if wan_best is None or recv > wan_best[0]:
                        wan_best = (recv, sent)
                    continue
                if sent == 0 and recv == 0:
                    continue                               # unused port / disabled SSID
                inst = row.get("_InstID", "")
                if "WLAN" in node.upper() or "TotalBytesSent" in row:
                    name = ssids.get(inst) or row.get("ESSID") or row.get("WLANViewName") or f"SSID{idx + 1}"
                    band = row.get("RealRF") or row.get("BAND") or ""
                    band = "5G" if "5" in band else "2.4G" if "2" in band else ""
                    label = f"Wi-Fi: {name}" + (f" ({band})" if band else "")
                    key = f"seg:wifi:{inst or idx + 1}"
                else:
                    label = row.get("AliasName") or (f"LAN{inst[-1]}" if inst[-1:].isdigit() else f"Port {idx + 1}")
                    key = f"seg:lan:{inst or label}"
                # LAN side: what the router SENT is what the devices DOWNLOADED.
                rx, tx = (recv, sent) if swap else (sent, recv)
                counters.append(CounterObs(key=key, rx=rx, tx=tx, label=label))
            elif mac and ("IPAddress" in row or "HostName" in row):
                alias = (row.get("AliasName") or "").strip()
                alias = ssids.get(alias, alias)
                wifi = "WLAN" in node.upper() or "ssiddev" in tag or "wlan" in tag
                lan = bool(re.match(r"(?i)lan\s?\d", alias)) or "landevs" in tag
                conn = "lan" if lan and not wifi else "wifi" if wifi or (alias and not lan) else None
                segment = None
                if alias:
                    segment = alias if conn == "lan" else f"Wi-Fi: {alias}"
                ip = (row.get("IPAddress") or "").strip()
                devices.append(DeviceObs(
                    mac=mac, ip=ip if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", ip) and ip != "0.0.0.0" else None,
                    hostname=(row.get("HostName") or "").strip() or None,
                    conn_type=conn, segment=segment,
                    online=row.get("Active", "1").strip().lower() not in ("0", "false")))
    if wan_best and (wan_best[0] or wan_best[1]):
        rx, tx = (wan_best[1], wan_best[0]) if swap else wan_best
        counters.append(CounterObs(key="total:wan", rx=rx, tx=tx))
    return devices, counters


class ZteCollector(Collector):
    name = "router"
    priority = 20
    timeout = 90

    def __init__(self, url: str, username: str, password_fn: Callable[[], str | None],
                 interval: float = 60, swap_directions: bool = False,
                 extra_tags: list[str] | None = None, takeover: bool = False):
        super().__init__()
        self.url, self.username, self.password_fn = url, username, password_fn
        self.interval = interval
        self.swap = swap_directions
        self.extra_tags = extra_tags or []
        self.takeover = takeover
        self.client: ZteClient | None = None
        self.plan: dict[str, list[str]] = {}       # view -> data tags that proved useful
        self._plan_at = 0.0
        self._bad_password: str | None = None

    def _connect(self) -> ZteClient:
        pw = self.password_fn()
        if not pw:
            raise CollectorError("no router password set. Run: python -m app.cli set-password")
        if pw == self._bad_password:
            # Never retry a password the router already rejected: repeated
            # failures lock the admin page.
            raise ZteAuthError("router password was rejected; update it and restart the app")
        if self.client is None or self.client.password != pw:
            self.client = ZteClient(self.url, self.username, pw, takeover=self.takeover)
        if not self.client.logged_in:
            try:
                self.client.login()
            except ZteAuthError:
                self._bad_password = pw
                raise
        return self.client

    def _discover(self, client: ZteClient) -> dict[str, list[tuple[str, dict]]]:
        """Find which status pages / data tags this firmware has. Returns fetched data too."""
        found: dict[str, list[tuple[str, dict]]] = {}
        plan: dict[str, list[str]] = {}
        for view, known in VIEWS.items():
            try:
                html = client.view(view)
            except CollectorError:
                continue
            offered = [t for t in dict.fromkeys(TAG_IN_PAGE.findall(html))
                       if INTERESTING.search(t) and not NEVER.search(t)]
            # Keep the query parameters of tags we know; try the known list if
            # the page does not reveal its tags.
            candidates = [k for k in known if not offered or k.split("&")[0] in offered]
            candidates += [t for t in offered if t not in {k.split("&")[0] for k in known}]
            if view == "localNetStatus":
                candidates += [t for t in self.extra_tags if t not in candidates]
            for tag in candidates:
                try:
                    nodes = client.data(tag)
                except SessionExpired:
                    continue                     # tag not offered by this page
                except CollectorError:
                    continue
                devs, ctrs = interpret(view, tag, nodes, self.swap)
                if devs or ctrs or "OBJ_WLANAP_ID" in nodes:
                    plan.setdefault(view, []).append(tag)
                    found.setdefault(view, []).append((tag, nodes))
        self.plan, self._plan_at = plan, time.time()
        log.info("router pages in use: %s", plan or "none")
        return found

    def _fetch_plan(self, client: ZteClient) -> dict[str, list[tuple[str, dict]]]:
        out: dict[str, list[tuple[str, dict]]] = {}
        for view, tags in self.plan.items():
            client.view(view)
            for tag in tags:
                out.setdefault(view, []).append((tag, client.data(tag)))
        return out

    def collect(self) -> Snapshot:
        client = self._connect()
        try:
            if not self.plan or time.time() - self._plan_at > REDISCOVER_SECONDS:
                fetched = self._discover(client)
            else:
                fetched = self._fetch_plan(client)
        except SessionExpired:
            client.logged_in = False             # session ran out: log in again once
            client = self._connect()
            fetched = self._discover(client)
        snap = Snapshot(source=self.name)
        seen: dict[str, DeviceObs] = {}
        counters: dict[str, CounterObs] = {}
        for view, answers in fetched.items():
            merged: dict[str, list[dict]] = {}
            for _, nodes in answers:             # SSID names may live in a sibling answer
                if "OBJ_WLANAP_ID" in nodes:
                    merged["OBJ_WLANAP_ID"] = nodes["OBJ_WLANAP_ID"]
            for tag, nodes in answers:
                devs, ctrs = interpret(view, tag, {**merged, **nodes}, self.swap)
                for d in devs:
                    old = seen.get(d.mac)
                    if old is None:
                        seen[d.mac] = d
                    else:                         # keep the richest description
                        old.ip = old.ip or d.ip
                        old.hostname = old.hostname or d.hostname
                        old.conn_type = old.conn_type or d.conn_type
                        old.segment = old.segment or d.segment
                for c in ctrs:
                    counters.setdefault(c.key, c)
        snap.devices = list(seen.values())
        snap.counters = list(counters.values())
        snap.authoritative_presence = bool(snap.devices)
        segs = [c for c in snap.counters if c.key.startswith("seg:")]
        self.capabilities = {
            "devices": len(snap.devices),
            "port_and_wifi_counters": len(segs),
            "wan_total": any(c.key == "total:wan" for c in snap.counters),
            "per_device": False,
        }
        if not snap.devices and not snap.counters:
            raise CollectorError("logged in, but this firmware returned no device list or counters. "
                                 "Run `python -m app.cli probe-router` and see README > Router probe.")
        return snap

    def close(self) -> None:
        if self.client:
            self.client.close()


# ---------------------------------------------------------------- probe
def probe_report(client: ZteClient, crawl: bool = True) -> dict:
    """Log in once and record what the firmware offers (secrets removed)."""
    report: dict = {"router": client.base, "login_ok": False, "pages": {}, "summary": ""}
    try:
        client.login()
    except CollectorError as e:
        report["summary"] = f"Login failed: {e}"
        return report
    report["login_ok"] = True
    views = dict(VIEWS)
    if crawl:
        try:
            home = client._request("GET", "").text
            for v in dict.fromkeys(re.findall(r"\b([a-z][A-Za-z0-9]{3,30}(?:Status|Info))\b", home)):
                if v not in views and not NEVER.search(v) and len(views) < 40:
                    views[v] = []
        except CollectorError:
            pass
    n_dev = n_seg = 0
    wan = per_device = False
    lines = []
    try:
        for view, known in views.items():
            try:
                html = client.view(view)
            except CollectorError:
                continue
            tags = [t for t in dict.fromkeys(TAG_IN_PAGE.findall(html)) if not NEVER.search(t)]
            tried = list(dict.fromkeys(known + [t for t in tags if t not in {k.split('&')[0] for k in known}]))
            page: dict = {}
            for tag in tried:
                try:
                    nodes = client.data(tag)
                except SessionExpired:
                    page[tag] = "not offered by this page"
                    continue
                except CollectorError as e:
                    page[tag] = f"error: {e}"
                    continue
                page[tag] = {
                    node: {"instances": len(rows), "fields": sorted({k for r in rows for k in r}),
                           "sample": {k: ("<removed>" if SECRET_FIELD.search(k) else v)
                                      for k, v in (rows[0] if rows else {}).items()}}
                    for node, rows in nodes.items()}
                devs, ctrs = interpret(view, tag, nodes)
                n_dev = max(n_dev, len(devs))
                n_seg += sum(1 for c in ctrs if c.key.startswith("seg:"))
                wan = wan or any(c.key == "total:wan" for c in ctrs)
                per_device = per_device or any(
                    normalize_mac(r.get("MACAddress")) and "IPAddress" in r
                    and _num(r, SENT_FIELDS) is not None for rows in nodes.values() for r in rows)
                if devs or ctrs:
                    lines.append(f"  {view} / {tag.split('&')[0]}: {len(devs)} devices, {len(ctrs)} counters")
            if page:
                report["pages"][view] = page
    finally:
        client.close()
    report["summary"] = "\n".join([
        "Login: OK",
        f"Device list:                 {'YES (' + str(n_dev) + ' devices)' if n_dev else 'not found'}",
        f"Per-port / per-Wi-Fi bytes:  {'YES (' + str(n_seg) + ' counters)' if n_seg else 'not found'}",
        f"Whole-house (WAN) bytes:     {'YES' if wan else 'not found (the app will use UPnP or the port/Wi-Fi sum)'}",
        f"Per-device bytes:            {'YES - tell the developer, this is unusual!' if per_device else 'no (expected on ZTE)'}",
        "Useful pages:", *(lines or ["  none"]),
    ])
    return report
