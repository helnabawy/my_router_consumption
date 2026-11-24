# WE Monitor

A local dashboard for a WE (Telecom Egypt) home connection: every device on your
network, how much data is used and when, a 250 GB quota tracker, alerts, and
CSV/PDF exports. Runs on your Mac at <http://localhost:8000>. Nothing leaves your
network.

**Read section 2 before anything else.** With a ZTE router and no extra hardware,
the app cannot give a true GB figure for every device out of the box, and it says
so on screen instead of guessing. Section 5 shows how to get real per-device
numbers anyway.

---

## 1. Why 250 GB can vanish in 14 days

250 GB in 14 days is about **18 GB per day**. That is not much:

| Activity | Typical data use |
|---|---|
| Netflix / Shahid / YouTube in HD (1080p) | about 3 GB per hour |
| The same in 4K | about 7 GB per hour or more |
| One console or PC game download or update | 20 to 150 GB each |
| Windows / macOS / phone system updates | 1 to 15 GB each, per device |
| iCloud Photos, Google Photos, OneDrive first sync | tens of GB, mostly **upload** |
| Video calls | 1 to 2.5 GB per hour |
| A neighbour on your Wi-Fi | unlimited |

Six hours of HD streaming a day across the whole family, or one 4K TV for two and
a half hours, reaches 18 GB. As far as I know WE counts upload as well as download,
so cloud photo backups count too.

### Checks you can do today, before installing anything

1. **Look for strangers.** Open the router page (usually `http://192.168.1.1`), find
   the connected-devices list and count. If there are more devices than you own,
   change the Wi-Fi password and switch off WPS.
2. **Change the router's admin password too.** On some WE ZTE units the default admin
   password is reported to be derived from the default Wi-Fi password, so anyone who
   knew the old Wi-Fi password may be able to open the admin page.
3. **Stop automatic game downloads.** PS5: Settings > Saved Data and Game/App Settings >
   Automatic Updates. Steam / Xbox / Epic have the same switch. This is the most common
   single cause of overnight usage.
4. **Cap streaming quality** on the TV and on shared accounts (Netflix: Account >
   Playback settings; YouTube: quality 720p). A TV left on "Auto" picks 4K if it can.
5. **Windows PCs:** Settings > Windows Update > Advanced > Delivery Optimization > turn off
   "Allow downloads from other PCs" (it uploads updates to strangers). Marking the Wi-Fi
   as a metered connection also holds back large updates.
6. **Cloud backups:** check iCloud Photos, Google Photos, OneDrive and WhatsApp backup on
   each phone and laptop.
7. **Read the per-device counters you already have.** Android: Settings > Network >
   Data usage > Wi-Fi data usage. Windows: Settings > Network & internet > Data usage.
   Mac: Activity Monitor > Network (since last restart). iPhones do not show Wi-Fi usage.
8. **Overnight elimination test.** Note the "used" figure in the My WE app, switch the
   router's Wi-Fi off overnight (or unplug the TV and console), and compare in the
   morning. WE's figure can lag by a few hours, so compare over a full night, not minutes.

---

## 2. Which data-collection method works on a WE ZTE router

Ranked from most to least reliable for **per-device GB**:

| # | Method | Per-device GB? | Whole-house total? | Cost | Verdict for your setup |
|---|---|---|---|---|---|
| 1 | OpenWrt router behind the WE router, running `nlbwmon` | Yes, exact | Yes | One cheap router | The proper fix. Not used now because you chose no new hardware. |
| 2 | This Mac as the gateway (macOS Internet Sharing) | Yes, exact, for devices that join the Mac's Wi-Fi | Yes | Free | Works without buying anything, with real drawbacks (section 5b). Experimental. |
| 3 | Reading the ZTE router's own pages | **No.** Per LAN port and per Wi-Fi network only | Sometimes | Free | Used by default. Gives the device list and port/Wi-Fi counters. |
| 4 | UPnP total counters | No | Yes, if UPnP is on | Free | Used by default for the quota total. |
| 5 | SNMP / TR-064 | No | No | Free | Not available to customers on WE ZTE firmware. Not used. |
| 6 | ARP scan from the Mac | No (devices only) | No | Free | Used by default for discovery and new-device alerts. |

What each one can and cannot do:

- **ZTE router pages (a).** I checked the open-source clients for ZTE's current web
  interface (H288A, H2640, F670L V9, F680, F6640 and relatives). None of them finds a
  byte counter per connected device; the firmware simply does not keep one. It does
  expose the device list (MAC, IP, hostname, which port or Wi-Fi network), byte counters
  per LAN port, byte counters per Wi-Fi network name, and on some firmware a WAN counter.
  No public code documents a WE-branded H188A or H168N specifically, so the first run on
  your router is the real test: `python -m app.cli probe-router` tells you in one screen.
  Older ZTE firmware (admin pages named `getpage.gch` or `getpage.lua`, for example
  H108N) uses a different protocol that this app does not read; discovery and the
  quota tracker still work through methods 4 and 6.
- **UPnP (b).** Total only, 32-bit counters that wrap every 4 GB (handled), reset when
  the router restarts, and one ZTE model is known to report a stuck value. If it does
  not work the dashboard says so.
- **OpenWrt (c).** The cheapest practical hardware fix: a new or used router that
  OpenWrt supports (for example Xiaomi Mi Router 4A Gigabit, TP-Link Archer C6 or C7),
  connected by cable to a LAN port of the WE router, with your devices on its Wi-Fi
  and the WE router's Wi-Fi switched off. Check the exact hardware revision in the
  OpenWrt "Table of Hardware" before paying. The collector design here makes adding it
  one small file later.
- **Always-on Pi with ntopng (d).** Only sees other devices' traffic if it is the
  gateway or sits on a mirror port, which ZTE home routers do not have. So it is the
  same idea as method 2 on different hardware.
- **Not used, on purpose:** ARP spoofing. It is the only software way to see other
  devices' traffic without being their gateway, and it can slow down or break the network.

**What you get with no changes at all:** device list with names, vendors, online
status and new-device alerts; exact usage of this Mac; whole-house total and quota
tracking (from the router or UPnP, or from readings you type in); port and Wi-Fi
network totals; the time-of-day heatmap; exports. **What you do not get yet:** GB for
each phone and TV. Section 5 fixes that.

---

## 3. Architecture

```
collectors (each reads ONE source)          poller                    storage / UI
  router   ZTE admin pages: devices,   -->  merges snapshots,    -->  SQLite, hourly totals
           port + Wi-Fi counters            turns cumulative          data/we-monitor.sqlite
  arp_scan devices on any router            counters into deltas,
  local    this Mac's exact usage           picks the best source     FastAPI  /api/...
  upnp     whole-house total                per device, raises        dashboard at /
  sniff    gateway mode (optional)          alerts                    (plain HTML/JS + Chart.js)
```

| File | Purpose |
|---|---|
| `app/main.py` | FastAPI app and all API routes |
| `app/poller.py` | Background loop that merges collector data and stores usage |
| `app/accounting.py` | Counter maths: resets, 32-bit wrap, glitches, hourly split |
| `app/collectors/zte.py` | ZTE login and page reading (read-only) |
| `app/collectors/arp_scan.py`, `local.py`, `upnp.py`, `sniff.py`, `demo.py` | The other sources |
| `app/alerts.py` | Alert rules, macOS and Telegram notifications |
| `app/stats.py`, `app/quota.py` | Queries and billing-cycle maths |
| `app/reports.py` | CSV and PDF export |
| `app/static/` | The dashboard |
| `tests/` | 29 automated tests, including a simulated ZTE router |

Stack choice: FastAPI plus plain HTML/JS is right here. There is no build step, and
Chart.js is bundled so the dashboard works when the internet is down.

Safety choices: the router password lives in the macOS Keychain (or `.env`), never in
`config.yaml`, the database or the logs. The app refuses to start if it finds
`router.password` in the config. The dashboard listens on `127.0.0.1` only. The router
collector only sends login and read requests, never retries a rejected password (repeated
wrong tries can lock a router's admin page), and will not kick you out of the admin page.

---

## 4. Setup (macOS)

You need Python 3.10 or newer. Check with `python3 --version`; if it is older:

```bash
brew install python@3.12
```

**Step 1. Try it with simulated data** (nothing touches your network):

```bash
cd we-monitor
./run.sh --demo
```

Open <http://localhost:8000>. Stop with Ctrl+C.

**Step 2. Configure.** `./run.sh` created `config.yaml`. Edit it:

- `quota.cycle_start_day`: the day your quota renews (shown in the My WE app).
- `router.url`: your router's address. If `http://` does not answer, try `https://`.

**Step 3. Store the router admin password in the Keychain:**

```bash
.venv/bin/python -m app.cli set-password
```

**Step 4. See what your router really offers:**

```bash
.venv/bin/python -m app.cli probe-router
```

It prints yes/no for device list, port and Wi-Fi counters, and WAN total, and saves
the details to `data/router-probe.json` (passwords and Wi-Fi keys removed). Then test
every source at once:

```bash
.venv/bin/python -m app.cli check
```

**Step 5. Run it:**

```bash
./run.sh
```

On the dashboard: mark the devices you recognise as trusted, name them (Edit), set the
quota and cycle day under Settings, and press **Add WE reading** to enter the figure
from the My WE app. That calibrates the quota card straight away.

**Step 6. Start automatically at login:**

```bash
./scripts/install_autostart.sh
```

Remove it with `./scripts/install_autostart.sh --remove`. The log is
`data/we-monitor.log`. The Mac must be awake to record: on a desktop Mac, enable
"Prevent automatic sleeping" in System Settings > Energy. Time while the Mac sleeps is
not lost for totals (the router keeps counting and the difference is picked up on wake)
but it is spread evenly across the gap, so the heatmap is blurry for those hours.

**Using the router's admin page yourself:** ZTE allows one admin login at a time.
Press Settings > "Pause router polling 15 min" first.

**Optional phone alerts:** create a Telegram bot, then put `TELEGRAM_BOT_TOKEN` and
`TELEGRAM_CHAT_ID` in `.env` (see `.env.example`).

---

## 5. Getting per-device numbers without buying hardware

### 5a. One device per port or per Wi-Fi network (recommended first)

The router counts bytes per LAN port and per Wi-Fi network name. A port or network
with exactly one device on it is a per-device counter, and the app credits that
device automatically.

1. Plug the TV, console or desktop PC into its own LAN port by cable.
2. In the router's Wi-Fi settings create extra network names (ZTE allows up to four per
   band), for example `Home-TV` and `Home-Kids`, each with its own password.
3. Move one suspect device to each. Leave everything else on the main network.

After that the TV, the console and the suspects are measured exactly; the main network
shows as one shared total. Attribution stops by itself if a second device joins that
network, so the numbers never get silently polluted. This depends on your firmware
exposing the counters: `probe-router` must say "Per-port / per-Wi-Fi bytes: YES".

### 5b. Gateway mode: this Mac shares the internet (experimental)

1. Connect the Mac to the WE router **by cable** (a USB-C Ethernet adapter if needed).
2. System Settings > General > Sharing > Internet Sharing: share from Ethernet to
   computers using Wi-Fi, and set a network name and password.
3. Connect your devices to the Mac's Wi-Fi. Switch off, or change the password of, the
   WE router's Wi-Fi so nothing bypasses the Mac.
4. Allow the app to count packets. Run `sudo visudo -f /etc/sudoers.d/we-monitor` and add
   this single line, replacing `yourname`:

   ```
   yourname ALL=(root) NOPASSWD: /usr/sbin/tcpdump -i bridge100 -e -n -q -l -tt -s 96 ip or ip6
   ```
5. In `config.yaml` set `collectors.sniff.enabled: true` and restart.

Every device is then measured exactly. The costs: the Mac must stay on and awake, a
Mac's Wi-Fi is weaker than a router's, and if the Mac sleeps the house has no internet.
I could not exercise this mode on a real Mac from where I built it; the packet-line
parser is tested, the end-to-end path is not. Run the checklist in section 6 on it.

---

## 6. Testing checklist

Automated tests (counter maths, parsers, simulated router, API, exports):

```bash
.venv/bin/python -m pip install pytest && .venv/bin/python -m pytest -q
```

Then on your real network:

- [ ] `probe-router` logs in and reports what exists. Paste its summary back to me if
      "Device list" says not found; the page names can be added in `config.yaml`
      (`router.extra_tags`).
- [ ] Every device you own appears. Phones with "Private Wi-Fi address" show as
      "Private (randomized) address"; name them once.
- [ ] Turn one phone's Wi-Fi off: it goes offline within about 3 minutes (router
      working) or up to 20 minutes (network scan only).
- [ ] Join with a device the app has never seen: a "New device" alert and a macOS
      notification appear within about a minute.
- [ ] **Known-size download.** On this Mac download a file of known size (for example a
      1 GB test file). The Mac's "Today" figure should rise by that amount within 3%.
- [ ] **Direction check.** During that download the house total must show mostly
      download. If it shows mostly upload, set `router.swap_directions: true`.
- [ ] **Port check (5a).** Do the same download on a device alone on its port or
      network; that device's figure should match within 5%.
- [ ] **Against WE.** Add a WE reading, wait 24 hours, add another. The "Difference"
      column should be within about 5%. Use full-day gaps because WE's figure updates
      late. A steady difference of a few percent is protocol overhead and timing.
- [ ] **If "measured here" is much lower than WE** with all your devices accounted for,
      that is the evidence for a complaint: export the PDF for that period.
- [ ] **If it is much higher,** the port/Wi-Fi sum is counting traffic between your own
      devices (for example a NAS). The Live card names the source in use.
- [ ] Restart the router: totals keep growing with no huge jump.
- [ ] Restart the Mac: the dashboard returns by itself and history is intact.

---

## 7. Known limits

- 1 GB is counted as 1024 MB.
- Totals from "sum of router ports and Wi-Fi networks" include traffic between your own
  devices. Totals from the WAN or UPnP counter do not.
- The "Who was online when data was used" table is circumstantial, not a measurement.
- PDF export uses a system Unicode font so Arabic device names print; if none is found
  they are replaced with `?` in the PDF only (CSV is always correct).
- Backup: copy `data/we-monitor.sqlite`.
