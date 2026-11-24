/* WE Monitor dashboard. Plain JavaScript + Chart.js, no build step.
 *
 * Security note: device hostnames come from the network (anyone joining the
 * Wi-Fi chooses their own), so every piece of dynamic text is inserted with
 * textContent, never innerHTML.
 */
"use strict";

const GB = 1024 ** 3, MB = 1024 ** 2;
const state = { range: "cycle", kind: "device", key: "", status: null, devices: [], settings: null };
const charts = {};
const $ = (id) => document.getElementById(id);

// ---------------------------------------------------------------- helpers
function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") node.className = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children) if (c !== null && c !== undefined) node.append(c);
  return node;
}
async function api(path, options = {}) {
  const opts = { ...options, headers: { ...(options.headers || {}) } };
  if (opts.body !== undefined) {
    opts.body = JSON.stringify(opts.body);
    opts.headers["Content-Type"] = "application/json";
  }
  if (opts.method && opts.method !== "GET") opts.headers["X-Requested-With"] = "we-monitor";
  const r = await fetch(path, opts);
  if (!r.ok) throw new Error(`${path}: ${r.status}`);
  return r.json();
}
function fmtBytes(n) {
  if (n === null || n === undefined) return "–";
  if (n >= 100 * GB) return (n / GB).toFixed(0) + " GB";
  if (n >= 10 * GB) return (n / GB).toFixed(1) + " GB";
  if (n >= GB) return (n / GB).toFixed(2) + " GB";
  if (n >= MB) return (n / MB).toFixed(0) + " MB";
  return n > 0 ? "<1 MB" : "0";
}
function fmtRate(bps) {
  if (bps === null || bps === undefined) return "–";
  if (bps >= 1e6) return (bps / 1e6).toFixed(1) + " Mbit/s";
  if (bps >= 1e3) return (bps / 1e3).toFixed(0) + " kbit/s";
  return "idle";
}
const fmtDate = (ts, opts) => new Date(ts * 1000).toLocaleString("en-GB", opts || { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" });
const css = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
function unitFor(maxBytes) { return maxBytes >= GB ? { div: GB, label: "GB" } : { div: MB, label: "MB" }; }

// Colour follows the device, not its rank: each device keeps its slot between
// refreshes and filter changes (remembered in this browser).
const SLOTS = 7;
let slotMap = {};
try { slotMap = JSON.parse(localStorage.getItem("we-slots") || "{}"); } catch (e) { slotMap = {}; }
function slotFor(key, visibleKeys) {
  if (slotMap[key]) return slotMap[key];
  const used = new Set(visibleKeys.map((k) => slotMap[k]).filter(Boolean));
  let slot = 0;
  for (let i = 1; i <= SLOTS; i++) if (!used.has(i)) { slot = i; break; }
  if (!slot) return 0;
  for (const k of Object.keys(slotMap)) if (slotMap[k] === slot) delete slotMap[k];
  slotMap[key] = slot;
  try { localStorage.setItem("we-slots", JSON.stringify(slotMap)); } catch (e) { /* private mode */ }
  return slot;
}
const colorFor = (key, visible) => {
  if (key === "other") return css("--other");
  if (key === "down") return css("--series-1");
  if (key === "up") return css("--series-2");
  const s = slotFor(key, visible);
  return s ? css(`--series-${s}`) : css("--other");
};

// ---------------------------------------------------------------- charts
function baseOptions(yTitle) {
  const ink = css("--text-secondary"), grid = css("--grid");
  return {
    responsive: true, maintainAspectRatio: false, animation: false,
    interaction: { mode: "index", intersect: false },
    plugins: {
      legend: { position: "top", align: "start",
        labels: { color: ink, boxWidth: 10, boxHeight: 10, usePointStyle: false, font: { size: 12 } } },
      tooltip: { backgroundColor: css("--surface-1"), titleColor: css("--text-primary"), bodyColor: css("--text-primary"),
        borderColor: css("--axis"), borderWidth: 1, padding: 8, boxWidth: 10, boxHeight: 2, boxPadding: 4 },
    },
    scales: {
      x: { grid: { display: false }, border: { color: css("--axis") }, ticks: { color: css("--text-muted"), maxRotation: 0, autoSkipPadding: 12, font: { size: 11 } } },
      y: { beginAtZero: true, grid: { color: grid }, border: { display: false },
        ticks: { color: css("--text-muted"), font: { size: 11 }, maxTicksLimit: 6 },
        title: { display: !!yTitle, text: yTitle, color: css("--text-muted"), font: { size: 11 } } },
    },
  };
}
function draw(id, config) {
  if (charts[id]) charts[id].destroy();
  charts[id] = new Chart($(id), config);
}
function showEmpty(canvasId, emptyId, message) {
  $(canvasId).parentElement.hidden = !!message;
  $(emptyId).hidden = !message;
  $(emptyId).textContent = message || "";
}
// Writes the total at the end of each horizontal bar (values stay in ink colour).
const barTotals = {
  id: "barTotals",
  afterDatasetsDraw(chart, _args, opts) {
    const { ctx } = chart;
    const meta = chart.getDatasetMeta(chart.data.datasets.length - 1);
    ctx.save();
    ctx.fillStyle = css("--text-secondary");
    ctx.font = "12px system-ui, -apple-system, sans-serif";
    ctx.textBaseline = "middle";
    meta.data.forEach((bar, i) => ctx.fillText(opts.labels[i], bar.x + 6, bar.y));
    ctx.restore();
  },
};

function renderLive(live) {
  const pts = live.total;
  const last = pts[pts.length - 1];
  const fresh = last && live.now - last[0] < Math.max(120, live.tick * 6);
  $("live-down").textContent = fresh ? fmtRate(last[1]) : "–";
  $("live-up").textContent = fresh ? fmtRate(last[2]) : "–";
  const src = { "wan:router": "router WAN counter", "wan:upnp": "router UPnP counter", "wan:demo": "simulated",
    "sum:sniff": "traffic through this Mac", "sum:segments": "sum of router ports and Wi-Fi networks" }[live.total_source];
  $("live-note").textContent = src ? `Source: ${src}.` : "No whole-house counter available yet (see the notice at the top).";
  if (!pts.length) return showEmpty("chart-live", "live-empty-shim", null);
  const opts = baseOptions("Mbit/s");
  opts.scales.x.ticks.maxTicksLimit = 6;
  opts.plugins.tooltip.callbacks = { label: (c) => ` ${c.dataset.label}: ${fmtRate(c.parsed.y * 1e6)}` };
  draw("chart-live", { type: "line", options: opts, data: {
    labels: pts.map((p) => new Date(p[0] * 1000).toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" })),
    datasets: [
      { label: "Download", data: pts.map((p) => p[1] / 1e6), borderColor: css("--series-1"), backgroundColor: css("--series-1"), borderWidth: 2, pointRadius: 0, pointHoverRadius: 4, tension: 0.25 },
      { label: "Upload", data: pts.map((p) => p[2] / 1e6), borderColor: css("--series-2"), backgroundColor: css("--series-2"), borderWidth: 2, pointRadius: 0, pointHoverRadius: 4, tension: 0.25 },
    ] } });
}

function renderTop(top) {
  const items = top.items.slice(0, 10);
  let sub = top.range;
  if (top.total !== null) sub += ` · house total ${fmtBytes(top.total)}`;
  if (top.unattributed !== null && top.total > 0 && top.unattributed / top.total >= 0.005)
    sub += ` · ${Math.round((top.unattributed / top.total) * 100)}% not attributed`;
  $("top-sub").textContent = sub;
  if (!items.length) {
    return showEmpty("chart-top", "top-empty", state.kind === "segment"
      ? "The router has not reported port or Wi-Fi counters in this period."
      : "No device has measured usage in this period yet. See the notice at the top for what can be measured on your network.");
  }
  showEmpty("chart-top", "top-empty", null);
  const max = Math.max(...items.map((i) => i.rx + i.tx));
  const u = unitFor(max);
  const opts = baseOptions();
  opts.indexAxis = "y";
  opts.layout = { padding: { right: 64 } };
  opts.scales.x = { stacked: true, beginAtZero: true, grid: { color: css("--grid") }, border: { display: false },
    ticks: { color: css("--text-muted"), font: { size: 11 }, callback: (v) => `${v} ${u.label}` } };
  opts.scales.y = { stacked: true, grid: { display: false }, border: { color: css("--axis") },
    ticks: { color: css("--text-secondary"), font: { size: 12 }, callback(v) { const s = this.getLabelForValue(v); return s.length > 22 ? s.slice(0, 21) + "…" : s; } } };
  opts.plugins.tooltip.callbacks = { label: (c) => ` ${c.dataset.label}: ${fmtBytes(c.parsed.x * u.div)}` };
  opts.plugins.barTotals = { labels: items.map((i) => fmtBytes(i.rx + i.tx)) };
  const surface = css("--surface-1");
  draw("chart-top", { type: "bar", options: opts, plugins: [barTotals], data: {
    labels: items.map((i) => i.name),
    datasets: [
      { label: "Download", data: items.map((i) => i.rx / u.div), backgroundColor: css("--series-1"), maxBarThickness: 20, borderColor: surface, borderWidth: { right: 2 } },
      { label: "Upload", data: items.map((i) => i.tx / u.div), backgroundColor: css("--series-2"), maxBarThickness: 20, borderRadius: { topRight: 4, bottomRight: 4 }, borderSkipped: false },
    ] } });
}

function stackedColumns(id, h, emptyId, emptyText) {
  const sums = h.labels.map((_, i) => h.series.reduce((a, s) => a + s.values[i], 0));
  const max = Math.max(0, ...sums);
  if (!max) return showEmpty(id, emptyId, emptyText);
  showEmpty(id, emptyId, null);
  const u = unitFor(max);
  const opts = baseOptions(u.label);
  opts.scales.x.stacked = true;
  opts.scales.y.stacked = true;
  opts.plugins.legend.display = h.series.length > 1;
  opts.plugins.tooltip.callbacks = {
    label: (c) => ` ${c.dataset.label}: ${fmtBytes(c.parsed.y * u.div)}`,
    footer: (items) => `Total: ${fmtBytes(items.reduce((a, c) => a + c.parsed.y, 0) * u.div)}`,
  };
  opts.plugins.tooltip.footerColor = css("--text-secondary");
  opts.plugins.tooltip.filter = (c) => c.parsed.y > 0;
  const keys = h.series.map((s) => s.key);
  const surface = css("--surface-1");
  draw(id, { type: "bar", options: opts, data: {
    labels: h.labels,
    datasets: h.series.map((s) => ({ label: s.name, data: s.values.map((v) => v / u.div),
      backgroundColor: colorFor(s.key, keys), maxBarThickness: 24, borderColor: surface, borderWidth: { top: 2 } })),
  } });
}

function renderHeatmap(hm) {
  const box = $("heatmap");
  box.replaceChildren(el("div"));
  for (let h = 0; h < 24; h++) box.append(el("div", { class: "hlabel" }, h % 3 === 0 ? String(h).padStart(2, "0") : ""));
  const tip = $("tooltip");
  hm.matrix.forEach((row, d) => {
    box.append(el("div", { class: "dlabel" }, hm.labels[d]));
    row.forEach((v, h) => {
      const level = v > 0 && hm.max > 0 ? Math.max(1, Math.ceil(5 * Math.sqrt(v / hm.max))) : 0;
      const cell = el("div", { class: "cell", style: `background: var(--heat-${level})` });
      cell.addEventListener("pointermove", (e) => {
        tip.replaceChildren(el("b", {}, fmtBytes(v)), `${hm.labels[d]}, ${String(h).padStart(2, "0")}:00–${String((h + 1) % 24).padStart(2, "0")}:00`);
        tip.hidden = false;
        tip.style.left = Math.min(e.clientX + 12, window.innerWidth - 190) + "px";
        tip.style.top = e.clientY + 14 + "px";
      });
      cell.addEventListener("pointerleave", () => { tip.hidden = true; });
      box.append(cell);
    });
  });
}

// ---------------------------------------------------------------- panels
function renderStatus(st) {
  state.status = st;
  const names = { router: "Router", arp_scan: "Network scan", local: "This Mac", upnp: "UPnP total", sniff: "Gateway mode", demo: "Demo data" };
  const pills = Object.entries(st.collectors).map(([name, c]) => {
    const paused = c.paused_until > st.now;
    const cls = paused ? "warn" : c.ok === true ? "ok" : c.ok === false ? "bad" : "";
    const word = paused ? "paused" : c.ok === true ? "working" : c.ok === false ? "not working" : "starting";
    return el("span", { class: "pill", title: c.error || c.note || JSON.stringify(c.capabilities) },
      el("span", { class: `dot ${cls}` }), `${names[name] || name}: ${word}`);
  });
  pills.push(el("span", { class: "pill" }, `${st.online} of ${st.devices} devices online`));
  $("pills").replaceChildren(...pills);

  const notes = [];
  if (st.demo) notes.push([el("b", {}, "Demo mode. "), "Devices and numbers are simulated. Run ./run.sh without --demo for your real network."]);
  else {
    const failing = Object.entries(st.collectors).filter(([, c]) => c.ok === false);
    for (const [name, c] of failing) notes.push([el("b", {}, `${names[name] || name}: `), c.error || "not working"]);
    if (st.devices && st.measured_devices < st.devices)
      notes.push([el("b", {}, `Usage is measured for ${st.measured_devices} of ${st.devices} devices. `),
        "ZTE routers count bytes per LAN port and per Wi-Fi network, not per device. To measure a device, give it its own LAN port or its own Wi-Fi network name (README: “Getting per-device numbers”)."]);
    if (!st.total_source) notes.push([el("b", {}, "No whole-house counter yet. "), "The quota card relies on the figures you enter with “Add WE reading”."]);
  }
  $("notice").hidden = !notes.length;
  $("notice").replaceChildren(...notes.map((n) => el("div", {}, ...n)));
  $("sel-kind").parentElement.hidden = !st.has_segments;
}

function renderQuota(q) {
  $("q-used").textContent = q.has_data ? q.used_gb.toFixed(1) : "–";
  $("q-of").textContent = `GB of ${q.quota_gb} GB used` + (q.has_data ? ` (${Math.round(q.percent)}%)` : "");
  $("q-fill").style.width = Math.min(q.percent, 100) + "%";
  const meter = $("q-meter");
  meter.className = "meter" + (q.percent >= 90 ? " crit" : q.percent >= 75 ? " warn" : "");
  meter.setAttribute("aria-label", `${Math.round(q.percent)}% of quota used`);
  const basis = {
    we_reading_plus_measured: "Based on your last WE reading plus what was measured since.",
    we_reading_only: "Based on your last WE reading only (no whole-house counter).",
    measured_total: "Measured from the whole-house counter.",
    measured_devices_only: "Only individually measured devices are counted: this is a lower bound.",
    none: "No data yet. Add a WE reading to start tracking.",
  }[q.basis];
  const cycle = `Billing cycle: ${q.cycle_label}.`;
  $("q-basis").textContent = `${basis} ${cycle}` + (q.partial && q.basis !== "none" ? " Monitoring started mid-cycle: add a WE reading to calibrate the total." : "");
  $("q-days").textContent = q.days_left.toFixed(0);
  $("q-avg").textContent = q.has_data ? q.daily_avg_gb.toFixed(1) + " GB" : "–";
  $("q-safe").textContent = q.has_data ? q.safe_daily_gb.toFixed(1) + " GB" : "–";
  $("q-runout").textContent = q.percent >= 100 ? "Used up" : q.runout_label ? q.runout_label
    : q.has_data && !q.partial ? "Lasts the cycle" : "–";
}

function usageCell(d, rx, tx) {
  if (rx === null && tx === null) return el("td", { class: "num muted", title: "The router has no byte counter for this device" }, "not measured");
  return el("td", { class: "num", title: `Download ${fmtBytes(rx)} · upload ${fmtBytes(tx)}` + (d.usage_source ? ` · source: ${d.usage_source}` : "") }, fmtBytes((rx || 0) + (tx || 0)));
}
function renderDevices(data) {
  state.devices = data.devices;
  $("th-range").textContent = data.range;
  const onlyOnline = $("only-online").checked;
  const rows = [];
  let shown = 0;
  for (const d of data.devices) {
    if (d.kind !== state.kind) continue;
    if (onlyOnline && !d.online) continue;
    shown++;
    const tags = [];
    if (d.is_self) tags.push(el("span", { class: "tag" }, "this computer"));
    if (d.is_gateway) tags.push(el("span", { class: "tag" }, "router"));
    if (d.kind === "device" && !d.known) tags.push(el("span", { class: "tag new", title: "You have not marked this device as trusted" }, "⚠ not recognised"));
    const conn = d.kind === "segment" ? "router counter" : (d.segment && d.segment.startsWith("Wi-Fi") ? d.segment
      : [d.conn_type === "wifi" ? "Wi-Fi" : d.conn_type === "lan" ? "Cable" : "", d.segment || ""].filter(Boolean).join(" · ")) || "–";
    rows.push(el("tr", { class: d.online ? "" : "offline" },
      el("td", {}, el("div", { class: "dname" },
        el("span", { class: `dot ${d.online ? "ok" : ""}`, title: d.online ? "online" : "offline" }),
        el("span", {}, d.name, d.custom_name && d.hostname ? el("small", {}, ` (${d.hostname})`) : null), ...tags)),
      el("td", { class: "mono" }, d.ip || "–"),
      el("td", { class: "mono" }, d.kind === "device" ? d.key : "–"),
      el("td", {}, d.vendor || "–"),
      el("td", {}, conn),
      el("td", { class: "num" }, d.down_bps === null ? "–" : `↓ ${fmtRate(d.down_bps)}  ↑ ${fmtRate(d.up_bps)}`),
      usageCell(d, d.today_rx, d.today_tx),
      usageCell(d, d.rx, d.tx),
      el("td", {}, d.kind === "device" ? el("input", { type: "checkbox", checked: !!d.known, "aria-label": `Trust ${d.name}`,
        onchange: (e) => saveDevice(d.key, { known: e.target.checked }) }) : null),
      el("td", {}, el("button", { class: "btn ghost", onclick: () => openDevice(d) }, "Edit"))));
  }
  $("dev-table").tBodies[0].replaceChildren(...rows);
  $("dev-count").textContent = `(${shown})`;

  // Focus selector: only things that have usage data.
  const sel = $("sel-key");
  const options = [el("option", { value: "" }, "All (whole house)")];
  for (const d of data.devices) if (d.measured) options.push(el("option", { value: d.key }, d.name));
  sel.replaceChildren(...options);
  sel.value = [...sel.options].some((o) => o.value === state.key) ? state.key : "";
  state.key = sel.value;
}

function renderAlerts(list) {
  const icon = { info: "ℹ", warning: "▲", serious: "▲", critical: "⛔" };
  $("alerts").replaceChildren(...(list.length ? list.map((a) => el("li", { class: a.acked ? "acked" : "" },
    el("span", { class: `icon ${a.severity}`, title: a.severity }, icon[a.severity] || "•"),
    el("div", {}, a.message, el("time", {}, `${fmtDate(a.ts)} · ${a.severity}`)),
    a.acked ? null : el("button", { class: "btn ghost", onclick: async () => { await api(`/api/alerts/${a.id}/ack`, { method: "POST" }); refreshSlow(); } }, "Mark read")))
    : [el("li", {}, el("span"), el("div", { class: "muted" }, "No alerts yet."))]));
}

function renderReadings(list) {
  const rows = list.map((r) => el("tr", {},
    el("td", {}, fmtDate(r.ts), r.note ? el("small", { class: "muted" }, ` ${r.note}`) : null),
    el("td", { class: "num" }, r.used_gb.toFixed(2) + " GB"),
    el("td", { class: "num" }, r.we_delta_gb === null ? "–" : r.we_delta_gb.toFixed(2) + " GB"),
    el("td", { class: "num" }, r.app_delta_gb === null ? "–" : r.app_delta_gb.toFixed(2) + " GB"),
    el("td", { class: "num" }, r.diff_pct === null ? "–" : (r.diff_pct > 0 ? "+" : "") + r.diff_pct.toFixed(1) + "%"),
    el("td", {}, el("button", { class: "btn ghost", "aria-label": "Delete reading", onclick: async () => { await api(`/api/readings/${r.id}`, { method: "DELETE" }); refreshSlow(); } }, "✕"))));
  $("readings").tBodies[0].replaceChildren(...(rows.length ? rows : [el("tr", {}, el("td", { colspan: 6, class: "muted" }, "No readings yet. Add two readings a day apart to check accuracy."))]));
}

function renderSuspects(data) {
  const st = state.status;
  const show = data.items.length > 0 && st && st.measured_devices < st.devices;
  $("suspects-card").hidden = !show;
  if (!show) return;
  $("suspects").tBodies[0].replaceChildren(...data.items.slice(0, 15).map((s) => el("tr", {},
    el("td", {}, s.name),
    el("td", { class: "num" }, `${s.online_hours.toFixed(0)} h (${Math.round(s.time_share * 100)}%)`),
    el("td", { class: "num" }, fmtBytes(s.usage_while_online)),
    el("td", { class: "num" }, Math.round(s.usage_share * 100) + "%"),
    el("td", { class: "num" }, s.lift.toFixed(2)))));
}

// ---------------------------------------------------------------- dialogs
let editing = null;
function openDevice(d) {
  editing = d;
  $("dd-info").textContent = `${d.kind === "device" ? d.key : "Router counter"} · ${d.vendor || "unknown vendor"} · first seen ${d.first_seen ? fmtDate(d.first_seen) : "–"}`;
  $("dd-name").value = d.custom_name || "";
  $("dd-limit").value = d.daily_limit_mb ? (d.daily_limit_mb / 1024).toFixed(1) : "";
  $("dd-known").checked = !!d.known;
  $("dlg-device").showModal();
}
async function saveDevice(key, changes) {
  await api(`/api/devices/${encodeURIComponent(key)}`, { method: "PATCH", body: changes });
  refreshSlow();
}
$("dlg-device").addEventListener("close", (e) => {
  if (e.target.returnValue !== "save" || !editing) return;
  const gb = parseFloat($("dd-limit").value);
  saveDevice(editing.key, { custom_name: $("dd-name").value, known: $("dd-known").checked,
    daily_limit_mb: gb > 0 ? Math.round(gb * 1024) : 0 });
});
$("dd-forget").addEventListener("click", async () => {
  if (!editing || !confirm(`Forget "${editing.name}" and delete its usage history?`)) return;
  await api(`/api/devices/${encodeURIComponent(editing.key)}`, { method: "DELETE" });
  $("dlg-device").close("cancel");
  refreshSlow();
});
$("btn-reading").addEventListener("click", () => { $("rd-gb").value = ""; $("rd-note").value = ""; $("dlg-reading").showModal(); });
$("dlg-reading").addEventListener("close", async (e) => {
  const gb = parseFloat($("rd-gb").value);
  if (e.target.returnValue !== "save" || !(gb >= 0)) return;
  await api("/api/readings", { method: "POST", body: { used_gb: gb, note: $("rd-note").value || null } });
  refreshSlow();
});
$("btn-settings").addEventListener("click", async () => {
  const s = await api("/api/settings");
  $("st-quota").value = s.quota_gb; $("st-day").value = s.cycle_start_day;
  $("st-daily").value = s.default_daily_limit_gb; $("st-spike").value = s.spike_gb_per_hour;
  $("st-night").value = s.night_gb; $("st-notify").checked = !!s.notify_macos;
  $("st-pause").hidden = !(state.status && state.status.collectors.router);
  $("dlg-settings").showModal();
});
$("dlg-settings").addEventListener("close", async (e) => {
  if (e.target.returnValue !== "save") return;
  const num = (id) => { const v = parseFloat($(id).value); return Number.isFinite(v) ? v : undefined; };
  await api("/api/settings", { method: "PUT", body: { quota_gb: num("st-quota"), cycle_start_day: num("st-day"),
    default_daily_limit_gb: num("st-daily"), spike_gb_per_hour: num("st-spike"), night_gb: num("st-night"),
    notify_macos: $("st-notify").checked } });
  refreshSlow();
});
$("st-pause").addEventListener("click", async () => {
  await api("/api/collectors/router/pause", { method: "POST", body: { minutes: 15 } });
  $("dlg-settings").close("cancel");
  refreshSlow();
});
$("btn-ack-all").addEventListener("click", async () => { await api("/api/alerts/ack-all", { method: "POST" }); refreshSlow(); });

// ---------------------------------------------------------------- filters
$("range-buttons").addEventListener("click", (e) => {
  const b = e.target.closest("button");
  if (!b) return;
  state.range = b.dataset.range;
  for (const x of $("range-buttons").children) x.classList.toggle("on", x === b);
  refreshSlow();
});
$("sel-kind").addEventListener("change", (e) => { state.kind = e.target.value; refreshSlow(); });
$("sel-key").addEventListener("change", (e) => { state.key = e.target.value; refreshSlow(); });
$("only-online").addEventListener("change", () => renderDevices({ devices: state.devices, range: $("th-range").textContent }));

// ---------------------------------------------------------------- refresh loops
async function refreshFast() {
  try { renderLive(await api("/api/live")); } catch (e) { /* server restarting */ }
}
let slowBusy = false;
async function refreshSlow() {
  if (slowBusy) return;
  slowBusy = true;
  document.body.classList.add("loading");        // keep the old frame, dimmed, while loading
  const r = `range=${state.range}`;
  try {
    const [st, quota, devs] = await Promise.all([api("/api/status"), api("/api/quota"), api(`/api/devices?${r}`)]);
    renderStatus(st);
    if (!st.has_segments && state.kind === "segment") { state.kind = "device"; $("sel-kind").value = "device"; }
    renderQuota(quota);
    renderDevices(devs);
    const keyQ = state.key ? `&key=${encodeURIComponent(state.key)}` : "";
    const focusName = state.key ? ($("sel-key").selectedOptions[0] || {}).textContent : null;
    const [top, hist, heat, month, alerts, readings, suspects] = await Promise.all([
      api(`/api/usage/top?${r}&kind=${state.kind}`),
      api(`/api/usage/history?${r}&kind=${state.kind}${keyQ}`),
      api(`/api/usage/heatmap?days=14&key=${encodeURIComponent(state.key || "total")}`),
      api(`/api/usage/monthly?key=${encodeURIComponent(state.key || "total")}`),
      api("/api/alerts?limit=50"), api("/api/readings"), api(`/api/usage/suspects?${r}`)]);
    renderTop(top);
    $("hist-title").textContent = focusName ? `Usage over time: ${focusName}` : "Usage over time";
    $("hist-sub").textContent = `${hist.range} · per ${hist.bucket}`;
    stackedColumns("chart-hist", hist, "hist-empty", "No usage recorded in this period yet.");
    $("heat-title").textContent = focusName ? `When data is used: ${focusName}`
      : heat.key === "measured_devices" ? "When data is used (measured devices only)" : "When data is used";
    renderHeatmap(heat);
    $("month-sub").textContent = focusName || "Whole house";
    stackedColumns("chart-month", month, "month-empty", "Monthly totals appear once usage has been recorded.");
    renderAlerts(alerts);
    renderReadings(readings);
    renderSuspects(suspects);
    $("exp-csv").href = `/api/export/usage.csv?${r}&bucket=${state.range === "today" ? "hour" : "day"}`;
    $("exp-pdf").href = `/api/export/report.pdf?${r}`;
  } catch (e) {
    $("notice").hidden = false;
    $("notice").textContent = "Cannot reach the WE Monitor server. Is it still running?";
  } finally {
    slowBusy = false;
    document.body.classList.remove("loading");
  }
}

// A tiny hidden placeholder so showEmpty() has a target for the live chart.
document.body.append(el("p", { id: "live-empty-shim", hidden: true }));
window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => { refreshFast(); refreshSlow(); });
refreshFast();
refreshSlow();
setInterval(refreshFast, 5000);
setInterval(refreshSlow, 30000);
