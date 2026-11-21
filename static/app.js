// MAC SIEM dashboard (plain JS + d3).
// Anything that came off the network (hostnames, orgs, paths) must go through esc().
"use strict";

const TOKEN = document.querySelector('meta[name="siem-token"]').content;
const SEVS = ["info", "low", "medium", "high", "critical"];
const SEV_RANK = Object.fromEntries(SEVS.map((s, i) => [s, i]));
const css = (v) => getComputedStyle(document.documentElement).getPropertyValue(v).trim();
const COLOR = {
  in: css("--series-in"), out: css("--series-out"), land: css("--land"),
  critical: css("--critical"), high: css("--serious"), medium: css("--warning"),
  low: "#c3c2b7", info: "#898781",
};
const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];

const state = {
  snap: null, tab: "overview",
  sort: { connections: { key: "bytes", asc: false }, alerts: { key: "ts", asc: false }, history: { key: "ts", asc: false } },
  alerts: [], rulesLoaded: false, lastAlertIds: new Set(),
};

// utils
function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
function fmtBytes(n) {
  n = +n || 0;
  if (n < 1024) return n.toFixed(0) + " B";
  const u = ["KB", "MB", "GB", "TB"]; let i = -1;
  do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
  return n.toFixed(n < 10 ? 1 : 0) + " " + u[i];
}
const fmtRate = (n) => fmtBytes(n) + "/s";
function fmtDur(s) {
  s = Math.max(0, Math.round(+s || 0));
  if (s < 60) return s + "s";
  if (s < 3600) return Math.floor(s / 60) + "m " + (s % 60) + "s";
  if (s < 86400) return Math.floor(s / 3600) + "h " + Math.floor((s % 3600) / 60) + "m";
  return Math.floor(s / 86400) + "d " + Math.floor((s % 86400) / 3600) + "h";
}
const fmtTime = (ts) => new Date(ts * 1000).toLocaleTimeString([], { hour12: false });
const fmtDateTime = (ts) => new Date(ts * 1000).toLocaleString([], { hour12: false, month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" });
function flag(cc) {
  if (!cc || cc.length !== 2) return "";
  return String.fromCodePoint(...[...cc.toUpperCase()].map((c) => 0x1f1a5 + c.charCodeAt(0)));
}
const sevBadge = (s) => s ? `<span class="sev sev-${esc(s)}">${sevIcon(s)} ${esc(s)}</span>` : "";
const sevIcon = (s) => ({ critical: "⛔", high: "▲", medium: "◆", low: "●", info: "ℹ" }[s] || "");
const destLabel = (f) => f.hostname || f.org || f.remote_ip;
const endpoint = (ip, port) => (ip.includes(":") ? `[${ip}]` : ip) + ":" + port;

async function api(path, body) {
  const opt = body === undefined ? {} : {
    method: "POST", headers: { "Content-Type": "application/json", "X-SIEM-Token": TOKEN }, body: JSON.stringify(body),
  };
  const r = await fetch(path, opt);
  const data = await r.json().catch(() => ({}));
  if (r.status === 403 && /token/.test(data.error || "")) { location.reload(); throw new Error("stale page, reloading"); }
  if (!r.ok && !("ok" in data)) throw new Error(data.error || r.statusText);
  return data;
}

// tooltip
const tip = $("#tooltip");
function showTip(html, ev) {
  tip.innerHTML = html;
  tip.classList.add("show");
  moveTip(ev);
}
function moveTip(ev) {
  const pad = 14, w = tip.offsetWidth, h = tip.offsetHeight;
  let x = ev.clientX + pad, y = ev.clientY + pad;
  if (x + w > innerWidth - 8) x = ev.clientX - w - pad;
  if (y + h > innerHeight - 8) y = ev.clientY - h - pad;
  tip.style.left = x + "px"; tip.style.top = y + "px";
}
const hideTip = () => tip.classList.remove("show");
const ttRow = (k, v) => `<div class="tt-r"><span>${esc(k)}</span><b>${esc(v)}</b></div>`;

// tabs
function setTab(name) {
  state.tab = name;
  $$(".tabs button").forEach((b) => b.classList.toggle("active", b.dataset.tab === name));
  $$(".tab").forEach((t) => t.classList.toggle("active", t.id === "tab-" + name));
  if (name === "alerts") loadAlerts();
  if (name === "rules" && !state.rulesLoaded) loadRules();
  if (name === "history") loadHistory();
  render();
}
$$(".tabs button").forEach((b) => b.addEventListener("click", () => setTab(b.dataset.tab)));
document.addEventListener("click", (e) => {
  const g = e.target.closest("[data-goto]");
  if (g) setTab(g.dataset.goto);
});

// polling
async function poll() {
  try {
    state.snap = await api("/api/snapshot");
    state.offline = false;
  } catch (e) {
    state.offline = true;
  }
  render();
  setTimeout(poll, 2000);
}

function render() {
  const s = state.snap;
  renderStatus();
  if (!s) return;
  if (state.tab === "overview") {
    renderKpis(); renderMap(); renderFeed(); renderThroughput(); renderTopApps(); renderTopCountries(); renderTopOrgs(); renderAppDest();
  } else if (state.tab === "connections") {
    renderConnections(); renderListeners();
  }
  const n = s.kpis.alerts_open;
  const b = $("#alertBadge");
  b.textContent = n > 999 ? "999+" : n;
  b.classList.toggle("hidden", !n);
  document.title = (n ? `(${n}) ` : "") + "MAC SIEM";
}

function renderStatus() {
  const s = state.snap, chips = [];
  if (state.offline || !s) chips.push(["bad", "backend offline"]);
  else {
    const st = s.status;
    chips.push(st.paused ? ["warn", "paused"] : st.poll_error ? ["bad", "capture error"] : ["ok", "live"]);
    chips.push(st.geo ? ["ok", "GeoIP"] : ["bad", "no GeoIP db"]);
    chips.push(st.dns_sniffing ? ["ok", "DNS names"] : ["warn", "reverse DNS only"]);
    chips.push(st.rules_error ? ["bad", "rules error"] : ["ok", `${st.rules} rules`]);
    if (st.learning_left > 0) chips.push(["warn", `learning ${fmtDur(st.learning_left)}`]);
    document.body.classList.toggle("paused", st.paused);
    $("#pauseBtn").textContent = st.paused ? "▶ Resume" : "❚❚ Pause";
  }
  const titles = {
    "reverse DNS only": "Run with sudo (or install Wireshark's ChmodBPF) to capture DNS and see the exact domains apps looked up.",
    "learning": "First run: building a baseline of normal apps/destinations before new_app/new_dest rules fire.",
  };
  $("#statusChips").innerHTML = chips.map(([c, t]) =>
    `<span class="chip ${c}" title="${esc(titles[t.split(" ")[0] === "learning" ? "learning" : t] || "")}"><i></i>${esc(t)}</span>`).join("");
}
$("#pauseBtn").addEventListener("click", async () => {
  const paused = !(state.snap && state.snap.status.paused);
  await api("/api/pause", { paused });
  if (state.snap) state.snap.status.paused = paused;
  renderStatus();
});

// KPIs
function renderKpis() {
  const k = state.snap.kpis, c = state.snap.alert_counts || {};
  const sevNote = SEVS.slice().reverse().filter((s) => c[s]).map((s) => `${c[s]} ${s}`).join(" · ") || "all clear";
  const tiles = [
    ["Internet connections", k.public_flows, `${k.flows} total incl. local`, null, "connections"],
    ["Remote hosts", k.remotes, "unique public IPs", null, "connections"],
    ["Countries", k.countries, "reached right now", null],
    ["Apps on network", k.apps, "processes with sockets", null, "connections"],
    ["Download", fmtRate(k.rate_in), "current", COLOR.in],
    ["Upload", fmtRate(k.rate_out), "current", COLOR.out],
    ["Open alerts", k.alerts_open, sevNote, null, "alerts"],
    ["Exposed listeners", k.listeners_exposed, "ports open on all interfaces", null, "connections"],
  ];
  $("#kpis").innerHTML = tiles.map(([label, value, note, sw, go]) => `
    <div class="kpi ${go ? "clickable" : ""}" ${go ? `data-goto="${go}"` : ""}>
      <div class="label">${sw ? `<span class="swatch" style="background:${sw}"></span>` : ""}${esc(label)}</div>
      <div class="value">${esc(value)}</div><div class="note">${esc(note)}</div>
    </div>`).join("");
}

// MAP
const map = { ready: false };
async function initMap() {
  const el = $("#map");
  try {
    const topo = await (await fetch("https://cdn.jsdelivr.net/npm/world-atlas@2.0.2/countries-110m.json")).json();
    map.countries = topojson.feature(topo, topo.objects.countries).features;
  } catch (e) {
    $("#mapNote").textContent = "Could not load the world map (needs internet for the map outline).";
    return;
  }
  map.svg = d3.select(el).append("svg");
  map.g = map.svg.append("g");
  map.gSphere = map.g.append("path").attr("class", "sphere");
  map.gGrat = map.g.append("path").attr("class", "graticule");
  map.gCountries = map.g.append("g");
  map.gArcs = map.g.append("g");
  map.gDests = map.g.append("g");
  map.gHome = map.g.append("g");
  map.zoom = d3.zoom().scaleExtent([1, 12]).on("zoom", (ev) => {
    map.k = ev.transform.k;
    map.g.attr("transform", ev.transform);
    map.gDests.selectAll("circle").attr("r", (d) => d.r / Math.sqrt(map.k));
    map.gHome.selectAll("circle.home").attr("r", 4 / Math.sqrt(map.k));
  });
  map.k = 1;
  map.svg.call(map.zoom).on("dblclick.zoom", null);
  const ctrl = d3.select(el).append("div").attr("class", "map-ctrl");
  ctrl.append("button").attr("class", "btn").attr("title", "Zoom in").text("+").on("click", () => map.svg.transition().call(map.zoom.scaleBy, 1.6));
  ctrl.append("button").attr("class", "btn").attr("title", "Zoom out").text("−").on("click", () => map.svg.transition().call(map.zoom.scaleBy, 1 / 1.6));
  ctrl.append("button").attr("class", "btn").attr("title", "Reset").text("⟲").on("click", () => map.svg.transition().call(map.zoom.transform, d3.zoomIdentity));
  new ResizeObserver(() => { layoutMap(); renderMap(); }).observe(el);
  layoutMap();
  map.ready = true;
  $("#mapLegend").innerHTML = `
    <span><span class="ramp"></span>data volume by country</span>
    <span><span class="dot" style="background:${COLOR.in}"></span>destination</span>
    <span><span class="dot" style="background:${COLOR.high}"></span>alerting</span>
    <span><span class="dot" style="background:#f0efec"></span>you</span>`;
  renderMap();
}
function layoutMap() {
  const el = $("#map"), w = el.clientWidth, h = el.clientHeight;
  if (!w || !h) return;
  map.w = w; map.h = h;
  map.svg.attr("viewBox", `0 0 ${w} ${h}`);
  // centre the map on "home" so arcs radiate out instead of wrapping at the edges
  const home = state.snap && state.snap.home;
  map.rot = home && home.lon != null ? Math.round(-home.lon) : 0;
  map.proj = d3.geoNaturalEarth1().rotate([map.rot, 0]).fitExtent([[6, 6], [w - 6, h - 6]], { type: "Sphere" });
  map.path = d3.geoPath(map.proj);
  map.gSphere.datum({ type: "Sphere" }).attr("d", map.path);
  map.gGrat.datum(d3.geoGraticule10()).attr("d", map.path);
  map.gCountries.selectAll("path").data(map.countries, (d) => d.id).join("path")
    .attr("class", "country").attr("d", map.path);
}

function aggregateDests(flows) {
  const by = new Map();
  for (const f of flows) {
    if (f.scope !== "public" || f.lat == null) continue;
    const key = f.lat.toFixed(2) + "," + f.lon.toFixed(2);
    let d = by.get(key);
    if (!d) by.set(key, d = { key, lat: f.lat, lon: f.lon, city: f.city, country: f.country, cc: f.country_code,
      flows: 0, bytes: 0, rate: 0, ips: new Set(), apps: new Set(), orgs: new Set(), hosts: new Set(), sev: "" });
    d.flows++; d.bytes += f.bytes_in + f.bytes_out; d.rate += f.rate_in + f.rate_out;
    d.ips.add(f.remote_ip); d.apps.add(f.app); if (f.org) d.orgs.add(f.org); if (f.hostname) d.hosts.add(f.hostname);
    if ((SEV_RANK[f.max_sev] ?? -1) > (SEV_RANK[d.sev] ?? -1)) d.sev = f.max_sev;
  }
  return [...by.values()];
}

function renderMap() {
  if (!map.ready || !state.snap || !map.proj) return;
  const h0 = state.snap.home;
  if (h0 && h0.lon != null && Math.round(-h0.lon) !== map.rot) layoutMap();
  const flows = state.snap.flows, home = state.snap.home;
  // choropleth: bytes per country (public flows)
  const byCC = d3.rollup(flows.filter((f) => f.scope === "public" && f.country_code),
    (v) => ({ bytes: d3.sum(v, (f) => f.bytes_in + f.bytes_out), n: v.length, name: v[0].country }), (f) => f.country_code);
  const byNum = new Map();
  for (const [cc, v] of byCC) { const num = window.ISO_NUM[cc]; if (num) byNum.set(num, { cc, ...v }); }
  const maxB = d3.max([...byNum.values()], (v) => v.bytes) || 1;
  const fill = d3.scaleSequentialLog([1, Math.max(10, maxB)], d3.interpolateRgb("#184f95", "#9ec5f4")).clamp(true);
  map.gCountries.selectAll("path")
    .attr("fill", (d) => { const v = byNum.get(d.id); return v ? fill(Math.max(1, v.bytes)) : COLOR.land; })
    .on("mousemove", (ev, d) => {
      const v = byNum.get(d.id);
      showTip(`<div class="tt-h">${esc(d.properties.name)}</div>` +
        (v ? ttRow("Connections", v.n) + ttRow("Data", fmtBytes(v.bytes)) : `<div class="tt-r">no live traffic</div>`), ev);
    })
    .on("mouseleave", hideTip)
    .on("click", (ev, d) => { const v = byNum.get(d.id); if (v) gotoConnections(`cc:${v.cc}`); });

  const dests = aggregateDests(flows);
  const maxD = d3.max(dests, (d) => d.bytes) || 1;
  const rS = d3.scaleSqrt([0, maxD], [3.5, 13]);
  dests.forEach((d) => { d.r = rS(d.bytes); d.xy = map.proj([d.lon, d.lat]); });
  const colorOf = (d) => d.sev && SEV_RANK[d.sev] >= SEV_RANK.medium ? COLOR[d.sev] : COLOR.in;

  if (home && home.lat != null) {
    const hxy = map.proj([home.lon, home.lat]);
    map.gArcs.selectAll("path").data(dests, (d) => d.key).join("path")
      .attr("class", (d) => "arc" + (d.rate > 50 ? " active" : ""))
      .attr("stroke", colorOf)
      .attr("d", (d) => map.path({ type: "LineString", coordinates: [[home.lon, home.lat], [d.lon, d.lat]] }));
    map.gHome.selectAll("circle.home-ring").data([hxy]).join("circle").attr("class", "home-ring")
      .attr("cx", (d) => d[0]).attr("cy", (d) => d[1]).attr("r", 5);
    map.gHome.selectAll("circle.home").data([hxy]).join("circle").attr("class", "home")
      .attr("cx", (d) => d[0]).attr("cy", (d) => d[1]).attr("r", 4 / Math.sqrt(map.k))
      .on("mousemove", (ev) => showTip(`<div class="tt-h">You</div><div class="tt-r">${esc(home.label || "home")}</div>`, ev))
      .on("mouseleave", hideTip);
    $("#mapNote").textContent = `${dests.length} destination locations · arcs from ${home.label || "home"} · animated = data flowing now · scroll to zoom, drag to pan, click a dot or country to drill in`;
  } else {
    map.gArcs.selectAll("path").remove();
    $("#mapNote").textContent = `${dests.length} destination locations · set "home" in config.yaml to draw arcs from your location`;
  }
  map.gDests.selectAll("circle").data(dests.sort((a, b) => b.bytes - a.bytes), (d) => d.key).join("circle")
    .attr("class", "dest").attr("cx", (d) => d.xy[0]).attr("cy", (d) => d.xy[1])
    .attr("r", (d) => d.r / Math.sqrt(map.k)).attr("fill", colorOf)
    .on("mousemove", (ev, d) => showTip(
      `<div class="tt-h">${flag(d.cc)} ${esc([d.city, d.country].filter(Boolean).join(", ") || "Unknown")}</div>` +
      ttRow("Connections", d.flows) + ttRow("Data", fmtBytes(d.bytes)) + ttRow("Now", fmtRate(d.rate)) +
      ttRow("IPs", [...d.ips].slice(0, 3).join(", ") + (d.ips.size > 3 ? ` +${d.ips.size - 3}` : "")) +
      ttRow("Apps", [...d.apps].slice(0, 4).join(", ")) +
      (d.orgs.size ? ttRow("Org", [...d.orgs].slice(0, 2).join(", ")) : "") +
      (d.hosts.size ? ttRow("Hosts", [...d.hosts].slice(0, 3).join(", ")) : "") +
      (d.sev ? `<div class="tt-r" style="margin-top:4px">${sevBadge(d.sev)}</div>` : ""), ev))
    .on("mouseleave", hideTip)
    .on("click", (ev, d) => { hideTip(); gotoConnections(d.ips.size === 1 ? `ip:${[...d.ips][0]}` : `city:"${d.city}" cc:${d.cc}`); });
}

// alert feed
function renderFeed() {
  const list = state.snap.alerts_recent || [];
  $("#alertFeed").innerHTML = list.length ? list.map((a) => `
    <li class="bl-${esc(a.severity)}" data-alert="${a.id}">
      <div class="t">${sevBadge(a.severity)} ${esc(a.rule_name)}</div>
      <div class="m">${esc(a.app)} → ${esc(a.hostname || a.org || a.remote_ip)}:${esc(a.remote_port)} ${flag(a.country_code)} · ${fmtTime(a.ts)}</div>
    </li>`).join("") : `<li class="empty" style="cursor:default;border:0;background:none">No open alerts 🎉</li>`;
  $$("#alertFeed li[data-alert]").forEach((li) => li.addEventListener("click", () => {
    const a = list.find((x) => String(x.id) === li.dataset.alert); if (a) openAlert(a);
  }));
}

// throughput
function renderThroughput() {
  const el = $("#throughput"), w = el.clientWidth, h = el.clientHeight;
  const data = (state.snap.series || []).map(([t, i, o]) => ({ t: new Date(t * 1000), i, o }));
  $("#tpLegend").innerHTML = `<span><span class="swatch" style="background:${COLOR.in}"></span>Download</span><span><span class="swatch" style="background:${COLOR.out}"></span>Upload</span>`;
  if (data.length < 2 || w < 200) { el.innerHTML = `<div class="empty">collecting…</div>`; return; }
  const m = { t: 8, r: 62, b: 22, l: 56 };
  const x = d3.scaleTime(d3.extent(data, (d) => d.t), [m.l, w - m.r]);
  const y = d3.scaleLinear([0, d3.max(data, (d) => Math.max(d.i, d.o)) * 1.1 || 1], [h - m.b, m.t]).nice();
  let svg = d3.select(el).select("svg");
  if (svg.empty()) {
    el.innerHTML = "";
    svg = d3.select(el).append("svg");
    svg.append("g").attr("class", "gridline");
    svg.append("g").attr("class", "axis x");
    svg.append("g").attr("class", "axis y");
    svg.append("path").attr("class", "l-in").attr("fill", "none").attr("stroke-width", 2).attr("stroke", COLOR.in);
    svg.append("path").attr("class", "l-out").attr("fill", "none").attr("stroke-width", 2).attr("stroke", COLOR.out);
    svg.append("text").attr("class", "lab-in").attr("font-size", 11).attr("fill", css("--text-secondary"));
    svg.append("text").attr("class", "lab-out").attr("font-size", 11).attr("fill", css("--text-secondary"));
    svg.append("line").attr("class", "crosshair").style("display", "none");
    svg.append("circle").attr("class", "hv-in").attr("r", 4).attr("fill", COLOR.in).attr("stroke", css("--surface-1")).attr("stroke-width", 2).style("display", "none");
    svg.append("circle").attr("class", "hv-out").attr("r", 4).attr("fill", COLOR.out).attr("stroke", css("--surface-1")).attr("stroke-width", 2).style("display", "none");
    svg.append("rect").attr("class", "overlay").attr("fill", "transparent");
  }
  svg.attr("viewBox", `0 0 ${w} ${h}`);
  const yFmt = (v) => fmtRate(v).replace(".0 ", " ");
  svg.select(".gridline").attr("transform", `translate(${m.l},0)`).call(d3.axisLeft(y).ticks(4).tickSize(-(w - m.l - m.r)).tickFormat(""));
  svg.select(".axis.x").attr("transform", `translate(0,${h - m.b})`).call(d3.axisBottom(x).ticks(Math.max(2, w / 110)).tickFormat(d3.timeFormat("%H:%M")).tickSizeOuter(0));
  svg.select(".axis.y").attr("transform", `translate(${m.l},0)`).call(d3.axisLeft(y).ticks(4).tickFormat(yFmt).tickSize(0).tickPadding(6)).select(".domain").remove();
  const line = (k) => d3.line().x((d) => x(d.t)).y((d) => y(d[k])).curve(d3.curveMonotoneX)(data);
  svg.select(".l-in").attr("d", line("i"));
  svg.select(".l-out").attr("d", line("o"));
  const last = data[data.length - 1];
  let yi = y(last.i), yo = y(last.o);
  if (Math.abs(yi - yo) < 12) { if (yi <= yo) { yi -= 6; yo += 6; } else { yi += 6; yo -= 6; } }
  svg.select(".lab-in").attr("x", w - m.r + 6).attr("y", yi + 4).text("↓ " + yFmt(last.i));
  svg.select(".lab-out").attr("x", w - m.r + 6).attr("y", yo + 4).text("↑ " + yFmt(last.o));
  const bis = d3.bisector((d) => d.t).center;
  svg.select(".overlay").attr("x", m.l).attr("y", m.t).attr("width", Math.max(0, w - m.l - m.r)).attr("height", Math.max(0, h - m.t - m.b))
    .on("mousemove", (ev) => {
      const d = data[bis(data, x.invert(d3.pointer(ev)[0]))];
      svg.select(".crosshair").style("display", null).attr("x1", x(d.t)).attr("x2", x(d.t)).attr("y1", m.t).attr("y2", h - m.b);
      svg.select(".hv-in").style("display", null).attr("cx", x(d.t)).attr("cy", y(d.i));
      svg.select(".hv-out").style("display", null).attr("cx", x(d.t)).attr("cy", y(d.o));
      showTip(`<div class="tt-h">${d.t.toLocaleTimeString([], { hour12: false })}</div>` +
        `<div class="tt-r"><span><span class="swatch" style="background:${COLOR.in}"></span> Download</span><b>${fmtRate(d.i)}</b></div>` +
        `<div class="tt-r"><span><span class="swatch" style="background:${COLOR.out}"></span> Upload</span><b>${fmtRate(d.o)}</b></div>`, ev);
    })
    .on("mouseleave", () => { svg.selectAll(".crosshair,.hv-in,.hv-out").style("display", "none"); hideTip(); });
}

// bars
function bars(el, rows, opts = {}) {
  if (!rows.length) { el.innerHTML = `<div class="empty">${esc(opts.empty || "no data yet")}</div>`; return; }
  const max = d3.max(rows, (r) => d3.sum(r.segs, (s) => s.v)) || 1;
  el.innerHTML = rows.map((r, i) => `
    <div class="bar-row" data-i="${i}">
      <div class="name" title="${esc(r.name)}">${r.icon || ""}${esc(r.name)}</div>
      <div class="track">${r.segs.map((s) => `<div class="seg" style="width:${(100 * s.v / max).toFixed(2)}%;background:${s.c}"></div>`).join("")}</div>
      <div class="val">${esc(r.label)}</div>
    </div>`).join("");
  $$(".bar-row", el).forEach((row) => {
    const r = rows[+row.dataset.i];
    row.addEventListener("mousemove", (ev) => showTip(`<div class="tt-h">${esc(r.name)}</div>${r.tip || ""}`, ev));
    row.addEventListener("mouseleave", hideTip);
    if (r.onClick) row.addEventListener("click", () => { hideTip(); r.onClick(); });
  });
}
const legendRow = (c, k, v) => `<div class="tt-r"><span><span class="swatch" style="background:${c}"></span> ${esc(k)}</span><b>${esc(v)}</b></div>`;

function renderTopApps() {
  const apps = state.snap.apps.filter((a) => a.bytes_in + a.bytes_out > 0).slice(0, 10);
  bars($("#topApps"), apps.map((a) => ({
    name: a.app, label: fmtBytes(a.bytes_in + a.bytes_out),
    segs: [{ v: a.bytes_in, c: COLOR.in }, { v: a.bytes_out, c: COLOR.out }],
    tip: legendRow(COLOR.in, "Downloaded", fmtBytes(a.bytes_in)) + legendRow(COLOR.out, "Uploaded", fmtBytes(a.bytes_out)) +
      ttRow("Connections", a.flows) + ttRow("Remote IPs", a.remotes) + ttRow("Countries", a.countries.join(" ") || "–"),
    onClick: () => gotoConnections(`app:"${a.app}"`),
  })), { empty: "waiting for traffic…" });
}
function countBy(keyFn, filter) {
  const m = new Map();
  for (const f of state.snap.flows) {
    if (f.scope !== "public" || (filter && !filter(f))) continue;
    const k = keyFn(f); if (!k) continue;
    const e = m.get(k) || { n: 0, bytes: 0, f }; e.n++; e.bytes += f.bytes_in + f.bytes_out; m.set(k, e);
  }
  return [...m.entries()].sort((a, b) => b[1].n - a[1].n || b[1].bytes - a[1].bytes);
}
function renderTopCountries() {
  bars($("#topCountries"), countBy((f) => f.country_code).slice(0, 10).map(([cc, e]) => ({
    name: e.f.country || cc, icon: flag(cc) + " ", label: e.n, segs: [{ v: e.n, c: COLOR.in }],
    tip: ttRow("Connections", e.n) + ttRow("Data", fmtBytes(e.bytes)), onClick: () => gotoConnections(`cc:${cc}`),
  })));
}
function renderTopOrgs() {
  bars($("#topOrgs"), countBy((f) => f.org).slice(0, 10).map(([org, e]) => ({
    name: org, label: e.n, segs: [{ v: e.n, c: COLOR.in }],
    tip: ttRow("Connections", e.n) + ttRow("Data", fmtBytes(e.bytes)) + ttRow("ASN", "AS" + e.f.asn),
    onClick: () => gotoConnections(`org:"${org}"`),
  })));
}
function renderAppDest() {
  const by = new Map();
  for (const f of state.snap.flows) {
    if (f.scope !== "public") continue;
    const a = by.get(f.app) || { app: f.app, path: f.path, signer: f.signer, dests: new Map(), bytes: 0 };
    const label = destLabel(f);
    const d = a.dests.get(label) || { label, cc: f.country_code, n: 0, sev: "", ip: f.remote_ip };
    d.n++; if ((SEV_RANK[f.max_sev] ?? -1) > (SEV_RANK[d.sev] ?? -1)) d.sev = f.max_sev;
    a.dests.set(label, d); a.bytes += f.bytes_in + f.bytes_out; by.set(f.app, a);
  }
  const apps = [...by.values()].sort((a, b) => b.dests.size - a.dests.size || b.bytes - a.bytes);
  const el = $("#appDest");
  if (!apps.length) { el.innerHTML = `<div class="empty">no internet traffic right now</div>`; return; }
  el.innerHTML = apps.map((a, i) => `
    <div class="ad-row">
      <div class="ad-app" data-app="${i}" title="${esc(a.path)}">${esc(a.app)}<span class="sub">${a.dests.size} destination${a.dests.size > 1 ? "s" : ""} · ${esc(a.signer || "")}</span></div>
      <div class="ad-dests">${[...a.dests.values()].sort((x, y) => y.n - x.n).map((d) =>
        `<span class="pill ${d.sev && SEV_RANK[d.sev] >= 2 ? "alert" : ""}" data-q="${esc(d.label === d.ip ? "ip:" + d.ip : '"' + d.label + '"')}" title="${esc(d.label)} (${d.n})">${flag(d.cc)} ${esc(d.label)}${d.n > 1 ? ` ×${d.n}` : ""}</span>`).join("")}</div>
    </div>`).join("");
  $$(".ad-app", el).forEach((n) => n.addEventListener("click", () => gotoConnections(`app:"${apps[+n.dataset.app].app}"`)));
  $$(".pill", el).forEach((p) => p.addEventListener("click", () => gotoConnections(p.dataset.q)));
}

// search DSL
const ALIAS = { cc: "country_code", port: "remote_port", ip: "remote_ip", host: "hostname", lport: "local_port", sev: "max_sev", rule: "alerts" };
function tokenize(q) {
  const out = []; const re = /(\w+:)?("([^"]*)"|\S+)/g; let m;
  while ((m = re.exec(q))) out.push({ field: m[1] ? m[1].slice(0, -1).toLowerCase() : null, val: (m[3] ?? m[2]).toLowerCase() });
  return out;
}
function matchQuery(f, toks) {
  for (const t of toks) {
    if (t.field) {
      const k = ALIAS[t.field] || t.field;
      const v = f[k];
      const s = Array.isArray(v) ? v.join(" ").toLowerCase() : String(v ?? "").toLowerCase();
      if (["remote_port", "local_port", "pid", "asn"].includes(k) ? s !== t.val : !s.includes(t.val)) return false;
    } else {
      const hay = [f.app, f.process, f.remote_ip, f.hostname, f.org, f.country, f.country_code, f.city, f.remote_port, f.service, f.proto, f.state, f.alerts.join(" ")].join(" ").toLowerCase();
      if (!hay.includes(t.val)) return false;
    }
  }
  return true;
}
function gotoConnections(q) {
  $("#connSearch").value = q;
  $("#connScope").value = "all";
  setTab("connections");
}

// tables
function table(el, cols, rows, sortState, onRow, rowClass) {
  if (sortState) {
    const c = cols.find((c) => c.key === sortState.key) || cols[0];
    const get = c.sort || c.get;
    rows = rows.slice().sort((a, b) => {
      const x = get(a), y = get(b);
      const r = typeof x === "number" && typeof y === "number" ? x - y : String(x ?? "").localeCompare(String(y ?? ""));
      return sortState.asc ? r : -r;
    });
  }
  const limit = 1500, shown = rows.slice(0, limit);
  const head = `<thead><tr>${cols.map((c) =>
    `<th data-k="${c.key}" class="${c.num ? "num" : ""} ${sortState && sortState.key === c.key ? "sorted" + (sortState.asc ? " asc" : "") : ""}">${esc(c.label)}</th>`).join("")}</tr></thead>`;
  const body = `<tbody>${shown.map((r, i) =>
    `<tr data-i="${i}" class="${rowClass ? rowClass(r) : ""}">${cols.map((c) => `<td class="${c.num ? "num" : ""} ${c.cls || ""}">${c.render ? c.render(r) : esc(c.get(r))}</td>`).join("")}</tr>`).join("")}</tbody>`;
  el.innerHTML = head + body;
  if (sortState) $$("th", el).forEach((th) => th.addEventListener("click", () => {
    if (sortState.key === th.dataset.k) sortState.asc = !sortState.asc; else { sortState.key = th.dataset.k; sortState.asc = false; }
    render(); if (state.tab === "alerts") renderAlerts(); if (state.tab === "history") renderHistoryTable();
  }));
  if (onRow) $$("tbody tr", el).forEach((tr) => tr.addEventListener("click", () => onRow(shown[+tr.dataset.i])));
  return rows.length;
}

const connCols = [
  { key: "app", label: "App", get: (f) => f.app, render: (f) => `<b>${esc(f.app)}</b> <span class="mut">${f.process !== f.app ? esc(f.process) : ""} ${f.pid}</span>` },
  { key: "proto", label: "Proto", get: (f) => f.proto, cls: "mut" },
  { key: "dest", label: "Destination", get: (f) => destLabel(f), render: (f) =>
      `${esc(f.hostname || "")} <span class="mono ${f.hostname ? "mut" : ""}">${esc(endpoint(f.remote_ip, f.remote_port))}</span> ${f.service ? `<span class="tag">${esc(f.service)}</span>` : ""}` },
  { key: "country", label: "Location", get: (f) => f.country_code || f.scope, render: (f) =>
      f.country_code ? `${flag(f.country_code)} ${esc(f.country_code)} <span class="mut">${esc(f.city)}</span>` : `<span class="tag">${esc(f.scope)}</span>` },
  { key: "org", label: "Organisation", get: (f) => f.org, render: (f) => f.org ? `${esc(f.org)} <span class="mut">AS${f.asn}</span>` : "" },
  { key: "state", label: "State", get: (f) => f.state, cls: "mut" },
  { key: "rate_in", label: "↓ now", num: true, get: (f) => f.rate_in, render: (f) => f.rate_in ? fmtRate(f.rate_in) : "<span class='mut'>–</span>" },
  { key: "rate_out", label: "↑ now", num: true, get: (f) => f.rate_out, render: (f) => f.rate_out ? fmtRate(f.rate_out) : "<span class='mut'>–</span>" },
  { key: "bytes", label: "Total", num: true, get: (f) => f.bytes_in + f.bytes_out, render: (f) => fmtBytes(f.bytes_in + f.bytes_out) },
  { key: "rtt_ms", label: "RTT", num: true, get: (f) => f.rtt_ms ?? -1, render: (f) => f.rtt_ms != null ? f.rtt_ms.toFixed(0) + " ms" : "" },
  { key: "duration", label: "Age", num: true, get: (f) => f.duration, render: (f) => fmtDur(f.duration) },
  { key: "sev", label: "Alerts", get: (f) => SEV_RANK[f.max_sev] ?? -1, render: (f) => f.max_sev ? sevBadge(f.max_sev) + (f.alerts.length > 1 ? ` <span class="mut">+${f.alerts.length - 1}</span>` : "") : "" },
];

function renderConnections() {
  const s = state.snap, scope = $("#connScope").value, app = $("#connApp").value, only = $("#connAlerting").checked;
  const toks = tokenize($("#connSearch").value.trim());
  const rows = s.flows.filter((f) =>
    (scope === "all" || (scope === "public" ? f.scope === "public" : f.scope !== "public")) &&
    (!app || f.app === app) && (!only || f.alerts.length) && matchQuery(f, toks));
  const sel = $("#connApp"), apps = [...new Set(s.flows.map((f) => f.app))].sort((a, b) => a.localeCompare(b));
  const cur = sel.value;
  if (sel.dataset.apps !== apps.join("\u0000")) {
    sel.innerHTML = `<option value="">All apps</option>` + apps.map((a) => `<option>${esc(a)}</option>`).join("");
    sel.value = apps.includes(cur) ? cur : ""; sel.dataset.apps = apps.join("\u0000");
  }
  const wrap = $("#connTable").parentElement, top = wrap.scrollTop;
  const n = table($("#connTable"), connCols, rows, state.sort.connections, openFlow, (f) => f.alerts.length ? "alerting" : "");
  wrap.scrollTop = top;
  $("#connCount").textContent = `${n} of ${s.flows.length} connections · tip: app:chrome cc:US port:443 org:"amazon"`;
}
["#connSearch", "#connScope", "#connApp", "#connAlerting"].forEach((id) => $(id).addEventListener("input", render));

function renderListeners() {
  const cols = [
    { key: "port", label: "Port", get: (l) => l.port, render: (l) => `<span class="mono">${l.port}</span> ${l.service ? `<span class="tag">${esc(l.service)}</span>` : ""}` },
    { key: "proto", label: "Proto", get: (l) => l.proto, cls: "mut" },
    { key: "ip", label: "Bound to", get: (l) => l.ip, render: (l) => `<span class="mono">${esc(l.ip)}</span> ${l.exposed ? `<span class="tag bad">exposed</span>` : `<span class="tag ok">local only</span>`}` },
    { key: "app", label: "App", get: (l) => l.app, render: (l) => `<b>${esc(l.app)}</b> <span class="mut">${esc(l.process)} ${l.pid}</span>` },
  ];
  table($("#listenTable"), cols, state.snap.listeners, null);
}

// drawer
function openDrawer(title, html) {
  $("#drawerTitle").textContent = title;
  $("#drawerBody").innerHTML = html;
  $("#drawer").classList.add("open");
  $("#drawer").setAttribute("aria-hidden", "false");
}
function closeDrawer() { $("#drawer").classList.remove("open"); $("#drawer").setAttribute("aria-hidden", "true"); }
$("#drawerClose").addEventListener("click", closeDrawer);
document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeDrawer(); });
const kv = (pairs) => `<dl class="kv">${pairs.filter(([, v]) => v !== undefined && v !== null && v !== "").map(([k, v]) => `<dt>${esc(k)}</dt><dd>${v}</dd>`).join("")}</dl>`;
const ipLinks = (ip) => `<a href="https://bgp.he.net/ip/${encodeURIComponent(ip)}" target="_blank" rel="noopener noreferrer">bgp.he.net</a> ·
  <a href="https://www.abuseipdb.com/check/${encodeURIComponent(ip)}" target="_blank" rel="noopener noreferrer">AbuseIPDB</a> ·
  <a href="https://www.shodan.io/host/${encodeURIComponent(ip)}" target="_blank" rel="noopener noreferrer">Shodan</a>`;

function openFlow(f) {
  const signed = f.signed === true ? `<span class="tag ok">signed</span>` : f.signed === false ? `<span class="tag bad">unsigned / invalid</span>` : `<span class="tag">unknown</span>`;
  openDrawer(`${f.app} → ${destLabel(f)}`, `
    <section><h3>Process</h3>${kv([
      ["App", esc(f.app)], ["Process", esc(f.process) + ` <span class="mut">pid ${f.pid}</span>`], ["User", esc(f.user)],
      ["Path", `<span class="mono">${esc(f.path)}</span>`], ["Signature", `${signed} ${esc(f.signer)}`], ["Team ID", esc(f.team_id)]])}</section>
    <section><h3>Remote</h3>${kv([
      ["Address", `<span class="mono">${esc(endpoint(f.remote_ip, f.remote_port))}</span> ${f.service ? `<span class="tag">${esc(f.service)}</span>` : ""}`],
      ["Hostname", f.hostname ? esc(f.hostname) + ` <span class="mut">(${f.host_src === "dns" ? "from DNS lookup" : "reverse DNS"})</span>` : `<span class="mut">unknown</span>`],
      ["Scope", esc(f.scope)], ["Location", f.country ? `${flag(f.country_code)} ${esc([f.city, f.country].filter(Boolean).join(", "))}` : ""],
      ["Organisation", f.org ? `${esc(f.org)} <span class="mut">AS${f.asn}</span>` : ""],
      ["Look up", f.scope === "public" ? ipLinks(f.remote_ip) : ""]])}</section>
    <section><h3>Traffic</h3>${kv([
      ["Protocol", esc(f.proto.toUpperCase())], ["State", esc(f.state)], ["Interface", esc(f.interface)],
      ["Local", `<span class="mono">${esc(endpoint(f.local_ip, f.local_port))}</span>`],
      ["Received", fmtBytes(f.bytes_in) + (f.rate_in ? ` <span class="mut">(${fmtRate(f.rate_in)})</span>` : "")],
      ["Sent", fmtBytes(f.bytes_out) + (f.rate_out ? ` <span class="mut">(${fmtRate(f.rate_out)})</span>` : "")],
      ["RTT", f.rtt_ms != null ? f.rtt_ms.toFixed(1) + " ms" : ""], ["Open for", fmtDur(f.duration)], ["First seen", fmtDateTime(f.first_seen)],
      ["Baseline", (f.new_app ? `<span class="tag bad">new app</span> ` : "") + (f.new_dest ? `<span class="tag bad">new destination</span>` : "") || `<span class="mut">known</span>`]])}</section>
    <section><h3>Matched rules</h3>${f.alerts.length ? f.alerts.map((r) => `<div>${sevBadge(f.max_sev)} <span class="mono">${esc(r)}</span></div>`).join("") : `<span class="mut">none</span>`}
      <div class="actions">
        <button class="btn sm" data-act="app">Only this app</button>
        <button class="btn sm" data-act="ip">Only this IP</button>
        <button class="btn sm" data-act="rule">Draft a rule for this…</button>
      </div></section>`);
  const b = $("#drawerBody");
  b.querySelector('[data-act="app"]').onclick = () => { closeDrawer(); gotoConnections(`app:"${f.app}"`); };
  b.querySelector('[data-act="ip"]').onclick = () => { closeDrawer(); gotoConnections(`ip:${f.remote_ip}`); };
  b.querySelector('[data-act="rule"]').onclick = () => {
    closeDrawer(); setTab("rules");
    const cond = f.org ? `app == ${JSON.stringify(f.app)} and org == ${JSON.stringify(f.org)}` : `app == ${JSON.stringify(f.app)} and remote_ip == ${JSON.stringify(f.remote_ip)}`;
    $("#testExpr").value = cond; runTest();
  };
}

function openAlert(a) {
  const d = a.details || {};
  openDrawer(a.rule_name, `
    <section>${sevBadge(a.severity)} <span class="mut">${fmtDateTime(a.ts)}</span>${a.acked ? ` <span class="tag">acknowledged</span>` : ""}
      ${d.description ? `<p>${esc(d.description)}</p>` : ""}
      <h3>Rule condition</h3><pre class="helpers">${esc(d.condition)}</pre></section>
    <section><h3>Connection</h3>${kv([
      ["App", esc(a.app)], ["Process", esc(a.process) + (d.pid ? ` <span class="mut">pid ${d.pid}</span>` : "")],
      ["Path", `<span class="mono">${esc(d.path)}</span>`], ["Signer", esc(d.signer)],
      ["Remote", `<span class="mono">${esc(endpoint(a.remote_ip, a.remote_port))}</span> <span class="mut">${esc(d.proto || "")}</span>`],
      ["Hostname", esc(a.hostname)], ["Location", a.country_code ? `${flag(a.country_code)} ${esc([d.city, d.country].filter(Boolean).join(", "))}` : esc(d.scope)],
      ["Organisation", a.org ? `${esc(a.org)} <span class="mut">AS${esc(d.asn)}</span>` : ""],
      ["Data at alert", `↓ ${fmtBytes(d.bytes_in)} · ↑ ${fmtBytes(d.bytes_out)}`],
      ["Look up", d.scope === "public" ? ipLinks(a.remote_ip) : ""]])}
      <div class="actions">${a.acked ? "" : `<button class="btn sm primary" data-act="ack">Acknowledge</button>`}
        <button class="btn sm" data-act="live">Show live connections</button></div></section>`);
  const b = $("#drawerBody");
  const ack = b.querySelector('[data-act="ack"]');
  if (ack) ack.onclick = async () => { await api("/api/alerts/ack", { ids: [a.id] }); closeDrawer(); loadAlerts(); };
  b.querySelector('[data-act="live"]').onclick = () => { closeDrawer(); gotoConnections(`app:"${a.app}" ip:${a.remote_ip}`); };
}

// alerts
async function loadAlerts() {
  try { state.alerts = await api(`/api/alerts?limit=1000&acked=${$("#alertShowAcked").checked ? 1 : 0}`); } catch (e) { /* offline */ }
  renderAlerts();
}
function renderAlerts() {
  const sev = $("#alertSev").value;
  const rows = state.alerts.filter((a) => !sev || a.severity === sev);
  const cols = [
    { key: "ts", label: "Time", get: (a) => a.ts, render: (a) => fmtDateTime(a.ts) },
    { key: "severity", label: "Severity", get: (a) => SEV_RANK[a.severity], render: (a) => sevBadge(a.severity) },
    { key: "rule_name", label: "Rule", get: (a) => a.rule_name },
    { key: "app", label: "App", get: (a) => a.app, render: (a) => `<b>${esc(a.app)}</b>` },
    { key: "dest", label: "Destination", get: (a) => a.hostname || a.remote_ip, render: (a) => `${esc(a.hostname)} <span class="mono mut">${esc(endpoint(a.remote_ip, a.remote_port))}</span>` },
    { key: "cc", label: "Country", get: (a) => a.country_code, render: (a) => `${flag(a.country_code)} ${esc(a.country_code)}` },
    { key: "org", label: "Organisation", get: (a) => a.org },
    { key: "ack", label: "", get: (a) => a.acked, render: (a) => a.acked ? `<span class="mut">acked</span>` : `<button class="btn sm" data-ack="${a.id}">Ack</button>` },
  ];
  table($("#alertTable"), cols, rows, state.sort.alerts, (a) => openAlert(a), (a) => a.acked ? "acked" : "");
  $$("#alertTable [data-ack]").forEach((b) => b.addEventListener("click", async (e) => {
    e.stopPropagation(); await api("/api/alerts/ack", { ids: [+b.dataset.ack] }); loadAlerts();
  }));
  if (!rows.length) $("#alertTable").insertAdjacentHTML("beforeend", `<tbody><tr><td colspan="8" class="empty">No alerts</td></tr></tbody>`);
}
$("#alertSev").addEventListener("input", renderAlerts);
$("#alertShowAcked").addEventListener("input", loadAlerts);
$("#ackAll").addEventListener("click", async () => {
  if (!confirm("Acknowledge all open alerts?")) return;
  await api("/api/alerts/ack", { ids: "all" }); loadAlerts();
});
setInterval(() => { if (state.tab === "alerts") loadAlerts(); }, 5000);

// rules
async function loadRules() {
  const r = await api("/api/rules");
  $("#ruleText").value = r.text;
  $("#ruleMsg").className = "msg " + (r.error ? "err" : "ok");
  $("#ruleMsg").textContent = r.error || `${r.rules.length} rules loaded`;
  $("#fieldRef").innerHTML = Object.entries(r.fields).map(([k, v]) => `<code data-f="${esc(k)}">${esc(k)}</code><span>${esc(v)}</span>`).join("");
  $$("#fieldRef code").forEach((c) => c.addEventListener("click", () => {
    const inp = $("#testExpr"); inp.value = (inp.value ? inp.value + " and " : "") + c.dataset.f + " "; inp.focus();
  }));
  state.rulesLoaded = true;
}
$("#ruleReload").addEventListener("click", loadRules);
$("#ruleSave").addEventListener("click", async () => {
  const r = await api("/api/rules", { text: $("#ruleText").value });
  $("#ruleMsg").className = "msg " + (r.ok ? "ok" : "err");
  $("#ruleMsg").textContent = r.ok ? `✓ saved · ${r.count} rules active` : r.error;
});
$("#ruleText").addEventListener("keydown", (e) => {
  if (e.key === "Tab") { e.preventDefault(); document.execCommand("insertText", false, "  "); }
  if ((e.metaKey || e.ctrlKey) && e.key === "s") { e.preventDefault(); $("#ruleSave").click(); }
});
async function runTest() {
  const r = await api("/api/rules/test", { condition: $("#testExpr").value });
  if (!r.ok) {
    $("#testMsg").className = "msg err"; $("#testMsg").textContent = r.error; $("#testTable").innerHTML = ""; return;
  }
  $("#testMsg").className = "msg ok";
  $("#testMsg").textContent = `${r.count} live connection${r.count === 1 ? "" : "s"} match`;
  table($("#testTable"), [connCols[0], connCols[2], connCols[3], connCols[4]], r.matches, null, openFlow);
}
$("#testBtn").addEventListener("click", runTest);
$("#testExpr").addEventListener("keydown", (e) => { if (e.key === "Enter") runTest(); });

// history
async function loadHistory() {
  const hours = $("#histHours").value, q = encodeURIComponent($("#histSearch").value.trim());
  const [ev, top] = await Promise.all([
    api(`/api/events?q=${q}&hours=${hours}&kind=${$("#histKind").value}&limit=2000`),
    api(`/api/history?hours=${hours}`),
  ]);
  state.history = ev;
  renderHistoryTable();
  bars($("#histApps"), top.apps.slice(0, 10).map((a) => ({
    name: a.app, label: fmtBytes(a.bytes_in + a.bytes_out), segs: [{ v: a.bytes_in, c: COLOR.in }, { v: a.bytes_out, c: COLOR.out }],
    tip: legendRow(COLOR.in, "Downloaded", fmtBytes(a.bytes_in)) + legendRow(COLOR.out, "Uploaded", fmtBytes(a.bytes_out)) + ttRow("Connections", a.conns),
    onClick: () => { $("#histSearch").value = a.app; loadHistory(); },
  })), { empty: "no closed connections in this range yet" });
  bars($("#histCountries"), top.countries.slice(0, 10).map((c) => ({
    name: c.country || c.cc, icon: flag(c.cc) + " ", label: fmtBytes(c.bytes), segs: [{ v: c.bytes, c: COLOR.in }],
    tip: ttRow("Connections", c.conns) + ttRow("Data", fmtBytes(c.bytes)),
    onClick: () => { $("#histSearch").value = c.cc; loadHistory(); },
  })), { empty: "no closed connections in this range yet" });
}
function renderHistoryTable() {
  const rows = state.history || [];
  const cols = [
    { key: "ts", label: "Time", get: (e) => e.ts, render: (e) => fmtDateTime(e.ts) },
    { key: "kind", label: "Event", get: (e) => e.kind, render: (e) => `<span class="tag">${esc(e.kind)}</span>` },
    { key: "app", label: "App", get: (e) => e.app, render: (e) => `<b>${esc(e.app)}</b> <span class="mut">${esc(e.process !== e.app ? e.process : "")}</span>` },
    { key: "dest", label: "Destination", get: (e) => e.hostname || e.remote_ip, render: (e) => `${esc(e.hostname)} <span class="mono mut">${esc(endpoint(e.remote_ip, e.remote_port))}</span>` },
    { key: "cc", label: "Location", get: (e) => e.country_code, render: (e) => e.country_code ? `${flag(e.country_code)} ${esc(e.country_code)} <span class="mut">${esc(e.city)}</span>` : `<span class="tag">${esc(e.scope)}</span>` },
    { key: "org", label: "Organisation", get: (e) => e.org },
    { key: "bytes", label: "Data", num: true, get: (e) => (e.bytes_in || 0) + (e.bytes_out || 0), render: (e) => fmtBytes((e.bytes_in || 0) + (e.bytes_out || 0)) },
    { key: "duration", label: "Duration", num: true, get: (e) => e.duration, render: (e) => e.kind === "close" ? fmtDur(e.duration) : "" },
  ];
  const n = table($("#histTable"), cols, rows, state.sort.history);
  $("#histCount").textContent = `${n} events${n >= 2000 ? " (showing newest 2000)" : ""}`;
}
$("#histGo").addEventListener("click", loadHistory);
$("#histSearch").addEventListener("keydown", (e) => { if (e.key === "Enter") loadHistory(); });
["#histHours", "#histKind"].forEach((id) => $(id).addEventListener("input", loadHistory));

// boot
initMap();
poll();
