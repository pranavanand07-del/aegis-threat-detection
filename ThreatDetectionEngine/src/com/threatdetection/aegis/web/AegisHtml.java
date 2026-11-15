package com.threatdetection.aegis.web;

/** The AEGIS dashboard page (served at /aegis). Kept as a plain text block so the project stays dependency-free. */
final class AegisHtml {
    private AegisHtml() {}

    static final String PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AEGIS - Security Operations</title>
<style>
:root{--bg:#0f1117;--panel:#171a23;--panel2:#1d2130;--line:#2a3042;--txt:#e6e9f0;--mut:#8b93a7;--acc:#4ade80;
--crit:#ff4d4d;--high:#ff9f43;--med:#ffd24d;--low:#5ac8fa;--safe:#4ade80;--obs:#4ade80;--api:#5ac8fa;--sim:#b388ff}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--txt);font:14px/1.45 Segoe UI,Roboto,Helvetica,Arial,sans-serif}
a{color:var(--acc);text-decoration:none}
header{display:flex;flex-wrap:wrap;align-items:center;gap:12px;padding:12px 20px;border-bottom:1px solid var(--line);position:sticky;top:0;background:rgba(15,17,23,.96);z-index:20}
h1{font-size:20px;margin:0;letter-spacing:3px}
h1 small{font-size:11px;letter-spacing:0;color:var(--mut);font-weight:normal;margin-left:8px}
.sp{flex:1}
select,input[type=text],input[type=datetime-local]{background:var(--panel2);color:var(--txt);border:1px solid var(--line);border-radius:6px;padding:6px 8px;font:inherit}
button{background:var(--panel2);color:var(--txt);border:1px solid var(--line);border-radius:6px;padding:6px 12px;cursor:pointer;font:inherit}
button:hover{border-color:var(--acc)}
.pill{padding:3px 10px;border-radius:12px;font-size:12px;font-weight:600;border:1px solid}
.ok{color:var(--acc);border-color:var(--acc)}.bad{color:var(--high);border-color:var(--high)}
main{padding:16px 20px;max-width:1500px;margin:0 auto}
.grid{display:grid;gap:14px;margin-bottom:14px}
.kpis{grid-template-columns:repeat(auto-fit,minmax(150px,1fr))}
.two{grid-template-columns:2fr 1fr}.three{grid-template-columns:1.4fr 1fr 1fr}
@media(max-width:1000px){.two,.three{grid-template-columns:1fr}}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px;min-width:0}
.card h2{margin:0 0 10px;font-size:13px;text-transform:uppercase;letter-spacing:1.2px;color:var(--mut);font-weight:600}
.kpi .v{font-size:28px;font-weight:700;line-height:1.1}.kpi .l{color:var(--mut);font-size:12px;margin-top:2px}.kpi .s{color:var(--mut);font-size:11px;margin-top:4px}
canvas{display:block;width:100%}
table{width:100%;border-collapse:collapse;font-size:13px}
th{color:var(--mut);text-align:left;font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.8px;padding:6px 8px;border-bottom:1px solid var(--line)}
td{padding:7px 8px;border-bottom:1px solid #20253a;vertical-align:top}
tr.row{cursor:pointer}tr.row:hover td{background:#1b2030}
.wrap{overflow-x:auto}
.b{display:inline-block;padding:1px 7px;border-radius:4px;font-size:11px;font-weight:700;white-space:nowrap}
.lv-CRITICAL{background:rgba(255,77,77,.18);color:var(--crit)}.lv-HIGH{background:rgba(255,159,67,.18);color:var(--high)}
.lv-MEDIUM{background:rgba(255,210,77,.16);color:var(--med)}.lv-LOW{background:rgba(90,200,250,.16);color:var(--low)}.lv-SAFE{background:rgba(74,222,128,.14);color:var(--safe)}
.s-OBSERVED{border:1px solid var(--obs);color:var(--obs)}.s-API{border:1px solid var(--api);color:var(--api)}.s-SIMULATED{border:1px dashed var(--sim);color:var(--sim)}
.t{background:#242a3d;color:#c5cbe0}.t-EXTERNAL{color:var(--high)}.t-INTERNAL{color:var(--low)}
.r-MALICIOUS{background:rgba(255,77,77,.2);color:var(--crit)}.r-SUSPICIOUS{background:rgba(255,159,67,.2);color:var(--high)}.r-NO_DATA{background:#242a3d;color:var(--mut)}.r-INTERNAL{background:rgba(90,200,250,.14);color:var(--low)}
.mut{color:var(--mut)}.small{font-size:12px}
.dot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:6px}
.d-ACTIVE{background:var(--acc)}.d-WAITING{background:var(--med)}.d-ERROR{background:var(--crit)}.d-DISABLED{background:#4a5068}
.src{padding:6px 0;border-bottom:1px solid #20253a}.src:last-child{border:0}
.bar{height:8px;border-radius:4px;background:#242a3d;overflow:hidden}.bar i{display:block;height:100%}
.exp td{background:#141826;padding:12px 16px}
.contrib{display:grid;grid-template-columns:190px 46px 1fr;gap:8px;align-items:center;margin:4px 0}
.mapwrap{position:relative}
#tip{position:absolute;pointer-events:none;background:#0b0d13;border:1px solid var(--line);border-radius:8px;padding:8px 10px;font-size:12px;max-width:320px;display:none;z-index:5}
.ctl{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin-top:10px}
.ctl input[type=range]{flex:1;min-width:160px}
.legend{display:flex;flex-wrap:wrap;gap:14px;margin-top:8px;font-size:12px;color:var(--mut)}
.note{background:#1a1f2e;border-left:3px solid var(--med);padding:8px 10px;border-radius:4px;font-size:12px;color:#c9cfe0;margin-top:10px}
.filters{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:10px;align-items:center}
</style>
</head>
<body>
<header>
  <h1>AEGIS<small>Security operations dashboard</small></h1>
  <span id="health" class="pill ok">...</span>
  <span class="sp"></span>
  <label class="mut small">Time range
    <select id="range">
      <option value="5">Last 5 min</option><option value="15">Last 15 min</option>
      <option value="60" selected>Last hour</option><option value="360">Last 6 hours</option>
      <option value="1440">Last 24 hours</option><option value="0">Everything stored</option>
      <option value="custom">Custom...</option>
    </select></label>
  <span id="custom" style="display:none"><input type="datetime-local" id="cFrom"> to <input type="datetime-local" id="cTo"></span>
  <a href="/">Platform site</a><a href="/classic">Classic dashboard</a><a href="/map">Classic map</a>
</header>
<main>
  <div class="grid kpis" id="kpis"></div>

  <div class="grid two">
    <div class="card"><h2>Risk score and alert volume</h2><canvas id="chart" height="220"></canvas>
      <div class="legend"><span><i class="dot" style="background:var(--crit)"></i>Critical</span><span><i class="dot" style="background:var(--high)"></i>High</span><span><i class="dot" style="background:var(--med)"></i>Medium</span><span><i class="dot" style="background:var(--low)"></i>Low</span><span>White line: max risk score &middot; dotted: average</span></div></div>
    <div class="card"><h2>System health and data sources</h2><div id="health-box"></div></div>
  </div>

  <div class="card" style="margin-bottom:14px">
    <h2>Threat map <span class="mut" style="text-transform:none;letter-spacing:0">- alerts (LOW and above) with a usable location</span></h2>
    <div class="mapwrap"><canvas id="map"></canvas><div id="tip"></div></div>
    <div class="ctl">
      <button id="play">&#9654; Play</button>
      <input type="range" id="slider" min="0" max="1000" value="1000">
      <select id="speed"><option value="0.5">0.5x</option><option value="1" selected>1x</option><option value="2">2x</option><option value="4">4x</option></select>
      <span id="cursor" class="mut small"></span>
    </div>
    <div class="ctl small">
      <label><input type="checkbox" id="f-OBSERVED" checked> Observed</label>
      <label><input type="checkbox" id="f-API" checked> API</label>
      <label><input type="checkbox" id="f-SIMULATED" checked> Simulated</label>
      <span id="mapstat" class="mut"></span>
    </div>
    <div class="legend">
      <span><svg width="16" height="16"><circle cx="8" cy="8" r="5" fill="#ff9f43" stroke="#fff" stroke-width="1.5"/></svg> Observed (location estimated from a GeoIP database)</span>
      <span><svg width="16" height="16"><circle cx="8" cy="8" r="4" fill="#ff9f43"/><circle cx="8" cy="8" r="7" fill="none" stroke="#5ac8fa" stroke-dasharray="2 2"/></svg> API-submitted</span>
      <span><svg width="16" height="16"><circle cx="8" cy="8" r="5" fill="none" stroke="#b388ff" stroke-width="2" stroke-dasharray="3 2"/></svg> Simulated (demo location, not real)</span>
      <span><svg width="16" height="16"><rect x="3" y="3" width="10" height="10" fill="#4ade80"/></svg> Protected server</span>
    </div>
    <div class="note" id="mapnote"></div>
  </div>

  <div class="grid three">
    <div class="card"><h2>Incidents</h2><div class="wrap" id="incidents"></div></div>
    <div class="card"><h2>Attack sources and reputation</h2><div class="wrap" id="attackers"></div></div>
    <div class="card"><h2>Targets and traffic mix</h2><div id="targets"></div></div>
  </div>

  <div class="card">
    <h2>Alerts with explanation <span class="mut" style="text-transform:none;letter-spacing:0">- click a row to see which rules produced the score</span></h2>
    <div class="filters">
      <select id="f-level"><option value="LOW">All alerts</option><option value="MEDIUM">Medium and above</option><option value="HIGH">High and above</option><option value="CRITICAL">Critical only</option><option value="ALL">Include safe events</option></select>
      <select id="f-source"><option value="ALL">All data sources</option><option value="OBSERVED">Observed</option><option value="API">API</option><option value="SIMULATED">Simulated</option></select>
      <input type="text" id="f-q" placeholder="Search IP, user, target...">
      <span id="alertcount" class="mut small"></span>
    </div>
    <div class="wrap" id="alerts"></div>
  </div>
</main>
<script>
const $ = id => document.getElementById(id);
const LV = {CRITICAL:'#ff4d4d', HIGH:'#ff9f43', MEDIUM:'#ffd24d', LOW:'#5ac8fa', SAFE:'#4ade80'};
const state = {range:'60', playing:false, cursor:0, from:0, to:0, events:[], geo:null, cfg:null, expanded:new Set(), drawn:[], series:[]};
const esc = s => String(s == null ? '' : s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
const fmtN = n => Number(n).toLocaleString();
const pad = n => String(n).padStart(2, '0');

function windowMs() {
  const now = Date.now();
  if (state.range === 'custom') {
    const f = Date.parse($('cFrom').value), t = Date.parse($('cTo').value);
    if (!isNaN(f) && !isNaN(t) && t > f) return {from:f, to:t};
  }
  const m = Number(state.range);
  if (!m || state.range === 'custom') return {from:0, to:now};
  return {from:now - m * 60000, to:now};
}
function q(extra) {
  const w = windowMs();
  state.from = w.from; state.to = w.to;
  return '?from=' + w.from + '&to=' + w.to + (extra ? '&' + extra : '');
}
async function get(path, extra) {
  const r = await fetch(path + q(extra));
  if (!r.ok) throw new Error(path + ' ' + r.status);
  return r.json();
}
function timeStr(t, long) {
  const d = new Date(t);
  const hms = pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds());
  return long ? d.toLocaleDateString() + ' ' + hms : hms;
}
function ago(ms) {
  if (ms < 0) return 'never';
  const s = Math.round(ms / 1000);
  if (s < 60) return s + 's ago';
  if (s < 3600) return Math.round(s / 60) + 'm ago';
  return Math.round(s / 3600) + 'h ago';
}
function uptime(ms) {
  const m = Math.floor(ms / 60000);
  return m < 60 ? m + ' min' : Math.floor(m / 60) + ' h ' + (m % 60) + ' min';
}
const lvBadge = l => '<span class="b lv-' + l + '">' + l + '</span>';
const srcBadge = s => '<span class="b s-' + s + '">' + s + '</span>';

// ------------------------------------------------------------------ KPIs, health
function renderOverview(o) {
  const k = o.kpi;
  const cards = [
    ['Events analyzed', fmtN(k.analyzedRange), 'in range &middot; ' + fmtN(k.analyzedSinceStart) + ' since start', ''],
    ['Critical', fmtN(k.critical), 'alerts in range', LV.CRITICAL],
    ['High', fmtN(k.high), 'alerts in range', LV.HIGH],
    ['Medium', fmtN(k.medium), 'alerts in range', LV.MEDIUM],
    ['Low', fmtN(k.low), 'alerts in range', LV.LOW],
    ['Open incidents', fmtN(k.openIncidents), fmtN(k.totalIncidents) + ' total', ''],
    ['Blocked IPs', fmtN(k.blockedIps), 'currently auto-blocked', ''],
    ['Ingestion rate', k.rate10s.toFixed(1) + '/s', k.rate60s.toFixed(1) + '/s over last minute', '']
  ];
  $('kpis').innerHTML = cards.map(c => '<div class="card kpi"><div class="v" style="color:' + (c[3] || 'var(--txt)') + '">' + c[1] +
    '</div><div class="l">' + c[0] + '</div><div class="s">' + c[2] + '</div></div>').join('');

  const h = o.health;
  const pill = $('health');
  pill.textContent = h.status;
  pill.className = 'pill ' + (h.status === 'HEALTHY' ? 'ok' : 'bad');
  let html = '<div class="small mut" style="margin-bottom:8px">Uptime ' + uptime(h.uptimeMs) + ' &middot; heap ' + h.heapUsedMb + '/' + h.heapMaxMb +
    ' MB (' + h.heapPct.toFixed(0) + '%) &middot; ' + fmtN(h.eventsInMemory) + ' events / ' + fmtN(h.alertsInMemory) + ' alerts in memory &middot; ' +
    h.errors + ' pipeline errors</div>';
  html += o.health.sources.map(s => '<div class="src"><span class="dot d-' + s.state + '"></span><b>' + esc(s.name) + '</b> <span class="mut small">' + s.state +
    (s.count ? ' &middot; ' + fmtN(s.count) + ' events, last ' + ago(s.lastEventAgeMs) : '') + '</span><div class="mut small">' + esc(s.detail) + '</div></div>').join('');
  html += '<div class="small" style="margin-top:10px"><b>Data mix</b> (since start)</div>';
  for (const key of Object.keys(o.bySource)) {
    const b = o.bySource[key];
    html += '<div class="small" style="margin-top:4px">' + srcBadge(key) + ' ' + fmtN(b.count) + ' <span class="mut">' + esc(b.description) + '</span></div>';
  }
  html += '<div class="small mut" style="margin-top:10px">GeoIP database: ' + (o.config.geoDatabase ? fmtN(o.config.geoRows) + ' ranges' : 'not loaded') +
    ' &middot; threat-intel feeds: ' + o.config.intelFeeds + ' (' + fmtN(o.config.intelEntries) + ' entries)' +
    (o.config.persistFile ? ' &middot; alerts persisted' : ' &middot; persistence off') + '</div>';
  $('health-box').innerHTML = html;
  state.cfg = o.config;
  state.series = o.series;
  drawChart();
}

// ------------------------------------------------------------------ chart
function setupCanvas(cv, h) {
  const dpr = window.devicePixelRatio || 1;
  const w = cv.clientWidth;
  cv.width = w * dpr; cv.height = h * dpr; cv.style.height = h + 'px';
  const c = cv.getContext('2d');
  c.setTransform(dpr, 0, 0, dpr, 0, 0);
  return {c, w, h};
}
function drawChart() {
  const {c, w, h} = setupCanvas($('chart'), 220);
  c.clearRect(0, 0, w, h);
  const s = state.series;
  const L = 40, R = 40, T = 10, B = 24, pw = w - L - R, ph = h - T - B;
  c.font = '11px sans-serif'; c.fillStyle = '#8b93a7'; c.strokeStyle = '#2a3042';
  if (!s.length) return;
  let maxN = 1, maxR = 100;
  s.forEach(r => { maxN = Math.max(maxN, r.c + r.h + r.m + r.l); maxR = Math.max(maxR, r.max); });
  for (let i = 0; i <= 4; i++) {
    const y = T + ph - ph * i / 4;
    c.beginPath(); c.moveTo(L, y); c.lineTo(w - R, y); c.stroke();
    c.textAlign = 'right'; c.fillText(Math.round(maxN * i / 4), L - 6, y + 4);
    c.textAlign = 'left'; c.fillText(Math.round(maxR * i / 4), w - R + 6, y + 4);
  }
  const bw = Math.max(2, pw / s.length - 2);
  s.forEach((r, i) => {
    const x = L + pw * (i + 0.5) / s.length - bw / 2;
    let y = T + ph;
    [['l', LV.LOW], ['m', LV.MEDIUM], ['h', LV.HIGH], ['c', LV.CRITICAL]].forEach(p => {
      const hh = ph * r[p[0]] / maxN;
      c.fillStyle = p[1]; c.fillRect(x, y - hh, bw, hh); y -= hh;
    });
  });
  const line = (key, dash, col) => {
    c.beginPath(); c.setLineDash(dash); c.strokeStyle = col; c.lineWidth = 1.5;
    s.forEach((r, i) => {
      const x = L + pw * (i + 0.5) / s.length, y = T + ph - ph * r[key] / maxR;
      if (i) c.lineTo(x, y); else c.moveTo(x, y);
    });
    c.stroke(); c.setLineDash([]);
  };
  line('max', [], '#ffffff'); line('avg', [3, 3], '#c5cbe0');
  c.fillStyle = '#8b93a7'; c.textAlign = 'center';
  [0, 0.5, 1].forEach(f => {
    const idx = Math.min(s.length - 1, Math.floor(f * (s.length - 1)));
    c.fillText(timeStr(s[idx].t, state.to - state.from > 86400000), L + pw * (idx + 0.5) / s.length, h - 6);
  });
}

// ------------------------------------------------------------------ tables
function renderAlerts(list) {
  $('alertcount').textContent = list.length + ' shown (newest first)';
  if (!list.length) { $('alerts').innerHTML = '<div class="mut small" style="padding:12px">No alerts in this range and filter.</div>'; return; }
  let h = '<table><tr><th>Time</th><th>Level</th><th>Score</th><th>Data</th><th>Source</th><th>Event</th><th>Reputation</th><th></th></tr>';
  for (const e of list) {
    const open = state.expanded.has(e.id);
    h += '<tr class="row" data-id="' + e.id + '"><td class="small">' + timeStr(e.ts, state.to - state.from > 86400000) + '</td><td>' + lvBadge(e.level) + '</td><td><b>' + e.score + '</b></td><td>' + srcBadge(e.source) +
      '</td><td>' + (e.ip ? esc(e.ip) + ' <span class="b t t-' + e.ipClass + '">' + (e.ipClass === 'INTERNAL' ? 'INT' : 'EXT') + '</span>' : '<span class="mut">' + esc(e.host || 'local host') + '</span>') +
      '<div class="mut small">' + esc(e.geoClass === 'UNAVAILABLE' ? 'no reliable location' : (e.city || '') + (e.country ? ', ' + e.country : '')) + '</div></td><td>' + esc(e.summary) +
      '<div class="mut small">' + e.rules.map(r => esc(r.rule)).join(' &middot; ') + '</div></td><td><span class="b r-' + e.rep + '">' + e.rep.replace('_', ' ') + '</span></td><td>' +
      (e.blocked ? '<span class="b lv-CRITICAL">BLOCKED</span>' : '') + '</td></tr>';
    if (open) h += '<tr class="exp"><td colspan="8">' + explain(e) + '</td></tr>';
  }
  $('alerts').innerHTML = h + '</table>';
}
function explain(e) {
  const max = Math.max(1, ...e.rules.map(r => r.score));
  let h = '<div class="small mut" style="margin-bottom:6px">Why this score (' + e.score + '): each row is one rule. <b>core</b> = original detectors, <b>aegis</b> = added rules.</div>';
  h += e.rules.length ? e.rules.map(r => '<div class="contrib"><div><b>' + esc(r.rule) + '</b> <span class="b t">' + r.origin + '</span></div><div>+' + r.score + '</div><div><div class="bar"><i style="width:' +
    (100 * r.score / max) + '%;background:' + LV[e.level] + '"></i></div><div class="small mut">' + esc(r.detail) + '</div></div></div>').join('') : '<div class="small mut">No rule fired.</div>';
  const loc = {ESTIMATED:'Estimated location from a GeoIP database (city level at best)', SIMULATED:'Simulated demo location - not real',
    INTERNAL:'Internal network address', UNAVAILABLE:'No reliable location available (' + esc(e.geoSource || '') + ')'}[e.geoClass] || e.geoClass;
  h += '<div class="small" style="margin-top:8px"><b>Reputation:</b> ' + esc(e.repDetail) + ' &middot; <b>Location:</b> ' + loc + ' &middot; <b>Channel:</b> ' + esc(e.channel) +
    (e.incident ? ' &middot; <b>Incident:</b> ' + e.incident : '') + '</div>';
  h += '<div class="small" style="margin-top:6px"><b>Data source:</b> ' + esc(e.source) + ' &middot; ' + esc(e.sourceMeaning || '') + '</div>';
  if (e.enrichments && e.enrichments.length) h += '<div class="small" style="margin-top:6px"><b>Enriched (extra context, not proof):</b>' +
    e.enrichments.map(x => '<div>' + esc(x.provider) + ' - ' + esc(x.status === 'OK' ? x.verdict : x.status) + ': ' + esc(x.detail) + (x.cached ? ' (cached)' : '') + '</div>').join('') + '</div>';
  return h;
}
function renderIncidents(list) {
  if (!list.length) { $('incidents').innerHTML = '<div class="mut small">No incidents in this range. An incident opens when an actor reaches a MEDIUM alert.</div>'; return; }
  $('incidents').innerHTML = '<table><tr><th>Incident</th><th>Level</th><th>Alerts</th><th>Window</th></tr>' + list.slice(0, 12).map(i =>
    '<tr><td><b>' + i.id + '</b> <span class="b ' + (i.status === 'OPEN' ? 'lv-HIGH' : 't') + '">' + i.status + '</span><div class="small">' + esc(i.title) + '</div><div class="small mut">' +
    i.sources.map(srcBadge).join(' ') + (i.location ? ' ' + esc(i.location) : '') + (i.blocked ? ' &middot; blocked' : '') + '</div></td><td>' + lvBadge(i.level) + '<div class="small mut">max ' + i.maxScore + '</div></td><td>' + i.count +
    '</td><td class="small">' + timeStr(i.firstSeen) + '<br>' + timeStr(i.lastSeen) + '</td></tr>').join('') + '</table>';
}
function renderIntel(d) {
  if (!d.attackers.length) $('attackers').innerHTML = '<div class="mut small">No remote attack sources in this range.</div>';
  else $('attackers').innerHTML = '<table><tr><th>Source</th><th>Reputation</th><th>Alerts</th><th>Max</th></tr>' + d.attackers.map(a =>
    '<tr><td>' + esc(a.ip) + ' <span class="b t t-' + a.ipClass + '">' + (a.ipClass === 'INTERNAL' ? 'INT' : 'EXT') + '</span><div class="small mut">' + srcBadge(a.source) + ' ' +
    esc(a.place || (a.geoClass === 'UNAVAILABLE' ? 'no reliable location' : '')) + '</div></td><td><span class="b r-' + a.rep + '" title="' + esc(a.repDetail) + '">' + a.rep.replace('_', ' ') + '</span>' +
    (a.blocked ? '<div class="small mut">blocked</div>' : '') + '</td><td>' + a.count + '</td><td>' + a.maxScore + '</td></tr>').join('') + '</table>';
  const tmax = Math.max(1, ...d.targets.map(t => t.count));
  let h = '<div class="small mut" style="margin-bottom:6px">Most targeted</div>' + (d.targets.length ? d.targets.map(t => '<div style="margin:6px 0"><div class="small"><b>' + esc(t.target) +
    '</b> <span class="mut">' + t.type + ' &middot; ' + t.count + '</span></div><div class="bar"><i style="width:' + (100 * t.count / tmax) + '%;background:var(--acc)"></i></div></div>').join('') : '<div class="mut small">None yet.</div>');
  const tot = Math.max(1, d.internal + d.external + d.hostLocal);
  h += '<div class="small mut" style="margin:14px 0 6px">Internal vs external origin</div><div class="bar" style="height:12px;display:flex"><i style="width:' + (100 * d.external / tot) + '%;background:var(--high)"></i><i style="width:' +
    (100 * d.internal / tot) + '%;background:var(--low)"></i><i style="width:' + (100 * d.hostLocal / tot) + '%;background:#4a5068"></i></div><div class="small mut" style="margin-top:4px">External ' + d.external + ' &middot; Internal ' + d.internal + ' &middot; Host-local ' + d.hostLocal + '</div>';
  const g = d.geoClass, gl = {ESTIMATED:'estimated (GeoIP)', SIMULATED:'simulated', INTERNAL:'internal', UNAVAILABLE:'no reliable location'};
  h += '<div class="small mut" style="margin:14px 0 4px">Location quality</div><div class="small">' + Object.keys(g).map(k => (gl[k] || k) + ': <b>' + g[k] + '</b>').join(' &middot; ') + '</div>';
  $('targets').innerHTML = h;
}

// ------------------------------------------------------------------ map
let landCanvas = null, MW = 0, MH = 0, MDPR = 1;
const LON0 = -180, LON1 = 180, LAT0 = -60, LAT1 = 84;
function mp(lon, lat) { return [(lon - LON0) / (LON1 - LON0) * MW, (LAT1 - lat) / (LAT1 - LAT0) * MH]; }
function buildLand() {
  const cv = $('map');
  MDPR = window.devicePixelRatio || 1;
  MW = cv.clientWidth; MH = Math.round(MW * (LAT1 - LAT0) / (LON1 - LON0));
  cv.width = MW * MDPR; cv.height = MH * MDPR; cv.style.height = MH + 'px';
  landCanvas = document.createElement('canvas');
  landCanvas.width = cv.width; landCanvas.height = cv.height;
  if (!state.geo) return;
  const c = landCanvas.getContext('2d');
  c.setTransform(MDPR, 0, 0, MDPR, 0, 0);
  const paint = (feature, fill) => {
    c.beginPath();
    feature.forEach(ring => ring.forEach((p, i) => { const xy = mp(p[0], p[1]); if (i) c.lineTo(xy[0], xy[1]); else c.moveTo(xy[0], xy[1]); }));
    c.fillStyle = fill; c.fill('evenodd');
  };
  state.geo.land.forEach(f => paint(f, 'rgba(120,140,185,0.28)'));
  paint(state.geo.india, 'rgba(74,222,128,0.28)');
}
async function loadGeometry() {
  try { state.geo = await (await fetch('/api/map/geometry')).json(); } catch (e) { console.error('geometry', e); }
  buildLand(); drawMap();
}
function srcVisible(e) { return $('f-' + e.source).checked; }
function drawMap() {
  const cv = $('map');
  if (!MW) return;
  const c = cv.getContext('2d');
  c.setTransform(MDPR, 0, 0, MDPR, 0, 0);
  c.clearRect(0, 0, MW, MH);
  c.fillStyle = '#10131b'; c.fillRect(0, 0, MW, MH);
  if (landCanvas) c.drawImage(landCanvas, 0, 0, MW, MH);
  const cfg = state.cfg;
  const tp = cfg ? mp(cfg.targetLon, cfg.targetLat) : null;
  const span = Math.max(1, state.to - state.from), trail = span * 0.06;
  state.drawn = [];
  let plotted = 0, unplotted = 0, hidden = 0;
  for (const e of state.events) {
    if (!srcVisible(e)) { hidden++; continue; }
    if (e.lat === undefined) { unplotted++; continue; }
    if (e.ts > state.cursor) continue;
    plotted++;
    const p = mp(e.lon, e.lat);
    const age = state.cursor - e.ts;
    const fresh = state.playing ? Math.max(0.25, 1 - age / (trail * 3)) : 0.85;
    if (tp && age < trail) {
      c.strokeStyle = LV[e.level]; c.globalAlpha = 0.35 * (1 - age / trail); c.lineWidth = 1;
      c.beginPath(); c.moveTo(p[0], p[1]);
      c.quadraticCurveTo((p[0] + tp[0]) / 2, Math.min(p[1], tp[1]) - 40, tp[0], tp[1]); c.stroke();
    }
    c.globalAlpha = fresh;
    const r = 3 + Math.min(4, e.score / 40);
    if (e.source === 'SIMULATED') {
      c.strokeStyle = LV[e.level]; c.lineWidth = 2; c.setLineDash([3, 2]);
      c.beginPath(); c.arc(p[0], p[1], r, 0, 6.2832); c.stroke(); c.setLineDash([]);
    } else {
      c.fillStyle = LV[e.level]; c.beginPath(); c.arc(p[0], p[1], r, 0, 6.2832); c.fill();
      if (e.source === 'API') { c.strokeStyle = '#5ac8fa'; c.lineWidth = 1; c.setLineDash([2, 2]); c.beginPath(); c.arc(p[0], p[1], r + 3, 0, 6.2832); c.stroke(); c.setLineDash([]); }
      else { c.strokeStyle = '#ffffff'; c.lineWidth = 1.2; c.beginPath(); c.arc(p[0], p[1], r, 0, 6.2832); c.stroke(); }
    }
    c.globalAlpha = 1;
    state.drawn.push({x:p[0], y:p[1], e:e});
  }
  if (tp) {
    c.fillStyle = '#4ade80'; c.fillRect(tp[0] - 5, tp[1] - 5, 10, 10);
    c.fillStyle = '#c5cbe0'; c.font = '11px sans-serif'; c.textAlign = 'left'; c.fillText(cfg.targetName, tp[0] + 9, tp[1] + 4);
  }
  $('cursor').textContent = timeStr(state.cursor, true);
  $('mapstat').textContent = plotted + ' plotted';
  const noLoc = unplotted;
  $('mapnote').innerHTML = '<b>How to read this map.</b> Locations are <b>estimates</b> (IP geolocation is city-level at best, often an ISP hub). ' +
    (cfg && cfg.geoDatabase ? 'A GeoIP database is loaded, so observed and API events with a match are plotted.' :
     'No GeoIP database is loaded, so <b>observed and API events are not plotted</b> (their locations would be guesses); only simulated events use demo locations. Load one with -Daegis.geo.csv=file.csv.') +
    ' ' + noLoc + ' alert(s) in range have no reliable location and appear only in the tables.' + (hidden ? ' ' + hidden + ' hidden by the data-source filter.' : '');
}
$('map').addEventListener('mousemove', ev => {
  const r = $('map').getBoundingClientRect(), x = ev.clientX - r.left, y = ev.clientY - r.top;
  let best = null, bd = 100;
  for (const d of state.drawn) { const dd = (d.x - x) * (d.x - x) + (d.y - y) * (d.y - y); if (dd < bd) { bd = dd; best = d; } }
  const tip = $('tip');
  if (!best) { tip.style.display = 'none'; return; }
  const e = best.e;
  tip.innerHTML = lvBadge(e.level) + ' ' + srcBadge(e.source) + ' <b>' + e.score + '</b><br>' + esc(e.ip) + '<br>' + esc(e.city || '') + (e.country ? ', ' + esc(e.country) : '') +
    ' <span class="mut">(' + (e.geoClass === 'SIMULATED' ? 'simulated location' : 'estimated location') + ')</span><br>' + esc(e.summary) + '<br><span class="mut">' + timeStr(e.ts, true) + '</span>';
  tip.style.display = 'block';
  tip.style.left = Math.min(x + 14, r.width - 330) + 'px'; tip.style.top = (y + 14) + 'px';
});
$('map').addEventListener('mouseleave', () => { $('tip').style.display = 'none'; });

// playback
let raf = 0, lastFrame = 0;
function setCursorFromSlider() { state.cursor = state.from + (state.to - state.from) * Number($('slider').value) / 1000; drawMap(); }
function stopPlay() { state.playing = false; $('play').innerHTML = '&#9654; Play'; cancelAnimationFrame(raf); }
function startPlay() {
  if (Number($('slider').value) >= 1000) { $('slider').value = 0; setCursorFromSlider(); }
  state.playing = true; $('play').innerHTML = '&#10074;&#10074; Pause'; lastFrame = performance.now();
  const step = now => {
    if (!state.playing) return;
    const dt = now - lastFrame; lastFrame = now;
    const frac = Number($('slider').value) / 1000 + dt / 25000 * Number($('speed').value);   // 25 s for the whole range at 1x
    if (frac >= 1) { $('slider').value = 1000; setCursorFromSlider(); stopPlay(); return; }
    $('slider').value = Math.round(frac * 1000); setCursorFromSlider();
    raf = requestAnimationFrame(step);
  };
  raf = requestAnimationFrame(step);
}
$('play').onclick = () => state.playing ? stopPlay() : startPlay();
$('slider').oninput = () => { if (state.playing) stopPlay(); setCursorFromSlider(); };
['OBSERVED', 'API', 'SIMULATED'].forEach(s => $('f-' + s).onchange = drawMap);

// ------------------------------------------------------------------ refresh loop
async function refresh() {
  try {
    const alertQ = 'level=' + $('f-level').value + '&source=' + $('f-source').value + '&limit=100&q=' + encodeURIComponent($('f-q').value);
    const [o, a, i, d] = await Promise.all([get('/aegis/api/overview'), get('/aegis/api/alerts', alertQ), get('/aegis/api/incidents'), get('/aegis/api/intel')]);
    renderOverview(o); renderAlerts(a.alerts); renderIncidents(i.incidents); renderIntel(d);
    if (!state.playing) {
      const ev = await get('/aegis/api/events', 'max=3000');
      state.events = ev.events;
      const live = state.range !== 'custom';
      if (Number($('slider').value) >= 1000 || live) { state.cursor = state.to; $('slider').value = 1000; }
      drawMap();
    }
  } catch (e) { $('health').textContent = 'DISCONNECTED'; $('health').className = 'pill bad'; console.error(e); }
}
$('alerts').addEventListener('click', ev => {
  const tr = ev.target.closest('tr.row');
  if (!tr) return;
  const id = Number(tr.dataset.id);
  if (state.expanded.has(id)) state.expanded.delete(id); else state.expanded.add(id);
  refresh();
});
$('range').onchange = () => {
  state.range = $('range').value;
  $('custom').style.display = state.range === 'custom' ? 'inline' : 'none';
  if (state.range === 'custom' && !$('cFrom').value) {
    const to = new Date(), from = new Date(Date.now() - 3600000), f = d => d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) + 'T' + pad(d.getHours()) + ':' + pad(d.getMinutes());
    $('cFrom').value = f(from); $('cTo').value = f(to);
  }
  stopPlay(); $('slider').value = 1000; refresh();
};
$('cFrom').onchange = $('cTo').onchange = () => { stopPlay(); $('slider').value = 1000; refresh(); };
['f-level', 'f-source'].forEach(id => $(id).onchange = refresh);
let qt = 0; $('f-q').oninput = () => { clearTimeout(qt); qt = setTimeout(refresh, 300); };
window.addEventListener('resize', () => { buildLand(); drawMap(); drawChart(); });
loadGeometry(); refresh(); setInterval(refresh, 3000);
</script>
</body>
</html>
""";
}
