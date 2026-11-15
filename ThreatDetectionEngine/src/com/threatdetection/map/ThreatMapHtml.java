package com.threatdetection.map;

/**
 * The Threat Map page (HTML + CSS + JS), served at /map.
 * Kept as plain text blocks (like DashboardHtml) so the project stays dependency-free.
 * It is split into parts only because a single Java string constant is limited to 64 KB.
 */
public final class ThreatMapHtml {
    private ThreatMapHtml() {}

    private static final String P1 = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Live Cyber Threat Map</title>
<style>
*{box-sizing:border-box;}
body{font-family:Arial,Helvetica,sans-serif;background:#0f1117;color:#e6e6e6;margin:0;padding:20px;}
header{display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;margin-bottom:14px;}
h1{color:#4ade80;font-size:22px;margin:0;}
nav a{color:#9ca3af;text-decoration:none;padding:7px 14px;border-radius:8px;font-size:14px;margin-left:6px;background:#1a1d27;}
nav a:hover{color:#e6e6e6;}
nav a.active{color:#0f1117;background:#4ade80;font-weight:bold;}
.cards{display:flex;gap:14px;flex-wrap:wrap;margin-bottom:14px;}
.card{background:#1a1d27;padding:12px 20px;border-radius:10px;min-width:140px;box-shadow:0 0 10px rgba(0,0,0,0.4);}
.card h2{margin:0;font-size:26px;}
.card p{margin:3px 0 0;color:#9ca3af;font-size:13px;}
.toolbar{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:12px;}
.modes button{background:#1a1d27;color:#cbd5e1;border:1px solid #2a2e3a;padding:8px 14px;border-radius:8px;cursor:pointer;font-size:13px;margin-right:6px;}
.modes button:hover{border-color:#4ade80;}
.modes button.active{background:#4ade80;color:#0f1117;font-weight:bold;border-color:#4ade80;}
.opt{color:#9ca3af;font-size:13px;display:flex;align-items:center;gap:5px;cursor:pointer;}
.legend{margin-left:auto;font-size:12px;color:#9ca3af;display:flex;gap:12px;flex-wrap:wrap;}
.dot{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:4px;vertical-align:middle;}
.layout{display:flex;gap:14px;align-items:flex-start;}
#stage{position:relative;flex:1;min-width:0;background:#0b0e14;border-radius:10px;border:1px solid #1f2430;overflow:hidden;}
#map{display:block;width:100%;cursor:default;}
#popup{position:absolute;display:none;width:250px;background:#151925;border:1px solid #2f3646;border-radius:10px;padding:12px 14px;box-shadow:0 8px 24px rgba(0,0,0,0.6);font-size:13px;z-index:5;}
#popup .ph{font-weight:bold;font-size:14px;margin-bottom:8px;}
#popup .pr{display:flex;justify-content:space-between;gap:10px;padding:3px 0;border-bottom:1px solid #20263a;}
#popup .pr span{color:#9ca3af;}
#popup .pr b{text-align:right;font-weight:600;word-break:break-all;}
#popup i{color:#9ca3af;font-weight:normal;font-size:11px;}
#popup .x{position:absolute;top:6px;right:10px;cursor:pointer;color:#9ca3af;font-size:16px;}
#popup .fn{color:#7b8499;font-size:11px;margin-top:8px;line-height:1.4;}
.st.blocked{color:#f87171;} .st.active{color:#fb923c;} .st.ok{color:#4ade80;}
#tip{position:absolute;display:none;pointer-events:none;background:#000c;color:#fff;font-size:12px;padding:4px 8px;border-radius:6px;z-index:4;white-space:nowrap;}
aside{width:310px;flex-shrink:0;}
.panel{background:#1a1d27;border-radius:10px;padding:12px 14px;margin-bottom:12px;}
.panel h3{margin:0 0 8px;font-size:13px;color:#9ca3af;text-transform:uppercase;letter-spacing:0.5px;}
.row{display:flex;align-items:center;gap:8px;font-size:12px;margin:5px 0;}
.row .lbl{width:112px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
.row .bar{flex:1;height:8px;background:#242a3a;border-radius:4px;overflow:hidden;}
.row .bar div{height:100%;border-radius:4px;}
.row .val{width:38px;text-align:right;color:#9ca3af;}
.feed div{font-size:12px;padding:4px 0;border-bottom:1px solid #232938;cursor:pointer;display:flex;gap:6px;align-items:center;}
.feed div:hover{background:#20263a;}
.feed .t{color:#6b7280;width:72px;flex-shrink:0;white-space:nowrap;}
.feed .ip{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
.badge{font-size:10px;padding:1px 6px;border-radius:8px;color:#0f1117;font-weight:bold;}
.muted{color:#6b7280;font-size:12px;}
footer{margin-top:6px;color:#7b8499;font-size:12px;line-height:1.5;}
@media (max-width:900px){.layout{flex-direction:column;}aside{width:100%;}}
</style>
</head>
<body>
<header>
  <h1>🗺️ Live Cyber Threat Map</h1>
  <nav>
    <a href="/">Overview / Live Threats</a>
    <a href="/map" class="active">🗺️ Threat Map</a>
  </nav>
</header>

<div class="cards">
  <div class="card"><h2 id="cAtt">0</h2><p>Attacking IPs</p></div>
  <div class="card"><h2 id="cCty">0</h2><p>Source Countries</p></div>
  <div class="card"><h2 id="cCrit" style="color:#f87171">0</h2><p>Critical Sources</p></div>
  <div class="card"><h2 id="cBlk">0</h2><p>Blocked IPs</p></div>
  <div class="card"><h2 id="cEvt">0</h2><p>Attack Events</p></div>
</div>

<div class="toolbar">
  <div class="modes" id="modes">
    <button data-m="global" class="active">🌍 Global Threat Map</button>
    <button data-m="india">🇮🇳 India Threat Map</button>
    <button data-m="target">🎯 Target Map</button>
    <button data-m="flow">🔥 Attack Flow</button>
  </div>
  <label class="opt"><input type="checkbox" id="safeToggle"> show safe traffic</label>
  <div class="legend">
    <span><i class="dot" style="background:#ef4444"></i>Critical</span>
    <span><i class="dot" style="background:#fb923c"></i>High</span>
    <span><i class="dot" style="background:#facc15"></i>Medium</span>
    <span><i class="dot" style="background:#a3e635"></i>Low</span>
    <span><i class="dot" style="background:#22d3ee"></i>Protected server</span>
  </div>
</div>

<div class="layout">
  <div id="stage">
    <canvas id="map"></canvas>
    <div id="tip"></div>
    <div id="popup"></div>
  </div>
  <aside id="side"></aside>
</div>

<footer>
  ⚠️ Locations are <b>approximate</b> IP geolocation (this build uses an offline demo database) - they show roughly where
  traffic appears to come from, <b>not</b> the attacker's exact physical location. Attackers can use VPNs, proxies and Tor.
</footer>

<script>
const COLORS = {SAFE:'#4ade80', LOW:'#a3e635', MEDIUM:'#facc15', HIGH:'#fb923c', CRITICAL:'#ef4444'};
const ICONS = {SAFE:'🟢', LOW:'🟢', MEDIUM:'🟡', HIGH:'🟠', CRITICAL:'🔴'};
const LEVELS = ['SAFE','LOW','MEDIUM','HIGH','CRITICAL'];
const KIND_COLORS = {endpoint:'#60a5fa', user:'#c084fc', port:'#fbbf24', file:'#f87171'};
const KIND_LABEL = {endpoint:'Endpoint', user:'User account', port:'Network port', file:'File / download'};
const TARGET_COLOR = '#22d3ee';
const VIEWS = {
  global: {lon0:-180, lon1:180, lat0:-58, lat1:84},
  india:  {lon0:65, lon1:100, lat0:5, lat1:38.5}
};
const THREAT_NAMES = {SQL_INJECTION:'SQL Injection', XSS_ATTACK:'XSS Attack', DDOS:'DDoS', BLACKLISTED_IP:'Blacklisted IP', BLOCKED_IP:'Repeat offender (blocked)'};

let geo = null, state = null, mode = 'global', showSafe = false;
let lastId = null, firstEventLoad = true;
let W = 800, H = 480, dpr = 1, view = null, landCanvas = null;
let hits = [], popupKey = null;
const arcs = [], particles = [], ripples = [], feedList = [], lastFxByIp = {}, pulses = {};
let engineBlocked = 0, engineAllowed = 0;

const cv = document.getElementById('map');
const ctx = cv.getContext('2d');
const stage = document.getElementById('stage');
const popup = document.getElementById('popup');
const tip = document.getElementById('tip');

function esc(s) {
  return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}
function pretty(t) {
  if (!t) return 'Unknown';
  if (THREAT_NAMES[t]) return THREAT_NAMES[t];
  return t.split('_').map(w => w.charAt(0) + w.slice(1).toLowerCase()).join(' ');
}
function flag(cc) {
  if (!cc || cc.length !== 2) return '';
  return String.fromCodePoint(...[...cc.toUpperCase()].map(c => 0x1F1E6 + c.charCodeAt(0) - 65));
}
function fmtTime(ms) { return new Date(ms).toLocaleTimeString([], {hour:'numeric', minute:'2-digit'}); }
function fmtTimeS(ms) { return new Date(ms).toLocaleTimeString([], {hour:'numeric', minute:'2-digit', second:'2-digit'}); }
function riskText(r) { return (r > 100 ? '100+' : r) + '/100'; }

// ---------------------------------------------------------------- geometry / projection
function setView() {
  const v = VIEWS[mode === 'india' ? 'india' : 'global'];
  const s = Math.min(W / (v.lon1 - v.lon0), H / (v.lat1 - v.lat0));
  view = {lon0:v.lon0, lon1:v.lon1, lat0:v.lat0, lat1:v.lat1, s:s,
          ox:(W - (v.lon1 - v.lon0) * s) / 2, oy:(H - (v.lat1 - v.lat0) * s) / 2};
}
function P(lon, lat) { return [view.ox + (lon - view.lon0) * view.s, view.oy + (view.lat1 - lat) * view.s]; }

function pip(ring, x, y) {
  let inside = false;
  for (let i = 0, j = ring.length - 1; i < ring.length; j = i++) {
    const xi = ring[i][0], yi = ring[i][1], xj = ring[j][0], yj = ring[j][1];
    if (((yi > y) !== (yj > y)) && (x < (xj - xi) * (y - yi) / (yj - yi) + xi)) inside = !inside;
  }
  return inside;
}
function inFeature(rings, x, y) {
  let c = 0;
  for (const r of rings) if (pip(r, x, y)) c++;
  return (c % 2) === 1;
}
function buildLand() {
  landCanvas = document.createElement('canvas');
  landCanvas.width = W * dpr; landCanvas.height = H * dpr;
  if (!geo) return;
  const c = landCanvas.getContext('2d');
  c.setTransform(dpr, 0, 0, dpr, 0, 0);
  const step = Math.max(0.3, 5 / view.s);
  const rad = Math.max(1.2, step * view.s * 0.22);
  const inIndia = mode === 'india';
  for (let lat = view.lat1; lat >= view.lat0; lat -= step) {
    for (let lon = view.lon0; lon <= view.lon1; lon += step) {
      let land = false;
      for (const f of geo.land) { if (inFeature(f, lon, lat)) { land = true; break; } }
      const ind = inFeature([geo.india], lon, lat);
      if (!land && !ind) continue;
      const p = P(lon, lat);
      c.fillStyle = ind ? (inIndia ? 'rgba(74,222,128,0.85)' : 'rgba(74,222,128,0.7)')
                        : (inIndia ? 'rgba(120,140,185,0.15)' : 'rgba(120,140,185,0.5)');
      c.beginPath(); c.arc(p[0], p[1], rad, 0, 6.2832); c.fill();
    }
  }
}

function resize() {
  W = Math.max(320, stage.clientWidth);
  const h = mode === 'india' ? Math.min(Math.max(W * 0.7, 420), 660) : Math.min(Math.max(W * 0.5, 380), 600);
  H = Math.round(h);
  dpr = window.devicePixelRatio || 1;
  cv.width = W * dpr; cv.height = H * dpr; cv.style.height = H + 'px';
  setView();
  buildLand();
}

// ---------------------------------------------------------------- data polling
async function loadGeometry() {
  try {
    const r = await fetch('/api/map/geometry');
    geo = await r.json();
    buildLand();
  } catch (e) { console.error('geometry failed', e); }
}
async function pollState() {
  try {
    const r = await fetch('/api/map/state');
    state = await r.json();
    renderCards(); renderSide();
    if (popupKey) refreshPopup();
  } catch (e) { console.error('state failed', e); }
}
async function pollEvents() {
  try {
    const r = await fetch('/api/map/events?since=' + (lastId == null ? 0 : lastId));
    const d = await r.json();
    if (firstEventLoad) {
      firstEventLoad = false;
      lastId = d.latest;
      d.events.slice(-14).forEach(ev => { if (ev.level !== 'SAFE') feedList.unshift(ev); });
      renderSide();
      return;
    }
    lastId = d.latest;
    let changed = false;
    d.events.forEach(ev => {
      if (ev.level === 'SAFE' && !showSafe) return;
      changed = true;
      feedList.unshift(ev);
      if (ev.blocked) engineBlocked++; else engineAllowed++;
      spawnFx(ev);
    });
    while (feedList.length > 14) feedList.pop();
    if (changed) renderSide();
  } catch (e) { console.error('events failed', e); }
}

function spawnFx(ev) {
  const now = Date.now();
  if (lastFxByIp[ev.ip] && now - lastFxByIp[ev.ip] < 500) return;
  lastFxByIp[ev.ip] = now;
  const color = COLORS[ev.level];
  if (arcs.length < 80) arcs.push({lon:ev.lon, lat:ev.lat, cc:ev.cc, color:color, born:now, dur:1300, hit:false});
  if (particles.length < 120) particles.push({ev:ev, color:color, born:now, key:ev.target ? ev.target.kind + '|' + ev.target.name : '', blocked:ev.blocked, burst:false});
}

// ---------------------------------------------------------------- rendering helpers
function ctrl(a, b) {
  const d = Math.hypot(b[0] - a[0], b[1] - a[1]);
  return [(a[0] + b[0]) / 2, (a[1] + b[1]) / 2 - 0.28 * d];
}
function qpt(a, c, b, t) {
  const u = 1 - t;
  return [u * u * a[0] + 2 * u * t * c[0] + t * t * b[0], u * u * a[1] + 2 * u * t * c[1] + t * t * b[1]];
}
function bez(a, b, c, d, t) {
  const u = 1 - t;
  return [u*u*u*a[0] + 3*u*u*t*b[0] + 3*u*t*t*c[0] + t*t*t*d[0],
          u*u*u*a[1] + 3*u*u*t*b[1] + 3*u*t*t*c[1] + t*t*t*d[1]];
}
function glowDot(p, r, color, alpha) {
  ctx.save();
  ctx.globalAlpha = alpha == null ? 1 : alpha;
  ctx.shadowColor = color; ctx.shadowBlur = 12;
  ctx.fillStyle = color;
  ctx.beginPath(); ctx.arc(p[0], p[1], r, 0, 6.2832); ctx.fill();
  ctx.restore();
}
function drawTargetMarker(p, label) {
  const t = (Date.now() % 2000) / 2000;
  for (let k = 0; k < 2; k++) {
    const q = (t + k * 0.5) % 1;
    ctx.strokeStyle = 'rgba(34,211,238,' + (0.5 * (1 - q)) + ')';
    ctx.lineWidth = 1.5;
    ctx.beginPath(); ctx.arc(p[0], p[1], 8 + 20 * q, 0, 6.2832); ctx.stroke();
  }
  glowDot(p, 7, TARGET_COLOR, 1);
  ctx.fillStyle = '#0b0e14'; ctx.beginPath(); ctx.arc(p[0], p[1], 3, 0, 6.2832); ctx.fill();
  if (label) {
    ctx.font = 'bold 12px Arial'; ctx.fillStyle = TARGET_COLOR; ctx.textAlign = 'left';
    ctx.fillText(label, p[0] + 14, p[1] + 4);
  }
}

// ---------------------------------------------------------------- MAP MODES (global + india)
function visibleAttackers() {
  if (!state) return [];
  return state.attackers.filter(a => {
    if (mode === 'india' && a.cc !== 'IN') return false;
    if (a.attacks === 0 && !showSafe) return false;
    return true;
  });
}
function drawMap() {
  ctx.drawImage(landCanvas, 0, 0, W, H);
  if (!state) { msg('Loading threat data...'); return; }
  const tp = P(state.target.lon, state.target.lat);
  const now = Date.now();
  const list = visibleAttackers().sort((a, b) => LEVELS.indexOf(a.peakLevel) - LEVELS.indexOf(b.peakLevel));

  // faint standing routes (attacker -> protected server)
  list.filter(a => a.attacks > 0).slice(-80).forEach(a => {
    const s = P(a.lon, a.lat);
    if (Math.hypot(s[0] - tp[0], s[1] - tp[1]) < 6) return;
    const c = ctrl(s, tp);
    ctx.strokeStyle = COLORS[a.peakLevel]; ctx.globalAlpha = 0.13; ctx.lineWidth = 1;
    ctx.beginPath(); ctx.moveTo(s[0], s[1]); ctx.quadraticCurveTo(c[0], c[1], tp[0], tp[1]); ctx.stroke();
    ctx.globalAlpha = 1;
  });

  // markers
  hits = [];
  list.forEach(a => {
    const p = P(a.lon, a.lat);
    if (p[0] < -10 || p[0] > W + 10 || p[1] < -10 || p[1] > H + 10) return;
    const r = 4 + Math.min(7, Math.log2(a.attacks + 1));
    const color = COLORS[a.peakLevel];
    const recent = now - a.lastSeen < 6000;
    if (recent) {
      const q = (now % 1400) / 1400;
      ctx.strokeStyle = color; ctx.globalAlpha = 0.6 * (1 - q); ctx.lineWidth = 2;
      ctx.beginPath(); ctx.arc(p[0], p[1], r + 3 + 14 * q, 0, 6.2832); ctx.stroke(); ctx.globalAlpha = 1;
    }
    glowDot(p, r, color, a.attacks > 0 ? 0.95 : 0.45);
    if (a.blocked) {
      ctx.strokeStyle = '#0b0e14'; ctx.lineWidth = 2;
      ctx.beginPath(); ctx.moveTo(p[0] - r * 0.5, p[1] - r * 0.5); ctx.lineTo(p[0] + r * 0.5, p[1] + r * 0.5);
      ctx.moveTo(p[0] + r * 0.5, p[1] - r * 0.5); ctx.lineTo(p[0] - r * 0.5, p[1] + r * 0.5); ctx.stroke();
    }
    hits.push({x:p[0], y:p[1], r:r, type:'attacker', data:a});
  });
  if (mode === 'india') {
    const placed = [];
    ctx.font = '11px Arial'; ctx.fillStyle = '#cbd5e1'; ctx.textAlign = 'left';
    for (let i = list.length - 1; i >= 0; i--) {
      const a = list[i], p = P(a.lon, a.lat), w = ctx.measureText(a.city).width;
      const box = {x:p[0] + 10, y:p[1] - 8, w:w, h:12};
      if (placed.some(b => box.x < b.x + b.w && box.x + box.w > b.x && box.y < b.y + b.h && box.y + box.h > b.y)) continue;
      placed.push(box);
      ctx.fillText(a.city, box.x, p[1] + 4);
    }
  }

  // animated attack arcs
  for (let i = arcs.length - 1; i >= 0; i--) {
    const f = arcs[i];
    const q = (now - f.born) / f.dur;
    if (q > 1.5) { arcs.splice(i, 1); continue; }
    if (mode === 'india' && f.cc !== 'IN') continue;
    const s = P(f.lon, f.lat);
    if (Math.hypot(s[0] - tp[0], s[1] - tp[1]) < 6) continue;
    const c = ctrl(s, tp);
    const head = Math.min(1, q), tail = Math.max(0, Math.min(1, (q - 0.5) / 1.0));
    if (q >= 1 && !f.hit) { f.hit = true; ripples.push({p:tp, color:f.color, born:now}); }
    ctx.strokeStyle = f.color; ctx.lineWidth = 2; ctx.globalAlpha = 0.9; ctx.lineCap = 'round';
    ctx.beginPath();
    const n = 22;
    for (let k = 0; k <= n; k++) {
      const pt = qpt(s, c, tp, tail + (head - tail) * k / n);
      if (k === 0) ctx.moveTo(pt[0], pt[1]); else ctx.lineTo(pt[0], pt[1]);
    }
    ctx.stroke(); ctx.globalAlpha = 1;
    if (q < 1) glowDot(qpt(s, c, tp, head), 3, f.color, 1);
  }
  for (let i = ripples.length - 1; i >= 0; i--) {
    const rp = ripples[i], q = (now - rp.born) / 900;
    if (q > 1) { ripples.splice(i, 1); continue; }
    ctx.strokeStyle = rp.color; ctx.globalAlpha = 0.8 * (1 - q); ctx.lineWidth = 2;
    ctx.beginPath(); ctx.arc(rp.p[0], rp.p[1], 6 + 26 * q, 0, 6.2832); ctx.stroke(); ctx.globalAlpha = 1;
  }

  drawTargetMarker(tp, mode === 'india' ? 'Protected server' : state.target.name);
  hits.push({x:tp[0], y:tp[1], r:10, type:'server', data:state.target});

  if (mode === 'india') {
    const abroad = state.attackers.filter(a => a.cc !== 'IN' && a.attacks > 0).length;
    ctx.font = '12px Arial'; ctx.fillStyle = '#7b8499'; ctx.textAlign = 'left';
    ctx.fillText(abroad + ' attacking source(s) outside India are not shown in this view', 12, H - 12);
  }
  if (list.length === 0) msg('No sources to show yet - waiting for attack traffic...');
}
function msg(t) {
  ctx.font = '14px Arial'; ctx.fillStyle = '#7b8499'; ctx.textAlign = 'center';
  ctx.fillText(t, W / 2, H / 2);
}

// ---------------------------------------------------------------- TARGET MODE
function drawTargetMode() {
  hits = [];
  if (!state) { msg('Loading threat data...'); return; }
  const items = state.targets.slice(0, 12);
  const cx = W / 2, cy = H / 2, rx = W * 0.34, ry = H * 0.34, now = Date.now();
  if (items.length === 0) { msg('No attacked targets yet...'); }
  const max = Math.max(1, ...items.map(t => t.count));
  const pos = {};
  items.forEach((t, i) => {
    const ang = -Math.PI / 2 + i * 2 * Math.PI / items.length;
    pos[t.kind + '|' + t.name] = {x:cx + rx * Math.cos(ang), y:cy + ry * Math.sin(ang), ang:ang, t:t};
  });
  Object.values(pos).forEach(n => {
    const col = KIND_COLORS[n.t.kind] || '#94a3b8';
    ctx.strokeStyle = col; ctx.globalAlpha = 0.25; ctx.lineWidth = 1 + 4 * n.t.count / max;
    ctx.beginPath(); ctx.moveTo(cx, cy); ctx.lineTo(n.x, n.y); ctx.stroke(); ctx.globalAlpha = 1;
  });
  // particles travel in toward the node, then on to the server
  for (let i = particles.length - 1; i >= 0; i--) {
    const pa = particles[i], q = (now - pa.born) / 1200;
    if (q > 1) { particles.splice(i, 1); continue; }
    const n = pos[pa.key]; if (!n) continue;
    const sx = n.x + Math.cos(n.ang) * 90, sy = n.y + Math.sin(n.ang) * 90;
    let p;
    if (q < 0.55) { const u = q / 0.55; p = [sx + (n.x - sx) * u, sy + (n.y - sy) * u]; }
    else { const u = (q - 0.55) / 0.45; p = [n.x + (cx - n.x) * u, n.y + (cy - n.y) * u]; }
    if (q >= 0.55 && !pa.burst) { pa.burst = true; pulses[pa.key] = {born:now, color:pa.color}; }
    glowDot(p, 3.5, pa.color, 1);
  }
  Object.keys(pos).forEach(k => {
    const n = pos[k], col = KIND_COLORS[n.t.kind] || '#94a3b8';
    const r = 10 + 16 * Math.sqrt(n.t.count / max);
    const pu = pulses[k];
    if (pu) {
      const q = (now - pu.born) / 700;
      if (q < 1) { ctx.strokeStyle = pu.color; ctx.globalAlpha = 0.8 * (1 - q); ctx.lineWidth = 2;
        ctx.beginPath(); ctx.arc(n.x, n.y, r + 4 + 14 * q, 0, 6.2832); ctx.stroke(); ctx.globalAlpha = 1; }
    }
    glowDot([n.x, n.y], r, col, 0.9);
""";

    private static final String P2 = """
    ctx.font = 'bold 11px Arial'; ctx.fillStyle = '#0b0e14'; ctx.textAlign = 'center';
    ctx.fillText(n.t.count, n.x, n.y + 4);
    ctx.font = '12px Arial'; ctx.fillStyle = '#cbd5e1';
    const above = Math.sin(n.ang) < -0.3;
    ctx.fillText(n.t.name, n.x, above ? n.y - r - 8 : n.y + r + 15);
    hits.push({x:n.x, y:n.y, r:r, type:'target', data:n.t});
  });
  drawTargetMarker([cx, cy], null);
  ctx.font = 'bold 12px Arial'; ctx.fillStyle = TARGET_COLOR; ctx.textAlign = 'center';
  ctx.fillText('Protected server', cx, cy + 34);
  ctx.font = '11px Arial'; ctx.textAlign = 'left';
  let ly = 18;
  Object.keys(KIND_COLORS).forEach(k => {
    ctx.fillStyle = KIND_COLORS[k]; ctx.beginPath(); ctx.arc(18, ly - 4, 5, 0, 6.2832); ctx.fill();
    ctx.fillStyle = '#9ca3af'; ctx.fillText(KIND_LABEL[k], 30, ly); ly += 18;
  });
}

// ---------------------------------------------------------------- ATTACK FLOW MODE
function drawFlow() {
  hits = [];
  if (!state) { msg('Loading threat data...'); return; }
  const now = Date.now();
  const xs = W * 0.13, xe = W * 0.5, xt = W * 0.87, eh = Math.min(H - 70, 360), ew = 96;
  const eTop = (H - eh) / 2;
  const srcs = state.countries.slice(0, 8).map(c => ({key:c.cc, label:flag(c.cc) + ' ' + c.name, n:c.attacks}));
  if (state.countries.length > 8) {
    srcs.push({key:'*', label:'Other sources', n:state.countries.slice(8).reduce((a, c) => a + c.attacks, 0)});
  }
  const tgts = state.targets.slice(0, 6).map(t => ({key:t.kind + '|' + t.name, label:t.name, n:t.count, kind:t.kind}));
  if (state.targets.length > 6) {
    tgts.push({key:'*', label:'Other targets', n:state.targets.slice(6).reduce((a, t) => a + t.count, 0), kind:'endpoint'});
  }
  const lay = (arr, x) => arr.forEach((o, i) => {
    o.x = x; o.y = arr.length === 1 ? H / 2 : 46 + i * (H - 92) / (arr.length - 1);
    o.ey = eTop + (i + 0.5) * eh / arr.length;
  });
  lay(srcs, xs); lay(tgts, xt);
  const smax = Math.max(1, ...srcs.map(s => s.n)), tmax = Math.max(1, ...tgts.map(t => t.n));

  // links
  srcs.forEach(s => {
    const a = [s.x + 10, s.y], d = [xe - ew, s.ey], m = (a[0] + d[0]) / 2;
    ctx.strokeStyle = '#ef4444'; ctx.globalAlpha = 0.22; ctx.lineWidth = 1 + 5 * s.n / smax;
    ctx.beginPath(); ctx.moveTo(a[0], a[1]); ctx.bezierCurveTo(m, a[1], m, d[1], d[0], d[1]); ctx.stroke(); ctx.globalAlpha = 1;
  });
  tgts.forEach(t => {
    const a = [xe + ew, t.ey], d = [t.x - 10, t.y], m = (a[0] + d[0]) / 2;
    ctx.strokeStyle = KIND_COLORS[t.kind] || '#94a3b8'; ctx.globalAlpha = 0.22; ctx.lineWidth = 1 + 5 * t.n / tmax;
    ctx.beginPath(); ctx.moveTo(a[0], a[1]); ctx.bezierCurveTo(m, a[1], m, d[1], d[0], d[1]); ctx.stroke(); ctx.globalAlpha = 1;
  });

  // engine box
  ctx.fillStyle = '#151c2c'; ctx.strokeStyle = '#2f3b57'; ctx.lineWidth = 2;
  ctx.beginPath(); ctx.roundRect(xe - ew, eTop, ew * 2, eh, 14); ctx.fill(); ctx.stroke();
  ctx.textAlign = 'center'; ctx.fillStyle = '#4ade80'; ctx.font = 'bold 13px Arial';
  ctx.fillText('THREAT DETECTION', xe, eTop + eh / 2 - 26); ctx.fillText('ENGINE', xe, eTop + eh / 2 - 9);
  ctx.fillStyle = '#9ca3af'; ctx.font = '11px Arial';
  ctx.fillText('11 detectors + risk score', xe, eTop + eh / 2 + 10);
  ctx.fillStyle = '#f87171'; ctx.fillText('blocked: ' + engineBlocked, xe, eTop + eh / 2 + 32);
  ctx.fillStyle = '#facc15'; ctx.fillText('detected & passed: ' + engineAllowed, xe, eTop + eh / 2 + 48);
  ctx.fillStyle = '#6b7280'; ctx.font = '10px Arial'; ctx.fillText('(since this page opened)', xe, eTop + eh / 2 + 64);

  // nodes
  srcs.forEach(s => {
    const r = 6 + 9 * Math.sqrt(s.n / smax);
    glowDot([s.x, s.y], r, '#ef4444', 0.9);
    ctx.font = '12px Arial'; ctx.fillStyle = '#cbd5e1'; ctx.textAlign = 'left';
    ctx.fillText(s.label + '  (' + s.n + ')', Math.max(4, s.x - r), s.y - r - 6);
  });
  tgts.forEach(t => {
    const r = 6 + 9 * Math.sqrt(t.n / tmax), col = KIND_COLORS[t.kind] || '#94a3b8';
    glowDot([t.x, t.y], r, col, 0.9);
    ctx.font = '12px Arial'; ctx.fillStyle = '#cbd5e1'; ctx.textAlign = 'right';
    ctx.fillText(t.label + '  (' + t.n + ')', Math.min(W - 4, t.x + r), t.y - r - 6);
    hits.push({x:t.x, y:t.y, r:r, type:'target', data:state.targets.find(x => x.kind + '|' + x.name === t.key) || null});
  });
  ctx.font = 'bold 11px Arial'; ctx.fillStyle = '#6b7280'; ctx.textAlign = 'left';
  ctx.fillText('SOURCE', 10, 16); ctx.textAlign = 'center'; ctx.fillText('NETWORK', xe, 16);
  ctx.textAlign = 'right'; ctx.fillText('TARGET', W - 10, 16);

  // moving packets
  for (let i = particles.length - 1; i >= 0; i--) {
    const pa = particles[i], q = (now - pa.born) / 1700;
    if (q > 1) { particles.splice(i, 1); continue; }
    const s = srcs.find(o => o.key === pa.ev.cc) || srcs.find(o => o.key === '*');
    if (!s) continue;
    const tg = (pa.key && tgts.find(o => o.key === pa.key)) || tgts.find(o => o.key === '*') || tgts[0];
    const a = [s.x + 10, s.y], d = [xe - ew, s.ey], m1 = (a[0] + d[0]) / 2;
    let p;
    if (q < 0.4) {
      p = bez(a, [m1, a[1]], [m1, d[1]], d, q / 0.4);
    } else if (pa.blocked) {
      if (!pa.burst) { pa.burst = true; ripples.push({p:d, color:'#ef4444', born:now}); }
      continue;
    } else if (q < 0.55) {
      const u = (q - 0.4) / 0.15, e2 = tg ? [xe + ew, tg.ey] : [xe + ew, d[1]];
      p = [d[0] + (e2[0] - d[0]) * u, d[1] + (e2[1] - d[1]) * u];
    } else if (tg) {
      const a2 = [xe + ew, tg.ey], d2 = [tg.x - 10, tg.y], m2 = (a2[0] + d2[0]) / 2;
      p = bez(a2, [m2, a2[1]], [m2, d2[1]], d2, (q - 0.55) / 0.45);
    } else continue;
    glowDot(p, 3.5, pa.color, 1);
  }
  for (let i = ripples.length - 1; i >= 0; i--) {
    const rp = ripples[i], q = (now - rp.born) / 900;
    if (q > 1) { ripples.splice(i, 1); continue; }
    ctx.strokeStyle = rp.color; ctx.globalAlpha = 0.8 * (1 - q); ctx.lineWidth = 2;
    ctx.beginPath(); ctx.arc(rp.p[0], rp.p[1], 5 + 22 * q, 0, 6.2832); ctx.stroke(); ctx.globalAlpha = 1;
  }
  if (srcs.length === 0) msg('No attack traffic yet...');
}

// ---------------------------------------------------------------- main loop
function frame() {
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, W, H);
  if (!geo && (mode === 'global' || mode === 'india')) msg('Loading map...');
  else if (mode === 'global' || mode === 'india') drawMap();
  else if (mode === 'target') drawTargetMode();
  else drawFlow();
  requestAnimationFrame(frame);
}

// ---------------------------------------------------------------- popup / tooltip
function hitAt(x, y) {
  let best = null, bd = 1e9;
  for (const h of hits) {
    const d = Math.hypot(h.x - x, h.y - y);
    if (d <= h.r + 5 && d < bd) { bd = d; best = h; }
  }
  return best;
}
function popupHtml(h) {
  if (h.type === 'attacker') {
    const a = h.data, lvl = a.peakLevel;
    const status = a.blocked ? '<b class="st blocked">BLOCKED</b>'
      : (a.attacks > 0 ? '<b class="st active">ACTIVE - MONITORED</b>' : '<b class="st ok">NORMAL</b>');
    const where = a.city + ', ' + a.country;
    return '<span class="x" onclick="closePopup()">x</span>' +
      '<div class="ph" style="color:' + COLORS[lvl] + '">' + ICONS[lvl] + ' ' + lvl + (a.attacks > 0 ? ' THREAT' : ' - NORMAL') + '</div>' +
      row('Location', esc(where) + ' <i>(approx.)</i>') + row('IP', esc(a.ip)) +
      row('Threat', esc(pretty(a.threat))) + row('Risk', riskText(a.peakRisk)) +
      row('Attacks', a.attacks) + row('First Seen', fmtTime(a.firstSeen)) +
      row('Last Seen', fmtTimeS(a.lastSeen)) + row('Status', status) +
      '<div class="fn">Approximate IP location - not the attacker&#39;s exact physical location.</div>';
  }
  if (h.type === 'target' && h.data) {
    const t = h.data, col = KIND_COLORS[t.kind] || '#94a3b8';
    return '<span class="x" onclick="closePopup()">x</span>' +
      '<div class="ph" style="color:' + col + '">🎯 ' + esc(KIND_LABEL[t.kind] || t.kind) + ' under attack</div>' +
      row('Target', esc(t.name)) + row('Attacks', t.count) + row('Distinct sources', t.attackers) +
      row('Main threat', esc(pretty(t.topThreat))) + row('Last attacked', fmtTimeS(t.lastSeen));
  }
  if (h.type === 'server') {
    return '<span class="x" onclick="closePopup()">x</span>' +
      '<div class="ph" style="color:' + TARGET_COLOR + '">🛡 Protected server</div>' +
      row('Location', esc(h.data.name + ', ' + h.data.country)) +
      '<div class="fn">Where attack routes end. Configure with -Dtarget.lat / -Dtarget.lon / -Dtarget.city.</div>';
  }
  return '';
}
function row(k, v) { return '<div class="pr"><span>' + k + '</span><b>' + v + '</b></div>'; }
function openPopup(h) {
  popupKey = h.type === 'attacker' ? 'a|' + h.data.ip : (h.type === 'target' && h.data ? 't|' + h.data.kind + '|' + h.data.name : 's');
  popup.innerHTML = popupHtml(h);
  popup.style.display = 'block';
  let x = h.x + 16, y = h.y - 20;
  if (x + 260 > W) x = h.x - 266;
  if (y + popup.offsetHeight > H) y = H - popup.offsetHeight - 8;
  popup.style.left = Math.max(6, x) + 'px'; popup.style.top = Math.max(6, y) + 'px';
}
function closePopup() { popup.style.display = 'none'; popupKey = null; }
function refreshPopup() {
  if (!popupKey || !state) return;
  const parts = popupKey.split('|');
  if (parts[0] === 'a') {
    const a = state.attackers.find(x => x.ip === parts[1]);
    if (a) popup.innerHTML = popupHtml({type:'attacker', data:a});
  } else if (parts[0] === 't') {
    const t = state.targets.find(x => x.kind === parts[1] && x.name === parts.slice(2).join('|'));
    if (t) popup.innerHTML = popupHtml({type:'target', data:t});
  }
}
cv.addEventListener('click', e => {
  const r = cv.getBoundingClientRect();
  const h = hitAt(e.clientX - r.left, e.clientY - r.top);
  if (h) openPopup(h); else closePopup();
});
cv.addEventListener('mousemove', e => {
  const r = cv.getBoundingClientRect(), x = e.clientX - r.left, y = e.clientY - r.top;
  const h = hitAt(x, y);
  cv.style.cursor = h ? 'pointer' : 'default';
  if (h && h.type === 'attacker') {
    tip.textContent = h.data.city + ', ' + h.data.country + '  -  ' + h.data.ip;
  } else if (h && h.type === 'target' && h.data) {
    tip.textContent = h.data.name + '  -  ' + h.data.count + ' attacks';
  } else { tip.style.display = 'none'; return; }
  tip.style.display = 'block'; tip.style.left = (x + 14) + 'px'; tip.style.top = (y + 14) + 'px';
});
cv.addEventListener('mouseleave', () => { tip.style.display = 'none'; });

// ---------------------------------------------------------------- sidebar / cards
function renderCards() {
  const s = state.summary;
  document.getElementById('cAtt').textContent = s.attackers;
  document.getElementById('cCty').textContent = s.countries;
  document.getElementById('cCrit').textContent = s.critical;
  document.getElementById('cBlk').textContent = s.blockedIps;
  document.getElementById('cEvt').textContent = s.attackEvents;
}
function bars(items, color) {
  const max = Math.max(1, ...items.map(i => i.v));
  return items.map(i => '<div class="row"><span class="lbl" title="' + esc(i.l) + '">' + esc(i.l) + '</span>' +
    '<span class="bar"><div style="width:' + Math.max(3, 100 * i.v / max) + '%;background:' + (i.c || color) + '"></div></span>' +
    '<span class="val">' + i.v + '</span></div>').join('');
}
function renderSide() {
  const el = document.getElementById('side');
  let h = '';
  if (state) {
    if (mode === 'india') {
      const st = state.states.map(s => ({l:s.state, v:s.attacks}));
      h += '<div class="panel"><h3>🇮🇳 India - threat concentration by state</h3>' +
        (st.length ? bars(st, '#4ade80') : '<div class="muted">No Indian sources yet.</div>') +
        '<div class="muted" style="margin-top:6px">' + state.summary.indiaSources + ' Indian source IP(s). City/state is approximate.</div></div>';
    } else {
      const c = state.countries.slice(0, 8).map(x => ({l:flag(x.cc) + ' ' + x.name, v:x.attacks}));
      h += '<div class="panel"><h3>Top source countries</h3>' +
        (c.length ? bars(c, '#ef4444') : '<div class="muted">No attacks yet.</div>') + '</div>';
    }
    const tt = state.threatTypes.slice(0, 7).map(x => ({l:pretty(x.name), v:x.count}));
    h += '<div class="panel"><h3>Attack types</h3>' + (tt.length ? bars(tt, '#fb923c') : '<div class="muted">-</div>') + '</div>';
    const tg = state.targets.slice(0, 5).map(x => ({l:x.name, v:x.count, c:KIND_COLORS[x.kind]}));
    h += '<div class="panel"><h3>Most targeted</h3>' + (tg.length ? bars(tg, '#60a5fa') : '<div class="muted">-</div>') + '</div>';
  }
  h += '<div class="panel"><h3>Live feed</h3><div class="feed">' + (feedList.length ? feedList.map(ev =>
    '<div data-ip="' + esc(ev.ip) + '"><span class="t">' + fmtTimeS(ev.ts) + '</span>' +
    '<span>' + flag(ev.cc) + '</span><span class="ip">' + esc(ev.ip) + ' - ' + esc(pretty(ev.threat)) + '</span>' +
    '<span class="badge" style="background:' + COLORS[ev.level] + '">' + ev.level + '</span></div>').join('')
    : '<div class="muted">Waiting for events...</div>') + '</div></div>';
  el.innerHTML = h;
  el.querySelectorAll('.feed div[data-ip]').forEach(d => d.onclick = () => focusIp(d.getAttribute('data-ip')));
}
function focusIp(ip) {
  if (!state || (mode !== 'global' && mode !== 'india')) return;
  const a = state.attackers.find(x => x.ip === ip);
  if (!a) return;
  if (mode === 'india' && a.cc !== 'IN') setMode('global');
  const p = P(a.lon, a.lat);
  openPopup({type:'attacker', data:a, x:p[0], y:p[1]});
}

function setMode(m) {
  mode = m; closePopup();
  document.querySelectorAll('#modes button').forEach(b => b.classList.toggle('active', b.getAttribute('data-m') === m));
  resize(); renderSide();
}
document.querySelectorAll('#modes button').forEach(b => b.onclick = () => setMode(b.getAttribute('data-m')));
document.getElementById('safeToggle').onchange = e => { showSafe = e.target.checked; };
new ResizeObserver(() => { if (stage.clientWidth !== W) resize(); }).observe(stage);

resize();
loadGeometry();
pollState(); pollEvents();
setInterval(pollState, 2000);
setInterval(pollEvents, 1000);
requestAnimationFrame(frame);
</script>
</body>
</html>
""";

    public static final String PAGE = P1 + P2;
}
