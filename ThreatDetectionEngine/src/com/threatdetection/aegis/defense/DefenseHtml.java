package com.threatdetection.aegis.defense;

/** Analyst console for AEGIS defensive actions. All dynamic text is inserted with textContent (event data is attacker-controlled). */
final class DefenseHtml {
    private DefenseHtml() {}

    static final String PAGE = """
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AEGIS - Defense</title>
<style>
:root{--bg:#f6f7f9;--card:#fff;--txt:#14181f;--mut:#667085;--line:#e1e5ea;--acc:#1d4ed8;--bad:#b42318;--ok:#067647;--warn:#b54708}
@media (prefers-color-scheme:dark){:root{--bg:#0e1116;--card:#171b22;--txt:#e7eaf0;--mut:#98a2b3;--line:#272d38;--acc:#6ea0ff;--bad:#ff8a80;--ok:#5fd39b;--warn:#f5b461}}
body{margin:0;font:14px system-ui,Segoe UI,sans-serif;background:var(--bg);color:var(--txt)}
header{padding:14px 20px;border-bottom:1px solid var(--line);background:var(--card);display:flex;gap:16px;align-items:center;flex-wrap:wrap}
header a{color:var(--acc);text-decoration:none}main{padding:16px 20px;display:grid;gap:16px;max-width:1200px;margin:auto}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px;overflow-x:auto}
h2{margin:0 0 8px;font-size:15px}table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--mut);font-weight:600;font-size:12px}.mut{color:var(--mut)}.b{display:inline-block;padding:1px 7px;border-radius:9px;border:1px solid var(--line);font-size:12px}
button{font:inherit;padding:3px 10px;border-radius:6px;border:1px solid var(--line);background:var(--card);color:var(--txt);cursor:pointer;margin-right:4px}
button.go{border-color:var(--ok);color:var(--ok)}button.no{border-color:var(--bad);color:var(--bad)}
.banner{padding:8px 12px;border-radius:8px;border:1px solid var(--warn);color:var(--warn)}
</style></head><body>
<header><b>AEGIS Defense</b><a href="/aegis">Alerts</a><a href="/">Platform</a><span id="mode" class="b"></span><span id="verify" class="mut"></span></header>
<main>
<div id="banner" class="banner" style="display:none"></div>
<div class="card"><h2>Policy</h2><div id="policy" class="mut"></div></div>
<div class="card"><h2>Waiting for an analyst</h2><div id="pending"></div></div>
<div class="card"><h2>Active and recent actions</h2><div id="actions"></div></div>
<div class="card"><h2>Audit trail <button id="vbtn">Verify chain</button></h2><div id="audit"></div></div>
</main>
<script>
function el(tag, text, cls){var e=document.createElement(tag); if(text!==undefined) e.textContent=text; if(cls) e.className=cls; return e;}
function when(t){return t? new Date(t).toLocaleString() : '-';}
function post(path){return fetch(path,{method:'POST',headers:{'X-Operator':'analyst'}}).then(function(r){return r.json();});}
function table(heads, rows){var t=el('table'), h=el('tr'); heads.forEach(function(x){h.appendChild(el('th',x));}); t.appendChild(h);
  rows.forEach(function(r){var tr=el('tr'); r.forEach(function(c){var td=el('td'); if(c instanceof Node) td.appendChild(c); else td.textContent=c; tr.appendChild(td);}); t.appendChild(tr);}); return t;}
function btn(label, cls, path){var b=el('button',label,cls); b.onclick=function(){b.disabled=true; post(path).then(function(r){if(!r.ok) alert(r.error||'failed'); load();});}; return b;}
function setBox(id, node){var box=document.getElementById(id); box.replaceChildren(node);}
function load(){
  fetch('/aegis/api/defense/status').then(function(r){return r.json();}).then(function(s){
    document.getElementById('mode').textContent='mode: '+s.mode;
    var ban=document.getElementById('banner');
    if(s.mode==='DRY_RUN'){ban.style.display='block';ban.textContent='DRY RUN: decisions are recorded but nothing is changed on this machine. Start with -Daegis.defense.mode=enforce to act (Windows Firewall also needs an Administrator process).';}
    else if(s.mode==='OFF'){ban.style.display='block';ban.textContent='Defense is off (-Daegis.defense.mode=off).';} else ban.style.display='none';
    document.getElementById('policy').textContent='LOW/MEDIUM: monitor. HIGH: alert + analyst approval. CRITICAL: reversible action only if policy allows ('+s.autoTypes.join(', ')+'), data is OBSERVED and at least '+s.minRules+' distinct rules fired. Temporary actions last '+s.ttlMinutes+' min. Firewall: '+s.firewall+'. Quarantine: '+(s.quarantineEnabled?'enabled':'off (no roots configured)')+'. Webhook: '+(s.webhook?'on':'off')+'.';
  });
  fetch('/aegis/api/defense/actions').then(function(r){return r.json();}).then(function(d){
    var pend=d.actions.filter(function(a){return a.state==='PENDING';});
    setBox('pending', pend.length? table(['Action','Target','Why','Offered','Decide'], pend.map(function(a){var c=el('span'); c.appendChild(btn('Approve','go','/aegis/api/defense/approve?id='+encodeURIComponent(a.id))); c.appendChild(btn('Reject','no','/aegis/api/defense/reject?id='+encodeURIComponent(a.id))); return [a.label,a.target,a.reason+' ('+a.result+')',when(a.created),c];})) : el('div','Nothing is waiting.','mut'));
    var rest=d.actions.filter(function(a){return a.state!=='PENDING';});
    setBox('actions', rest.length? table(['Action','Target','State','Result','Expires','By',''], rest.map(function(a){var c=el('span'); if(a.state==='ACTIVE') c.appendChild(btn('Undo now','no','/aegis/api/defense/revert?id='+encodeURIComponent(a.id))); return [a.label,a.target,a.state,a.result,a.expires?when(a.expires):'held',a.decidedBy,c];})) : el('div','No actions yet.','mut'));
  });
  fetch('/aegis/api/defense/audit?limit=60').then(function(r){return r.json();}).then(function(d){
    setBox('audit', d.records.length? table(['#','Time','Operator','Action','Target','Level','Result'], d.records.map(function(r){return [String(r.seq),when(r.ts),r.operator,r.action,r.target,r.level,r.result];})) : el('div','No records yet.','mut'));
  });
}
document.getElementById('vbtn').onclick=function(){fetch('/aegis/api/defense/audit?limit=1&verify=1').then(function(r){return r.json();}).then(function(d){var v=document.getElementById('verify'); v.textContent=d.verification.message; v.style.color=d.verification.ok?'var(--ok)':'var(--bad)';});};
load(); setInterval(load,5000);
</script></body></html>
""";
}
