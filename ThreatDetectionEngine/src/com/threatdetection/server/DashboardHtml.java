package com.threatdetection.server;

/** Static dashboard page (HTML + CSS + JS) served at "/". Polls /api/stats every 2s. */
public class DashboardHtml {
    public static final String PAGE = "<!DOCTYPE html>\n" +
        "<html lang=\"en\">\n" +
        "<head>\n" +
        "<meta charset=\"UTF-8\">\n" +
        "<title>Real-Time Cybersecurity Threat Detection Dashboard</title>\n" +
        "<script src=\"https://cdn.jsdelivr.net/npm/chart.js\"></script>\n" +
        "<style>\n" +
        "body{font-family:Arial,Helvetica,sans-serif;background:#0f1117;color:#e6e6e6;margin:0;padding:20px;}\n" +
        "h1{color:#4ade80;font-size:22px;}\n" +
        ".cards{display:flex;gap:16px;flex-wrap:wrap;margin-bottom:20px;}\n" +
        ".card{background:#1a1d27;padding:16px 24px;border-radius:10px;min-width:160px;box-shadow:0 0 10px rgba(0,0,0,0.4);}\n" +
        ".card h2{margin:0;font-size:28px;}\n" +
        ".card p{margin:4px 0 0;color:#9ca3af;}\n" +
        "table{width:100%;border-collapse:collapse;background:#1a1d27;border-radius:10px;overflow:hidden;}\n" +
        "th,td{padding:10px 12px;text-align:left;border-bottom:1px solid #2a2e3a;font-size:13px;vertical-align:top;}\n" +
        "th{background:#20242f;color:#9ca3af;}\n" +
        ".SAFE{color:#4ade80;} .LOW{color:#a3e635;} .MEDIUM{color:#facc15;} .HIGH{color:#fb923c;} .CRITICAL{color:#f87171;font-weight:bold;}\n" +
        "#chartWrap{background:#1a1d27;padding:16px;border-radius:10px;margin-bottom:20px;}\n" +
        "</style>\n" +
        "</head>\n" +
        "<body>\n" +
        "<h1>Real-Time Cybersecurity Threat Detection - Java Engine</h1>\n" +
        "<p><a href=\"/map\" style=\"color:#0f1117;background:#4ade80;padding:7px 14px;border-radius:8px;text-decoration:none;font-weight:bold;font-size:14px\">&#128506; Open Live Threat Map</a></p>\n" +
        "<div class=\"cards\">\n" +
        "  <div class=\"card\"><h2 id=\"totalEvents\">0</h2><p>Total Events Processed</p></div>\n" +
        "  <div class=\"card\"><h2 id=\"totalCritical\">0</h2><p>Critical Alerts</p></div>\n" +
        "  <div class=\"card\"><h2 id=\"blockedCount\">0</h2><p>Blocked IPs</p></div>\n" +
        "</div>\n" +
        "<div id=\"chartWrap\"><canvas id=\"riskChart\" height=\"80\"></canvas></div>\n" +
        "<table>\n" +
        "<thead><tr><th>Time</th><th>IP</th><th>Risk Score</th><th>Level</th><th>Blocked</th><th>Triggered Rules</th></tr></thead>\n" +
        "<tbody id=\"threatTable\"></tbody>\n" +
        "</table>\n" +
        "<script>\n" +
        "const ctx = document.getElementById('riskChart').getContext('2d');\n" +
        "const chart = new Chart(ctx, {\n" +
        "  type: 'line',\n" +
        "  data: { labels: [], datasets: [{ label: 'Risk Score', data: [], borderColor: '#f87171', tension: 0.3 }] },\n" +
        "  options: { scales: { y: { beginAtZero: true } } }\n" +
        "});\n" +
        "\n" +
        "function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/'/g,'&#39;').replace(/\"/g,'&quot;');}\n" +
        "async function refresh() {\n" +
        "  try {\n" +
        "    const res = await fetch('/api/stats');\n" +
        "    const data = await res.json();\n" +
        "    document.getElementById('totalEvents').innerText = data.totalEvents;\n" +
        "    document.getElementById('totalCritical').innerText = data.totalCriticalAlerts;\n" +
        "    document.getElementById('blockedCount').innerText = data.blockedIps.length;\n" +
        "\n" +
        "    const tbody = document.getElementById('threatTable');\n" +
        "    tbody.innerHTML = '';\n" +
        "    data.recentThreats.forEach(t => {\n" +
        "      const tr = document.createElement('tr');\n" +
        "      const time = new Date(t.timestamp).toLocaleTimeString();\n" +
        "      tr.innerHTML = `<td>${time}</td><td>${esc(t.ip)}</td><td>${Number(t.riskScore)}</td>` +\n" +
        "        `<td class=\"${t.level}\">${t.level}</td><td>${t.blocked ? 'YES' : 'no'}</td>` +\n" +
        "        `<td>${t.triggeredRules.map(esc).join('<br>')}</td>`;\n" +
        "      tbody.appendChild(tr);\n" +
        "    });\n" +
        "\n" +
        "    const recent = [...data.recentThreats].reverse().slice(-20);\n" +
        "    chart.data.labels = recent.map(t => new Date(t.timestamp).toLocaleTimeString());\n" +
        "    chart.data.datasets[0].data = recent.map(t => t.riskScore);\n" +
        "    chart.update();\n" +
        "  } catch (e) {\n" +
        "    console.error('Failed to refresh dashboard', e);\n" +
        "  }\n" +
        "}\n" +
        "setInterval(refresh, 2000);\n" +
        "refresh();\n" +
        "</script>\n" +
        "</body>\n" +
        "</html>";
}
