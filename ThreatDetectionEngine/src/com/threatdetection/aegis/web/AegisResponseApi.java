package com.threatdetection.aegis.web;

import com.sun.net.httpserver.HttpExchange;
import com.threatdetection.aegis.Aegis;
import com.threatdetection.correlation.AttackChainEngine;
import com.threatdetection.response.AuditLogger;
import com.threatdetection.response.OsResponseCoordinator;
import com.threatdetection.response.WindowsFirewallAdapter;
import com.threatdetection.server.ApiServer;
import com.threatdetection.server.WriteGuard;

import java.io.IOException;
import java.io.OutputStream;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.threatdetection.aegis.JsonUtil.str;

/**
 * Endpoints for the hardening features:
 *   GET  /aegis/api/chains                    correlated attack chains (live + sandbox lane)
 *   GET  /aegis/api/pipeline                  normalisation counters and blocklist status
 *   GET  /aegis/api/response                  firewall mode, active rules, pending approvals, recent audit entries
 *   POST /aegis/api/response/approve?id=N     analyst approves a pending block      (write-guarded)
 *   POST /aegis/api/response/reject?id=N      analyst declines                      (write-guarded)
 *   POST /aegis/api/response/unblock?ip=X     remove one firewall rule              (write-guarded)
 *   POST /aegis/api/response/rollback         remove every AEGIS firewall rule      (write-guarded)
 */
public final class AegisResponseApi {
    private final Aegis aegis;

    public AegisResponseApi(Aegis aegis) { this.aegis = aegis; }

    public void register(ApiServer server) {
        server.addHandler("/aegis/api/chains", ex -> { send(ex, 200, chains()); });
        server.addHandler("/aegis/api/pipeline", ex -> { send(ex, 200, pipeline()); });
        server.addHandler("/aegis/api/response", this::response);
    }

    private String chains() {
        List<AttackChainEngine.Finding> all = new ArrayList<>();
        if (aegis.chains() != null) all.addAll(aegis.chains().findings());
        if (aegis.sandboxChains() != null) all.addAll(aegis.sandboxChains().findings());
        all.sort((a, b) -> Long.compare(b.last, a.last));
        StringBuilder sb = new StringBuilder("{\"count\":").append(all.size()).append(",\"chains\":[");
        for (int i = 0; i < all.size(); i++) {
            AttackChainEngine.Finding f = all.get(i);
            if (i > 0) sb.append(',');
            sb.append("{\"id\":").append(str(f.id)).append(",\"lane\":").append(str(f.lane))
              .append(",\"type\":").append(str(f.type)).append(",\"entity\":").append(str(f.entity))
              .append(",\"severity\":").append(str(f.severity)).append(",\"first\":").append(f.first).append(",\"last\":").append(f.last)
              .append(",\"tactics\":").append(arr(f.tactics)).append(",\"techniques\":").append(arr(f.techniques))
              .append(",\"evidence\":").append(arr(f.evidence)).append(",\"explanation\":").append(str(f.explanation))
              .append(",\"recommendation\":").append(str(f.recommendation)).append(",\"response\":").append(str(f.response)).append('}');
        }
        return sb.append("]}").toString();
    }

    private String pipeline() {
        return "{\"normalization\":" + map(aegis.normalizerStats()) + ",\"blocklist\":" + map(aegis.intelStatus()) + "}";
    }

    private void response(HttpExchange ex) throws IOException {
        String path = ex.getRequestURI().getPath();
        OsResponseCoordinator os = aegis.osResponse();
        if (os == null) { send(ex, 503, "{\"error\":\"OS response layer not attached\"}"); return; }
        if (path.equals("/aegis/api/response")) { send(ex, 200, responseStatus(os)); return; }
        if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) { send(ex, 405, "{\"error\":\"POST only\"}"); return; }
        if (!WriteGuard.allow(ex)) return;
        Map<String, String> q = query(ex.getRequestURI().getRawQuery());
        String actor = "analyst@" + (ex.getRemoteAddress() == null ? "?" : ex.getRemoteAddress().getAddress().getHostAddress());
        switch (path) {
            case "/aegis/api/response/approve" -> {
                WindowsFirewallAdapter.Outcome o = os.approve(lng(q.get("id")), actor);
                send(ex, o.ok() ? 200 : 400, "{\"status\":" + str(o.status().name()) + ",\"message\":" + str(o.message()) + "}");
            }
            case "/aegis/api/response/reject" -> send(ex, 200, "{\"rejected\":" + os.reject(lng(q.get("id")), actor) + "}");
            case "/aegis/api/response/unblock" -> {
                String ip = q.getOrDefault("ip", "");
                aegis.unblock(ip);
                WindowsFirewallAdapter.Outcome o = os.firewall().unblock(ip, "analyst override", actor);
                send(ex, 200, "{\"status\":" + str(o.status().name()) + ",\"message\":" + str(o.message()) + "}");
            }
            case "/aegis/api/response/rollback" -> send(ex, 200, "{\"removed\":" + os.firewall().rollbackAll(actor, "analyst rollback") + "}");
            default -> send(ex, 404, "{\"error\":\"not found\"}");
        }
    }

    private String responseStatus(OsResponseCoordinator os) {
        StringBuilder sb = new StringBuilder("{\"status\":").append(map(os.status())).append(",\"activeRules\":[");
        List<Map<String, Object>> rules = os.firewall().activeRules();
        for (int i = 0; i < rules.size(); i++) { if (i > 0) sb.append(','); sb.append(map(rules.get(i))); }
        sb.append("],\"pending\":[");
        List<OsResponseCoordinator.Pending> p = os.pending();
        for (int i = 0; i < p.size(); i++) {
            OsResponseCoordinator.Pending x = p.get(i);
            if (i > 0) sb.append(',');
            sb.append("{\"id\":").append(x.id()).append(",\"ip\":").append(str(x.ip())).append(",\"ts\":").append(x.ts())
              .append(",\"score\":").append(x.score()).append(",\"confidence\":").append(String.format("%.2f", x.confidence()))
              .append(",\"reasons\":").append(arr(x.reasons())).append('}');
        }
        sb.append("],\"audit\":[");
        List<AuditLogger.Entry> a = os.audit().recent(50);
        for (int i = a.size() - 1; i >= 0; i--) {
            AuditLogger.Entry e = a.get(i);
            if (i != a.size() - 1) sb.append(',');
            sb.append("{\"seq\":").append(e.seq()).append(",\"ts\":").append(e.ts()).append(",\"actor\":").append(str(e.actor()))
              .append(",\"action\":").append(str(e.action())).append(",\"target\":").append(str(e.target()))
              .append(",\"result\":").append(str(e.result())).append(",\"detail\":").append(str(e.detail())).append('}');
        }
        return sb.append("]}").toString();
    }

    private static String arr(Iterable<String> it) {
        StringBuilder sb = new StringBuilder("[");
        boolean first = true;
        for (String s : it) { if (!first) sb.append(','); first = false; sb.append(str(s)); }
        return sb.append(']').toString();
    }

    private static String map(Map<String, Object> m) {
        StringBuilder sb = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, Object> e : m.entrySet()) {
            if (!first) sb.append(',');
            first = false;
            sb.append(str(e.getKey())).append(':');
            Object v = e.getValue();
            if (v instanceof Number || v instanceof Boolean) sb.append(v);
            else if (v instanceof Iterable<?> it) {
                List<String> l = new ArrayList<>();
                for (Object o : it) l.add(String.valueOf(o));
                sb.append(arr(l));
            } else sb.append(str(String.valueOf(v)));
        }
        return sb.append('}').toString();
    }

    private static long lng(String s) {
        try { return Long.parseLong(s == null ? "" : s.trim()); } catch (NumberFormatException e) { return -1; }
    }

    private static Map<String, String> query(String raw) {
        Map<String, String> m = new HashMap<>();
        if (raw == null) return m;
        for (String pair : raw.split("&")) {
            String[] kv = pair.split("=", 2);
            try { m.put(URLDecoder.decode(kv[0], StandardCharsets.UTF_8), kv.length > 1 ? URLDecoder.decode(kv[1], StandardCharsets.UTF_8) : ""); }
            catch (IllegalArgumentException ignored) { /* skip */ }
        }
        return m;
    }

    private static void send(HttpExchange ex, int status, String body) throws IOException {
        byte[] b = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "application/json");
        ex.getResponseHeaders().set("Cache-Control", "no-store");
        ex.sendResponseHeaders(status, b.length);
        try (OutputStream os = ex.getResponseBody()) { os.write(b); }
    }
}
