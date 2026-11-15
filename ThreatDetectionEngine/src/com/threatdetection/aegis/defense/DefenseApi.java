package com.threatdetection.aegis.defense;

import com.sun.net.httpserver.HttpExchange;
import com.threatdetection.server.ApiServer;
import com.threatdetection.server.WriteGuard;

import java.io.IOException;
import java.io.OutputStream;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.threatdetection.aegis.JsonUtil.str;

/**
 * /aegis/defense (page) and /aegis/api/defense/{status,actions,audit,check} (read) plus
 * {approve,reject,revert,manual} (write; local requests only, or X-API-Key when -Daegis.api.key is set).
 */
public final class DefenseApi {
    private final DefenseCoordinator defense;

    public DefenseApi(DefenseCoordinator defense) { this.defense = defense; }

    public void register(ApiServer server) {
        server.addHandler("/aegis/defense", ex -> send(ex, 200, "text/html; charset=utf-8", WriteGuard.withBootstrap(DefenseHtml.PAGE)));
        server.addHandler("/aegis/api/defense/status", ex -> send(ex, 200, "application/json", defense.statusJson()));
        server.addHandler("/aegis/api/defense/actions", this::actions);
        server.addHandler("/aegis/api/defense/audit", this::audit);
        server.addHandler("/aegis/api/defense/check", this::check);
        server.addHandler("/aegis/api/defense/approve", ex -> decide(ex, "approve"));
        server.addHandler("/aegis/api/defense/reject", ex -> decide(ex, "reject"));
        server.addHandler("/aegis/api/defense/revert", ex -> decide(ex, "revert"));
        server.addHandler("/aegis/api/defense/manual", this::manual);
    }

    private void actions(HttpExchange ex) throws IOException {
        Map<String, String> q = query(ex);
        String state = q.getOrDefault("state", "");
        StringBuilder sb = new StringBuilder("{\"actions\":[");
        int n = 0;
        for (DefenseAction a : defense.list()) {
            if (!state.isEmpty() && !a.state.name().equalsIgnoreCase(state)) continue;
            if (n++ > 0) sb.append(',');
            sb.append(a.toJson());
            if (n >= 200) break;
        }
        send(ex, 200, "application/json", sb.append("]}").toString());
    }

    private void audit(HttpExchange ex) throws IOException {
        Map<String, String> q = query(ex);
        int limit = 100;
        try { limit = Math.max(1, Math.min(500, Integer.parseInt(q.getOrDefault("limit", "100")))); } catch (NumberFormatException ignored) { }
        List<AuditTrail.Record> recs = defense.audit().tail(limit);
        StringBuilder sb = new StringBuilder("{");
        if (q.containsKey("verify")) {
            AuditTrail.Verification v = defense.audit().verify();
            sb.append("\"verification\":{\"ok\":").append(v.ok()).append(",\"records\":").append(v.records())
              .append(",\"firstBadSeq\":").append(v.firstBadSeq()).append(",\"message\":").append(str(v.message())).append("},");
        }
        sb.append("\"records\":[");
        for (int i = recs.size() - 1, n = 0; i >= 0; i--, n++) {
            if (n > 0) sb.append(',');
            sb.append(recs.get(i).toJson());
        }
        send(ex, 200, "application/json", sb.append("]}").toString());
    }

    /** For the protected application: may this session / account / source proceed? Read-only. */
    private void check(HttpExchange ex) throws IOException {
        Map<String, String> q = query(ex);
        String type = q.getOrDefault("type", ""), id = q.getOrDefault("id", "");
        boolean allowed;
        String why = "";
        switch (type) {
            case "session" -> { allowed = !defense.controls().sessionRevoked(id); if (!allowed) why = "session revoked by AEGIS"; }
            case "account" -> { allowed = !defense.controls().accountLocked(id); if (!allowed) why = "account temporarily locked by AEGIS"; }
            case "ip" -> { allowed = defense.controls().allowRequest(id); if (!allowed) why = "source is rate-limited by AEGIS"; }
            default -> {
                send(ex, 400, "application/json", "{\"error\":\"type must be session, account or ip\"}");
                return;
            }
        }
        send(ex, 200, "application/json", "{\"allowed\":" + allowed + ",\"reason\":" + str(why) + "}");
    }

    private void decide(HttpExchange ex, String what) throws IOException {
        if (!post(ex)) return;
        String id = query(ex).getOrDefault("id", "");
        String op = operator(ex);
        String err = switch (what) {
            case "approve" -> defense.approve(id, op);
            case "reject" -> defense.reject(id, op);
            default -> defense.revert(id, op);
        };
        send(ex, err == null ? 200 : 409, "application/json", err == null ? "{\"ok\":true}" : "{\"ok\":false,\"error\":" + str(err) + "}");
    }

    private void manual(HttpExchange ex) throws IOException {
        if (!post(ex)) return;
        Map<String, String> q = query(ex);
        DefenseAction.Type type;
        try {
            type = DefenseAction.Type.valueOf(q.getOrDefault("type", "").toUpperCase());
        } catch (IllegalArgumentException e) {
            send(ex, 400, "application/json", "{\"error\":\"type must be one of FIREWALL_BLOCK, QUARANTINE_FILE, REVOKE_SESSION, LOCK_ACCOUNT, RATE_LIMIT\"}");
            return;
        }
        String target = q.getOrDefault("target", "").trim();
        if (target.isEmpty()) {
            send(ex, 400, "application/json", "{\"error\":\"target is required\"}");
            return;
        }
        if (defense.config().mode == DefenseMode.OFF) {
            send(ex, 409, "application/json", "{\"error\":\"defense mode is off\"}");
            return;
        }
        DefenseAction a = defense.manual(type, target, q.getOrDefault("reason", ""), operator(ex));
        send(ex, 200, "application/json", a.toJson());
    }

    private static boolean post(HttpExchange ex) throws IOException {
        if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) {
            send(ex, 405, "application/json", "{\"error\":\"POST only\"}");
            return false;
        }
        return WriteGuard.allow(ex);
    }

    /** Operator name for the audit trail. Without -Daegis.api.key the name is self-declared, and is marked as such. */
    private static String operator(HttpExchange ex) {
        String h = ex.getRequestHeaders().getFirst("X-Operator");
        String name = h == null ? "" : h.replaceAll("[^A-Za-z0-9._@-]", "");
        if (name.length() > 40) name = name.substring(0, 40);
        if (name.isEmpty()) name = "analyst";
        return WriteGuard.isTrustedWrite(ex) ? name : name + " (local, unverified)";
    }

    private static Map<String, String> query(HttpExchange ex) {
        Map<String, String> m = new HashMap<>();
        String raw = ex.getRequestURI().getRawQuery();
        if (raw == null) return m;
        for (String pair : raw.split("&")) {
            String[] kv = pair.split("=", 2);
            try {
                m.put(URLDecoder.decode(kv[0], StandardCharsets.UTF_8), kv.length > 1 ? URLDecoder.decode(kv[1], StandardCharsets.UTF_8) : "");
            } catch (IllegalArgumentException ignored) { }
        }
        return m;
    }

    private static void send(HttpExchange ex, int status, String type, String body) throws IOException {
        byte[] b = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", type);
        ex.getResponseHeaders().set("Cache-Control", "no-store");
        if (type.startsWith("text/html")) com.threatdetection.server.WriteGuard.htmlHeaders(ex.getResponseHeaders());
        ex.sendResponseHeaders(status, b.length);
        try (OutputStream os = ex.getResponseBody()) { os.write(b); }
    }
}
