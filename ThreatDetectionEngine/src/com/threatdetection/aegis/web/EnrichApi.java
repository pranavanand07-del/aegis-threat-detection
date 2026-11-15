package com.threatdetection.aegis.web;

import com.sun.net.httpserver.HttpExchange;
import com.threatdetection.aegis.intel.Enrichment;
import com.threatdetection.aegis.intel.EnrichmentService;
import com.threatdetection.server.ApiServer;
import com.threatdetection.server.WriteGuard;

import java.io.IOException;
import java.io.OutputStream;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * GET /aegis/api/trust          source-trust legend, providers, quota use, cache (read-only)
 * GET /aegis/api/enrich?ip=...  | ?hash=... | ?url=...   on-demand lookup (uses your API quota, so it needs the write guard)
 */
public final class EnrichApi {
    private final EnrichmentService service;

    public EnrichApi(EnrichmentService service) { this.service = service; }

    public void register(ApiServer server) {
        server.addHandler("/aegis/api/trust", ex -> send(ex, 200, service.statusJson()));
        server.addHandler("/aegis/api/enrich", this::enrich);
    }

    private void enrich(HttpExchange ex) throws IOException {
        if (!WriteGuard.allow(ex)) return;
        Map<String, String> q = new HashMap<>();
        String raw = ex.getRequestURI().getRawQuery();
        if (raw != null) for (String pair : raw.split("&")) {
            String[] kv = pair.split("=", 2);
            try { q.put(URLDecoder.decode(kv[0], StandardCharsets.UTF_8), kv.length > 1 ? URLDecoder.decode(kv[1], StandardCharsets.UTF_8) : ""); } catch (IllegalArgumentException ignored) { }
        }
        List<Enrichment> out;
        if (q.containsKey("ip")) out = service.lookupIp(q.get("ip").trim());
        else if (q.containsKey("hash")) out = List.of(service.lookupHash(q.get("hash").trim()));
        else if (q.containsKey("url") && q.get("url").length() <= 2000) out = List.of(service.lookupUrl(q.get("url").trim()));
        else { send(ex, 400, "{\"error\":\"give ip=, hash= or url=\"}"); return; }
        StringBuilder sb = new StringBuilder("{\"enrichments\":[");
        for (int i = 0; i < out.size(); i++) { if (i > 0) sb.append(','); sb.append(out.get(i).toJson()); }
        send(ex, 200, sb.append("]}").toString());
    }

    private static void send(HttpExchange ex, int status, String body) throws IOException {
        byte[] b = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "application/json");
        ex.getResponseHeaders().set("Cache-Control", "no-store");
        ex.sendResponseHeaders(status, b.length);
        try (OutputStream os = ex.getResponseBody()) { os.write(b); }
    }
}
