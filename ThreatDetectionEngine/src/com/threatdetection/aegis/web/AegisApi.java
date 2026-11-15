package com.threatdetection.aegis.web;

import com.sun.net.httpserver.HttpExchange;
import com.threatdetection.aegis.AegisEvent;
import com.threatdetection.aegis.AegisIncident;
import com.threatdetection.aegis.Aegis;
import com.threatdetection.aegis.DataSource;
import com.threatdetection.aegis.JsonUtil;
import com.threatdetection.aegis.storage.AegisStore;
import com.threatdetection.model.ThreatLevel;
import com.threatdetection.server.ApiServer;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;

import static com.threatdetection.aegis.JsonUtil.esc;
import static com.threatdetection.aegis.JsonUtil.num;
import static com.threatdetection.aegis.JsonUtil.str;

/** HTTP endpoints of AEGIS: /aegis (page) and /aegis/api/{overview,alerts,incidents,intel,events,ingest}. */
public final class AegisApi {
    private final Aegis aegis;
    private final AegisStore store;

    public AegisApi(Aegis aegis) {
        this.aegis = aegis;
        this.store = aegis.store();
    }

    public void register(ApiServer server) {
        server.addHandler("/aegis", this::page);
        server.addHandler("/aegis/api/overview", ex -> json(ex, this::overview));
        server.addHandler("/aegis/api/alerts", ex -> json(ex, this::alerts));
        server.addHandler("/aegis/api/incidents", ex -> json(ex, this::incidents));
        server.addHandler("/aegis/api/intel", ex -> json(ex, this::intel));
        server.addHandler("/aegis/api/events", ex -> json(ex, this::events));
        server.addHandler("/aegis/api/ingest", this::ingest);
    }

    // ---------------------------------------------------------------- plumbing

    private interface Handler {
        String handle(Map<String, String> q);
    }

    private void json(HttpExchange ex, Handler h) throws IOException {
        try {
            send(ex, 200, "application/json", h.handle(query(ex.getRequestURI().getRawQuery())));
        } catch (RuntimeException e) {
            store.countError();
            System.err.println("[AEGIS] request failed: " + e);   // details stay in the server log, not in the response
            send(ex, 500, "application/json", "{\"error\":\"internal error\"}");
        }
    }

    private void page(HttpExchange ex) throws IOException {
        String path = ex.getRequestURI().getPath();
        if (!path.equals("/aegis") && !path.equals("/aegis/")) {
            send(ex, 404, "application/json", "{\"error\":\"not found\"}");
            return;
        }
        send(ex, 200, "text/html; charset=utf-8", com.threatdetection.server.WriteGuard.withBootstrap(AegisHtml.PAGE));
    }

    private void ingest(HttpExchange ex) throws IOException {
        if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) {
            send(ex, 405, "application/json", "{\"error\":\"POST only\"}");
            return;
        }
        if (!com.threatdetection.server.WriteGuard.allow(ex)) return;
        Map<String, String> q = query(ex.getRequestURI().getRawQuery());
        String body;
        try {
            body = com.threatdetection.server.HttpBody.read(ex, com.threatdetection.server.HttpBody.ingestLimit());
        } catch (com.threatdetection.server.HttpBody.TooLarge e) {
            send(ex, 413, "application/json", "{\"error\":\"request body too large (limit "
                    + com.threatdetection.server.HttpBody.ingestLimit() + " bytes, -Daegis.max.body)\"}");
            return;
        } catch (IOException e) {
            send(ex, 400, "application/json", "{\"error\":\"could not read the request body\"}");
            return;
        }
        try {
            int[] r = aegis.ingestPushed(q.getOrDefault("type", "web"), body);
            send(ex, 200, "application/json", "{\"accepted\":" + r[0] + ",\"ignored\":" + r[1] + "}");
        } catch (IllegalArgumentException e) {
            send(ex, 400, "application/json", "{\"error\":" + str(e.getMessage()) + "}");      // e.g. unknown type
        } catch (org.xml.sax.SAXException e) {
            send(ex, 400, "application/json", "{\"error\":\"malformed XML\"}");               // client sent bad data
        } catch (Exception e) {
            store.countError();                                                                     // a genuine server failure is NOT reported as a client error
            System.err.println("[AEGIS] ingest failed: " + e);
            send(ex, 500, "application/json", "{\"error\":\"internal error while ingesting\"}");
        }
    }

    private static void send(HttpExchange ex, int status, String type, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", type);
        ex.getResponseHeaders().set("Cache-Control", "no-store");
        if (type.startsWith("text/html")) com.threatdetection.server.WriteGuard.htmlHeaders(ex.getResponseHeaders());
        ex.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(bytes);
        }
    }

    private static Map<String, String> query(String raw) {
        Map<String, String> m = new HashMap<>();
        if (raw == null || raw.isEmpty()) return m;
        for (String pair : raw.split("&")) {
            if (pair.isEmpty()) continue;
            String[] kv = pair.split("=", 2);
            try {
                m.put(URLDecoder.decode(kv[0], StandardCharsets.UTF_8), kv.length > 1 ? URLDecoder.decode(kv[1], StandardCharsets.UTF_8) : "");
            } catch (IllegalArgumentException ignored) {
                // skip malformed pair
            }
        }
        return m;
    }

    private static long lng(String s, long fallback) {
        if (s == null || s.isEmpty()) return fallback;
        try { return Long.parseLong(s.trim()); } catch (NumberFormatException e) { return fallback; }
    }

    /** {from, to}: explicit from/to (epoch ms) or range=minutes (0 = everything retained). */
    private static long[] window(Map<String, String> q) {
        long now = System.currentTimeMillis();
        long to = lng(q.get("to"), now);
        long from;
        if (q.containsKey("from")) from = lng(q.get("from"), now - 3600_000L);
        else {
            long minutes = lng(q.get("range"), 60);
            from = minutes <= 0 ? 0 : to - minutes * 60_000L;
        }
        return new long[]{Math.max(0, from), to};
    }

    private static DataSource source(String s) {
        if (s == null || s.isEmpty() || s.equalsIgnoreCase("ALL")) return null;
        try { return DataSource.valueOf(s.toUpperCase()); } catch (IllegalArgumentException e) { return null; }
    }

    // ---------------------------------------------------------------- JSON builders

    private String eventJson(AegisEvent e, boolean full) {
        StringBuilder sb = new StringBuilder(256);
        sb.append("{\"id\":").append(e.id)
          .append(",\"ts\":").append(e.ts)
          .append(",\"ip\":").append(str(e.ip))
          .append(",\"ipClass\":").append(str(e.ip.isEmpty() ? "HOST" : (e.internal ? "INTERNAL" : "EXTERNAL")))
          .append(",\"host\":").append(str(e.host))
          .append(",\"user\":").append(str(e.user))
          .append(",\"kind\":").append(str(e.kind))
          .append(",\"channel\":").append(str(e.channel))
          .append(",\"summary\":").append(str(e.summary))
          .append(",\"target\":").append(str(e.target))
          .append(",\"targetType\":").append(str(e.targetType))
          .append(",\"source\":").append(str(e.source.name()))
          .append(",\"score\":").append(e.score)
          .append(",\"level\":").append(str(e.level.name()))
          .append(",\"blocked\":").append(e.blocked)
          .append(",\"incident\":").append(str(e.incident))
          .append(",\"rep\":").append(str(e.repVerdict))
          .append(",\"geoClass\":").append(str(e.geoClass))
          .append(",\"cc\":").append(str(e.cc))
          .append(",\"country\":").append(str(e.country))
          .append(",\"city\":").append(str(e.city))
          .append(",\"trust\":").append(str(e.source.name()))
          .append(",\"enriched\":").append(!e.enrichments.isEmpty());
        if (e.plottable()) sb.append(",\"lat\":").append(num(e.lat)).append(",\"lon\":").append(num(e.lon));
        if (full) {
            sb.append(",\"repDetail\":").append(str(e.repDetail))
              .append(",\"geoSource\":").append(str(e.geoSource))
              .append(",\"rules\":[");
            for (int i = 0; i < e.rules.size(); i++) {
                AegisEvent.Contribution c = e.rules.get(i);
                if (i > 0) sb.append(',');
                sb.append("{\"rule\":").append(str(c.rule)).append(",\"score\":").append(c.score)
                  .append(",\"origin\":").append(str(c.origin)).append(",\"detail\":").append(str(c.detail)).append('}');
            }
            sb.append("],\"sourceMeaning\":").append(str(e.source.description)).append(",\"enrichments\":[");
            int n = 0;
            for (com.threatdetection.aegis.intel.Enrichment en : e.enrichments) {
                if (n++ > 0) sb.append(',');
                sb.append(en.toJson());
            }
            sb.append(']');
        }
        return sb.append('}').toString();
    }

    private String overview(Map<String, String> q) {
        long[] w = window(q);
        long now = System.currentTimeMillis();
        long[] t = store.totals(w[0], w[1]);
        Runtime rt = Runtime.getRuntime();
        long used = rt.totalMemory() - rt.freeMemory();
        double heapPct = 100.0 * used / rt.maxMemory();
        List<AegisStore.SourceStatus> sources = store.sources();
        boolean srcError = false;
        for (AegisStore.SourceStatus s : sources) if ("ERROR".equals(s.state)) srcError = true;
        String health = srcError || heapPct > 85 ? "DEGRADED" : "HEALTHY";

        StringBuilder sb = new StringBuilder();
        sb.append("{\"now\":").append(now)
          .append(",\"from\":").append(w[0]).append(",\"to\":").append(w[1])
          .append(",\"kpi\":{")
          .append("\"analyzedRange\":").append(t[0])
          .append(",\"analyzedSinceStart\":").append(store.analyzed())
          .append(",\"coreTotalEvents\":").append(aegis.legacyStore().getTotalEvents())
          .append(",\"coreCriticalAlerts\":").append(aegis.legacyStore().getTotalCriticalAlerts())
          .append(",\"critical\":").append(t[1]).append(",\"high\":").append(t[2])
          .append(",\"medium\":").append(t[3]).append(",\"low\":").append(t[4])
          .append(",\"openIncidents\":").append(store.openIncidents(now))
          .append(",\"totalIncidents\":").append(store.totalIncidents())
          .append(",\"blockedIps\":").append(aegis.legacyStore().getBlockedIps().size())
          .append(",\"rate10s\":").append(num(store.countSince(10_000) / 10.0))
          .append(",\"rate60s\":").append(num(store.countSince(60_000) / 60.0))
          .append("},\"blocked\":[");
        boolean first = true;
        for (String ip : new TreeSet<>(aegis.legacyStore().getBlockedIps())) {
            if (!first) sb.append(',');
            first = false;
            sb.append(str(ip));
        }
        sb.append("],\"bySource\":{");
        DataSource[] ds = DataSource.values();
        for (int i = 0; i < ds.length; i++) {
            if (i > 0) sb.append(',');
            sb.append(str(ds[i].name())).append(":{\"count\":").append(store.countFor(ds[i]))
              .append(",\"label\":").append(str(ds[i].label)).append(",\"description\":").append(str(ds[i].description)).append('}');
        }
        sb.append("},\"health\":{\"status\":").append(str(health))
          .append(",\"uptimeMs\":").append(now - store.startedAt())
          .append(",\"heapUsedMb\":").append(used / (1024 * 1024))
          .append(",\"heapMaxMb\":").append(rt.maxMemory() / (1024 * 1024))
          .append(",\"heapPct\":").append(num(heapPct))
          .append(",\"eventsInMemory\":").append(store.recentSize())
          .append(",\"alertsInMemory\":").append(store.alertSize())
          .append(",\"errors\":").append(store.errors())
          .append(",\"sources\":[");
        for (int i = 0; i < sources.size(); i++) {
            AegisStore.SourceStatus s = sources.get(i);
            if (i > 0) sb.append(',');
            sb.append("{\"name\":").append(str(s.name)).append(",\"type\":").append(str(s.type))
              .append(",\"state\":").append(str(s.state)).append(",\"detail\":").append(str(s.detail))
              .append(",\"count\":").append(s.count)
              .append(",\"lastEventAgeMs\":").append(s.lastEvent == 0 ? -1 : now - s.lastEvent).append('}');
        }
        sb.append("]},\"series\":[");
        List<long[]> series = store.series(w[0] == 0 ? now - 24L * 3600_000 : w[0], w[1], 60);
        for (int i = 0; i < series.size(); i++) {
            long[] r = series.get(i);
            if (i > 0) sb.append(',');
            sb.append("{\"t\":").append(r[0]).append(",\"n\":").append(r[1]).append(",\"avg\":").append(r[2])
              .append(",\"max\":").append(r[3]).append(",\"c\":").append(r[4]).append(",\"h\":").append(r[5])
              .append(",\"m\":").append(r[6]).append(",\"l\":").append(r[7]).append('}');
        }
        sb.append("],\"config\":{\"targetName\":").append(str(aegis.target().city))
          .append(",\"targetLat\":").append(num(aegis.target().lat))
          .append(",\"targetLon\":").append(num(aegis.target().lon))
          .append(",\"geoDatabase\":").append(aegis.geo().hasDatabase())
          .append(",\"geoRows\":").append(aegis.geo().databaseRows())
          .append(",\"intelFeeds\":").append(aegis.reputation().feedCount())
          .append(",\"intelEntries\":").append(aegis.reputation().entryCount())
          .append(",\"persistFile\":").append(str(aegis.persistFile()))
          .append("}}");
        return sb.toString();
    }

    private String alerts(Map<String, String> q) {
        long[] w = window(q);
        String lv = q.getOrDefault("level", "LOW").toUpperCase();
        ThreatLevel min = lv.equals("ALL") || lv.equals("SAFE") ? ThreatLevel.SAFE : parseLevel(lv);
        int limit = (int) Math.min(500, Math.max(1, lng(q.get("limit"), 100)));
        List<AegisEvent> list = store.query(w[0], w[1], min, source(q.get("source")), q.get("q"), limit);
        StringBuilder sb = new StringBuilder("{\"alerts\":[");
        for (int i = 0; i < list.size(); i++) {
            if (i > 0) sb.append(',');
            sb.append(eventJson(list.get(i), true));
        }
        return sb.append("]}").toString();
    }

    private static ThreatLevel parseLevel(String s) {
        try { return ThreatLevel.valueOf(s); } catch (IllegalArgumentException e) { return ThreatLevel.LOW; }
    }

    private String incidents(Map<String, String> q) {
        long now = System.currentTimeMillis();
        long[] w = window(q);
        StringBuilder sb = new StringBuilder("{\"incidents\":[");
        boolean first = true;
        for (AegisIncident i : store.incidents(200)) {
            if (i.lastSeen < w[0] || i.firstSeen > w[1]) continue;
            if (!first) sb.append(',');
            first = false;
            sb.append("{\"id\":").append(str(i.id)).append(",\"title\":").append(str(i.title()))
              .append(",\"actor\":").append(str(i.actor))
              .append(",\"firstSeen\":").append(i.firstSeen).append(",\"lastSeen\":").append(i.lastSeen)
              .append(",\"count\":").append(i.count).append(",\"maxScore\":").append(i.maxScore)
              .append(",\"level\":").append(str(i.maxLevel.name()))
              .append(",\"status\":").append(str(i.isOpen(now) ? "OPEN" : "CLOSED"))
              .append(",\"blocked\":").append(i.blocked)
              .append(",\"location\":").append(str(i.location))
              .append(",\"sources\":[");
            int k = 0;
            for (DataSource d : i.sources) sb.append(k++ > 0 ? "," : "").append(str(d.name()));
            sb.append("],\"rules\":[");
            k = 0;
            for (String r : i.rules.keySet()) sb.append(k++ > 0 ? "," : "").append(str(r));
            sb.append("]}");
        }
        return sb.append("]}").toString();
    }

    private String intel(Map<String, String> q) {
        long[] w = window(q);
        DataSource src = source(q.get("source"));
        List<AegisEvent> list = store.alertsBetween(w[0], w[1], 50_000);
        Map<String, int[]> attackers = new LinkedHashMap<>();       // ip -> {count, maxScore, blocked}
        Map<String, AegisEvent> lastBy = new HashMap<>();
        Map<String, int[]> targets = new LinkedHashMap<>();
        Map<String, int[]> geoClass = new LinkedHashMap<>();
        Map<String, int[]> bySource = new LinkedHashMap<>();
        int internal = 0, external = 0, hostLocal = 0;
        for (AegisEvent e : list) {
            if (src != null && e.source != src) continue;
            if (e.ip.isEmpty()) hostLocal++;
            else if (e.internal) internal++;
            else external++;
            geoClass.computeIfAbsent(e.geoClass, k -> new int[1])[0]++;
            bySource.computeIfAbsent(e.source.name(), k -> new int[1])[0]++;
            if (!e.target.isEmpty()) targets.computeIfAbsent(e.targetType + "|" + e.target, k -> new int[1])[0]++;
            if (!e.ip.isEmpty()) {
                int[] a = attackers.computeIfAbsent(e.ip, k -> new int[3]);
                a[0]++;
                a[1] = Math.max(a[1], e.score);
                if (e.blocked) a[2] = 1;
                lastBy.put(e.ip, e);
            }
        }
        StringBuilder sb = new StringBuilder("{\"internal\":").append(internal).append(",\"external\":").append(external)
                .append(",\"hostLocal\":").append(hostLocal).append(",\"attackers\":[");
        List<Map.Entry<String, int[]>> top = new ArrayList<>(attackers.entrySet());
        top.sort((a, b) -> a.getValue()[1] != b.getValue()[1] ? b.getValue()[1] - a.getValue()[1] : b.getValue()[0] - a.getValue()[0]);
        for (int i = 0; i < Math.min(10, top.size()); i++) {
            Map.Entry<String, int[]> en = top.get(i);
            AegisEvent last = lastBy.get(en.getKey());
            if (i > 0) sb.append(',');
            sb.append("{\"ip\":").append(str(en.getKey())).append(",\"count\":").append(en.getValue()[0])
              .append(",\"maxScore\":").append(en.getValue()[1]).append(",\"blocked\":").append(en.getValue()[2] == 1)
              .append(",\"ipClass\":").append(str(last.internal ? "INTERNAL" : "EXTERNAL"))
              .append(",\"rep\":").append(str(last.repVerdict)).append(",\"repDetail\":").append(str(last.repDetail))
              .append(",\"geoClass\":").append(str(last.geoClass))
              .append(",\"place\":").append(str(last.city.isEmpty() ? "" : last.city + (last.country.isEmpty() ? "" : ", " + last.country)))
              .append(",\"source\":").append(str(last.source.name())).append('}');
        }
        sb.append("],\"targets\":[");
        List<Map.Entry<String, int[]>> tt = new ArrayList<>(targets.entrySet());
        tt.sort((a, b) -> b.getValue()[0] - a.getValue()[0]);
        for (int i = 0; i < Math.min(8, tt.size()); i++) {
            String[] kv = tt.get(i).getKey().split("\\|", 2);
            if (i > 0) sb.append(',');
            sb.append("{\"type\":").append(str(kv[0])).append(",\"target\":").append(str(kv[1]))
              .append(",\"count\":").append(tt.get(i).getValue()[0]).append('}');
        }
        sb.append("],\"geoClass\":{");
        appendCounts(sb, geoClass);
        sb.append("},\"bySource\":{");
        appendCounts(sb, bySource);
        return sb.append("}}").toString();
    }

    private static void appendCounts(StringBuilder sb, Map<String, int[]> m) {
        int i = 0;
        for (Map.Entry<String, int[]> e : m.entrySet()) {
            if (i++ > 0) sb.append(',');
            sb.append('"').append(esc(e.getKey())).append("\":").append(e.getValue()[0]);
        }
    }

    /** Compact alert list (oldest first) for the map, time filter and playback. */
    private String events(Map<String, String> q) {
        long[] w = window(q);
        int max = (int) Math.min(5000, Math.max(1, lng(q.get("max"), 3000)));
        DataSource src = source(q.get("source"));
        List<AegisEvent> list = store.alertsBetween(w[0], w[1], 50_000);
        List<AegisEvent> picked = new ArrayList<>();
        for (AegisEvent e : list) if (src == null || e.source == src) picked.add(e);
        if (picked.size() > max) picked = picked.subList(picked.size() - max, picked.size());
        StringBuilder sb = new StringBuilder("{\"from\":").append(w[0]).append(",\"to\":").append(w[1]).append(",\"events\":[");
        for (int i = 0; i < picked.size(); i++) {
            if (i > 0) sb.append(',');
            sb.append(eventJson(picked.get(i), false));
        }
        return sb.append("]}").toString();
    }
}
