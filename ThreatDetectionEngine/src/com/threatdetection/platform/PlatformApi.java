package com.threatdetection.platform;

import com.sun.net.httpserver.HttpExchange;
import com.threatdetection.aegis.Aegis;
import com.threatdetection.aegis.AegisEvent;
import com.threatdetection.aegis.AegisSignal;
import com.threatdetection.aegis.DataSource;
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
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static com.threatdetection.aegis.JsonUtil.str;

/**
 * Endpoints behind the platform website ("/"):
 *   GET  /api/platform/model      rules, bands, attack-chain stages, campaign formula
 *   GET  /api/platform/summary    live numbers, chart series, top rules, recent detections, sources
 *   GET  /api/platform/campaigns  per-actor campaign view
 *   POST /api/platform/analyze    attack lab: run one event through the real pipeline, get the full explanation
 *   GET  /api/platform/selftest   run the verification cases against the live rule code
 *
 * Additive: nothing here changes how events are scored or blocked.
 */
public final class PlatformApi {
    private static final long MAX_BODY = 256 * 1024;
    private static final String BROWSER = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)";

    private final Aegis aegis;
    private final AegisStore store;
    private final CampaignAnalyzer campaigns;

    private PlatformApi(Aegis aegis) {
        this.aegis = aegis;
        this.store = aegis.store();
        this.campaigns = new CampaignAnalyzer(store);
    }

    public static void register(ApiServer server, Aegis aegis) {
        PlatformApi api = new PlatformApi(aegis);
        server.addHandler("/api/platform/model", ex -> api.json(ex, q -> api.model()));
        server.addHandler("/api/platform/summary", ex -> api.json(ex, api::summary));
        server.addHandler("/api/platform/campaigns", ex -> api.json(ex, api::campaignList));
        server.addHandler("/api/platform/selftest", ex -> api.json(ex, q -> SelfTest.toJson(SelfTest.run())));
        server.addHandler("/api/platform/analyze", api::analyze);
    }

    // ------------------------------------------------------------------ model

    private String model() {
        StringBuilder sb = new StringBuilder(16_384);
        int core = 0, extra = 0;
        for (RuleCatalog.Rule r : RuleCatalog.RULES) if (r.origin().equals("core")) core++; else extra++;
        sb.append("{\"counts\":{\"core\":").append(core).append(",\"aegis\":").append(extra)
          .append(",\"total\":").append(core + extra).append('}');
        sb.append(",\"bands\":[")
          .append(band("SAFE", 0, 20, "Logged only. Nothing to review."))
          .append(',').append(band("LOW", 21, 50, "Logged and shown on the dashboard."))
          .append(',').append(band("MEDIUM", 51, 80, "Alert for an analyst to review."))
          .append(',').append(band("HIGH", 81, 100, "Urgent alert."))
          .append(',').append(band("CRITICAL", 101, 140, "Source IP is blocked for 10 minutes."))
          .append(']');
        sb.append(",\"block\":{\"level\":\"CRITICAL\",\"minutes\":10}");
        sb.append(",\"campaign\":{\"halfLifeMinutes\":").append(CampaignAnalyzer.HALF_LIFE_MS / 60_000)
          .append(",\"stageBonus\":").append(CampaignAnalyzer.STAGE_BONUS)
          .append(",\"escalateAt\":").append(CampaignAnalyzer.ESCALATE_AT)
          .append(",\"blockAt\":").append(CampaignAnalyzer.BLOCK_AT).append('}');
        sb.append(",\"stages\":[");
        for (int i = 0; i < RuleCatalog.STAGES.size(); i++) {
            RuleCatalog.Stage s = RuleCatalog.STAGES.get(i);
            if (i > 0) sb.append(',');
            sb.append("{\"id\":").append(str(s.id())).append(",\"name\":").append(str(s.name()))
              .append(",\"summary\":").append(str(s.summary())).append('}');
        }
        sb.append("],\"rules\":[");
        for (int i = 0; i < RuleCatalog.RULES.size(); i++) {
            RuleCatalog.Rule r = RuleCatalog.RULES.get(i);
            if (i > 0) sb.append(',');
            sb.append("{\"id\":").append(str(r.id()))
              .append(",\"origin\":").append(str(r.origin()))
              .append(",\"family\":").append(str(r.family()))
              .append(",\"stage\":").append(r.stage() == null ? "null" : str(r.stage()))
              .append(",\"technique\":").append(str(r.technique()))
              .append(",\"trigger\":").append(str(r.trigger()))
              .append(",\"min\":").append(r.min())
              .append(",\"max\":").append(r.max())
              .append(",\"caution\":").append(str(r.caution()))
              .append('}');
        }
        return sb.append("]}").toString();
    }

    private static String band(String level, int from, int to, String meaning) {
        return "{\"level\":" + str(level) + ",\"from\":" + from + ",\"to\":" + to + ",\"meaning\":" + str(meaning) + "}";
    }

    // ------------------------------------------------------------------ summary

    private String summary(Map<String, String> q) {
        long now = System.currentTimeMillis();
        long minutes = lng(q.get("range"), 60);
        long from = minutes <= 0 ? 0 : now - minutes * 60_000L;
        long[] t = store.totals(from, now);

        Map<String, long[]> byRule = new LinkedHashMap<>();   // rule -> {count, points}
        Map<String, String> ruleOrigin = new HashMap<>();
        Map<String, java.util.Set<String>> ruleActors = new HashMap<>();
        long[] byStage = new long[RuleCatalog.STAGES.size()];
        List<AegisEvent> recent = new ArrayList<>();
        for (AegisEvent e : store.query(from, now, ThreatLevel.SAFE, null, "", 10_000)) {
            boolean[] seenStage = new boolean[byStage.length];
            boolean hit = false;
            for (AegisEvent.Contribution c : e.rules) {
                if (c.rule.equals("IP_ALREADY_BLOCKED")) continue;
                hit = true;
                long[] agg = byRule.computeIfAbsent(c.rule, k -> new long[2]);
                agg[0]++;
                agg[1] += c.score;
                ruleOrigin.putIfAbsent(c.rule, c.origin);
                ruleActors.computeIfAbsent(c.rule, k -> new java.util.HashSet<>()).add(CampaignAnalyzer.actorOf(e));
                int si = RuleCatalog.stageIndex(RuleCatalog.stageOf(c.rule));
                if (si >= 0 && !seenStage[si]) {
                    seenStage[si] = true;
                    byStage[si]++;
                }
            }
            if (hit && recent.size() < 14) recent.add(e);
        }

        StringBuilder sb = new StringBuilder(16_384);
        sb.append("{\"now\":").append(now)
          .append(",\"startedAt\":").append(store.startedAt())
          .append(",\"analyzed\":").append(store.analyzed())
          .append(",\"errors\":").append(store.errors())
          .append(",\"window\":{\"from\":").append(from).append(",\"events\":").append(t[0])
          .append(",\"critical\":").append(t[1]).append(",\"high\":").append(t[2])
          .append(",\"medium\":").append(t[3]).append(",\"low\":").append(t[4]).append(",\"safe\":").append(t[5]).append('}')
          .append(",\"perMinute\":").append(store.countSince(60_000))
          .append(",\"blockedIps\":").append(aegis.legacyStore().getBlockedIps().size())
          .append(",\"openIncidents\":").append(store.openIncidents(now))
          .append(",\"totalIncidents\":").append(store.totalIncidents())
          .append(",\"bySource\":{\"OBSERVED\":").append(store.countFor(DataSource.OBSERVED))
          .append(",\"API\":").append(store.countFor(DataSource.API))
          .append(",\"SIMULATED\":").append(store.countFor(DataSource.SIMULATED)).append('}');

        sb.append(",\"series\":[");
        List<long[]> series = store.series(from == 0 ? now - 24 * 3600_000L : from, now, 48);
        for (int i = 0; i < series.size(); i++) {
            long[] r = series.get(i);
            if (i > 0) sb.append(',');
            sb.append('[');
            for (int k = 0; k < r.length; k++) {
                if (k > 0) sb.append(',');
                sb.append(r[k]);
            }
            sb.append(']');
        }
        sb.append(']');

        sb.append(",\"topRules\":[");
        List<Map.Entry<String, long[]>> ranked = new ArrayList<>(byRule.entrySet());
        ranked.sort(Comparator.comparingInt((Map.Entry<String, long[]> e) -> ruleActors.get(e.getKey()).size()).reversed()
                .thenComparing(Comparator.comparingLong((Map.Entry<String, long[]> e) -> e.getValue()[0]).reversed()));
        for (int i = 0; i < Math.min(10, ranked.size()); i++) {
            Map.Entry<String, long[]> e = ranked.get(i);
            if (i > 0) sb.append(',');
            sb.append("{\"rule\":").append(str(e.getKey()))
              .append(",\"origin\":").append(str(ruleOrigin.getOrDefault(e.getKey(), "core")))
              .append(",\"count\":").append(e.getValue()[0])
              .append(",\"actors\":").append(ruleActors.get(e.getKey()).size())
              .append(",\"points\":").append(e.getValue()[1]).append('}');
        }
        sb.append("],\"stages\":[");
        for (int i = 0; i < byStage.length; i++) {
            if (i > 0) sb.append(',');
            sb.append("{\"id\":").append(str(RuleCatalog.STAGES.get(i).id())).append(",\"events\":").append(byStage[i]).append('}');
        }
        sb.append("],\"recent\":[");
        for (int i = 0; i < recent.size(); i++) {
            if (i > 0) sb.append(',');
            sb.append(eventJson(recent.get(i)));
        }
        sb.append("],\"sources\":[");
        List<AegisStore.SourceStatus> sources = store.sources();
        for (int i = 0; i < sources.size(); i++) {
            AegisStore.SourceStatus s = sources.get(i);
            if (i > 0) sb.append(',');
            sb.append("{\"name\":").append(str(s.name)).append(",\"type\":").append(str(s.type))
              .append(",\"state\":").append(str(s.state)).append(",\"detail\":").append(str(s.detail))
              .append(",\"lastEvent\":").append(s.lastEvent).append(",\"count\":").append(s.count).append('}');
        }
        return sb.append("]}").toString();
    }

    private static String eventJson(AegisEvent e) {
        StringBuilder sb = new StringBuilder(512);
        sb.append("{\"id\":").append(e.id)
          .append(",\"ts\":").append(e.ts)
          .append(",\"ip\":").append(str(e.ip))
          .append(",\"internal\":").append(e.internal)
          .append(",\"kind\":").append(str(e.kind))
          .append(",\"summary\":").append(str(e.summary))
          .append(",\"score\":").append(e.score)
          .append(",\"level\":").append(str(e.level.name()))
          .append(",\"blocked\":").append(e.blocked)
          .append(",\"source\":").append(str(e.source.name()))
          .append(",\"geoClass\":").append(str(e.geoClass))
          .append(",\"place\":").append(str(e.city.isEmpty() ? e.country : e.city + ", " + e.country))
          .append(",\"reputation\":").append(str(e.repVerdict))
          .append(",\"rules\":[");
        for (int i = 0; i < e.rules.size(); i++) {
            AegisEvent.Contribution c = e.rules.get(i);
            RuleCatalog.Rule r = RuleCatalog.find(c.rule);
            if (i > 0) sb.append(',');
            sb.append("{\"rule\":").append(str(c.rule))
              .append(",\"score\":").append(c.score)
              .append(",\"origin\":").append(str(c.origin))
              .append(",\"detail\":").append(str(c.detail))
              .append(",\"stage\":").append(r == null || r.stage() == null ? "null" : str(r.stage()))
              .append(",\"technique\":").append(str(r == null ? "" : r.technique()))
              .append('}');
        }
        return sb.append("]}").toString();
    }

    // ------------------------------------------------------------------ campaigns

    private String campaignList(Map<String, String> q) {
        long now = System.currentTimeMillis();
        long minutes = lng(q.get("range"), 60);
        long from = minutes <= 0 ? 0 : now - minutes * 60_000L;
        List<CampaignAnalyzer.Campaign> list = campaigns.analyze(from, now, (int) lng(q.get("limit"), 12));
        StringBuilder sb = new StringBuilder(8192).append("{\"campaigns\":[");
        for (int i = 0; i < list.size(); i++) {
            if (i > 0) sb.append(',');
            sb.append(list.get(i).toJson());
        }
        return sb.append("]}").toString();
    }

    // ------------------------------------------------------------------ attack lab

    private void analyze(HttpExchange ex) throws IOException {
        if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) {
            send(ex, 405, "{\"error\":\"POST only\"}");
            return;
        }
        if (!com.threatdetection.server.WriteGuard.allow(ex)) return;
        String raw;
        try {
            raw = com.threatdetection.server.HttpBody.read(ex, MAX_BODY);
        } catch (com.threatdetection.server.HttpBody.TooLarge e) {
            send(ex, 413, "{\"error\":\"request body too large\"}");
            return;
        } catch (IOException e) {
            send(ex, 400, "{\"error\":\"could not read the request body\"}");
            return;
        }
        Map<String, String> p;
        try {
            p = parse(raw);
        } catch (IllegalArgumentException e) {
            send(ex, 400, "{\"error\":\"malformed form encoding\"}");
            return;
        }
        String ip = p.getOrDefault("ip", "").trim();
        if (ip.isEmpty()) {
            send(ex, 400, "{\"error\":\"ip is required\"}");
            return;
        }
        AegisSignal s;
        try {
            s = signalFrom(p, ip);
        } catch (IllegalArgumentException e) {
            send(ex, 400, "{\"error\":" + str(e.getMessage()) + "}");
            return;
        }
        aegis.ingestLab(s);

        long now = System.currentTimeMillis();
        AegisEvent found = null;
        for (AegisEvent e : store.query(now - 60_000, now + 5_000, ThreatLevel.SAFE, DataSource.API, ip, 20)) {
            if (ip.equals(e.ip)) { found = e; break; }
        }
        if (found == null) {
            send(ex, 500, "{\"error\":\"event was not recorded\"}");
            return;
        }
        CampaignAnalyzer.Campaign c = campaigns.forActor(ip, 60 * 60_000L);
        send(ex, 200, "{\"actor\":" + str(ip) + ",\"event\":" + eventJson(found)
                + ",\"campaign\":" + (c == null ? "null" : c.toJson()) + "}");
    }

    private static AegisSignal signalFrom(Map<String, String> p, String ip) {
        String kind = p.getOrDefault("kind", "web");
        AegisSignal s;
        switch (kind) {
            case "web" -> {
                s = new AegisSignal(AegisSignal.Kind.WEB);
                s.path = p.getOrDefault("path", "/");
                s.command = p.getOrDefault("body", "");
            }
            case "download" -> {
                s = new AegisSignal(AegisSignal.Kind.WEB);
                s.fileName = p.getOrDefault("file", "file.bin");
                s.path = "/files/" + s.fileName;
            }
            case "auth_fail", "auth_ok" -> {
                s = new AegisSignal(AegisSignal.Kind.AUTH);
                s.authFailure = kind.equals("auth_fail");
                s.path = p.getOrDefault("path", "");
            }
            case "port" -> {
                s = new AegisSignal(AegisSignal.Kind.NETWORK);
                s.direction = "in";
                s.action = p.getOrDefault("action", "DROP");
            }
            case "process" -> {
                s = new AegisSignal(AegisSignal.Kind.PROCESS);
                s.path = p.getOrDefault("path", "");
                s.command = p.getOrDefault("command", "");
                s.parent = p.getOrDefault("parent", "");
            }
            case "win" -> {
                int id = (int) lng(p.get("event"), 0);
                if (id <= 0) throw new IllegalArgumentException("event (Windows event id) is required for kind=win");
                s = new AegisSignal(id == 4624 || id == 4625 ? AegisSignal.Kind.AUTH : AegisSignal.Kind.AUDIT);
                s.winEventId = id;
                s.authFailure = id == 4625;
                s.logonType = (int) lng(p.get("logon"), -1);
                s.path = p.getOrDefault("path", "");
            }
            default -> throw new IllegalArgumentException("unknown kind: " + kind);
        }
        s.ip = ip;
        s.user = p.getOrDefault("user", "guest");
        s.userAgent = p.getOrDefault("ua", BROWSER);
        s.country = p.getOrDefault("country", "UNKNOWN");
        s.port = (int) lng(p.get("port"), 0);
        s.host = p.getOrDefault("host", "");
        return s;
    }

    // ------------------------------------------------------------------ plumbing

    private interface Handler {
        String handle(Map<String, String> q);
    }

    private void json(HttpExchange ex, Handler h) throws IOException {
        try {
            send(ex, 200, h.handle(parse(ex.getRequestURI().getRawQuery())));
        } catch (RuntimeException e) {
            store.countError();
            send(ex, 500, "{\"error\":" + str(String.valueOf(e.getMessage())) + "}");
        }
    }

    private static void send(HttpExchange ex, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        ex.getResponseHeaders().set("Cache-Control", "no-store");
        ex.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(bytes);
        }
    }

    private static Map<String, String> parse(String raw) {
        Map<String, String> m = new HashMap<>();
        if (raw == null || raw.isEmpty()) return m;
        for (String pair : raw.split("&")) {
            if (pair.isEmpty()) continue;
            String[] kv = pair.split("=", 2);
            try {
                m.put(URLDecoder.decode(kv[0], StandardCharsets.UTF_8),
                        kv.length > 1 ? URLDecoder.decode(kv[1], StandardCharsets.UTF_8) : "");
            } catch (IllegalArgumentException ignored) {
                // skip a malformed pair
            }
        }
        return m;
    }

    private static long lng(String s, long fallback) {
        if (s == null || s.isEmpty()) return fallback;
        try {
            return Long.parseLong(s.trim());
        } catch (NumberFormatException e) {
            return fallback;
        }
    }
}
