package com.threatdetection.server;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import com.threatdetection.engine.ThreatDetectionEngine;
import com.threatdetection.model.EventType;
import com.threatdetection.model.LogEvent;
import com.threatdetection.model.ThreatResult;
import com.threatdetection.storage.InMemoryStore;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** Tiny zero-dependency REST API + dashboard server, built on the JDK's HttpServer. */
public class ApiServer {
    private final ThreatDetectionEngine engine;
    private final InMemoryStore store;
    private final int port;
    // Extra endpoints registered by optional modules (e.g. the Threat Map) before start().
    private final Map<String, HttpHandler> extraHandlers = new java.util.LinkedHashMap<>();

    public ApiServer(ThreatDetectionEngine engine, InMemoryStore store, int port) {
        this.engine = engine;
        this.store = store;
        this.port = port;
    }

    /** Lets an optional module (such as the Threat Map) add its own endpoints. Call before start(). */
    public void addHandler(String path, HttpHandler handler) {
        extraHandlers.put(path, handler);
    }

    /** Worker threads and queue length: see the backpressure note below. */
    static final int WORKERS = 16, QUEUE = 256;

    public void start() throws IOException {
        // Loopback by default: the API accepts events that can trigger blocking, so it is not exposed to the
        // network unless you ask for it:  -Dbind=0.0.0.0  (and set -Daegis.api.key for write access).
        String bind = System.getProperty("bind", "127.0.0.1");
        // Connection-level time limits (JDK HttpServer reads these once, before the first server is created).
        System.getProperties().putIfAbsent("sun.net.httpserver.maxReqTime", "20");     // seconds to receive a full request
        System.getProperties().putIfAbsent("sun.net.httpserver.maxRspTime", "60");     // seconds to send a response
        System.getProperties().putIfAbsent("sun.net.httpserver.idleInterval", "30");   // idle keep-alive connections are closed
        System.getProperties().putIfAbsent("sun.net.httpserver.maxIdleConnections", "200");
        HttpServer server = HttpServer.create(new InetSocketAddress(java.net.InetAddress.getByName(bind), port), 128);
        server.createContext("/", this::handleDashboard);
        server.createContext("/classic", this::handleClassicDashboard);
        server.createContext("/api/event", this::handleEvent);
        server.createContext("/api/stats", this::handleStats);
        server.createContext("/api/session", WriteGuard::session);
        extraHandlers.forEach(server::createContext);
        // BACKPRESSURE: 16 workers + a queue of 256 requests. When both are full the accepting thread runs the request
        // itself (CallerRunsPolicy), which slows accepting: new connections wait in the OS backlog (128) or are refused
        // and the client retries. Nothing already accepted is dropped silently. Per-client write rate limits (429) and
        // the request/response time limits above stop one client from holding workers forever.
        java.util.concurrent.ThreadPoolExecutor pool = new java.util.concurrent.ThreadPoolExecutor(WORKERS, WORKERS, 30, java.util.concurrent.TimeUnit.SECONDS,
                new java.util.concurrent.ArrayBlockingQueue<>(QUEUE), r -> {
                    Thread t = new Thread(r, "aegis-http");
                    t.setDaemon(true);
                    return t;
                }, new java.util.concurrent.ThreadPoolExecutor.CallerRunsPolicy());
        server.setExecutor(pool);
        WriteGuard.effectiveKey();   // generate (and file) the per-run key now, so it exists before the first request
        this.server = server;
        server.start();
        System.out.println("Real-Time Threat Detection Engine running at http://" + (bind.equals("0.0.0.0") ? "localhost" : bind) + ":" + port
                + "  (bound to " + bind + (WriteGuard.keyConfigured() ? ", write access needs X-API-Key" : ", write access needs the per-run API key (aegis-data/api-key.txt)") + ")");
    }

    private volatile HttpServer server;

    /** Stops the server (tests and shutdown). */
    public void stop() {
        HttpServer s = server;
        if (s != null) {
            s.stop(0);
            if (s.getExecutor() instanceof java.util.concurrent.ExecutorService es) es.shutdownNow();
        }
    }

    /** Actual port when constructed with port 0 (tests). */
    public int boundPort() { return server == null ? port : server.getAddress().getPort(); }

    /** "/" now serves the platform website; the original dashboard stays available at /classic. */
    private void handleDashboard(HttpExchange exchange) throws IOException {
        sendHtml(exchange, com.threatdetection.platform.PlatformHtml.PAGE);
    }

    private void handleClassicDashboard(HttpExchange exchange) throws IOException {
        sendHtml(exchange, DashboardHtml.PAGE);
    }

    private void sendHtml(HttpExchange exchange, String html) throws IOException {
        byte[] response = WriteGuard.withBootstrap(html).getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/html; charset=utf-8");
        WriteGuard.htmlHeaders(exchange.getResponseHeaders());
        exchange.sendResponseHeaders(200, response.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(response);
        }
    }

    /** Field limits for POST /api/event (documented in the README). */
    private static final int MAX_USER = 128, MAX_ENDPOINT = 2048, MAX_UA = 512, MAX_BODY_FIELD = 16 * 1024, MAX_FILE = 260;

    private void handleEvent(HttpExchange exchange) throws IOException {
        if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendJson(exchange, 405, "{\"error\":\"POST only\"}");
            return;
        }
        if (!WriteGuard.allow(exchange)) return;
        String body;
        try {
            body = readBody(exchange.getRequestBody());
        } catch (IOException tooBig) {
            sendJson(exchange, 413, "{\"error\":\"request body too large (limit 64 KB)\"}");
            return;
        }
        Map<String, String> params;
        try {
            params = parseQuery(body);
        } catch (IllegalArgumentException bad) {
            sendJson(exchange, 400, "{\"error\":\"malformed form encoding\"}");
            return;
        }

        // Validate EVERYTHING before the engine sees the event: nothing invalid is silently turned into a different event.
        String problem = null;
        String ip = params.get("ip");
        if (ip == null || ip.isBlank()) problem = "ip is required";
        else if (!com.threatdetection.aegis.intel.IpClassifier.isValid(ip.trim()) || ip.trim().equals("0.0.0.0") || ip.trim().equals("::")
                || !ip.trim().matches("[0-9a-fA-F:.]{2,45}")) problem = "ip is not a valid source address";
        EventType type = EventType.HTTP_REQUEST;
        if (problem == null && params.containsKey("eventType")) {
            try {
                type = EventType.valueOf(params.get("eventType").trim().toUpperCase(java.util.Locale.ROOT));
            } catch (IllegalArgumentException e) {
                problem = "eventType must be one of " + java.util.Arrays.toString(EventType.values());
            }
        }
        int port = 0;
        if (problem == null && params.containsKey("port")) {
            try {
                port = Integer.parseInt(params.get("port").trim());
                if (port < 0 || port > 65535) problem = "port must be between 0 and 65535";
            } catch (NumberFormatException e) {
                problem = "port must be a whole number between 0 and 65535";
            }
        }
        String username = params.getOrDefault("username", "unknown");
        String endpoint = params.getOrDefault("endpoint", "/");
        String userAgent = params.getOrDefault("userAgent", "");
        String requestBody = params.getOrDefault("body", "");
        String country = params.getOrDefault("country", "UNKNOWN");
        String file = params.getOrDefault("file", "");
        if (problem == null && username.length() > MAX_USER) problem = "username longer than " + MAX_USER;
        if (problem == null && endpoint.length() > MAX_ENDPOINT) problem = "endpoint longer than " + MAX_ENDPOINT;
        if (problem == null && userAgent.length() > MAX_UA) problem = "userAgent longer than " + MAX_UA;
        if (problem == null && requestBody.length() > MAX_BODY_FIELD) problem = "body longer than " + MAX_BODY_FIELD;
        if (problem == null && file.length() > MAX_FILE) problem = "file longer than " + MAX_FILE;
        if (problem == null && !country.matches("[A-Za-z ]{2,32}")) problem = "country must be letters only (e.g. IN, India, UNKNOWN)";
        if (problem != null) {
            sendJson(exchange, 400, "{\"error\":\"" + escape(problem) + "\"}");
            return;
        }

        LogEvent event = new LogEvent(ip.trim(), username, endpoint, userAgent, requestBody,
                country, type, port, file);

        ThreatResult result;
        try {
            result = engine.process(event);
        } catch (RuntimeException e) {
            System.err.println("[AEGIS] event processing failed: " + e);   // details stay in the server log
            sendJson(exchange, 500, "{\"error\":\"internal error while processing the event\"}");
            return;
        }

        // "blocked" is kept for compatibility and means the APPLICATION-level block. osFirewall says what, if anything,
        // happened at the operating-system firewall (only APPLIED / ALREADY_BLOCKED mean a real rule exists).
        String json = "{"
                + "\"ip\":\"" + escape(result.ip) + "\","
                + "\"riskScore\":" + result.riskScore + ","
                + "\"level\":\"" + result.level + "\","
                + "\"blocked\":" + result.blocked + ","
                + "\"appBlocked\":" + result.appBlocked() + ","
                + "\"osFirewall\":\"" + escape(result.osFirewall) + "\","
                + "\"osFirewallEnforced\":" + result.osEnforced() + ","
                + "\"triggeredRules\":" + toJsonArray(result.triggeredRules)
                + "}";

        sendJson(exchange, 200, json);
    }

    private void handleStats(HttpExchange exchange) throws IOException {
        List<ThreatResult> recent = store.getRecent(25);
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        sb.append("\"totalEvents\":").append(store.getTotalEvents()).append(",");
        sb.append("\"totalCriticalAlerts\":").append(store.getTotalCriticalAlerts()).append(",");
        sb.append("\"blockedIps\":").append(toJsonArray(new ArrayList<>(store.getBlockedIps()))).append(",");
        sb.append("\"recentThreats\":[");
        for (int i = 0; i < recent.size(); i++) {
            ThreatResult r = recent.get(i);
            if (i > 0) sb.append(",");
            sb.append("{")
              .append("\"ip\":\"").append(escape(r.ip)).append("\",")
              .append("\"riskScore\":").append(r.riskScore).append(",")
              .append("\"level\":\"").append(r.level).append("\",")
              .append("\"blocked\":").append(r.blocked).append(",")
              .append("\"timestamp\":").append(r.timestamp).append(",")
              .append("\"triggeredRules\":").append(toJsonArray(r.triggeredRules))
              .append("}");
        }
        sb.append("]}");
        sendJson(exchange, 200, sb.toString());
    }

    private String toJsonArray(List<String> items) {
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < items.size(); i++) {
            if (i > 0) sb.append(",");
            sb.append("\"").append(escape(items.get(i))).append("\"");
        }
        sb.append("]");
        return sb.toString();
    }

    private String escape(String s) {
        StringBuilder sb = new StringBuilder(s.length() + 8);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '\\' -> sb.append("\\\\");
                case '"' -> sb.append("\\\"");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> { if (c < 0x20) sb.append(String.format("\\u%04x", (int) c)); else sb.append(c); }
            }
        }
        return sb.toString();
    }

    private void sendJson(HttpExchange exchange, int status, String json) throws IOException {
        byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    private String readBody(InputStream is) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        byte[] data = new byte[1024];
        int read;
        while ((read = is.read(data)) != -1) {
            buffer.write(data, 0, read);
            if (buffer.size() > 64 * 1024) throw new IOException("body too large");
        }
        return buffer.toString(StandardCharsets.UTF_8);
    }

    private Map<String, String> parseQuery(String query) {
        Map<String, String> map = new HashMap<>();
        if (query == null || query.isEmpty()) return map;
        for (String pair : query.split("&")) {
            if (pair.isEmpty()) continue;
            String[] kv = pair.split("=", 2);
            String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
            String value = kv.length > 1 ? URLDecoder.decode(kv[1], StandardCharsets.UTF_8) : "";
            map.put(key, value);
        }
        return map;
    }
}
