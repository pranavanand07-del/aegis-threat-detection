package com.threatdetection.map;

import com.sun.net.httpserver.HttpExchange;
import com.threatdetection.server.ApiServer;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

/**
 * Registers the Threat Map page and its JSON endpoints on the existing ApiServer:
 *   GET /map                   the map page
 *   GET /api/map/state         attackers, countries, India states, targets, summary
 *   GET /api/map/events?since= new geolocated events (drives the animations)
 *   GET /api/map/geometry      offline world outline used to draw the map
 */
public final class ThreatMapApi {
    private ThreatMapApi() {}

    public static void register(ApiServer server, ThreatMapService service) {
        server.addHandler("/map", ex -> send(ex, 200, "text/html; charset=utf-8", com.threatdetection.server.WriteGuard.withBootstrap(ThreatMapHtml.PAGE)));
        server.addHandler("/api/map/state", ex -> send(ex, 200, "application/json", service.stateJson()));
        server.addHandler("/api/map/events", ex -> {
            long since = 0;
            String q = ex.getRequestURI().getRawQuery();
            if (q != null) {
                for (String pair : q.split("&")) {
                    if (pair.startsWith("since=")) {
                        try {
                            since = Long.parseLong(pair.substring(6));
                        } catch (NumberFormatException ignored) {
                            // keep 0
                        }
                    }
                }
            }
            send(ex, 200, "application/json", service.eventsJson(since));
        });
        server.addHandler("/api/map/geometry", ex -> send(ex, 200, "application/json", WorldGeometry.JSON));
    }

    private static void send(HttpExchange ex, int status, String contentType, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", contentType);
        ex.getResponseHeaders().set("Cache-Control", "no-store");
        if (contentType.startsWith("text/html")) com.threatdetection.server.WriteGuard.htmlHeaders(ex.getResponseHeaders());
        ex.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(bytes);
        }
    }
}
