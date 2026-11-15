package com.threatdetection.detector;

import com.threatdetection.model.DetectionOutcome;
import com.threatdetection.model.EventType;
import com.threatdetection.model.LogEvent;
import com.threatdetection.tracking.IpActivityTracker;

import java.util.Locale;
import java.util.Set;

/**
 * Flags automated-tool user agents, with context so routine monitoring is not an alert.
 *
 * Offensive tools (sqlmap, nikto, nmap, masscan...) are always flagged. Generic HTTP clients
 * (curl, wget, python-requests...) and a missing User-Agent are flagged EXCEPT for a plain
 * health-check request: GET of a well-known health path, no query string and no body.
 * Anything else a generic client does (search, login, API calls) is still scored.
 */
public class BotDetector implements Detector {
    private static final String[] OFFENSIVE = {"sqlmap", "nikto", "masscan", "nmap", "wpscan", "dirbuster", "gobuster", "hydra"};
    private static final String[] GENERIC_CLIENTS = {"python-requests", "curl", "wget", "scrapy", "libwww-perl"};
    private static final Set<String> HEALTH_PATHS = Set.of("/health", "/healthz", "/livez", "/readyz", "/ready", "/ping",
            "/status", "/_health", "/api/health", "/actuator/health", "/health/live", "/health/ready");

    @Override
    public DetectionOutcome evaluate(LogEvent event, IpActivityTracker tracker) {
        // Port and firewall events carry no HTTP headers, so a missing User-Agent says nothing about them.
        if (event.eventType == EventType.PORT_ACCESS) {
            return null;
        }
        String ua = event.userAgent.toLowerCase(Locale.ROOT);
        boolean healthCheck = isPlainHealthCheck(event);

        for (String sig : OFFENSIVE) {
            if (ua.contains(sig)) {
                return new DetectionOutcome("BOT_DETECTED", 15, "Automated tool signature in User-Agent: " + sig);
            }
        }
        if (healthCheck) {
            return null;   // monitoring probe, or curl/empty UA doing a bare health request
        }
        if (ua.isEmpty()) {
            return new DetectionOutcome("BOT_DETECTED", 10, "Missing User-Agent header");
        }
        for (String sig : GENERIC_CLIENTS) {
            if (ua.contains(sig)) {
                return new DetectionOutcome("BOT_DETECTED", 15, "Automated tool signature in User-Agent: " + sig);
            }
        }
        return null;
    }

    /** GET-style request for a known health path with nothing attached to it. */
    static boolean isPlainHealthCheck(LogEvent e) {
        if (e.eventType != EventType.HTTP_REQUEST) return false;
        if (!e.requestBody.isEmpty()) return false;
        String path = e.endpoint.toLowerCase(Locale.ROOT);
        if (path.indexOf('?') >= 0 || path.indexOf('%') >= 0) return false;   // parameters / encoding: not a bare probe
        if (path.length() > 1 && path.endsWith("/")) path = path.substring(0, path.length() - 1);
        return HEALTH_PATHS.contains(path);
    }
}
