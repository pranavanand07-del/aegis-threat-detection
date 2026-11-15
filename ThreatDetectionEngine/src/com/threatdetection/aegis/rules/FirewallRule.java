package com.threatdetection.aegis.rules;

import com.threatdetection.aegis.AegisRule;
import com.threatdetection.aegis.AegisSignal;
import com.threatdetection.aegis.intel.IpClassifier;
import com.threatdetection.model.DetectionOutcome;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * Firewall-log checks: repeated attempts to the same port, probes of sensitive service ports,
 * and ALLOWED external access to risky services. (Wide scans are caught by the core PortScan detector.)
 */
public class FirewallRule implements AegisRule {
    private static final Set<Integer> SENSITIVE = Set.of(21, 23, 135, 139, 445, 1433, 2375, 3306, 3389, 5432, 5900, 6379, 9200, 27017);
    private static final Set<Integer> NEVER_EXPOSE = Set.of(23, 135, 139, 445, 2375, 3389, 5900);
    private static final long WINDOW_MS = 60_000L;
    private static final int REPEAT_THRESHOLD = 15;

    private final Map<String, Deque<Long>> attempts = new HashMap<>();

    @Override
    public synchronized DetectionOutcome evaluate(AegisSignal s) {
        if (s.kind != AegisSignal.Kind.NETWORK || s.ip.isEmpty() || s.port <= 0 || "out".equals(s.direction)) return null;
        long now = s.ts > 0 ? s.ts : System.currentTimeMillis();
        String key = s.ip + ":" + s.port;
        if (attempts.size() > 50_000) attempts.clear();
        Deque<Long> q = attempts.computeIfAbsent(key, k -> new ArrayDeque<>());
        q.addLast(now);
        while (!q.isEmpty() && q.peekFirst() < now - WINDOW_MS) q.pollFirst();

        boolean allowed = "ALLOW".equalsIgnoreCase(s.action) || "OPEN".equalsIgnoreCase(s.action);
        if (allowed && NEVER_EXPOSE.contains(s.port) && !IpClassifier.isInternal(s.ip)) {
            return new DetectionOutcome("EXPOSED_SERVICE_ACCESS", 25,
                    "External address was ALLOWED to reach port " + s.port + " - this service should not be internet-facing");
        }
        if (q.size() >= REPEAT_THRESHOLD) {
            return new DetectionOutcome("REPEATED_CONNECTIONS", 20,
                    q.size() + " connection attempts to port " + s.port + " within 60 seconds");
        }
        if (!allowed && SENSITIVE.contains(s.port)) {
            return new DetectionOutcome("SENSITIVE_PORT_PROBE", 10, "Blocked attempt to sensitive port " + s.port);
        }
        return null;
    }
}
