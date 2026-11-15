package com.threatdetection.tracking;

import java.util.concurrent.ConcurrentHashMap;

/**
 * Thread-safe registry of per-IP activity trackers. Bounded: an attacker spraying spoofed source
 * addresses must not be able to exhaust memory. Idle trackers are evicted when the table is full.
 */
public class TrackingStore {
    private static final long IDLE_MS = 15 * 60 * 1000L;
    private final int maxEntries = Integer.getInteger("tracking.max", 100_000);
    private final ConcurrentHashMap<String, IpActivityTracker> trackers = new ConcurrentHashMap<>();

    public IpActivityTracker get(String ip) {
        IpActivityTracker t = trackers.get(ip);
        if (t != null) return t;
        if (trackers.size() >= maxEntries) evict();
        return trackers.computeIfAbsent(ip, k -> new IpActivityTracker());
    }

    public int size() { return trackers.size(); }

    private void evict() {
        long cutoff = System.currentTimeMillis() - IDLE_MS;
        trackers.entrySet().removeIf(e -> e.getValue().lastTouched() < cutoff);
        if (trackers.size() >= maxEntries) {          // still full: drop the oldest 10%
            int drop = Math.max(1, maxEntries / 10);
            trackers.entrySet().stream()
                    .sorted((a, b) -> Long.compare(a.getValue().lastTouched(), b.getValue().lastTouched()))
                    .limit(drop).map(java.util.Map.Entry::getKey).toList().forEach(trackers::remove);
        }
    }
}
