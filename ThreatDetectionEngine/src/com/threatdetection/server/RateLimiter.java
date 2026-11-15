package com.threatdetection.server;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Small per-client token bucket used by the write guard. Bounded (the client table is an LRU of at most
 * {@code maxClients} entries), so an attacker rotating source addresses cannot grow it without limit.
 */
public final class RateLimiter {
    private static final class Bucket { double tokens; long last; }

    private final double perSecond;
    private final double burst;
    private final Map<String, Bucket> buckets;

    public RateLimiter(double perSecond, double burst, int maxClients) {
        this.perSecond = Math.max(0.1, perSecond);
        this.burst = Math.max(1, burst);
        this.buckets = new LinkedHashMap<>(256, 0.75f, true) {
            @Override protected boolean removeEldestEntry(Map.Entry<String, Bucket> e) { return size() > maxClients; }
        };
    }

    /** @return true when the caller may proceed, false when it is over its rate. */
    public synchronized boolean tryAcquire(String client) { return tryAcquire(client, System.nanoTime()); }

    synchronized boolean tryAcquire(String client, long nowNanos) {
        Bucket b = buckets.computeIfAbsent(client, k -> { Bucket nb = new Bucket(); nb.tokens = burst; nb.last = nowNanos; return nb; });
        double elapsed = Math.max(0, (nowNanos - b.last) / 1e9);
        b.tokens = Math.min(burst, b.tokens + elapsed * perSecond);
        b.last = nowNanos;
        if (b.tokens < 1) return false;
        b.tokens -= 1;
        return true;
    }
}
