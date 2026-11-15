package com.threatdetection.tracking;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Holds rolling behavioral state for a single IP address so detectors can reason about patterns
 * over time, not just a single event.
 *
 * Window queries are READ-ONLY: a query for "the last 10 seconds" must never delete data that a
 * query for "the last minute" still needs. Old data is dropped only once it is older than the
 * retention of its own series.
 */
public class IpActivityTracker {
    private static final long LOGIN_RETENTION_MS = 10 * 60 * 1000L;
    private static final long REQUEST_RETENTION_MS = 10 * 60 * 1000L;
    private static final long BASELINE_SLOT_MS = 10_000L;
    private static final int MAX_SERIES = 20_000;   // hard cap so one noisy IP cannot grow without bound

    private final Deque<Long> loginFailures = new ArrayDeque<>();
    private final Deque<Long> requestTimestamps = new ArrayDeque<>();
    private final Map<Integer, Long> recentPorts = new LinkedHashMap<>();
    private String lastCountry = null;
    private long lastCountryTimestamp = 0L;
    private final AtomicInteger totalRequests = new AtomicInteger(0);
    private double baselineRequestsPerMinute = -1;
    private int baselineSamples = 0;
    private long lastBaselineSlot = -1;
    private volatile long lastTouched = System.currentTimeMillis();

    public synchronized void recordLoginFailure(long now) {
        touch();
        loginFailures.addLast(now);
        trim(loginFailures, now, LOGIN_RETENTION_MS);
    }

    public synchronized int loginFailuresInWindow(long now, long windowMs) {
        return countSince(loginFailures, now - windowMs);
    }

    public synchronized void recordRequest(long now) {
        touch();
        requestTimestamps.addLast(now);
        trim(requestTimestamps, now, REQUEST_RETENTION_MS);
        totalRequests.incrementAndGet();
    }

    public synchronized int requestsInWindow(long now, long windowMs) {
        return countSince(requestTimestamps, now - windowMs);
    }

    public synchronized void recordPortAccess(int port, long now) {
        touch();
        recentPorts.put(port, now);
        long cutoff = now - 60 * 1000L;
        recentPorts.values().removeIf(t -> t < cutoff);
    }

    public synchronized int distinctPortsInLastMinute(long now) {
        long cutoff = now - 60 * 1000L;
        int n = 0;
        for (long t : recentPorts.values()) if (t >= cutoff) n++;
        return n;
    }

    public synchronized String getLastCountry() { return lastCountry; }

    public synchronized long getLastCountryTimestamp() { return lastCountryTimestamp; }

    public synchronized void updateCountry(String country, long now) {
        this.lastCountry = country;
        this.lastCountryTimestamp = now;
    }

    public synchronized double getBaselineRequestsPerMinute() { return baselineRequestsPerMinute; }

    /** Number of baseline observations folded in so far (a baseline with 1-2 samples is not "normal" yet). */
    public synchronized int getBaselineSamples() { return baselineSamples; }

    /**
     * Folds one rate observation into the baseline. At most one observation per 10 s slot is accepted
     * (so a burst of events cannot drag the baseline up event by event), and the caller must pass
     * {@code anomalous=true} for abnormal observations so an attacker cannot teach the baseline that
     * the attack is normal.
     */
    public synchronized void updateBaseline(long now, double currentRatePerMinute, boolean anomalous) {
        if (anomalous) return;
        long slot = now / BASELINE_SLOT_MS;
        if (slot == lastBaselineSlot) return;
        lastBaselineSlot = slot;
        baselineSamples++;
        if (baselineRequestsPerMinute < 0) {
            baselineRequestsPerMinute = currentRatePerMinute;
        } else {
            baselineRequestsPerMinute = (baselineRequestsPerMinute * 0.9) + (currentRatePerMinute * 0.1);
        }
    }

    public int getTotalRequests() { return totalRequests.get(); }

    public long lastTouched() { return lastTouched; }

    private void touch() { lastTouched = System.currentTimeMillis(); }

    private static int countSince(Deque<Long> d, long cutoff) {
        int n = 0;
        Iterator<Long> it = d.descendingIterator();
        while (it.hasNext()) {
            if (it.next() >= cutoff) n++; else break;   // timestamps are appended in order
        }
        return n;
    }

    private static void trim(Deque<Long> deque, long now, long retentionMs) {
        while (!deque.isEmpty() && (now - deque.peekFirst()) > retentionMs) deque.pollFirst();
        while (deque.size() > MAX_SERIES) deque.pollFirst();
    }
}
