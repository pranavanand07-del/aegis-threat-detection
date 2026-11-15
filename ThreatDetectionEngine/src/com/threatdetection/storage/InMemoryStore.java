package com.threatdetection.storage;

import com.threatdetection.model.ThreatLevel;
import com.threatdetection.model.ThreatResult;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/** Central in-memory store for history, counters and blocked IPs (swap for MySQL/JDBC later). */
public class InMemoryStore {
    private static final int MAX_HISTORY = 500;

    private final LinkedList<ThreatResult> history = new LinkedList<>();
    private final Set<String> blockedIps = ConcurrentHashMap.newKeySet();
    private final AtomicInteger totalEvents = new AtomicInteger(0);
    private final AtomicInteger totalCriticalAlerts = new AtomicInteger(0);

    public synchronized void recordThreat(ThreatResult result) {
        history.addFirst(result);
        if (history.size() > MAX_HISTORY) {
            history.removeLast();
        }
        // A request rejected because the IP is already blocked is not a new critical detection.
        if (result.level == ThreatLevel.CRITICAL && !result.repeatOfBlock) {
            totalCriticalAlerts.incrementAndGet();
        }
    }

    public synchronized List<ThreatResult> getRecent(int limit) {
        int n = Math.min(limit, history.size());
        return new ArrayList<>(history.subList(0, n));
    }

    public void incrementTotalEvents() {
        totalEvents.incrementAndGet();
    }

    public int getTotalEvents() {
        return totalEvents.get();
    }

    public int getTotalCriticalAlerts() {
        return totalCriticalAlerts.get();
    }

    public void addBlockedIp(String ip) {
        blockedIps.add(ip);
    }

    public void removeBlockedIp(String ip) {
        blockedIps.remove(ip);
    }

    public Set<String> getBlockedIps() {
        return Collections.unmodifiableSet(blockedIps);
    }
}
