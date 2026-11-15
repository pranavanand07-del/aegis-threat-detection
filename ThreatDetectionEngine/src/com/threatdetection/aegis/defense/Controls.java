package com.threatdetection.aegis.defense;

import java.util.ArrayDeque;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The "soft" controls: revoked sessions, locked accounts and rate-limited sources. AEGIS cannot reach
 * inside another application, so it keeps these lists and exposes them at
 * GET /aegis/api/defense/check?type=session|account|ip&amp;id=... . The protected application calls that
 * endpoint (or embeds this class) and refuses a revoked session, a locked account, or a request over the limit.
 */
public final class Controls {
    private final Map<String, Long> revokedSessions = new ConcurrentHashMap<>();
    private final Map<String, Long> lockedAccounts = new ConcurrentHashMap<>();
    private final Map<String, Long> restricted = new ConcurrentHashMap<>();
    private final Map<String, ArrayDeque<Long>> hits = new ConcurrentHashMap<>();
    private final int max;
    private final long windowMs;

    public Controls(int max, long windowMs) {
        this.max = max;
        this.windowMs = windowMs;
    }

    public void revokeSession(String id, long until) { revokedSessions.put(id, until); }
    public void lockAccount(String user, long until) { lockedAccounts.put(user.toLowerCase(Locale.ROOT), until); }
    public void restrict(String ip, long until) { restricted.put(ip, until); }
    public void releaseSession(String id) { revokedSessions.remove(id); }
    public void unlockAccount(String user) { lockedAccounts.remove(user.toLowerCase(Locale.ROOT)); }
    public void unrestrict(String ip) { restricted.remove(ip); hits.remove(ip); }

    public boolean sessionRevoked(String id) { return active(revokedSessions, id); }
    public boolean accountLocked(String user) { return active(lockedAccounts, user.toLowerCase(Locale.ROOT)); }

    /** @return true when the request may proceed. Only sources AEGIS has restricted are ever limited. */
    public boolean allowRequest(String ip) {
        if (!active(restricted, ip)) return true;
        long now = System.currentTimeMillis();
        ArrayDeque<Long> q = hits.computeIfAbsent(ip, k -> new ArrayDeque<>());
        synchronized (q) {
            while (!q.isEmpty() && now - q.peekFirst() > windowMs) q.pollFirst();
            if (q.size() >= max) return false;
            q.addLast(now);
            return true;
        }
    }

    public int counts() { return revokedSessions.size() + lockedAccounts.size() + restricted.size(); }

    private static boolean active(Map<String, Long> m, String key) {
        Long until = m.get(key);
        if (until == null) return false;
        if (until != 0 && System.currentTimeMillis() > until) { m.remove(key, until); return false; }
        return true;
    }
}
