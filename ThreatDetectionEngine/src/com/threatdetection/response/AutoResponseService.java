package com.threatdetection.response;

import com.threatdetection.storage.InMemoryStore;

import java.lang.ref.WeakReference;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Handles automatic defensive action once a threat is classified CRITICAL.
 * Safety properties: allowlisted addresses are never blocked, blocks expire on their own (a
 * background sweep also removes them from the dashboard list), and the table is bounded.
 */
public class AutoResponseService {
    private static final long BLOCK_DURATION_MS = 10 * 60 * 1000L;
    private static final int MAX_BLOCKS = 50_000;

    // One shared daemon thread sweeps every service (engines are created freely, e.g. by the self-test).
    private static final List<WeakReference<AutoResponseService>> ALL = new CopyOnWriteArrayList<>();
    private static final ScheduledExecutorService SWEEPER = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "block-expiry-sweeper");
        t.setDaemon(true);
        return t;
    });
    static {
        SWEEPER.scheduleWithFixedDelay(() -> {
            ALL.removeIf(ref -> ref.get() == null);
            for (WeakReference<AutoResponseService> ref : ALL) {
                AutoResponseService svc = ref.get();
                if (svc != null) svc.sweepExpired();
            }
        }, 15, 15, TimeUnit.SECONDS);
    }

    private final ConcurrentHashMap<String, Long> blockedIps = new ConcurrentHashMap<>();
    private final InMemoryStore store;
    private final Allowlist allowlist;

    public AutoResponseService(InMemoryStore store) {
        this(store, Allowlist.fromSystemProperties());
    }

    public AutoResponseService(InMemoryStore store, Allowlist allowlist) {
        this.store = store;
        this.allowlist = allowlist;
        // NOTE: the instance is registered with the sweeper lazily (first block), never from the constructor,
        // so `this` is not published before construction completes (also safe for subclasses).
    }

    private final java.util.concurrent.atomic.AtomicBoolean registered = new java.util.concurrent.atomic.AtomicBoolean();
    private final Object admission = new Object();

    private void ensureRegistered() {
        if (registered.compareAndSet(false, true)) ALL.add(new WeakReference<>(this));
    }

    private volatile OsResponseCoordinator osResponse;

    public Allowlist allowlist() { return allowlist; }

    /** Maximum simultaneous in-memory blocks (overridable by tests through -Daegis.block.max). */
    private static int capacity() { return Math.max(1, Integer.getInteger("aegis.block.max", MAX_BLOCKS)); }

    /** Attach real firewall enforcement (live lane only). The in-memory block below still applies either way. */
    public void attachOsResponse(OsResponseCoordinator c) { this.osResponse = c; }

    public OsResponseCoordinator osResponse() { return osResponse; }

    /** @return null when the block was applied, otherwise the reason it was NOT applied. */
    public String block(String ip) {
        if (ip == null || ip.isBlank()) return "not blocked: no address";
        String why = allowlist.why(ip);
        if (why != null) return "not blocked: " + why;
        ensureRegistered();
        // Capacity check and insertion are ONE atomic step; otherwise concurrent events could all pass the check
        // and push the table past MAX_BLOCKS. An address already in the table only has its expiry extended.
        synchronized (admission) {
            long expiry = System.currentTimeMillis() + BLOCK_DURATION_MS;
            if (!blockedIps.containsKey(ip)) {
                if (blockedIps.size() >= capacity()) sweepExpired();
                if (blockedIps.size() >= capacity()) return "not blocked: block table full";
            }
            blockedIps.put(ip, expiry);
        }
        store.addBlockedIp(ip);
        return null;
    }

    /** Asks the OS-level response (if attached) what to do for this address. @return a note, or null when none attached. */
    public String osResponse(String ip, int score, com.threatdetection.model.ThreatLevel level, List<String> rules, String source) {
        OsResponseCoordinator c = osResponse;
        return c == null ? null : c.handle(ip, score, level, rules, source);
    }

    /** Structured variant of {@link #osResponse}; null when no OS response is attached. */
    public OsResponseCoordinator.Handled osResponseDetailed(String ip, int score, com.threatdetection.model.ThreatLevel level, List<String> rules, String source) {
        OsResponseCoordinator c = osResponse;
        return c == null ? null : c.handleDetailed(ip, score, level, rules, source);
    }

    /** Analyst override: lifts the in-memory block immediately. */
    public void unblock(String ip) {
        if (ip != null && blockedIps.remove(ip) != null) store.removeBlockedIp(ip);
    }

    public boolean isBlocked(String ip) {
        if (ip == null) return false;
        Long expiry = blockedIps.get(ip);
        if (expiry == null) {
            return false;
        }
        if (System.currentTimeMillis() > expiry) {
            if (blockedIps.remove(ip, expiry)) store.removeBlockedIp(ip);   // conditional: never drop a block renewed meanwhile
            return false;
        }
        return true;
    }

    public void sweepExpired() {
        long now = System.currentTimeMillis();
        for (Map.Entry<String, Long> e : blockedIps.entrySet()) {
            if (now > e.getValue() && blockedIps.remove(e.getKey(), e.getValue())) {
                store.removeBlockedIp(e.getKey());
            }
        }
    }
}
