package com.threatdetection.aegis.intel;

import com.threatdetection.aegis.AegisEvent;
import com.threatdetection.aegis.DataSource;
import com.threatdetection.model.ThreatLevel;

import java.net.ConnectException;
import java.net.http.HttpTimeoutException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import static com.threatdetection.aegis.JsonUtil.str;

/**
 * Optional external intelligence, built so that it can never hurt detection:
 *  - OFF by default per provider: no key means no network traffic at all
 *  - only public addresses are ever sent out (private/internal addresses never leave the machine)
 *  - SIMULATED events are never looked up
 *  - lookups run on background threads; the pipeline never waits for them
 *  - 3 s connect / 5 s request timeouts, a per-provider rate gate and daily budget, and a circuit
 *    breaker that pauses a provider after repeated failures
 *  - results are cached (6 h for answers, 2 min for failures), and an unreachable provider simply
 *    leaves the event un-enriched: a missing answer is NEVER read as "this address is safe"
 */
public final class EnrichmentService {
    private record Cached(Enrichment value, long expires) {}

    private static final class State {
        long last, openUntil, dayKey;
        int used, fails;

        /** @return ms to wait before calling, -1 when today's budget is gone, -2 when too soon and waiting is not allowed. */
        synchronized long reserve(IntelProvider p, boolean mayWait) {
            long now = System.currentTimeMillis(), day = now / 86_400_000L;
            if (day != dayKey) { dayKey = day; used = 0; }
            if (used >= p.dailyLimit()) return -1;
            long wait = Math.max(0, last + p.minIntervalMs() - now);
            if (wait > 0 && !mayWait) return -2;
            last = now + wait;
            used++;
            return wait;
        }

        synchronized boolean open() { return System.currentTimeMillis() < openUntil; }

        synchronized void success() { fails = 0; }

        synchronized void failure() {
            if (++fails >= 3) { openUntil = System.currentTimeMillis() + 120_000L; fails = 0; }
        }
    }

    private static final long OK_TTL = 6L * 3600 * 1000, FAIL_TTL = 2L * 60 * 1000;
    private static final int MAX_CACHE = 20_000;

    private final List<IntelProvider> providers = new ArrayList<>();
    private final Map<String, State> states = new HashMap<>();
    private final Map<String, ExecutorService> pools = new HashMap<>();
    private final Map<String, Cached> cache = new ConcurrentHashMap<>();
    private final Map<String, List<AegisEvent>> waiting = new HashMap<>();
    private final AtomicLong dropped = new AtomicLong(), lookups = new AtomicLong();
    private final ThreatLevel minLevel;

    public EnrichmentService(List<IntelProvider> list, ThreatLevel minLevel) {
        this.minLevel = minLevel;
        for (IntelProvider p : list) {
            providers.add(p);
            states.put(p.name(), new State());
            pools.put(p.name(), new ThreadPoolExecutor(1, 1, 0, TimeUnit.SECONDS, new ArrayBlockingQueue<>(100), r -> {
                Thread t = new Thread(r, "aegis-enrich-" + p.name());
                t.setDaemon(true);
                return t;
            }));
        }
    }

    public static EnrichmentService fromSystemProperties() {
        List<IntelProvider> list = new ArrayList<>();
        if (!"false".equalsIgnoreCase(System.getProperty("aegis.enrich"))) {
            list.add(new AbuseIpDbProvider());
            list.add(new VirusTotalProvider());
        }
        ThreatLevel min;
        try { min = ThreatLevel.valueOf(System.getProperty("aegis.enrich.minLevel", "MEDIUM").toUpperCase()); } catch (IllegalArgumentException e) { min = ThreatLevel.MEDIUM; }
        return new EnrichmentService(list, min);
    }

    public boolean anyConfigured() { return providers.stream().anyMatch(IntelProvider::configured); }

    // ------------------------------------------------------------------ automatic enrichment of events

    /** Queues background lookups for an event. Returns immediately. */
    public void submit(AegisEvent e) {
        if (!eligible(e)) return;
        for (IntelProvider p : providers) {
            if (!p.configured()) continue;
            String key = p.name() + "|" + e.ip;
            Cached c = cache.get(key);
            if (c != null && c.expires > System.currentTimeMillis()) { e.enrichments.add(c.value.asCached()); continue; }
            boolean first;
            synchronized (waiting) {
                List<AegisEvent> w = waiting.get(key);
                first = w == null;
                if (first) { w = new ArrayList<>(); waiting.put(key, w); }
                if (w.size() < 50) w.add(e);
            }
            if (!first) continue;
            try {
                pools.get(p.name()).execute(() -> {
                    Enrichment en = call(p, key, true, () -> p.lookupIp(e.ip));
                    List<AegisEvent> w;
                    synchronized (waiting) { w = waiting.remove(key); }
                    if (w != null) for (AegisEvent ev : w) ev.enrichments.add(en);
                });
            } catch (RejectedExecutionException ex) {
                dropped.incrementAndGet();
                synchronized (waiting) { waiting.remove(key); }
            }
        }
    }

    private boolean eligible(AegisEvent e) {
        return e.source != DataSource.SIMULATED && !e.ip.isEmpty() && !e.internal && IpClassifier.isValid(e.ip)
                && e.level.ordinal() >= minLevel.ordinal();
    }

    // ------------------------------------------------------------------ on-demand lookups (analyst)

    public List<Enrichment> lookupIp(String ip) {
        List<Enrichment> out = new ArrayList<>();
        if (!IpClassifier.isValid(ip)) return List.of(Enrichment.unavailable("input", Enrichment.NOT_APPLICABLE, "not a valid IP address"));
        if (IpClassifier.isInternal(ip)) return List.of(Enrichment.unavailable("input", Enrichment.NOT_APPLICABLE, "internal address: never sent to external services"));
        for (IntelProvider p : providers) {
            if (!p.configured()) { out.add(Enrichment.unavailable(p.name(), Enrichment.NOT_CONFIGURED, "no API key set")); continue; }
            out.add(call(p, p.name() + "|" + ip, false, () -> p.lookupIp(ip)));
        }
        return out;
    }

    public Enrichment lookupHash(String hash) {
        if (hash == null || !hash.matches("[0-9a-fA-F]{32,64}")) return Enrichment.unavailable("VirusTotal", Enrichment.NOT_APPLICABLE, "not a file hash");
        VirusTotalProvider vt = vt();
        if (vt == null || !vt.configured()) return Enrichment.unavailable("VirusTotal", Enrichment.NOT_CONFIGURED, "no API key set");
        return call(vt, "VirusTotal|file|" + hash.toLowerCase(), false, () -> vt.lookupHash(hash));
    }

    public Enrichment lookupUrl(String url) {
        VirusTotalProvider vt = vt();
        if (vt == null || !vt.configured()) return Enrichment.unavailable("VirusTotal", Enrichment.NOT_CONFIGURED, "no API key set");
        return call(vt, "VirusTotal|url|" + url, false, () -> vt.lookupUrl(url));
    }

    private VirusTotalProvider vt() {
        for (IntelProvider p : providers) if (p instanceof VirusTotalProvider v) return v;
        return null;
    }

    public List<Enrichment> cachedFor(String ip) {
        List<Enrichment> out = new ArrayList<>();
        for (IntelProvider p : providers) {
            Cached c = cache.get(p.name() + "|" + ip);
            if (c != null && c.expires > System.currentTimeMillis()) out.add(c.value.asCached());
        }
        return out;
    }

    // ------------------------------------------------------------------ the guarded call

    private Enrichment call(IntelProvider p, String key, boolean mayWait, Callable<Enrichment> action) {
        Cached c = cache.get(key);
        if (c != null && c.expires > System.currentTimeMillis()) return c.value.asCached();
        State st = states.get(p.name());
        if (st.open()) return Enrichment.unavailable(p.name(), Enrichment.OFFLINE, "paused after repeated failures; will retry shortly");
        long wait = st.reserve(p, mayWait);
        if (wait == -1) return Enrichment.unavailable(p.name(), Enrichment.RATE_LIMITED, "daily request budget used");
        if (wait == -2) return Enrichment.unavailable(p.name(), Enrichment.RATE_LIMITED, "throttled (free-tier limit), try again shortly");
        if (wait > 0) {
            try { Thread.sleep(wait); } catch (InterruptedException ie) { Thread.currentThread().interrupt(); }
        }
        lookups.incrementAndGet();
        Enrichment result;
        try {
            result = action.call();
            st.success();
        } catch (HttpTimeoutException e) {
            st.failure();
            result = Enrichment.unavailable(p.name(), Enrichment.TIMEOUT, "no answer within 5 s");
        } catch (ConnectException e) {
            st.failure();
            result = Enrichment.unavailable(p.name(), Enrichment.OFFLINE, "service unreachable (offline?)");
        } catch (java.io.IOException e) {
            st.failure();
            result = Enrichment.unavailable(p.name(), Enrichment.OFFLINE, "network error: " + e.getClass().getSimpleName());
        } catch (Exception e) {
            result = Enrichment.unavailable(p.name(), Enrichment.ERROR, "unexpected reply: " + e.getClass().getSimpleName());
        }
        if (cache.size() >= MAX_CACHE) cache.clear();
        cache.put(key, new Cached(result, System.currentTimeMillis() + (result.usable() ? OK_TTL : FAIL_TTL)));
        return result;
    }

    // ------------------------------------------------------------------ status

    public String statusJson() {
        StringBuilder sb = new StringBuilder("{\"providers\":[");
        for (int i = 0; i < providers.size(); i++) {
            IntelProvider p = providers.get(i);
            State st = states.get(p.name());
            if (i > 0) sb.append(',');
            synchronized (st) {
                sb.append("{\"name\":").append(str(p.name())).append(",\"configured\":").append(p.configured())
                  .append(",\"usedToday\":").append(st.used).append(",\"dailyLimit\":").append(p.dailyLimit())
                  .append(",\"paused\":").append(System.currentTimeMillis() < st.openUntil).append('}');
            }
        }
        sb.append("],\"minLevel\":").append(str(minLevel.name())).append(",\"cacheEntries\":").append(cache.size())
          .append(",\"lookups\":").append(lookups.get()).append(",\"dropped\":").append(dropped.get())
          .append(",\"trust\":[")
          .append("{\"tag\":\"OBSERVED\",\"meaning\":\"Read from a configured local security log\"},")
          .append("{\"tag\":\"API\",\"meaning\":\"Submitted by an external client; not independently verified\"},")
          .append("{\"tag\":\"SIMULATED\",\"meaning\":\"Generated by the attack simulator; never a real-world attack\"},")
          .append("{\"tag\":\"ENRICHED\",\"meaning\":\"Extra intelligence attached to an event; context only, and a missing answer is not proof of safety\"}")
          .append("]}");
        return sb.toString();
    }
}
