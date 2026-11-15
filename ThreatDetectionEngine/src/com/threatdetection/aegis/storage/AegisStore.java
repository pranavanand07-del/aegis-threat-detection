package com.threatdetection.aegis.storage;

import com.threatdetection.aegis.AegisEvent;
import com.threatdetection.aegis.AegisIncident;
import com.threatdetection.aegis.DataSource;
import com.threatdetection.model.ThreatLevel;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * AEGIS state: a ring of recent events, a longer ring of alerts (LOW+, persisted), 10-second
 * aggregate buckets kept for 24 h (KPIs, rate, charts), incidents and ingestion-source health.
 * All access is synchronized; the volume (a few events per second) makes this ample.
 */
public final class AegisStore {
    public static final long BUCKET_MS = 10_000L;
    private static final long RETENTION_MS = 24L * 3600 * 1000;
    // bucket layout: [count, scoreSum, scoreMax, critical, high, medium, low, safe]
    private static final int B_COUNT = 0, B_SUM = 1, B_MAX = 2, B_CRIT = 3, B_HIGH = 4, B_MED = 5, B_LOW = 6, B_SAFE = 7;

    public static final class SourceStatus {
        public final String name, type;
        public String state = "WAITING";     // ACTIVE | WAITING | ERROR | DISABLED
        public String detail = "";
        public long lastEvent;
        public long count;

        SourceStatus(String name, String type) {
            this.name = name;
            this.type = type;
        }
    }

    private final int maxRecent, maxAlerts;
    private final ArrayDeque<AegisEvent> recent = new ArrayDeque<>();
    private final ArrayDeque<AegisEvent> alerts = new ArrayDeque<>();
    private final TreeMap<Long, long[]> buckets = new TreeMap<>();
    private final List<AegisIncident> incidents = new ArrayList<>();
    private final Map<String, AegisIncident> openByActor = new HashMap<>();
    private final Map<String, SourceStatus> sources = new LinkedHashMap<>();
    private final EnumMap<DataSource, AtomicLong> bySource = new EnumMap<>(DataSource.class);
    private final AtomicLong analyzed = new AtomicLong();
    private final AtomicLong errors = new AtomicLong();
    private final long startedAt = System.currentTimeMillis();
    private long seq;
    private int incidentSeq;
    private AegisPersistence persistence;

    public AegisStore(int maxRecent, int maxAlerts) {
        this.maxRecent = maxRecent;
        this.maxAlerts = maxAlerts;
        for (DataSource d : DataSource.values()) bySource.put(d, new AtomicLong());
    }

    public void attach(AegisPersistence p) { this.persistence = p; }

    public long startedAt() { return startedAt; }
    public long analyzed() { return analyzed.get(); }
    public long errors() { return errors.get(); }
    public void countError() { errors.incrementAndGet(); }
    public long countFor(DataSource d) { return bySource.get(d).get(); }

    // ---------------------------------------------------------------- writes

    public synchronized void add(AegisEvent e) {
        long now = System.currentTimeMillis();
        e.id = ++seq;
        analyzed.incrementAndGet();
        bySource.get(e.source).incrementAndGet();
        correlate(e, now);
        push(recent, e, maxRecent);
        boolean alert = e.level.ordinal() >= ThreatLevel.LOW.ordinal();
        if (alert) {
            push(alerts, e, maxAlerts);
            if (persistence != null) persistence.append(e);
        }
        long[] b = buckets.computeIfAbsent(now / BUCKET_MS, k -> new long[8]);
        b[B_COUNT]++;
        b[B_SUM] += e.score;
        b[B_MAX] = Math.max(b[B_MAX], e.score);
        switch (e.level) {
            case CRITICAL -> b[B_CRIT]++;
            case HIGH -> b[B_HIGH]++;
            case MEDIUM -> b[B_MED]++;
            case LOW -> b[B_LOW]++;
            default -> b[B_SAFE]++;
        }
        while (!buckets.isEmpty() && buckets.firstKey() * BUCKET_MS < now - RETENTION_MS) buckets.pollFirstEntry();
        if (e.source != null) touchSource(e.channel);
    }

    /** Re-loads a persisted alert (does not re-persist, does not count as newly analysed traffic). */
    public synchronized void restore(AegisEvent e) {
        e.id = ++seq;
        correlate(e, e.ts);
        push(alerts, e, maxAlerts);
        long key = e.ts / BUCKET_MS;
        if (e.ts >= System.currentTimeMillis() - RETENTION_MS) {
            long[] b = buckets.computeIfAbsent(key, k -> new long[8]);
            b[B_COUNT]++;
            b[B_SUM] += e.score;
            b[B_MAX] = Math.max(b[B_MAX], e.score);
            switch (e.level) {
                case CRITICAL -> b[B_CRIT]++;
                case HIGH -> b[B_HIGH]++;
                case MEDIUM -> b[B_MED]++;
                default -> b[B_LOW]++;
            }
        }
    }

    private static void push(ArrayDeque<AegisEvent> q, AegisEvent e, int cap) {
        q.addLast(e);
        while (q.size() > cap) q.pollFirst();
    }

    private void correlate(AegisEvent e, long clock) {
        if (e.level.ordinal() < ThreatLevel.LOW.ordinal()) return;
        String actor = !e.ip.isEmpty() ? e.ip : (e.host.isEmpty() ? e.user : e.host + "/" + e.user);
        AegisIncident inc = openByActor.get(actor);
        if (inc != null && clock - inc.lastSeen > AegisIncident.OPEN_WINDOW_MS) {
            openByActor.remove(actor);
            inc = null;
        }
        if (inc == null && e.level.ordinal() >= ThreatLevel.MEDIUM.ordinal()) {
            inc = new AegisIncident(String.format("INC-%04d", ++incidentSeq), actor, clock);
            openByActor.put(actor, inc);
            incidents.add(inc);
            if (incidents.size() > 1000) incidents.remove(0);
        }
        if (inc != null) {
            inc.add(e, clock);
            e.incident = inc.id;
        }
    }

    // ---------------------------------------------------------------- sources / health

    public synchronized void registerSource(String name, String type, String state, String detail) {
        SourceStatus s = sources.computeIfAbsent(name, k -> new SourceStatus(name, type));
        s.state = state;
        s.detail = detail;
    }

    public synchronized void setSourceState(String name, String state, String detail) {
        SourceStatus s = sources.get(name);
        if (s != null) {
            s.state = state;
            s.detail = detail;
        }
    }

    public synchronized void touchSource(String name) {
        SourceStatus s = sources.get(name);
        if (s != null) {
            s.lastEvent = System.currentTimeMillis();
            s.count++;
            if (!"ERROR".equals(s.state)) s.state = "ACTIVE";
        }
    }

    public synchronized List<SourceStatus> sources() {
        List<SourceStatus> copy = new ArrayList<>();
        for (SourceStatus s : sources.values()) {
            SourceStatus c = new SourceStatus(s.name, s.type);
            c.state = s.state; c.detail = s.detail; c.lastEvent = s.lastEvent; c.count = s.count;
            copy.add(c);
        }
        return copy;
    }

    // ---------------------------------------------------------------- reads

    public synchronized int recentSize() { return recent.size(); }
    public synchronized int alertSize() { return alerts.size(); }

    /** Newest first. minLevel SAFE reads the all-events ring, anything else the alert ring. */
    public synchronized List<AegisEvent> query(long from, long to, ThreatLevel minLevel, DataSource source,
                                               String text, int limit) {
        ArrayDeque<AegisEvent> ring = minLevel == ThreatLevel.SAFE ? recent : alerts;
        List<AegisEvent> out = new ArrayList<>();
        String q = text == null ? "" : text.toLowerCase();
        var it = ring.descendingIterator();
        while (it.hasNext() && out.size() < limit) {
            AegisEvent e = it.next();
            if (e.ts < from || e.ts > to) continue;
            if (e.level.ordinal() < minLevel.ordinal()) continue;
            if (source != null && e.source != source) continue;
            if (!q.isEmpty() && !(e.ip + " " + e.summary + " " + e.user + " " + e.target + " " + e.city)
                    .toLowerCase().contains(q)) continue;
            out.add(e);
        }
        return out;
    }

    /** Alerts in [from,to], oldest first, capped to the newest {@code max}. */
    public synchronized List<AegisEvent> alertsBetween(long from, long to, int max) {
        List<AegisEvent> out = new ArrayList<>();
        for (AegisEvent e : alerts) if (e.ts >= from && e.ts <= to) out.add(e);
        out.sort((a, b) -> Long.compare(a.ts, b.ts));
        if (out.size() > max) out = new ArrayList<>(out.subList(out.size() - max, out.size()));
        return out;
    }

    /** Totals over the range: [events, critical, high, medium, low, safe]. */
    public synchronized long[] totals(long from, long to) {
        long[] t = new long[6];
        for (long[] b : buckets.subMap(from / BUCKET_MS, true, to / BUCKET_MS, true).values()) {
            t[0] += b[B_COUNT];
            t[1] += b[B_CRIT];
            t[2] += b[B_HIGH];
            t[3] += b[B_MED];
            t[4] += b[B_LOW];
            t[5] += b[B_SAFE];
        }
        return t;
    }

    /** Events in the last {@code windowMs}. */
    public synchronized long countSince(long windowMs) {
        long now = System.currentTimeMillis();
        long n = 0;
        for (long[] b : buckets.tailMap((now - windowMs) / BUCKET_MS, true).values()) n += b[B_COUNT];
        return n;
    }

    /** Merged chart series: each row {startMs, count, avgScore, maxScore, crit, high, med, low}. */
    public synchronized List<long[]> series(long from, long to, int points) {
        long span = Math.max(BUCKET_MS, to - from);
        long step = Math.max(BUCKET_MS, ((span / points) / BUCKET_MS + 1) * BUCKET_MS);
        long start = (from / step) * step;
        TreeMap<Long, long[]> merged = new TreeMap<>();
        for (long t = start; t <= to; t += step) merged.put(t, new long[8]);
        for (Map.Entry<Long, long[]> e : buckets.subMap(from / BUCKET_MS, true, to / BUCKET_MS, true).entrySet()) {
            long t = (e.getKey() * BUCKET_MS / step) * step;
            long[] m = merged.get(t);
            if (m == null) continue;
            long[] b = e.getValue();
            m[B_COUNT] += b[B_COUNT];
            m[B_SUM] += b[B_SUM];
            m[B_MAX] = Math.max(m[B_MAX], b[B_MAX]);
            m[B_CRIT] += b[B_CRIT];
            m[B_HIGH] += b[B_HIGH];
            m[B_MED] += b[B_MED];
            m[B_LOW] += b[B_LOW];
        }
        List<long[]> out = new ArrayList<>();
        for (Map.Entry<Long, long[]> e : merged.entrySet()) {
            long[] m = e.getValue();
            long avg = m[B_COUNT] == 0 ? 0 : m[B_SUM] / m[B_COUNT];
            out.add(new long[]{e.getKey(), m[B_COUNT], avg, m[B_MAX], m[B_CRIT], m[B_HIGH], m[B_MED], m[B_LOW]});
        }
        return out;
    }

    public synchronized List<AegisIncident> incidents(int limit) {
        List<AegisIncident> copy = new ArrayList<>(incidents);
        copy.sort((a, b) -> Long.compare(b.lastSeen, a.lastSeen));
        return copy.size() > limit ? copy.subList(0, limit) : copy;
    }

    public synchronized int openIncidents(long now) {
        int n = 0;
        for (AegisIncident i : incidents) if (i.isOpen(now)) n++;
        return n;
    }

    public synchronized int totalIncidents() { return incidents.size(); }

    public List<AegisEvent> empty() { return Collections.emptyList(); }
}
