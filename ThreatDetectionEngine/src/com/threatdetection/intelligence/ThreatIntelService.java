package com.threatdetection.intelligence;

import com.threatdetection.aegis.intel.IpClassifier;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Configurable blocklist used by the core engine's BlacklistDetector. Replaces the hard-coded demo set.
 *
 * Sources (all optional, none built in):
 *   -Daegis.blacklist.file=a.txt,b.txt   one IP or IPv4 CIDR per line, optional label after it, '#' comments.
 *                                        Files are re-read automatically when they change (checked every 30 s).
 *   runtime add()/remove()               e.g. from an analyst action; entries may carry an expiry.
 *   -Daegis.intel.demo=true              loads three clearly labelled DEMO entries so the simulator/Attack Lab
 *                                        have something to hit. Demo entries are never "live intelligence".
 *
 * With nothing configured the service is empty and says so: it never pretends an unknown IP is clean
 * or dirty (see status()).
 */
public final class ThreatIntelService {
    public static final String DEMO_SOURCE = "DEMO-SAMPLE (not live intelligence)";

    public record Entry(String value, String source, String label, long addedAt, long expiresAt) {
        boolean expired(long now) { return expiresAt > 0 && now > expiresAt; }
    }

    public record Match(String entry, String source, String label) {
        public String describe() {
            return "IP address matches blocklist entry " + entry + " (source: " + source
                    + (label == null || label.isEmpty() ? "" : ", " + label) + ")";
        }
    }

    private static final long RECHECK_MS = 30_000L;

    private final Map<String, Entry> exact = new ConcurrentHashMap<>();
    private final Map<Integer, Map<Long, Entry>> cidrs = new ConcurrentHashMap<>();   // prefix -> masked base -> entry
    private final Map<String, Entry> fileExact = new ConcurrentHashMap<>();
    private final Map<Integer, Map<Long, Entry>> fileCidrs = new ConcurrentHashMap<>();
    private final List<Path> files = new ArrayList<>();
    private final Map<Path, Long> fileStamp = new HashMap<>();
    private final List<String> errors = Collections.synchronizedList(new ArrayList<>());
    private volatile long lastCheck;
    private volatile long lastLoad;
    private volatile boolean demo;

    public ThreatIntelService() {}

    /** -Daegis.blacklist.file and -Daegis.intel.demo. Never throws: a bad file is reported in status(). */
    public static ThreatIntelService fromSystemProperties() {
        ThreatIntelService svc = new ThreatIntelService();
        for (String f : System.getProperty("aegis.blacklist.file", "").split(",")) {
            if (!f.isBlank()) svc.addFile(Path.of(f.trim()));
        }
        if (Boolean.getBoolean("aegis.intel.demo")) svc.addDemoEntries();
        return svc;
    }

    /** Three labelled sample addresses (documentation / well-known scanner ranges) for simulators and tests. */
    public static ThreatIntelService demo() {
        ThreatIntelService svc = new ThreatIntelService();
        svc.addDemoEntries();
        return svc;
    }

    public static ThreatIntelService ofExact(Collection<String> ips, String source) {
        ThreatIntelService svc = new ThreatIntelService();
        for (String ip : ips) svc.add(ip, source, "", 0);
        return svc;
    }

    private void addDemoEntries() {
        demo = true;
        for (String ip : new String[]{"1.2.3.4", "45.33.32.156", "185.220.101.1"}) add(ip, DEMO_SOURCE, "demo entry", 0);
    }

    // ------------------------------------------------------------------ lookups

    /** @return the matching entry, or null. Internal/invalid addresses never match. */
    public Match lookup(String ip) {
        if (ip == null || ip.isEmpty() || !IpClassifier.isValid(ip)) return null;
        maybeReload();
        long now = System.currentTimeMillis();
        Entry e = exact.get(ip);
        if (e == null) e = fileExact.get(ip);
        if (e != null && !e.expired(now)) return new Match(e.value(), e.source(), e.label());
        long v = IpClassifier.toLong(ip);
        if (v >= 0) {
            Entry c = scan(cidrs, v, now);
            if (c == null) c = scan(fileCidrs, v, now);
            if (c != null) return new Match(c.value(), c.source(), c.label());
        }
        return null;
    }

    private static Entry scan(Map<Integer, Map<Long, Entry>> table, long v, long now) {
        for (Map.Entry<Integer, Map<Long, Entry>> t : table.entrySet()) {
            int bits = t.getKey();
            long mask = bits == 0 ? 0 : (0xFFFFFFFFL << (32 - bits)) & 0xFFFFFFFFL;
            Entry e = t.getValue().get(v & mask);
            if (e != null && !e.expired(now)) return e;
        }
        return null;
    }

    // ------------------------------------------------------------------ runtime changes

    /** Adds an IP or IPv4 CIDR. ttlMs &lt;= 0 means no expiry. @return false when the value is not an IP/CIDR. */
    public boolean add(String value, String source, String label, long ttlMs) {
        long now = System.currentTimeMillis();
        Entry e = new Entry(value == null ? "" : value.trim(), source, label == null ? "" : label, now,
                ttlMs > 0 ? now + ttlMs : 0);
        return put(e, exact, cidrs);
    }

    public boolean remove(String value) {
        if (value == null) return false;
        String v = value.trim();
        boolean removed = exact.remove(v) != null;
        int slash = v.indexOf('/');
        if (slash > 0) {
            long base = IpClassifier.toLong(v.substring(0, slash));
            try {
                int bits = Integer.parseInt(v.substring(slash + 1));
                Map<Long, Entry> m = cidrs.get(bits);
                if (m != null && base >= 0) removed |= m.remove(base & mask(bits)) != null;
            } catch (NumberFormatException ignored) { /* not a CIDR */ }
        }
        return removed;
    }

    private static long mask(int bits) { return bits == 0 ? 0 : (0xFFFFFFFFL << (32 - bits)) & 0xFFFFFFFFL; }

    private static boolean put(Entry e, Map<String, Entry> exactMap, Map<Integer, Map<Long, Entry>> cidrMap) {
        String v = e.value();
        int slash = v.indexOf('/');
        if (slash > 0) {
            long base = IpClassifier.toLong(v.substring(0, slash));
            int bits;
            try { bits = Integer.parseInt(v.substring(slash + 1)); } catch (NumberFormatException ex) { return false; }
            if (base < 0 || bits < 0 || bits > 32) return false;
            cidrMap.computeIfAbsent(bits, k -> new ConcurrentHashMap<>()).put(base & mask(bits), e);
            return true;
        }
        if (!IpClassifier.isValid(v)) return false;
        exactMap.put(v, e);
        return true;
    }

    // ------------------------------------------------------------------ files

    public synchronized void addFile(Path file) {
        if (!files.contains(file)) files.add(file);
        loadFiles();
    }

    private void maybeReload() {
        long now = System.currentTimeMillis();
        if (files.isEmpty() || now - lastCheck < RECHECK_MS) return;
        lastCheck = now;
        boolean changed = false;
        synchronized (this) {
            for (Path f : files) {
                long stamp;
                try { stamp = Files.getLastModifiedTime(f).toMillis(); } catch (IOException e) { stamp = -1; }
                if (!fileStamp.containsKey(f) || fileStamp.get(f) != stamp) changed = true;
            }
            if (changed) loadFiles();
        }
    }

    private synchronized void loadFiles() {
        Map<String, Entry> newExact = new HashMap<>();
        Map<Integer, Map<Long, Entry>> newCidrs = new HashMap<>();
        errors.clear();
        for (Path f : files) {
            try {
                long stamp = Files.getLastModifiedTime(f).toMillis();
                for (String raw : Files.readAllLines(f, StandardCharsets.UTF_8)) {
                    String line = raw;
                    int hash = line.indexOf('#');
                    if (hash >= 0) line = line.substring(0, hash);
                    line = line.trim();
                    if (line.isEmpty()) continue;
                    String[] tok = line.split("[\\s,;]+", 2);
                    put(new Entry(tok[0], "file:" + f.getFileName(), tok.length > 1 ? tok[1].trim() : "",
                            System.currentTimeMillis(), 0), newExact, newCidrs);
                }
                fileStamp.put(f, stamp);
            } catch (IOException e) {
                errors.add(f + ": " + e.getMessage());
                fileStamp.put(f, -1L);
            }
        }
        fileExact.clear();
        fileExact.putAll(newExact);
        fileCidrs.clear();
        fileCidrs.putAll(newCidrs);
        lastLoad = System.currentTimeMillis();
    }

    // ------------------------------------------------------------------ status

    public int size() {
        int n = exact.size() + fileExact.size();
        for (Map<Long, Entry> m : cidrs.values()) n += m.size();
        for (Map<Long, Entry> m : fileCidrs.values()) n += m.size();
        return n;
    }

    public boolean demoEntriesLoaded() { return demo; }

    public Map<String, Object> status() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("entries", size());
        m.put("demoEntriesLoaded", demo);
        m.put("files", files.stream().map(Path::toString).toList());
        m.put("lastLoad", lastLoad);
        m.put("errors", new ArrayList<>(errors));
        m.put("note", size() == 0
                ? "No blocklist configured (-Daegis.blacklist.file). Nothing is treated as known-bad."
                : demo ? "Contains DEMO entries that are not verified intelligence." : "Operator-supplied entries.");
        return m;
    }
}
