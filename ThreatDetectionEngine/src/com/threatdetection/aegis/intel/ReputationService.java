package com.threatdetection.aegis.intel;

import com.threatdetection.model.ThreatLevel;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Offline IP reputation. Two sources, both honest about what they are:
 *  1. Threat-intel feed files you load (one IP or IPv4 CIDR per line, optional label), e.g. a
 *     Tor exit list, Spamhaus DROP, FireHOL or your own blocklist:
 *       -Daegis.intel.feeds=malicious:/path/drop.txt,suspicious:/path/tor-exits.txt
 *  2. Local history: an IP that already raised several HIGH/CRITICAL alerts on THIS system.
 * With no feed loaded the verdict is NO_DATA - it never pretends an unknown IP is clean.
 */
public final class ReputationService {
    public static final class Reputation {
        public final String verdict;   // INTERNAL | MALICIOUS | SUSPICIOUS | NO_DATA
        public final String detail;

        Reputation(String verdict, String detail) {
            this.verdict = verdict;
            this.detail = detail;
        }

        public boolean malicious() {
            return "MALICIOUS".equals(verdict);
        }
    }

    private static final class Feed {
        final String name;
        final String verdict;
        final Set<String> exact = new HashSet<>();
        final Map<Integer, Map<Long, String>> cidrs = new HashMap<>();   // prefix length -> masked base -> label
        final Map<String, String> labels = new HashMap<>();
        int entries;

        Feed(String name, String verdict) {
            this.name = name;
            this.verdict = verdict;
        }
    }

    private final List<Feed> feeds = new ArrayList<>();
    private final ConcurrentHashMap<String, AtomicInteger> localHighAlerts = new ConcurrentHashMap<>();
    private final List<String> loadErrors = new ArrayList<>();

    /** Reads -Daegis.intel.feeds. Never throws: a bad feed is reported, not fatal. */
    public static ReputationService fromSystemProperties() {
        ReputationService svc = new ReputationService();
        String spec = System.getProperty("aegis.intel.feeds", "");
        for (String part : spec.split(",")) {
            part = part.trim();
            if (part.isEmpty()) continue;
            String verdict = "MALICIOUS";
            if (part.toLowerCase().startsWith("malicious:")) part = part.substring(10);
            else if (part.toLowerCase().startsWith("suspicious:")) { verdict = "SUSPICIOUS"; part = part.substring(11); }
            svc.loadFeed(Path.of(part.trim()), verdict);
        }
        return svc;
    }

    public void loadFeed(Path file, String verdict) {
        Feed feed = new Feed(file.getFileName().toString(), verdict);
        try {
            for (String raw : Files.readAllLines(file, StandardCharsets.UTF_8)) {
                String line = raw;
                int hash = line.indexOf('#');
                if (hash >= 0) line = line.substring(0, hash);
                int semi = line.indexOf(';');
                if (semi >= 0) line = line.substring(0, semi);
                line = line.trim();
                if (line.isEmpty()) continue;
                String[] tok = line.split("[\\s,]+", 2);
                String entry = tok[0];
                String label = tok.length > 1 ? tok[1].trim() : "";
                int slash = entry.indexOf('/');
                if (slash > 0) {
                    long base = IpClassifier.toLong(entry.substring(0, slash));
                    int bits;
                    try { bits = Integer.parseInt(entry.substring(slash + 1)); } catch (NumberFormatException e) { continue; }
                    if (base < 0 || bits < 0 || bits > 32) continue;
                    long mask = bits == 0 ? 0 : (0xFFFFFFFFL << (32 - bits)) & 0xFFFFFFFFL;
                    feed.cidrs.computeIfAbsent(bits, k -> new HashMap<>()).put(base & mask, label);
                    feed.entries++;
                } else if (IpClassifier.isValid(entry)) {
                    feed.exact.add(entry);
                    if (!label.isEmpty()) feed.labels.put(entry, label);
                    feed.entries++;
                }
            }
            feeds.add(feed);
        } catch (IOException e) {
            loadErrors.add(file + ": " + e.getMessage());
        }
    }

    public int feedCount() { return feeds.size(); }

    public int entryCount() {
        int n = 0;
        for (Feed f : feeds) n += f.entries;
        return n;
    }

    public List<String> loadErrors() { return loadErrors; }

    /** Called by the pipeline so the service can learn which IPs keep attacking this system. */
    public void noteAlert(String ip, ThreatLevel level) {
        if (ip == null || ip.isEmpty() || level.ordinal() < ThreatLevel.HIGH.ordinal()) return;
        if (localHighAlerts.size() > 100_000) localHighAlerts.clear();
        localHighAlerts.computeIfAbsent(ip, k -> new AtomicInteger()).incrementAndGet();
    }

    public Reputation lookup(String ip) {
        if (ip == null || ip.isEmpty()) return new Reputation("NO_DATA", "No remote address (host-local event)");
        if (IpClassifier.isInternal(ip)) return new Reputation("INTERNAL", "Private / internal address");
        Reputation suspicious = null;
        long v = IpClassifier.toLong(ip);
        for (Feed f : feeds) {
            String label = null;
            boolean hit = f.exact.contains(ip);
            if (hit) label = f.labels.get(ip);
            if (!hit && v >= 0) {
                for (Map.Entry<Integer, Map<Long, String>> e : f.cidrs.entrySet()) {
                    int bits = e.getKey();
                    long mask = bits == 0 ? 0 : (0xFFFFFFFFL << (32 - bits)) & 0xFFFFFFFFL;
                    if (e.getValue().containsKey(v & mask)) { hit = true; label = e.getValue().get(v & mask); break; }
                }
            }
            if (hit) {
                Reputation r = new Reputation(f.verdict, "Listed in feed '" + f.name + "'"
                        + (label == null || label.isEmpty() ? "" : " (" + label + ")"));
                if (r.malicious()) return r;
                if (suspicious == null) suspicious = r;
            }
        }
        if (suspicious != null) return suspicious;
        AtomicInteger local = localHighAlerts.get(ip);
        if (local != null && local.get() >= 3) {
            return new Reputation("SUSPICIOUS", "Raised " + local.get() + " HIGH/CRITICAL alerts on this system");
        }
        return new Reputation("NO_DATA", feeds.isEmpty()
                ? "No threat-intel feed loaded (-Daegis.intel.feeds)"
                : "Not listed in " + feeds.size() + " loaded feed(s)");
    }
}
