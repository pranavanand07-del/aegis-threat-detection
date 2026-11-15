package com.threatdetection.normalization;

import com.threatdetection.aegis.AegisSignal;
import com.threatdetection.aegis.intel.IpClassifier;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Brings every signal to one safe shape before detection: tidy addresses (IPv4-mapped IPv6 unwrapped, garbage is
 * never kept as an address), sane timestamps, bounded text with control characters removed (stops log-line
 * injection), and de-duplication of Windows events that a poller may report twice.
 * Nothing here invents data: an address that is unusable is left EMPTY and flagged, never replaced by a guess.
 */
public final class EventNormalizer {
    private static final long DEDUPE_TTL_MS = 10 * 60 * 1000L;
    private static final int DEDUPE_MAX = 20_000;

    private final AtomicLong accepted = new AtomicLong(), repaired = new AtomicLong(), duplicates = new AtomicLong(), noAddress = new AtomicLong();
    private final Map<String, Long> seen = new LinkedHashMap<>(256, 0.75f, true) {
        @Override protected boolean removeEldestEntry(Map.Entry<String, Long> e) { return size() > DEDUPE_MAX; }
    };

    /** @return false when the signal is a duplicate and must be dropped. Mutates the signal in place. */
    public boolean process(AegisSignal s) {
        long now = System.currentTimeMillis();
        List<String> issues = EventValidator.issues(s, now);
        boolean changed = !issues.isEmpty();

        String ip = s.ip == null ? "" : s.ip.trim();
        if (ip.regionMatches(true, 0, "::ffff:", 0, 7) && IpClassifier.isValid(ip.substring(7))) { ip = ip.substring(7); changed = true; }
        if (!ip.isEmpty() && !IpClassifier.isValid(ip)) { ip = ""; s.ipMissing = true; }
        s.ip = ip;
        if (ip.isEmpty() && s.kind != AegisSignal.Kind.PROCESS && s.kind != AegisSignal.Kind.AUDIT) {
            if (!s.ipMissing) s.ipMissing = true;
            noAddress.incrementAndGet();
        }
        if (s.ts > 0 && s.ts < EventValidator.MIN_TS) s.ts = 0;
        if (s.ts > now + EventValidator.FUTURE_SLACK_MS) s.ts = now;
        if (s.port < 0 || s.port > 65535) s.port = 0;
        s.user = clean(s.user, 256, "unknown");
        s.host = clean(s.host, 255, "");
        s.path = clean(s.path, 4096, "");
        s.parent = clean(s.parent, 4096, "");
        if (s.command != null && s.command.length() > 8192) s.command = s.command.substring(0, 8192);

        if (changed) repaired.incrementAndGet();
        if (isWindowsChannel(s) && s.ts > 0 && duplicate(s, now)) {
            duplicates.incrementAndGet();
            return false;
        }
        accepted.incrementAndGet();
        return true;
    }

    private static boolean isWindowsChannel(AegisSignal s) {
        return "windows-security".equals(s.channel) || "sysmon".equals(s.channel);
    }

    private synchronized boolean duplicate(AegisSignal s, long now) {
        String key = s.channel + "|" + s.winEventId + "|" + s.ts + "|" + s.host + "|" + s.user + "|" + s.ip + "|" + s.path + "|"
                + s.command + "|" + s.port + "|" + s.remotePort;
        Long prev = seen.get(key);
        if (prev != null && now - prev < DEDUPE_TTL_MS) return true;
        seen.put(key, now);
        return false;
    }

    private static String clean(String v, int max, String fallback) {
        if (v == null || v.isEmpty()) return fallback;
        String t = v.length() > max ? v.substring(0, max) : v;
        if (!EventValidator.hasControl(t)) return t;
        StringBuilder sb = new StringBuilder(t.length());
        for (int i = 0; i < t.length(); i++) {
            char c = t.charAt(i);
            sb.append(c < 0x20 || c == 0x7f ? ' ' : c);
        }
        return sb.toString();
    }

    public Map<String, Object> stats() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("accepted", accepted.get());
        m.put("repaired", repaired.get());
        m.put("duplicatesDropped", duplicates.get());
        m.put("withoutSourceAddress", noAddress.get());
        return m;
    }
}
