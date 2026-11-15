package com.threatdetection.map;

import com.threatdetection.geo.GeoIpProvider;
import com.threatdetection.geo.GeoLocation;
import com.threatdetection.model.LogEvent;
import com.threatdetection.model.ThreatLevel;
import com.threatdetection.model.ThreatResult;
import com.threatdetection.storage.InMemoryStore;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Builds the geographic view of the engine's results: where attacks come from,
 * what they hit, and a live event feed for the animated map.
 * It only OBSERVES results - it never influences detection or blocking.
 */
public class ThreatMapService {
    private static final int MAX_PROFILES = 2000;
    private static final int MAX_FEED = 400;
    private static final int MAX_TARGETS = 300;
    private static final int MAX_ATTACKERS_PER_TARGET = 500;

    private final InMemoryStore store;
    private final GeoIpProvider geo;
    private final GeoLocation target;

    private final Map<String, AttackerProfile> profiles = new LinkedHashMap<>();
    private final Map<String, TargetStats> targets = new LinkedHashMap<>();
    private final ArrayDeque<MapEvent> feed = new ArrayDeque<>();
    private long seq = 0;
    private long attackEvents = 0;
    private long internalThreats = 0;

    public ThreatMapService(InMemoryStore store, GeoIpProvider geo, GeoLocation target) {
        this.store = store;
        this.geo = geo;
        this.target = target;
    }

    public GeoLocation getTarget() {
        return target;
    }

    /** Builds the protected-server location from -Dtarget.* properties (defaults: New Delhi, India). */
    public static GeoLocation targetFromSystemProperties() {
        String name = System.getProperty("target.name", "Protected Server");
        double lat = parse(System.getProperty("target.lat"), 28.6139);
        double lon = parse(System.getProperty("target.lon"), 77.2090);
        String city = System.getProperty("target.city", "New Delhi");
        String region = System.getProperty("target.region", "Delhi");
        return new GeoLocation("IN", "India", region, city + " (" + name + ")", lat, lon, false, "configured");
    }

    private static double parse(String s, double fallback) {
        if (s == null) return fallback;
        try {
            return Double.parseDouble(s);
        } catch (NumberFormatException e) {
            return fallback;
        }
    }

    // ------------------------------------------------------------------ recording

    public synchronized void record(LogEvent e, ThreatResult r) {
        String ip = e.ip == null ? "" : (e.ip.length() > 64 ? e.ip.substring(0, 64) : e.ip);
        GeoLocation loc = geo.locate(ip, e.country);
        boolean threat = r.level != ThreatLevel.SAFE || r.blocked;

        // Quiet traffic from inside the protected network is not a map marker.
        if (loc.internal && !threat) return;

        String dominant = dominantRule(r.triggeredRules);

        if (loc.internal) {
            internalThreats++;
        } else {
            AttackerProfile p = profiles.get(ip);
            if (p == null) {
                evictIfNeeded();
                p = new AttackerProfile(ip, loc, r.timestamp);
                profiles.put(ip, p);
            }
            p.events++;
            p.lastSeen = r.timestamp;
            p.lastRisk = r.riskScore;
            p.lastLevel = r.level;
            if (r.riskScore > p.peakRisk) p.peakRisk = r.riskScore;
            if (r.level.ordinal() > p.peakLevel.ordinal()) p.peakLevel = r.level;
            if (threat) {
                p.attacks++;
                if (dominant != null) {
                    p.lastThreat = dominant;
                    p.threatCounts.merge(dominant, 1, Integer::sum);
                } else if (p.lastThreat == null) {
                    p.lastThreat = "BLOCKED_IP";
                }
            }
        }

        String tKind = null, tName = null;
        if (threat) {
            attackEvents++;
            String[] t = targetOf(e);
            tKind = t[0];
            tName = t[1];
            recordTarget(tKind, tName, ip, dominant, r.timestamp);
        }

        if (!loc.internal) {
            String threatName = dominant != null ? dominant : (threat ? "BLOCKED_IP" : null);
            feed.addLast(new MapEvent(++seq, r.timestamp, ip, loc, r.level, r.riskScore,
                    threatName, r.blocked, tKind, tName));
            while (feed.size() > MAX_FEED) feed.removeFirst();
        }
    }

    private void recordTarget(String kind, String name, String ip, String dominant, long ts) {
        String key = kind + "|" + name;
        TargetStats t = targets.get(key);
        if (t == null) {
            if (targets.size() >= MAX_TARGETS) return;
            t = new TargetStats(kind, name);
            targets.put(key, t);
        }
        t.count++;
        t.lastSeen = ts;
        if (t.attackers.size() < MAX_ATTACKERS_PER_TARGET) t.attackers.add(ip);
        if (dominant != null) t.threatCounts.merge(dominant, 1, Integer::sum);
    }

    private void evictIfNeeded() {
        if (profiles.size() < MAX_PROFILES) return;
        String oldest = null;
        long oldestSeen = Long.MAX_VALUE;
        for (AttackerProfile p : profiles.values()) {
            if (p.lastSeen < oldestSeen) {
                oldestSeen = p.lastSeen;
                oldest = p.ip;
            }
        }
        if (oldest != null) profiles.remove(oldest);
    }

    /** What did this event hit? -> {kind, name} */
    private static String[] targetOf(LogEvent e) {
        return switch (e.eventType) {
            case PORT_ACCESS -> new String[]{"port", "Port " + e.port};
            case DOWNLOAD_REQUEST -> new String[]{"file", e.fileName.isEmpty() ? e.endpoint : e.fileName};
            case LOGIN_FAILED, LOGIN_SUCCESS -> new String[]{"user", "Account: " + clip(e.username)};
            default -> new String[]{"endpoint", clip(e.endpoint)};
        };
    }

    private static String clip(String s) {
        if (s == null) return "";
        return s.length() > 48 ? s.substring(0, 48) : s;
    }

    /** The highest-scoring rule that fired, parsed from "RULE_NAME (+40): detail". */
    static String dominantRule(List<String> rules) {
        String best = null;
        int bestScore = -1;
        for (String r : rules) {
            int p = r.indexOf(" (+");
            if (p < 0) continue;
            int q = r.indexOf(')', p);
            if (q < 0) continue;
            int score;
            try {
                score = Integer.parseInt(r.substring(p + 3, q));
            } catch (NumberFormatException ex) {
                continue;
            }
            if (score > bestScore) {
                bestScore = score;
                best = r.substring(0, p);
            }
        }
        return best;
    }

    // ------------------------------------------------------------------ JSON output

    public synchronized String eventsJson(long since) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\"latest\":").append(seq).append(",\"events\":[");
        boolean first = true;
        for (MapEvent m : feed) {
            if (m.id <= since) continue;
            if (!first) sb.append(',');
            first = false;
            sb.append('{')
              .append("\"id\":").append(m.id)
              .append(",\"ts\":").append(m.timestamp)
              .append(",\"ip\":").append(Json.str(m.ip))
              .append(",\"lat\":").append(Json.num(m.location.lat))
              .append(",\"lon\":").append(Json.num(m.location.lon))
              .append(",\"cc\":").append(Json.str(m.location.countryCode))
              .append(",\"city\":").append(Json.str(m.location.city))
              .append(",\"level\":").append(Json.str(m.level.name()))
              .append(",\"risk\":").append(m.risk)
              .append(",\"threat\":").append(m.threat == null ? "null" : Json.str(m.threat))
              .append(",\"blocked\":").append(m.blocked)
              .append(",\"target\":").append(m.targetKind == null ? "null"
                      : "{\"kind\":" + Json.str(m.targetKind) + ",\"name\":" + Json.str(m.targetName) + "}")
              .append('}');
        }
        sb.append("]}");
        return sb.toString();
    }

    public synchronized String stateJson() {
        Set<String> blocked = store.getBlockedIps();
        List<AttackerProfile> list = new ArrayList<>(profiles.values());
        list.sort(Comparator.comparingLong((AttackerProfile p) -> p.lastSeen).reversed());

        // ---- aggregates
        int attackers = 0, critical = 0, indiaSources = 0;
        Set<String> countries = new HashSet<>();
        Map<String, int[]> byCountry = new HashMap<>();      // cc -> {attacks, ips, maxRisk}
        Map<String, String> countryNames = new HashMap<>();
        Map<String, int[]> byState = new HashMap<>();        // state -> {attacks, ips}
        Map<String, Set<String>> stateCities = new HashMap<>();
        Map<String, Integer> threatTypes = new HashMap<>();

        for (AttackerProfile p : list) {
            if (p.attacks == 0) continue;
            attackers++;
            if (p.peakLevel == ThreatLevel.CRITICAL) critical++;
            String cc = p.location.countryCode;
            countries.add(cc);
            countryNames.put(cc, p.location.country);
            int[] c = byCountry.computeIfAbsent(cc, k -> new int[3]);
            c[0] += p.attacks;
            c[1] += 1;
            c[2] = Math.max(c[2], p.peakRisk);
            if ("IN".equals(cc)) {
                indiaSources++;
                String st = p.location.region.isEmpty() ? p.location.city : p.location.region;
                int[] s = byState.computeIfAbsent(st, k -> new int[2]);
                s[0] += p.attacks;
                s[1] += 1;
                stateCities.computeIfAbsent(st, k -> new HashSet<>()).add(p.location.city);
            }
            for (Map.Entry<String, Integer> t : p.threatCounts.entrySet()) {
                threatTypes.merge(t.getKey(), t.getValue(), Integer::sum);
            }
        }

        StringBuilder sb = new StringBuilder(8192);
        sb.append('{');
        sb.append("\"accuracy\":\"approximate\",");
        sb.append("\"target\":{")
          .append("\"name\":").append(Json.str(target.city))
          .append(",\"country\":").append(Json.str(target.country))
          .append(",\"lat\":").append(Json.num(target.lat))
          .append(",\"lon\":").append(Json.num(target.lon)).append("},");

        sb.append("\"summary\":{")
          .append("\"attackers\":").append(attackers)
          .append(",\"countries\":").append(countries.size())
          .append(",\"critical\":").append(critical)
          .append(",\"blockedIps\":").append(blocked.size())
          .append(",\"attackEvents\":").append(attackEvents)
          .append(",\"indiaSources\":").append(indiaSources)
          .append(",\"internalThreats\":").append(internalThreats)
          .append("},");

        // countries
        List<Map.Entry<String, int[]>> cl = new ArrayList<>(byCountry.entrySet());
        cl.sort((a, b) -> b.getValue()[0] - a.getValue()[0]);
        sb.append("\"countries\":[");
        for (int i = 0; i < Math.min(15, cl.size()); i++) {
            Map.Entry<String, int[]> e = cl.get(i);
            if (i > 0) sb.append(',');
            sb.append("{\"cc\":").append(Json.str(e.getKey()))
              .append(",\"name\":").append(Json.str(countryNames.get(e.getKey())))
              .append(",\"attacks\":").append(e.getValue()[0])
              .append(",\"ips\":").append(e.getValue()[1])
              .append(",\"maxRisk\":").append(e.getValue()[2]).append('}');
        }
        sb.append("],");

        // India states
        List<Map.Entry<String, int[]>> sl = new ArrayList<>(byState.entrySet());
        sl.sort((a, b) -> b.getValue()[0] - a.getValue()[0]);
        sb.append("\"states\":[");
        for (int i = 0; i < Math.min(15, sl.size()); i++) {
            Map.Entry<String, int[]> e = sl.get(i);
            if (i > 0) sb.append(',');
            sb.append("{\"state\":").append(Json.str(e.getKey()))
              .append(",\"attacks\":").append(e.getValue()[0])
              .append(",\"ips\":").append(e.getValue()[1])
              .append(",\"cities\":").append(Json.str(String.join(", ", new java.util.TreeSet<>(stateCities.get(e.getKey())))))
              .append('}');
        }
        sb.append("],");

        // threat types
        List<Map.Entry<String, Integer>> tl = new ArrayList<>(threatTypes.entrySet());
        tl.sort((a, b) -> b.getValue() - a.getValue());
        sb.append("\"threatTypes\":[");
        for (int i = 0; i < tl.size(); i++) {
            if (i > 0) sb.append(',');
            sb.append("{\"name\":").append(Json.str(tl.get(i).getKey()))
              .append(",\"count\":").append(tl.get(i).getValue()).append('}');
        }
        sb.append("],");

        // targets
        List<TargetStats> tsl = new ArrayList<>(targets.values());
        tsl.sort((a, b) -> b.count - a.count);
        sb.append("\"targets\":[");
        for (int i = 0; i < Math.min(20, tsl.size()); i++) {
            TargetStats t = tsl.get(i);
            if (i > 0) sb.append(',');
            sb.append("{\"kind\":").append(Json.str(t.kind))
              .append(",\"name\":").append(Json.str(t.name))
              .append(",\"count\":").append(t.count)
              .append(",\"attackers\":").append(t.attackers.size())
              .append(",\"topThreat\":").append(t.topThreat() == null ? "null" : Json.str(t.topThreat()))
              .append(",\"lastSeen\":").append(t.lastSeen).append('}');
        }
        sb.append("],");

        // attackers (most recently active first, capped)
        sb.append("\"attackers\":[");
        int n = 0;
        for (AttackerProfile p : list) {
            if (n >= 250) break;
            if (n > 0) sb.append(',');
            n++;
            GeoLocation g = p.location;
            sb.append('{')
              .append("\"ip\":").append(Json.str(p.ip))
              .append(",\"lat\":").append(Json.num(g.lat))
              .append(",\"lon\":").append(Json.num(g.lon))
              .append(",\"city\":").append(Json.str(g.city))
              .append(",\"region\":").append(Json.str(g.region))
              .append(",\"country\":").append(Json.str(g.country))
              .append(",\"cc\":").append(Json.str(g.countryCode))
              .append(",\"level\":").append(Json.str(p.lastLevel.name()))
              .append(",\"peakLevel\":").append(Json.str(p.peakLevel.name()))
              .append(",\"risk\":").append(p.lastRisk)
              .append(",\"peakRisk\":").append(p.peakRisk)
              .append(",\"attacks\":").append(p.attacks)
              .append(",\"events\":").append(p.events)
              .append(",\"threat\":").append(p.topThreat() == null ? "null" : Json.str(p.topThreat()))
              .append(",\"firstSeen\":").append(p.firstSeen)
              .append(",\"lastSeen\":").append(p.lastSeen)
              .append(",\"blocked\":").append(blocked.contains(p.ip))
              .append(",\"source\":").append(Json.str(g.source))
              .append('}');
        }
        sb.append("]}");
        return sb.toString();
    }
}
