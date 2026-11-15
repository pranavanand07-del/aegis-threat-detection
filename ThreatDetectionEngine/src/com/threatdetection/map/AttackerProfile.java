package com.threatdetection.map;

import com.threatdetection.geo.GeoLocation;
import com.threatdetection.model.ThreatLevel;

import java.util.HashMap;
import java.util.Map;

/** Everything the map knows about one source IP. */
public class AttackerProfile {
    public final String ip;
    public final GeoLocation location;
    public final long firstSeen;

    public long lastSeen;
    public int events;          // every event seen from this IP
    public int attacks;         // events that were non-SAFE (or rejected because the IP is blocked)
    public int lastRisk;
    public int peakRisk;
    public ThreatLevel lastLevel = ThreatLevel.SAFE;
    public ThreatLevel peakLevel = ThreatLevel.SAFE;
    public String lastThreat = null;
    public final Map<String, Integer> threatCounts = new HashMap<>();

    public AttackerProfile(String ip, GeoLocation location, long firstSeen) {
        this.ip = ip;
        this.location = location;
        this.firstSeen = firstSeen;
        this.lastSeen = firstSeen;
    }

    /** The most frequent dominant threat type seen from this IP. */
    public String topThreat() {
        String best = lastThreat;
        int bestCount = -1;
        for (Map.Entry<String, Integer> e : threatCounts.entrySet()) {
            if (e.getValue() > bestCount) {
                bestCount = e.getValue();
                best = e.getKey();
            }
        }
        return best;
    }
}
