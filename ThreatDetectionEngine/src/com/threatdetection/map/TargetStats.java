package com.threatdetection.map;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/** How often one thing (endpoint / user account / port / file) is being attacked. */
public class TargetStats {
    public final String kind;   // endpoint | user | port | file
    public final String name;
    public int count;
    public long lastSeen;
    public final Set<String> attackers = new HashSet<>();
    public final Map<String, Integer> threatCounts = new HashMap<>();

    public TargetStats(String kind, String name) {
        this.kind = kind;
        this.name = name;
    }

    public String topThreat() {
        String best = null;
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
