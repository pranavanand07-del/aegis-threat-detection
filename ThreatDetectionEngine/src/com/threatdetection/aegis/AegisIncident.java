package com.threatdetection.aegis;

import com.threatdetection.model.ThreatLevel;

import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/** Related alerts from one actor (IP or host) grouped into a single incident. */
public final class AegisIncident {
    public static final long OPEN_WINDOW_MS = 10 * 60 * 1000L;

    public final String id;
    public final String actor;
    public final long firstSeen;
    public long lastSeen;
    public int count;
    public int maxScore;
    public ThreatLevel maxLevel = ThreatLevel.LOW;
    public boolean blocked;
    public String location = "";
    /** rule name -> highest score it contributed (the incident title uses the most severe rule). */
    public final Map<String, Integer> rules = new LinkedHashMap<>();
    public final Set<DataSource> sources = EnumSet.noneOf(DataSource.class);

    public AegisIncident(String id, String actor, long firstSeen) {
        this.id = id;
        this.actor = actor;
        this.firstSeen = firstSeen;
        this.lastSeen = firstSeen;
    }

    public void add(AegisEvent e, long clock) {
        lastSeen = Math.max(lastSeen, clock);
        count++;
        maxScore = Math.max(maxScore, e.score);
        if (e.level.ordinal() > maxLevel.ordinal()) maxLevel = e.level;
        blocked |= e.blocked;
        sources.add(e.source);
        if (!e.city.isEmpty() && e.plottable()) location = e.city + ", " + e.country;
        for (AegisEvent.Contribution c : e.rules) rules.merge(c.rule, c.score, Math::max);
    }

    public String title() {
        String top = null;
        int best = -1;
        for (Map.Entry<String, Integer> r : rules.entrySet()) {
            if (r.getValue() > best) { best = r.getValue(); top = r.getKey(); }
        }
        return (top == null ? "Suspicious activity" : top.replace('_', ' ').toLowerCase()) + " from " + actor;
    }

    public boolean isOpen(long now) {
        return now - lastSeen <= OPEN_WINDOW_MS;
    }
}
