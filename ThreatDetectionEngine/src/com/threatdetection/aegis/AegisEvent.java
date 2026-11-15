package com.threatdetection.aegis;

import com.threatdetection.aegis.intel.Enrichment;
import com.threatdetection.model.ThreatLevel;

import java.util.ArrayList;
import java.util.List;

/** A fully analysed event as stored by AEGIS: score, explanation, reputation, location, data source. */
public final class AegisEvent {
    /** One line of the explanation: which rule added how many points. */
    public static final class Contribution {
        public final String rule;
        public final int score;
        public final String origin;   // "core" (original 11 detectors) or "aegis" (added rules)
        public final String detail;

        public Contribution(String rule, int score, String origin, String detail) {
            this.rule = rule;
            this.score = score;
            this.origin = origin;
            this.detail = detail;
        }
    }

    public long id;
    public long ts;
    public String ip = "";
    public boolean internal;
    public String host = "";
    public String user = "";
    public String kind = "";
    public String channel = "";
    public String summary = "";
    public String target = "";
    public String targetType = "";
    public DataSource source = DataSource.OBSERVED;
    public int score;
    public ThreatLevel level = ThreatLevel.SAFE;
    public boolean blocked;
    public List<Contribution> rules = new ArrayList<>();
    public String repVerdict = "";
    public String repDetail = "";
    /** ESTIMATED (GeoIP database) | SIMULATED (demo location) | INTERNAL | UNAVAILABLE */
    public String geoClass = "UNAVAILABLE";
    public String geoSource = "";
    public String cc = "";
    public String country = "";
    public String city = "";
    public double lat;
    public double lon;
    public String incident = "";
    /** ENRICHED layer: MITRE mapping (immediate) and external intelligence (added later by background lookups). */
    public final java.util.List<Enrichment> enrichments = new java.util.concurrent.CopyOnWriteArrayList<>();

    public boolean plottable() {
        return "ESTIMATED".equals(geoClass) || "SIMULATED".equals(geoClass);
    }
}
