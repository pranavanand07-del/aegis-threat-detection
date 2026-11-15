package com.threatdetection.platform;

import com.threatdetection.aegis.AegisEvent;
import com.threatdetection.aegis.DataSource;
import com.threatdetection.aegis.storage.AegisStore;
import com.threatdetection.model.ThreatLevel;

import java.util.ArrayList;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import static com.threatdetection.aegis.JsonUtil.esc;
import static com.threatdetection.aegis.JsonUtil.str;

/**
 * Connects the dots between events from the same actor.
 *
 * The core engine scores each event on its own, so an attacker who spreads steps over time can stay
 * under the block line every time. This class looks at everything one actor did and asks three
 * questions: how much distinct evidence is there, how recent is it, and how far along the attack
 * chain did the actor get?
 *
 * <pre>
 *   evidence(rule)  = strongestPoints x repeat(count) x decay(age of last hit)
 *   repeat(n)       = min(2, 1 + 0.1 x (n - 1))
 *   decay(age)      = 0.5 ^ (age / 10 minutes)
 *   campaignRisk    = sum of evidence over distinct rules + 15 x (stages reached - 1)
 *   WATCH below 80, ESCALATE from 80, BLOCK recommended from 150
 * </pre>
 *
 * Observe-only: it reads stored results and never changes scoring or blocking.
 */
public final class CampaignAnalyzer {
    public static final long HALF_LIFE_MS = 10 * 60_000L;
    public static final int STAGE_BONUS = 15;
    public static final int ESCALATE_AT = 80;
    public static final int BLOCK_AT = 150;
    private static final String IGNORED_RULE = "IP_ALREADY_BLOCKED";   // a response, not behaviour

    /** Evidence one rule has produced for one actor. */
    public static final class Evidence {
        public final String rule;
        public final String origin;
        public int maxPoints;
        public int count;
        public long lastSeen;
        public double weight;

        Evidence(String rule, String origin) {
            this.rule = rule;
            this.origin = origin;
        }
    }

    /** Everything known about one actor in the analysed window. */
    public static final class Campaign {
        public final String actor;
        public boolean internal;
        public int detections;
        public int peakScore;
        public long firstSeen = Long.MAX_VALUE;
        public long lastSeen;
        public boolean blocked;
        public String location = "";
        public final Set<DataSource> sources = EnumSet.noneOf(DataSource.class);
        public final Map<String, Evidence> evidence = new LinkedHashMap<>();
        public final Set<Integer> stageIdx = new TreeSet<>();
        public int risk;
        public String verdict = "";
        public String action = "WATCH";
        public boolean engineMissed;

        Campaign(String actor) {
            this.actor = actor;
        }

        void add(AegisEvent e) {
            detections++;
            peakScore = Math.max(peakScore, e.score);
            firstSeen = Math.min(firstSeen, e.ts);
            lastSeen = Math.max(lastSeen, e.ts);
            blocked |= e.blocked;
            internal = e.internal;
            sources.add(e.source);
            if (location.isEmpty() && !e.city.isEmpty() && e.plottable()) location = e.city + ", " + e.country;
            for (AegisEvent.Contribution c : e.rules) {
                if (IGNORED_RULE.equals(c.rule)) continue;
                Evidence ev = evidence.computeIfAbsent(c.rule, k -> new Evidence(c.rule, c.origin));
                ev.maxPoints = Math.max(ev.maxPoints, c.score);
                ev.count++;
                ev.lastSeen = Math.max(ev.lastSeen, e.ts);
                int si = RuleCatalog.stageIndex(RuleCatalog.stageOf(c.rule));
                if (si >= 0) stageIdx.add(si);
            }
        }

        void finish(long now) {
            double total = 0;
            for (Evidence ev : evidence.values()) {
                double repeat = Math.min(2.0, 1.0 + 0.1 * (ev.count - 1));
                double age = Math.max(0, now - ev.lastSeen);
                double decay = Math.pow(0.5, age / HALF_LIFE_MS);
                ev.weight = ev.maxPoints * repeat * decay;
                total += ev.weight;
            }
            total += STAGE_BONUS * Math.max(0, stageIdx.size() - 1);
            risk = (int) Math.round(total);
            int stages = stageIdx.size();
            if (stages >= 3) verdict = "Multi-stage campaign";
            else if (stages == 2) verdict = "Progressing attack";
            else if (detections >= 5) verdict = "Persistent probing";
            else verdict = "Isolated detection";
            action = risk >= BLOCK_AT ? "BLOCK" : risk >= ESCALATE_AT ? "ESCALATE" : "WATCH";
            engineMissed = "BLOCK".equals(action) && !blocked;
            if (firstSeen == Long.MAX_VALUE) firstSeen = 0;
        }

        public String toJson() {
            StringBuilder sb = new StringBuilder(512);
            sb.append("{\"actor\":").append(str(actor))
              .append(",\"internal\":").append(internal)
              .append(",\"detections\":").append(detections)
              .append(",\"peakScore\":").append(peakScore)
              .append(",\"firstSeen\":").append(firstSeen)
              .append(",\"lastSeen\":").append(lastSeen)
              .append(",\"risk\":").append(risk)
              .append(",\"verdict\":").append(str(verdict))
              .append(",\"action\":").append(str(action))
              .append(",\"blockedByEngine\":").append(blocked)
              .append(",\"engineMissed\":").append(engineMissed)
              .append(",\"location\":").append(str(location));
            sb.append(",\"sources\":[");
            boolean first = true;
            for (DataSource d : sources) {
                if (!first) sb.append(',');
                first = false;
                sb.append(str(d.name()));
            }
            sb.append("],\"stages\":[");
            first = true;
            for (int i : stageIdx) {
                if (!first) sb.append(',');
                first = false;
                sb.append(str(RuleCatalog.STAGES.get(i).id()));
            }
            sb.append("],\"rules\":[");
            first = true;
            for (Evidence ev : evidence.values()) {
                if (!first) sb.append(',');
                first = false;
                String stage = RuleCatalog.stageOf(ev.rule);
                sb.append("{\"rule\":").append(str(ev.rule))
                  .append(",\"origin\":").append(str(ev.origin))
                  .append(",\"points\":").append(ev.maxPoints)
                  .append(",\"count\":").append(ev.count)
                  .append(",\"weight\":").append(Math.round(ev.weight))
                  .append(",\"stage\":").append(stage == null ? "null" : str(stage))
                  .append('}');
            }
            sb.append("]}");
            return sb.toString();
        }
    }

    private final AegisStore store;

    public CampaignAnalyzer(AegisStore store) {
        this.store = store;
    }

    /** Campaigns in [from, to], highest risk first. Actors with no rule hits are left out. */
    public List<Campaign> analyze(long from, long to, int limit) {
        long now = System.currentTimeMillis();
        Map<String, Campaign> byActor = new LinkedHashMap<>();
        for (AegisEvent e : store.query(from, to, ThreatLevel.SAFE, null, "", 20_000)) {
            String actor = actorOf(e);
            if (actor.isEmpty() || !hasRuleHit(e)) continue;
            byActor.computeIfAbsent(actor, Campaign::new).add(e);
        }
        List<Campaign> out = new ArrayList<>(byActor.values());
        for (Campaign c : out) c.finish(now);
        out.sort((a, b) -> Integer.compare(b.risk, a.risk));
        return out.size() > limit ? new ArrayList<>(out.subList(0, limit)) : out;
    }

    /** The campaign for one actor over the last {@code windowMs}, or null when it has no detections. */
    public Campaign forActor(String actor, long windowMs) {
        long now = System.currentTimeMillis();
        Campaign c = new Campaign(actor);
        for (AegisEvent e : store.query(now - windowMs, now + 5000, ThreatLevel.SAFE, null, actor, 20_000)) {
            if (actor.equals(actorOf(e)) && hasRuleHit(e)) c.add(e);
        }
        if (c.detections == 0) return null;
        c.finish(now);
        return c;
    }

    public static String actorOf(AegisEvent e) {
        if (e.ip != null && !e.ip.isEmpty()) return e.ip;
        return e.host != null && !e.host.isEmpty() ? "host:" + e.host : "";
    }

    private static boolean hasRuleHit(AegisEvent e) {
        for (AegisEvent.Contribution c : e.rules) if (!IGNORED_RULE.equals(c.rule)) return true;
        return false;
    }

    static String jsonEsc(String s) {
        return esc(s);
    }
}
