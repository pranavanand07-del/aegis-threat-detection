package com.threatdetection.aegis;

import com.threatdetection.aegis.defense.DefenseCoordinator;
import com.threatdetection.aegis.geo.AegisGeo;
import com.threatdetection.aegis.intel.EnrichmentService;
import com.threatdetection.aegis.intel.IpClassifier;
import com.threatdetection.aegis.intel.MitreMapper;
import com.threatdetection.aegis.intel.ReputationService;
import com.threatdetection.aegis.storage.AegisStore;
import com.threatdetection.correlation.AttackChainEngine;
import com.threatdetection.engine.ThreatClassifier;
import com.threatdetection.normalization.EventNormalizer;
import com.threatdetection.engine.ThreatDetectionEngine;
import com.threatdetection.model.DetectionOutcome;
import com.threatdetection.model.LogEvent;
import com.threatdetection.model.ThreatLevel;
import com.threatdetection.model.ThreatResult;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Turns signals into analysed AEGIS events: core engine result + AEGIS rules + reputation + location. */
public final class AegisPipeline {
    private static final Pattern CORE_RULE = Pattern.compile("^(\\S+) \\(([+-]\\d+)\\): (.*)$", Pattern.DOTALL);

    private final ThreatDetectionEngine engine;
    private final AegisStore store;
    private final List<AegisRule> rules;
    private final ReputationService reputation;
    private final AegisGeo geo;
    private final ThreatClassifier classifier = new ThreatClassifier();
    private volatile DefenseCoordinator defense;
    private volatile EnrichmentService enrichment;
    private final EventNormalizer normalizer = new EventNormalizer();
    private volatile AttackChainEngine chains;

    public EventNormalizer normalizer() { return normalizer; }
    public AttackChainEngine chains() { return chains; }
    public void setChains(AttackChainEngine c) { this.chains = c; }

    public AegisPipeline(ThreatDetectionEngine engine, AegisStore store, List<AegisRule> rules,
                         ReputationService reputation, AegisGeo geo) {
        this.engine = engine;
        this.store = store;
        this.rules = rules;
        this.reputation = reputation;
        this.geo = geo;
    }

    /** Optional: the live lane hands every stored event to the defense layer. The sandbox lane never gets one. */
    public void setDefense(DefenseCoordinator d) { this.defense = d; }

    /** Optional: external intelligence for the live lane (never for simulated events). */
    public void setEnrichment(EnrichmentService en) { this.enrichment = en; }

    public AegisStore store() { return store; }
    public ReputationService reputation() { return reputation; }
    public AegisGeo geo() { return geo; }

    /** Real-log path: feeds the core engine when the signal maps onto a core event, then analyses. */
    public void ingest(AegisSignal s, DataSource source) {
        try {
            if (!normalizer.process(s)) return;   // duplicate Windows record
            LogEvent le = s.toLogEvent();
            ThreatResult base = le != null ? engine.process(le) : null;
            record(s, base, source);
        } catch (RuntimeException e) {
            store.countError();
            System.err.println("[AEGIS] failed to ingest signal: " + e);
        }
    }

    /** Observer path: the core engine already processed this event (HTTP API / simulators). */
    public void observe(LogEvent e, ThreatResult base, DataSource source) {
        AegisSignal s = AegisSignal.fromLogEvent(e);
        s.channel = source == DataSource.SIMULATED ? "simulator" : "http-api";
        record(s, base, source);
    }

    private void record(AegisSignal s, ThreatResult base, DataSource source) {
        List<AegisEvent.Contribution> contributions = new ArrayList<>();
        boolean coreBlacklist = false;
        if (base != null) {
            for (String r : base.triggeredRules) {
                Matcher m = CORE_RULE.matcher(r);
                if (m.matches()) {
                    contributions.add(new AegisEvent.Contribution(m.group(1), Integer.parseInt(m.group(2)), "core", m.group(3)));
                    if (m.group(1).equals("BLACKLISTED_IP")) coreBlacklist = true;
                } else {
                    int i = r.indexOf(':');
                    contributions.add(new AegisEvent.Contribution(i > 0 ? r.substring(0, i) : r, 0, "core",
                            i > 0 ? r.substring(i + 1).trim() : r));
                }
            }
        }
        for (AegisRule rule : rules) {
            try {
                DetectionOutcome o = rule.evaluate(s);
                if (o != null) contributions.add(new AegisEvent.Contribution(o.ruleName, o.score, "aegis", o.detail));
            } catch (RuntimeException ex) {
                store.countError();
            }
        }
        boolean internal = IpClassifier.isInternal(s.ip);
        ReputationService.Reputation rep = reputation.lookup(s.ip);
        if (rep.malicious() && !coreBlacklist) {
            contributions.add(new AegisEvent.Contribution("THREAT_INTEL_MATCH", 30, "aegis", rep.detail));
        }

        int extra = 0;
        for (AegisEvent.Contribution c : contributions) if (c.origin.equals("aegis")) extra += c.score;
        int score = (base == null ? 0 : base.riskScore) + extra;
        ThreatLevel level = classifier.classify(score);
        // The core classifier labels 0-20 SAFE; an AEGIS finding is never "safe".
        if (extra > 0 && level == ThreatLevel.SAFE) level = ThreatLevel.LOW;

        AegisEvent e = new AegisEvent();
        e.ts = s.ts > 0 ? s.ts : System.currentTimeMillis();
        e.ip = s.ip == null ? "" : s.ip;
        e.internal = internal;
        e.host = s.host;
        e.user = s.user;
        e.kind = s.kind.name();
        e.channel = s.channel;
        e.source = source;
        e.score = score;
        e.level = level;
        e.blocked = base != null && base.blocked;
        e.rules = contributions;
        e.repVerdict = rep.verdict;
        e.repDetail = rep.detail;
        describe(s, e);

        AegisGeo.Result g = geo.resolve(e.ip, s.country, source);
        e.geoClass = g.geoClass;
        e.geoSource = g.source;
        e.cc = g.cc;
        e.country = g.country;
        e.city = g.city;
        e.lat = g.lat;
        e.lon = g.lon;

        e.enrichments.addAll(MitreMapper.forRules(contributions, s.extMitre));
        reputation.noteAlert(e.ip, level);
        store.add(e);
        AttackChainEngine ch = chains;
        if (ch != null) ch.observe(e, s);
        EnrichmentService en = enrichment;
        if (en != null) en.submit(e);
        DefenseCoordinator d = defense;
        if (d != null) {
            try {
                d.onEvent(e, s);
            } catch (RuntimeException ex) {
                store.countError();
                System.err.println("[AEGIS] defense layer failed on event " + e.id + ": " + ex);
            }
        }
    }

    private static void describe(AegisSignal s, AegisEvent e) {
        switch (s.kind) {
            case WEB -> {
                e.summary = "HTTP request " + trim(s.path, 140) + (s.status > 0 ? " -> " + s.status : "");
                e.target = stripQuery(s.path);
                e.targetType = "endpoint";
            }
            case AUTH -> {
                e.summary = (s.authFailure ? "Failed" : "Successful") + " logon for '" + s.user + "'"
                        + (s.logonType >= 0 ? " (type " + s.logonType + ")" : "")
                        + (s.path.isEmpty() ? "" : " via " + trim(s.path, 80))
                        + (s.ipMissing ? " [source address unavailable]" : "");
                e.target = s.user;
                e.targetType = "account";
            }
            case NETWORK -> {
                e.summary = (s.action.isEmpty() ? "" : s.action + " ") + ("out".equals(s.direction) ? "outbound" : "inbound")
                        + " connection, port " + s.port;
                e.target = "port " + s.port;
                e.targetType = "port";
            }
            case EXTERNAL -> {
                e.summary = "Wazuh rule " + s.extId + " (level " + s.extLevel + "): " + trim(s.extDesc, 140);
                e.target = s.host;
                e.targetType = "host";
            }
            case PROCESS -> {
                e.summary = trim(s.path + " " + s.command, 160);
                e.target = lastSegment(s.path);
                e.targetType = "process";
            }
            default -> {
                e.summary = "Windows audit event " + s.winEventId + (s.path.isEmpty() ? "" : ": " + trim(s.path, 80));
                e.target = s.user;
                e.targetType = "account";
            }
        }
    }

    private static String stripQuery(String p) {
        int i = p.indexOf('?');
        return i >= 0 ? p.substring(0, i) : p;
    }

    private static String lastSegment(String p) {
        int i = Math.max(p.lastIndexOf('\\'), p.lastIndexOf('/'));
        return i >= 0 ? p.substring(i + 1) : p;
    }

    private static String trim(String s, int n) {
        return s.length() > n ? s.substring(0, n) + "..." : s;
    }
}
