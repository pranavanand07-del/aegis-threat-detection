package com.threatdetection.engine;

import com.threatdetection.detector.BehaviorAnomalyDetector;
import com.threatdetection.detector.BlacklistDetector;
import com.threatdetection.detector.BotDetector;
import com.threatdetection.detector.BruteForceDetector;
import com.threatdetection.detector.DdosDetector;
import com.threatdetection.detector.Detector;
import com.threatdetection.detector.ImpossibleLoginDetector;
import com.threatdetection.detector.MalwareDownloadDetector;
import com.threatdetection.detector.PortScanDetector;
import com.threatdetection.detector.SqlInjectionDetector;
import com.threatdetection.detector.SuspiciousTimeDetector;
import com.threatdetection.detector.XssDetector;
import com.threatdetection.intelligence.ThreatIntelService;
import com.threatdetection.model.LogEvent;
import com.threatdetection.model.ThreatLevel;
import com.threatdetection.model.ThreatResult;
import com.threatdetection.response.AutoResponseService;
import com.threatdetection.storage.InMemoryStore;
import com.threatdetection.tracking.IpActivityTracker;
import com.threatdetection.tracking.TrackingStore;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Orchestrates the whole pipeline for one incoming event:
 * tracker update -> multi-rule risk scoring -> classification -> auto response.
 */
public class ThreatDetectionEngine {
    /** Events older than this are history being replayed, not an attack in progress: never block on them. */
    private static final long HISTORICAL_MS = 5 * 60 * 1000L;

    private final RiskScoreEngine riskScoreEngine;
    private final ThreatClassifier classifier = new ThreatClassifier();
    private final TrackingStore trackingStore = new TrackingStore();
    private final AutoResponseService responseService;
    private final InMemoryStore store;

    private final ThreatIntelService intel;

    /** Blocklist comes from -Daegis.blacklist.file (empty when not configured: nothing is assumed known-bad). */
    public ThreatDetectionEngine(InMemoryStore store) {
        this(store, ThreatIntelService.fromSystemProperties());
    }

    public ThreatDetectionEngine(InMemoryStore store, ThreatIntelService intel) {
        this.store = store;
        this.intel = intel;
        this.responseService = new AutoResponseService(store);

        List<Detector> detectors = Arrays.asList(
                new BlacklistDetector(intel),
                new BruteForceDetector(),
                new SqlInjectionDetector(),
                new XssDetector(),
                new DdosDetector(),
                new PortScanDetector(),
                new BotDetector(),
                new ImpossibleLoginDetector(),
                new MalwareDownloadDetector(),
                new SuspiciousTimeDetector(),
                new BehaviorAnomalyDetector()
        );

        this.riskScoreEngine = new RiskScoreEngine(detectors);
    }

    public ThreatResult process(LogEvent event) {
        if (responseService.isBlocked(event.ip)) {
            ThreatResult blockedResult = new ThreatResult(event.ip, 100, ThreatLevel.CRITICAL,
                    List.of("IP_ALREADY_BLOCKED: request rejected without processing"),
                    event.timestamp, true, true);
            store.recordThreat(blockedResult);
            store.incrementTotalEvents();
            return blockedResult;
        }

        IpActivityTracker tracker = trackingStore.get(event.ip);
        RiskScoreEngine.ScoreResult scoreResult = riskScoreEngine.score(event, tracker);
        ThreatLevel level = classifier.classify(scoreResult.totalScore);

        boolean blocked = false;
        String osStatus = "NOT_ATTEMPTED", osDetail = "";
        List<String> rules = scoreResult.triggeredRules;
        if (level == ThreatLevel.CRITICAL) {
            boolean historical = System.currentTimeMillis() - event.timestamp > HISTORICAL_MS;
            String skipped = historical ? "not blocked: event is historical (log replay)" : responseService.block(event.ip);
            blocked = skipped == null;     // application-level block only: this process rejects the address
            if (blocked) {
                com.threatdetection.response.OsResponseCoordinator.Handled h = responseService.osResponseDetailed(
                        event.ip, scoreResult.totalScore, level, rules, "core-engine");
                if (h == null) {
                    osStatus = "NOT_ATTACHED";
                } else {
                    osStatus = h.status();
                    osDetail = h.note();
                    rules = new ArrayList<>(rules);
                    rules.add(h.note());
                }
            } else {
                osStatus = "NOT_ATTEMPTED";
                osDetail = skipped;
                rules = new ArrayList<>(rules);
                rules.add("BLOCK_SKIPPED: " + skipped);
            }
        }

        ThreatResult result = new ThreatResult(event.ip, scoreResult.totalScore, level,
                rules, event.timestamp, blocked);
        result.osFirewall = osStatus;
        result.osFirewallDetail = osDetail;

        store.recordThreat(result);
        store.incrementTotalEvents();
        return result;
    }

    public AutoResponseService responseService() { return responseService; }

    public ThreatIntelService intel() { return intel; }
}
