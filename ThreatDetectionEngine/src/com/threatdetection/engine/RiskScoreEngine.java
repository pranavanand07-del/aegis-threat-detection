package com.threatdetection.engine;

import com.threatdetection.detector.Detector;
import com.threatdetection.model.DetectionOutcome;
import com.threatdetection.model.LogEvent;
import com.threatdetection.tracking.IpActivityTracker;

import java.util.ArrayList;
import java.util.List;

/** Runs every registered detector against an event and sums the risk score. */
public class RiskScoreEngine {
    private final List<Detector> detectors;

    public RiskScoreEngine(List<Detector> detectors) {
        this.detectors = detectors;
    }

    public static class ScoreResult {
        public final int totalScore;
        public final List<String> triggeredRules;

        public ScoreResult(int totalScore, List<String> triggeredRules) {
            this.totalScore = totalScore;
            this.triggeredRules = triggeredRules;
        }
    }

    public ScoreResult score(LogEvent event, IpActivityTracker tracker) {
        int total = 0;
        List<String> reasons = new ArrayList<>();
        for (Detector detector : detectors) {
            DetectionOutcome outcome = detector.evaluate(event, tracker);
            if (outcome != null) {
                total += outcome.score;
                reasons.add(outcome.ruleName + " (+" + outcome.score + "): " + outcome.detail);
            }
        }
        return new ScoreResult(total, reasons);
    }
}
