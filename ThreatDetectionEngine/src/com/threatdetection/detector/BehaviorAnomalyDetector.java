package com.threatdetection.detector;

import com.threatdetection.model.DetectionOutcome;
import com.threatdetection.model.LogEvent;
import com.threatdetection.tracking.IpActivityTracker;

/**
 * Detects traffic that deviates sharply from an IP's own historical baseline - catches attacks that
 * don't match any known signature.
 *
 * Fixed over the first version: (1) the one-minute rate is now a real one-minute count (the tracker
 * used to discard everything older than 10 s), (2) there is a learning period, so an IP's first few
 * requests are not "normal" by definition, and (3) abnormal observations are never folded into the
 * baseline, so an attacker cannot talk the baseline into accepting the attack.
 */
public class BehaviorAnomalyDetector implements Detector {
    private static final long ONE_MINUTE = 60 * 1000L;
    private static final double SPIKE_MULTIPLIER = 5.0;
    private static final int MIN_REQUESTS_FOR_ALERT = 20;
    private static final int MIN_BASELINE_SAMPLES = 3;

    @Override
    public DetectionOutcome evaluate(LogEvent event, IpActivityTracker tracker) {
        int currentRate = tracker.requestsInWindow(event.timestamp, ONE_MINUTE);
        double baseline = tracker.getBaselineRequestsPerMinute();

        DetectionOutcome outcome = null;
        boolean learned = tracker.getBaselineSamples() >= MIN_BASELINE_SAMPLES;
        boolean anomalous = baseline > 0 && currentRate >= MIN_REQUESTS_FOR_ALERT
                && currentRate > baseline * SPIKE_MULTIPLIER;
        if (learned && anomalous) {
            outcome = new DetectionOutcome("BEHAVIOR_ANOMALY", 20,
                    "Traffic spike: " + currentRate + " req/min vs normal baseline of "
                            + String.format("%.1f", baseline) + " req/min");
        }
        tracker.updateBaseline(event.timestamp, currentRate, anomalous);
        return outcome;
    }
}
