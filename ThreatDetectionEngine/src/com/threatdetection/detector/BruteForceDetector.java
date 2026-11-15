package com.threatdetection.detector;

import com.threatdetection.model.DetectionOutcome;
import com.threatdetection.model.EventType;
import com.threatdetection.model.LogEvent;
import com.threatdetection.tracking.IpActivityTracker;

/** Flags an IP that racks up repeated failed logins in a short window. */
public class BruteForceDetector implements Detector {
    private static final long WINDOW_MS = 2 * 60 * 1000L;
    private static final int FAILURE_THRESHOLD = 5;

    @Override
    public DetectionOutcome evaluate(LogEvent event, IpActivityTracker tracker) {
        if (event.eventType != EventType.LOGIN_FAILED) {
            return null;
        }
        tracker.recordLoginFailure(event.timestamp);
        int failures = tracker.loginFailuresInWindow(event.timestamp, WINDOW_MS);
        if (failures >= FAILURE_THRESHOLD) {
            int score = 10 + Math.min(40, (failures - FAILURE_THRESHOLD) * 5);
            return new DetectionOutcome("BRUTE_FORCE", score,
                    failures + " failed login attempts within 2 minutes");
        }
        return null;
    }
}
