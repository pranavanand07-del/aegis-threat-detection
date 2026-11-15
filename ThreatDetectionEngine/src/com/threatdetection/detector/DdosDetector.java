package com.threatdetection.detector;

import com.threatdetection.model.DetectionOutcome;
import com.threatdetection.model.LogEvent;
import com.threatdetection.tracking.IpActivityTracker;

/** Flags an IP sending an abnormally high volume of requests in seconds. */
public class DdosDetector implements Detector {
    private static final long WINDOW_MS = 10 * 1000L;
    private static final int REQUEST_THRESHOLD = 50;

    @Override
    public DetectionOutcome evaluate(LogEvent event, IpActivityTracker tracker) {
        tracker.recordRequest(event.timestamp);
        int count = tracker.requestsInWindow(event.timestamp, WINDOW_MS);
        if (count >= REQUEST_THRESHOLD) {
            int score = 30 + Math.min(30, ((count - REQUEST_THRESHOLD) / 10) * 5);
            return new DetectionOutcome("DDOS", score,
                    count + " requests within 10 seconds");
        }
        return null;
    }
}
