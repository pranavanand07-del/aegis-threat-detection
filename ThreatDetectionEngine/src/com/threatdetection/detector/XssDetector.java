package com.threatdetection.detector;

import com.threatdetection.model.DetectionOutcome;
import com.threatdetection.model.LogEvent;
import com.threatdetection.tracking.IpActivityTracker;
import com.threatdetection.util.InputNormalizer;

/** Scans endpoint + request body for cross-site scripting payloads (after URL-decoding). */
public class XssDetector implements Detector {
    private static final String[] PATTERNS = {
            "<script", "onerror=", "onload=", "onmouseover=", "javascript:", "<iframe", "<svg/onload",
            "document.cookie", "alert("
    };

    @Override
    public DetectionOutcome evaluate(LogEvent event, IpActivityTracker tracker) {
        String hay = InputNormalizer.forSql(event.endpoint + " " + event.requestBody);
        for (String pattern : PATTERNS) {
            if (hay.contains(pattern)) {
                return new DetectionOutcome("XSS_ATTACK", 25, "XSS pattern detected: " + pattern);
            }
        }
        return null;
    }
}
