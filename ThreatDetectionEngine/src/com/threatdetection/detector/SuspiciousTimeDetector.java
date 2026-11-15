package com.threatdetection.detector;

import com.threatdetection.model.DetectionOutcome;
import com.threatdetection.model.EventType;
import com.threatdetection.model.LogEvent;
import com.threatdetection.tracking.IpActivityTracker;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;

/** Flags login activity happening during typical "off hours" (2 AM - 4 AM). */
public class SuspiciousTimeDetector implements Detector {
    @Override
    public DetectionOutcome evaluate(LogEvent event, IpActivityTracker tracker) {
        if (event.eventType != EventType.LOGIN_FAILED && event.eventType != EventType.LOGIN_SUCCESS) {
            return null;
        }
        LocalDateTime time = LocalDateTime.ofInstant(Instant.ofEpochMilli(event.timestamp), ZoneId.systemDefault());
        int hour = time.getHour();
        if (hour >= 2 && hour < 4) {
            return new DetectionOutcome("SUSPICIOUS_TIME", 10,
                    "Login activity during unusual hours (" + hour + ":00)");
        }
        return null;
    }
}
