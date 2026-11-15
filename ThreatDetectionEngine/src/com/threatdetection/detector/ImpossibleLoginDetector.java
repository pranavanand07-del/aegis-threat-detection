package com.threatdetection.detector;

import com.threatdetection.model.DetectionOutcome;
import com.threatdetection.model.EventType;
import com.threatdetection.model.LogEvent;
import com.threatdetection.tracking.IpActivityTracker;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Flags a successful login for the SAME ACCOUNT from a different country shortly after another.
 * The state is per user, not per IP: one IP never changes country, so an IP-keyed check could only
 * ever fire on made-up data. Real impossible travel is "same account, two places, minutes apart".
 */
public class ImpossibleLoginDetector implements Detector {
    private static final long WINDOW_MS = 10 * 60 * 1000L;
    private static final int MAX_USERS = 100_000;

    private record Last(String country, long ts, String ip) {}

    private final Map<String, Last> lastByUser = new ConcurrentHashMap<>();

    @Override
    public DetectionOutcome evaluate(LogEvent event, IpActivityTracker tracker) {
        if (event.eventType != EventType.LOGIN_SUCCESS) {
            return null;
        }
        String user = event.username == null ? "" : event.username.toLowerCase();
        if (user.isEmpty() || user.equals("unknown") || event.country.equalsIgnoreCase("UNKNOWN")) {
            return null;   // nothing to compare against
        }
        if (lastByUser.size() > MAX_USERS) lastByUser.clear();
        Last prev = lastByUser.put(user, new Last(event.country, event.timestamp, event.ip));
        if (prev != null && !prev.country().equalsIgnoreCase(event.country)
                && event.timestamp - prev.ts() >= 0 && (event.timestamp - prev.ts()) < WINDOW_MS) {
            return new DetectionOutcome("IMPOSSIBLE_LOGIN", 35,
                    "Account '" + event.username + "' logged in from " + event.country + " (" + event.ip + ") "
                            + ((event.timestamp - prev.ts()) / 1000) + "s after a login from " + prev.country()
                            + " (" + prev.ip() + ")");
        }
        return null;
    }
}
