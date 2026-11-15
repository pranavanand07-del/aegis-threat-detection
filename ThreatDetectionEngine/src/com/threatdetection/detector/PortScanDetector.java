package com.threatdetection.detector;

import com.threatdetection.model.DetectionOutcome;
import com.threatdetection.model.EventType;
import com.threatdetection.model.LogEvent;
import com.threatdetection.tracking.IpActivityTracker;

/** Flags an IP probing many distinct ports in a short time. */
public class PortScanDetector implements Detector {
    private static final int PORT_THRESHOLD = 5;

    @Override
    public DetectionOutcome evaluate(LogEvent event, IpActivityTracker tracker) {
        if (event.eventType != EventType.PORT_ACCESS) {
            return null;
        }
        tracker.recordPortAccess(event.port, event.timestamp);
        int distinctPorts = tracker.distinctPortsInLastMinute(event.timestamp);
        if (distinctPorts >= PORT_THRESHOLD) {
            return new DetectionOutcome("PORT_SCAN", 25,
                    distinctPorts + " distinct ports probed within 1 minute");
        }
        return null;
    }
}
