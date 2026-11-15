package com.threatdetection.detector;

import com.threatdetection.intelligence.ThreatIntelService;
import com.threatdetection.model.DetectionOutcome;
import com.threatdetection.model.LogEvent;
import com.threatdetection.tracking.IpActivityTracker;

import java.util.Set;

/** Flags any IP listed in the configured {@link ThreatIntelService} (blocklist files / runtime entries). */
public class BlacklistDetector implements Detector {
    private final ThreatIntelService intel;

    public BlacklistDetector(ThreatIntelService intel) {
        this.intel = intel;
    }

    /** Kept for callers that still pass a fixed set; it is labelled as a caller-supplied list. */
    public BlacklistDetector(Set<String> blacklistedIps) {
        this(ThreatIntelService.ofExact(blacklistedIps, "caller-supplied list"));
    }

    @Override
    public DetectionOutcome evaluate(LogEvent event, IpActivityTracker tracker) {
        ThreatIntelService.Match m = intel.lookup(event.ip);
        if (m != null) return new DetectionOutcome("BLACKLISTED_IP", 50, m.describe());
        return null;
    }
}
