package com.threatdetection.detector;

import com.threatdetection.model.DetectionOutcome;
import com.threatdetection.model.LogEvent;
import com.threatdetection.tracking.IpActivityTracker;

/**
 * Every threat rule implements this. Returns null when the event does not
 * trip the rule, or a DetectionOutcome (score + reason) when it does.
 */
public interface Detector {
    DetectionOutcome evaluate(LogEvent event, IpActivityTracker tracker);
}
