package com.threatdetection.engine;

import com.threatdetection.model.ThreatLevel;

/** Converts a raw risk score into a human-meaningful threat level. */
public class ThreatClassifier {
    public ThreatLevel classify(int score) {
        if (score <= 20) return ThreatLevel.SAFE;
        if (score <= 50) return ThreatLevel.LOW;
        if (score <= 80) return ThreatLevel.MEDIUM;
        if (score <= 100) return ThreatLevel.HIGH;
        return ThreatLevel.CRITICAL;
    }
}
