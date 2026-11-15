package com.threatdetection.aegis.rules;

import com.threatdetection.aegis.AegisRule;
import com.threatdetection.aegis.AegisSignal;
import com.threatdetection.model.DetectionOutcome;

/**
 * Turns a Wazuh alert level (0-15) into AEGIS points. Deliberately modest: Wazuh already did the
 * detection, and one product's opinion alone must not be enough for an automatic response
 * (a single rule can never satisfy the defense layer's "two distinct rules" requirement).
 */
public class WazuhRule implements AegisRule {
    @Override
    public DetectionOutcome evaluate(AegisSignal s) {
        if (s.kind != AegisSignal.Kind.EXTERNAL) return null;
        int pts = s.extLevel >= 12 ? 55 : s.extLevel >= 10 ? 40 : s.extLevel >= 7 ? 25 : s.extLevel >= 4 ? 10 : 0;
        if (pts == 0) return null;
        return new DetectionOutcome("WAZUH_ALERT", pts, "Wazuh rule " + s.extId + " level " + s.extLevel + ": " + s.extDesc
                + (s.host.isEmpty() ? "" : " (agent " + s.host + ")"));
    }
}
