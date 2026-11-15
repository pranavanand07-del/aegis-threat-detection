package com.threatdetection.aegis;

import com.threatdetection.model.DetectionOutcome;

/**
 * An AEGIS detection rule. Rules run in ADDITION to the 11 core detectors and never change
 * the core engine's score, level or auto-blocking: their findings are added on top in the
 * AEGIS layer, with their own names so the alert explanation shows where each point came from.
 */
public interface AegisRule {
    /** @return null when the signal does not trip the rule. */
    DetectionOutcome evaluate(AegisSignal signal);
}
