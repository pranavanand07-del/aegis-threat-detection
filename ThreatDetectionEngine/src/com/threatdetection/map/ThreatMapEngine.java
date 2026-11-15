package com.threatdetection.map;

import com.threatdetection.engine.ThreatDetectionEngine;
import com.threatdetection.intelligence.ThreatIntelService;
import com.threatdetection.model.LogEvent;
import com.threatdetection.model.ThreatResult;
import com.threatdetection.storage.InMemoryStore;

/**
 * Drop-in replacement for ThreatDetectionEngine that ALSO feeds every result to the
 * threat map. Detection, scoring, classification and auto-blocking are exactly the
 * parent's - this class only observes the result afterwards.
 */
public class ThreatMapEngine extends ThreatDetectionEngine {
    private final ThreatMapService map;

    public ThreatMapEngine(InMemoryStore store, ThreatMapService map) {
        super(store);
        this.map = map;
    }

    public ThreatMapEngine(InMemoryStore store, ThreatMapService map, ThreatIntelService intel) {
        super(store, intel);
        this.map = map;
    }

    @Override
    public ThreatResult process(LogEvent event) {
        ThreatResult result = super.process(event);
        try {
            map.record(event, result);
        } catch (RuntimeException e) {
            // The map is a visualization layer: it must never break detection.
            System.err.println("[ThreatMap] failed to record event: " + e);
        }
        return result;
    }
}
