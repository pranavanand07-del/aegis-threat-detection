package com.threatdetection.aegis;

import com.threatdetection.engine.ThreatDetectionEngine;
import com.threatdetection.model.LogEvent;
import com.threatdetection.model.ThreatResult;
import com.threatdetection.storage.InMemoryStore;

/**
 * Transparent wrapper: the event is processed by the original engine exactly as before and the
 * identical result is returned. AEGIS only observes the result afterwards (and tags where the
 * event came from), so existing detection, scoring, blocking and the original dashboard/map
 * are untouched.
 */
public class AegisEngine extends ThreatDetectionEngine {
    private final ThreatDetectionEngine delegate;
    private final AegisPipeline pipeline;
    private final DataSource source;

    public AegisEngine(InMemoryStore store, ThreatDetectionEngine delegate, AegisPipeline pipeline, DataSource source) {
        super(store);
        this.delegate = delegate;
        this.pipeline = pipeline;
        this.source = source;
    }

    @Override
    public ThreatResult process(LogEvent event) {
        ThreatResult result = delegate.process(event);
        try {
            pipeline.observe(event, result, source);
        } catch (RuntimeException e) {
            pipeline.store().countError();
            System.err.println("[AEGIS] failed to record event: " + e);
        }
        return result;
    }
}
