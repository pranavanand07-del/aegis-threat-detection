package com.threatdetection.aegis;

/**
 * Where an event came from. The dashboard and map always show this, so real telemetry is
 * never confused with demo traffic.
 */
public enum DataSource {
    OBSERVED("Observed", "Read from a real log source (log file or Windows event log)"),
    API("API", "Submitted over HTTP (/api/event or /aegis/api/ingest) - not independently verified"),
    SIMULATED("Simulated", "Produced by the built-in traffic simulators");

    public final String label;
    public final String description;

    DataSource(String label, String description) {
        this.label = label;
        this.description = description;
    }
}
