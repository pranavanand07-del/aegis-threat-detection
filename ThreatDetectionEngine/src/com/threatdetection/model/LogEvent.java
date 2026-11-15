package com.threatdetection.model;

import java.time.Instant;

public class LogEvent {
    public final String ip;
    public final String username;
    public final String endpoint;
    public final String userAgent;
    public final String requestBody;
    public final String country;
    public final EventType eventType;
    public final int port;
    public final String fileName;
    public final long timestamp;
    /** Optional: session / logon id (lets correlation link several IPs to one session). */
    public final String session;
    /** Optional: the host or asset the event relates to. */
    public final String host;

    public LogEvent(String ip, String username, String endpoint, String userAgent,
                     String requestBody, String country, EventType eventType,
                     int port, String fileName) {
        this(ip, username, endpoint, userAgent, requestBody, country, eventType, port, fileName,
                0L, null, null);
    }

    /**
     * Full constructor. {@code timestamp <= 0} means "now". Passing the log line's own time matters
     * when replaying old logs: detection windows must follow the time the event happened, not the
     * time we happened to read it.
     */
    public LogEvent(String ip, String username, String endpoint, String userAgent,
                     String requestBody, String country, EventType eventType,
                     int port, String fileName, long timestamp, String session, String host) {
        this.ip = ip;
        this.username = username == null ? "unknown" : username;
        this.endpoint = endpoint == null ? "/" : endpoint;
        this.userAgent = userAgent == null ? "" : userAgent;
        this.requestBody = requestBody == null ? "" : requestBody;
        this.country = country == null ? "UNKNOWN" : country;
        this.eventType = eventType;
        this.port = port;
        this.fileName = fileName == null ? "" : fileName;
        this.timestamp = timestamp > 0 ? timestamp : Instant.now().toEpochMilli();
        this.session = session == null ? "" : session;
        this.host = host == null ? "" : host;
    }
}
