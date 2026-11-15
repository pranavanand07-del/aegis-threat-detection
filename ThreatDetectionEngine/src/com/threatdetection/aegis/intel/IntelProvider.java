package com.threatdetection.aegis.intel;

/** One optional external intelligence source. Implementations throw on network problems; the service turns that into a status. */
public interface IntelProvider {
    String name();

    boolean configured();

    /** Daily request budget the service enforces (free tiers are small). */
    int dailyLimit();

    /** Minimum gap between two requests in ms (free tiers throttle hard). */
    long minIntervalMs();

    Enrichment lookupIp(String ip) throws Exception;
}
