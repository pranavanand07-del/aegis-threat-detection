package com.threatdetection.geo;

/**
 * Pluggable IP -> location lookup. The default implementation is fully offline;
 * to use real data, implement this interface on top of a MaxMind GeoLite2 database
 * (or any other provider) and pass it to ThreatMapService in Main.
 */
public interface GeoIpProvider {
    /**
     * @param ip          the source IP address
     * @param countryHint ISO country code already present on the log event, or "UNKNOWN"
     */
    GeoLocation locate(String ip, String countryHint);
}
