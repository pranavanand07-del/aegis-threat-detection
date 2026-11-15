package com.threatdetection.geo;

/**
 * Approximate location of an IP address.
 * NOTE: IP geolocation is never exact - it points to a city/region level at best
 * (often the ISP's hub), so the UI always labels it "approximate".
 */
public class GeoLocation {
    public final String countryCode;   // ISO-3166 alpha-2, e.g. "IN"
    public final String country;
    public final String region;        // state / province (used for the India state view)
    public final String city;
    public final double lat;
    public final double lon;
    public final boolean internal;     // true for private / loopback addresses
    public final String source;        // "demo-table" | "country-hint" | "demo-estimate" | "internal"

    public GeoLocation(String countryCode, String country, String region, String city,
                       double lat, double lon, boolean internal, String source) {
        this.countryCode = countryCode;
        this.country = country;
        this.region = region;
        this.city = city;
        this.lat = lat;
        this.lon = lon;
        this.internal = internal;
        this.source = source;
    }
}
