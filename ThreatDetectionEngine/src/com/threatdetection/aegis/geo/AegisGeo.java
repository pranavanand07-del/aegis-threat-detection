package com.threatdetection.aegis.geo;

import com.threatdetection.aegis.DataSource;
import com.threatdetection.aegis.intel.IpClassifier;
import com.threatdetection.geo.GeoIpProvider;
import com.threatdetection.geo.GeoLocation;

/**
 * Decides how an event may be located and, crucially, how trustworthy that location is:
 *  ESTIMATED   - found in a real GeoIP database you loaded (city-level at best)
 *  SIMULATED   - demo location for simulator traffic only (not real)
 *  INTERNAL    - private address; shown as the protected network, not on the world map
 *  UNAVAILABLE - no reliable source, so the event is listed but NOT plotted
 * The offline demo table of the original threat map is never used to place real traffic.
 */
public final class AegisGeo {
    public static final class Result {
        public final String geoClass, source, cc, country, city;
        public final double lat, lon;

        Result(String geoClass, String source, String cc, String country, String city, double lat, double lon) {
            this.geoClass = geoClass;
            this.source = source;
            this.cc = cc;
            this.country = country;
            this.city = city;
            this.lat = lat;
            this.lon = lon;
        }
    }

    private final CsvGeoIpProvider db;          // may be null
    private final GeoIpProvider demo;
    private final GeoLocation target;

    public AegisGeo(CsvGeoIpProvider db, GeoIpProvider demo, GeoLocation target) {
        this.db = db;
        this.demo = demo;
        this.target = target;
    }

    public boolean hasDatabase() { return db != null && db.size() > 0; }

    public int databaseRows() { return db == null ? 0 : db.size(); }

    public GeoLocation target() { return target; }

    public Result resolve(String ip, String countryHint, DataSource source) {
        if (ip == null || ip.isEmpty()) {
            return new Result("UNAVAILABLE", "host-local event", "", "", "", 0, 0);
        }
        if (IpClassifier.isInternal(ip)) {
            return new Result("INTERNAL", "private address", target.countryCode, target.country,
                    "Internal network", target.lat, target.lon);
        }
        if (db != null) {
            CsvGeoIpProvider.Hit h = db.lookup(ip);
            if (h != null) {
                return new Result("ESTIMATED", "GeoIP database", h.cc, h.cc, h.city.isEmpty() ? h.region : h.city, h.lat, h.lon);
            }
        }
        if (source == DataSource.SIMULATED) {
            GeoLocation g = demo.locate(ip, countryHint);
            return new Result("SIMULATED", "demo location (" + g.source + ")", g.countryCode, g.country, g.city, g.lat, g.lon);
        }
        return new Result("UNAVAILABLE", db == null ? "no GeoIP database loaded (-Daegis.geo.csv)" : "not in GeoIP database",
                "", "", "", 0, 0);
    }
}
