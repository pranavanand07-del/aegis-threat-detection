package com.threatdetection.geo;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Zero-dependency, offline geolocation for demos (works without internet).
 *
 * Resolution order:
 *   1. private/loopback address        -> the protected network (map target)
 *   2. exact entry in the demo table   -> stable, hand-picked location
 *   3. country code on the log event   -> a city in that country (stable per IP)
 *   4. anything else                   -> a stable pseudo-random city (demo estimate)
 *
 * It is a DEMO database, not real geolocation data. Swap in a real provider
 * (see GeoIpProvider) for production use.
 */
public class OfflineGeoIpProvider implements GeoIpProvider {

    private static final class City {
        final String cc, country, region, city;
        final double lat, lon;
        City(String cc, String country, String region, String city, double lat, double lon) {
            this.cc = cc; this.country = country; this.region = region; this.city = city;
            this.lat = lat; this.lon = lon;
        }
    }

    private final Map<String, List<City>> byCountry = new HashMap<>();
    private final List<City> all = new ArrayList<>();
    private final Map<String, City> exact = new HashMap<>();
    private final GeoLocation target;

    /** @param target location of the protected server; internal IPs resolve here. */
    public OfflineGeoIpProvider(GeoLocation target) {
        this.target = target;
        loadCatalog();
        // Demo IPs used by the project's simulator / README so they keep a stable position.
        exact.put("66.77.88.99",     find("RU", "Moscow"));
        exact.put("203.0.113.5",     find("CN", "Beijing"));
        exact.put("1.2.3.4",         find("NL", "Amsterdam"));
        exact.put("45.33.32.156",    find("US", "San Francisco"));
        exact.put("185.220.101.1",   find("DE", "Berlin"));
    }

    private void add(String cc, String country, String region, String city, double lat, double lon) {
        City c = new City(cc, country, region, city, lat, lon);
        byCountry.computeIfAbsent(cc, k -> new ArrayList<>()).add(c);
        all.add(c);
    }

    private City find(String cc, String cityName) {
        for (City c : byCountry.get(cc)) if (c.city.equals(cityName)) return c;
        throw new IllegalStateException("catalog missing " + cityName);
    }

    private void loadCatalog() {
        // India (with states, for the India threat map)
        add("IN","India","Maharashtra","Mumbai",19.076,72.878);
        add("IN","India","Delhi","New Delhi",28.614,77.209);
        add("IN","India","Karnataka","Bengaluru",12.972,77.594);
        add("IN","India","Tamil Nadu","Chennai",13.083,80.271);
        add("IN","India","Telangana","Hyderabad",17.385,78.487);
        add("IN","India","West Bengal","Kolkata",22.573,88.364);
        add("IN","India","Gujarat","Ahmedabad",23.023,72.572);
        add("IN","India","Maharashtra","Pune",18.520,73.857);
        add("IN","India","Rajasthan","Jaipur",26.912,75.787);
        add("IN","India","Uttar Pradesh","Lucknow",26.847,80.947);
        add("IN","India","Kerala","Kochi",9.931,76.267);
        add("IN","India","Madhya Pradesh","Bhopal",23.260,77.413);
        add("IN","India","Bihar","Patna",25.594,85.137);
        add("IN","India","Assam","Guwahati",26.144,91.736);
        add("IN","India","Punjab","Chandigarh",30.733,76.779);
        // Rest of world
        add("RU","Russia","","Moscow",55.756,37.617);
        add("RU","Russia","","Saint Petersburg",59.934,30.336);
        add("RU","Russia","","Novosibirsk",55.030,82.920);
        add("CN","China","","Beijing",39.904,116.407);
        add("CN","China","","Shanghai",31.230,121.474);
        add("CN","China","","Shenzhen",22.543,114.058);
        add("CN","China","","Chengdu",30.572,104.066);
        add("US","United States","","Ashburn",39.044,-77.487);
        add("US","United States","","New York",40.713,-74.006);
        add("US","United States","","San Francisco",37.775,-122.419);
        add("US","United States","","Dallas",32.777,-96.797);
        add("US","United States","","Chicago",41.878,-87.630);
        add("DE","Germany","","Frankfurt",50.110,8.680);
        add("DE","Germany","","Berlin",52.520,13.405);
        add("GB","United Kingdom","","London",51.507,-0.128);
        add("FR","France","","Paris",48.857,2.352);
        add("NL","Netherlands","","Amsterdam",52.370,4.900);
        add("UA","Ukraine","","Kyiv",50.450,30.520);
        add("IR","Iran","","Tehran",35.689,51.389);
        add("KP","North Korea","","Pyongyang",39.039,125.763);
        add("KR","South Korea","","Seoul",37.566,126.978);
        add("JP","Japan","","Tokyo",35.676,139.650);
        add("SG","Singapore","","Singapore",1.352,103.820);
        add("AU","Australia","","Sydney",-33.869,151.209);
        add("BR","Brazil","","Sao Paulo",-23.550,-46.633);
        add("ZA","South Africa","","Johannesburg",-26.204,28.047);
        add("NG","Nigeria","","Lagos",6.524,3.379);
        add("TR","Turkey","","Istanbul",41.008,28.978);
        add("VN","Vietnam","","Hanoi",21.028,105.854);
        add("PK","Pakistan","","Karachi",24.861,67.010);
        add("ID","Indonesia","","Jakarta",-6.200,106.816);
        add("EG","Egypt","","Cairo",30.044,31.236);
        add("CA","Canada","","Toronto",43.653,-79.383);
        add("MX","Mexico","","Mexico City",19.433,-99.133);
        add("AE","United Arab Emirates","","Dubai",25.205,55.271);
        add("RO","Romania","","Bucharest",44.430,26.100);
        add("PL","Poland","","Warsaw",52.230,21.010);
        add("SE","Sweden","","Stockholm",59.330,18.070);
        add("BD","Bangladesh","","Dhaka",23.810,90.410);
    }

    @Override
    public GeoLocation locate(String ip, String countryHint) {
        if (ip == null) ip = "";
        if (isInternal(ip)) {
            return new GeoLocation(target.countryCode, target.country, target.region, "Internal network",
                    target.lat, target.lon, true, "internal");
        }
        City c = exact.get(ip);
        if (c != null) {
            return new GeoLocation(c.cc, c.country, c.region, c.city, c.lat, c.lon, false, "demo-table");
        }
        int h = mix(ip.hashCode());
        String hint = countryHint == null ? "" : countryHint.trim().toUpperCase();
        List<City> pool = byCountry.get(hint);
        String source = "country-hint";
        if (pool == null) {
            pool = all;
            source = "demo-estimate";
        }
        c = pool.get(Math.floorMod(h, pool.size()));
        // small deterministic jitter so many IPs in one city don't sit on exactly the same pixel
        double jLat = (((h >>> 8) & 0xFF) / 255.0 - 0.5) * 0.8;
        double jLon = (((h >>> 16) & 0xFF) / 255.0 - 0.5) * 0.8;
        return new GeoLocation(c.cc, c.country, c.region, c.city, c.lat + jLat, c.lon + jLon, false, source);
    }

    private static int mix(int h) {
        h ^= (h >>> 16);
        h *= 0x45d9f3b;
        h ^= (h >>> 16);
        h *= 0x45d9f3b;
        h ^= (h >>> 16);
        return h;
    }

    /** RFC1918 private ranges, loopback, link-local and the unspecified address. */
    static boolean isInternal(String ip) {
        String[] p = ip.split("\\.");
        if (p.length != 4) return false;
        int a, b;
        try {
            a = Integer.parseInt(p[0]);
            b = Integer.parseInt(p[1]);
        } catch (NumberFormatException e) {
            return false;
        }
        return a == 10
                || a == 127
                || (a == 192 && b == 168)
                || (a == 172 && b >= 16 && b <= 31)
                || (a == 169 && b == 254)
                || (a == 0 && b == 0);
    }
}
