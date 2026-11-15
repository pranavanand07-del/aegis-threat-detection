package com.threatdetection.aegis.geo;

import com.threatdetection.aegis.intel.IpClassifier;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Real GeoIP lookups from a CSV database you supply (IPv4 rows). The header decides the columns, so
 * DB-IP "City Lite", GeoLite2 "City-Blocks" or your own export all work as long as they contain
 * a range (start/end IP, or a CIDR "network") plus latitude and longitude:
 *   start: ip_start | start_ip | network_start_ip      end: ip_end | end_ip | network_end_ip
 *   cidr:  network | cidr                               lat/lon: latitude|lat, longitude|lon|lng
 *   optional: country | country_code | country_iso_code, region | stateprov, city | city_name
 * Enable with -Daegis.geo.csv=/path/to/file.csv. The result is still an estimate (city level at best).
 */
public final class CsvGeoIpProvider {
    public static final class Hit {
        public final String cc, region, city;
        public final double lat, lon;

        Hit(String cc, String region, String city, double lat, double lon) {
            this.cc = cc;
            this.region = region;
            this.city = city;
            this.lat = lat;
            this.lon = lon;
        }
    }

    private long[] starts = new long[0];
    private long[] ends = new long[0];
    private float[] lats = new float[0];
    private float[] lons = new float[0];
    private String[] ccs = new String[0];
    private String[] regions = new String[0];
    private String[] cities = new String[0];

    public int size() { return starts.length; }

    public static CsvGeoIpProvider load(Path file) throws IOException {
        CsvGeoIpProvider p = new CsvGeoIpProvider();
        List<long[]> ranges = new ArrayList<>();
        List<Object[]> info = new ArrayList<>();
        Map<String, String> intern = new HashMap<>();
        try (BufferedReader r = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
            String header = r.readLine();
            if (header == null) return p;
            String[] h = split(header);
            int iStart = idx(h, "ip_start", "start_ip", "network_start_ip", "start");
            int iEnd = idx(h, "ip_end", "end_ip", "network_end_ip", "end");
            int iCidr = idx(h, "network", "cidr");
            int iLat = idx(h, "latitude", "lat");
            int iLon = idx(h, "longitude", "lon", "lng");
            int iCc = idx(h, "country_iso_code", "country_code", "country");
            int iReg = idx(h, "subdivision_1_name", "stateprov", "region", "state");
            int iCity = idx(h, "city_name", "city");
            if (iLat < 0 || iLon < 0 || (iCidr < 0 && (iStart < 0 || iEnd < 0))) {
                throw new IOException("GeoIP CSV needs lat/lon plus start+end IP or a CIDR column; header was: " + header);
            }
            String line;
            while ((line = r.readLine()) != null) {
                String[] c = split(line);
                try {
                    long a, b;
                    if (iStart >= 0 && iEnd >= 0 && iStart < c.length && iEnd < c.length) {
                        a = IpClassifier.toLong(c[iStart]);
                        b = IpClassifier.toLong(c[iEnd]);
                    } else {
                        String cidr = c[iCidr];
                        int slash = cidr.indexOf('/');
                        if (slash < 0) continue;
                        long base = IpClassifier.toLong(cidr.substring(0, slash));
                        int bits = Integer.parseInt(cidr.substring(slash + 1));
                        if (base < 0 || bits < 0 || bits > 32) continue;
                        long size = 1L << (32 - bits);
                        a = base & ~(size - 1);
                        b = a + size - 1;
                    }
                    if (a < 0 || b < a) continue;
                    double lat = Double.parseDouble(c[iLat]);
                    double lon = Double.parseDouble(c[iLon]);
                    ranges.add(new long[]{a, b});
                    info.add(new Object[]{lat, lon,
                            intern.computeIfAbsent(get(c, iCc), k -> k),
                            intern.computeIfAbsent(get(c, iReg), k -> k),
                            intern.computeIfAbsent(get(c, iCity), k -> k)});
                } catch (RuntimeException ignored) {
                    // skip IPv6 / malformed rows
                }
            }
        }
        int n = ranges.size();
        Integer[] order = new Integer[n];
        for (int i = 0; i < n; i++) order[i] = i;
        Arrays.sort(order, (x, y) -> Long.compare(ranges.get(x)[0], ranges.get(y)[0]));
        p.starts = new long[n]; p.ends = new long[n]; p.lats = new float[n]; p.lons = new float[n];
        p.ccs = new String[n]; p.regions = new String[n]; p.cities = new String[n];
        for (int k = 0; k < n; k++) {
            int i = order[k];
            p.starts[k] = ranges.get(i)[0];
            p.ends[k] = ranges.get(i)[1];
            Object[] o = info.get(i);
            p.lats[k] = (float) (double) (Double) o[0];
            p.lons[k] = (float) (double) (Double) o[1];
            p.ccs[k] = (String) o[2];
            p.regions[k] = (String) o[3];
            p.cities[k] = (String) o[4];
        }
        return p;
    }

    public Hit lookup(String ip) {
        long v = IpClassifier.toLong(ip);
        if (v < 0 || starts.length == 0) return null;
        int lo = 0, hi = starts.length - 1, found = -1;
        while (lo <= hi) {
            int mid = (lo + hi) >>> 1;
            if (starts[mid] <= v) { found = mid; lo = mid + 1; } else hi = mid - 1;
        }
        if (found < 0 || v > ends[found]) return null;
        return new Hit(ccs[found], regions[found], cities[found], lats[found], lons[found]);
    }

    private static String get(String[] c, int i) {
        return i >= 0 && i < c.length ? c[i] : "";
    }

    private static int idx(String[] h, String... names) {
        for (String n : names) {
            for (int i = 0; i < h.length; i++) {
                if (h[i].trim().toLowerCase(Locale.ROOT).equals(n)) return i;
            }
        }
        return -1;
    }

    /** Minimal CSV splitter with quote support. */
    static String[] split(String line) {
        List<String> out = new ArrayList<>();
        StringBuilder cur = new StringBuilder();
        boolean q = false;
        for (int i = 0; i < line.length(); i++) {
            char ch = line.charAt(i);
            if (ch == '"') {
                if (q && i + 1 < line.length() && line.charAt(i + 1) == '"') { cur.append('"'); i++; }
                else q = !q;
            } else if (ch == ',' && !q) {
                out.add(cur.toString());
                cur.setLength(0);
            } else {
                cur.append(ch);
            }
        }
        out.add(cur.toString());
        return out.toArray(new String[0]);
    }
}
