package com.threatdetection.aegis.intel;

import java.net.InetAddress;
import java.util.regex.Pattern;

/** Internal vs external IP identification (private, loopback, link-local, CGNAT, IPv6 ULA). */
public final class IpClassifier {
    private static final Pattern V4 = Pattern.compile("^(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})$");
    private static final Pattern V6 = Pattern.compile("^[0-9a-fA-F:.]+$");

    private IpClassifier() {}

    public static boolean isValid(String ip) {
        if (ip == null) return false;
        var m = V4.matcher(ip);
        if (m.matches()) {
            for (int i = 1; i <= 4; i++) if (Integer.parseInt(m.group(i)) > 255) return false;
            return true;
        }
        return ip.indexOf(':') >= 0 && V6.matcher(ip).matches();
    }

    /** True for addresses that never leave the local network. Invalid/empty input is not internal. */
    public static boolean isInternal(String ip) {
        if (!isValid(ip)) return false;
        try {
            InetAddress a = InetAddress.getByName(ip);   // literal only, never triggers DNS
            if (a.isAnyLocalAddress() || a.isLoopbackAddress() || a.isLinkLocalAddress()
                    || a.isSiteLocalAddress()) return true;
            byte[] b = a.getAddress();
            if (b.length == 4) {
                int b0 = b[0] & 0xFF, b1 = b[1] & 0xFF;
                return b0 == 100 && b1 >= 64 && b1 <= 127;          // 100.64.0.0/10 carrier-grade NAT
            }
            return (b[0] & 0xFE) == 0xFC;                            // fc00::/7 unique local
        } catch (Exception e) {
            return false;
        }
    }

    public static String classify(String ip) {
        if (!isValid(ip)) return "UNKNOWN";
        return isInternal(ip) ? "INTERNAL" : "EXTERNAL";
    }

    /** IPv4 dotted quad to unsigned int in a long, or -1. */
    public static long toLong(String ip) {
        var m = V4.matcher(ip == null ? "" : ip);
        if (!m.matches()) return -1;
        long v = 0;
        for (int i = 1; i <= 4; i++) {
            int o = Integer.parseInt(m.group(i));
            if (o > 255) return -1;
            v = (v << 8) | o;
        }
        return v;
    }
}
