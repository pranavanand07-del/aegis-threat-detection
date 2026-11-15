package com.threatdetection.response;

import com.threatdetection.aegis.intel.IpClassifier;

import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Addresses that must never be blocked automatically: loopback and private (RFC1918 / link-local /
 * CGNAT) ranges, this machine's own addresses, and anything listed in -Daegis.allowlist
 * (comma separated IPs or IPv4 CIDRs). Blocking your own gateway, DNS server or admin PC is the
 * classic way an automatic blocker takes a network down.
 */
public final class Allowlist {
    private record Cidr(long base, long mask) {}

    private final Set<String> exact = Collections.synchronizedSet(new HashSet<>());
    private final List<Cidr> ranges = Collections.synchronizedList(new ArrayList<>());
    private final boolean internalTrusted;

    public Allowlist(boolean internalTrusted, String spec) {
        this.internalTrusted = internalTrusted;
        addLocalInterfaces();
        if (spec != null) for (String part : spec.split(",")) add(part.trim());
    }

    public static Allowlist fromSystemProperties() {
        return new Allowlist(!"false".equalsIgnoreCase(System.getProperty("aegis.allowlist.internal")),
                System.getProperty("aegis.allowlist", ""));
    }

    public boolean add(String entry) {
        if (entry == null || entry.isBlank()) return false;
        int slash = entry.indexOf('/');
        if (slash > 0) {
            long base = IpClassifier.toLong(entry.substring(0, slash));
            int bits;
            try { bits = Integer.parseInt(entry.substring(slash + 1)); } catch (NumberFormatException e) { return false; }
            if (base < 0 || bits < 0 || bits > 32) return false;
            long mask = bits == 0 ? 0 : (0xFFFFFFFFL << (32 - bits)) & 0xFFFFFFFFL;
            ranges.add(new Cidr(base & mask, mask));
            return true;
        }
        if (!IpClassifier.isValid(entry)) return false;
        exact.add(entry);
        return true;
    }

    public boolean remove(String entry) { return exact.remove(entry); }

    public List<String> entries() {
        List<String> out = new ArrayList<>(exact);
        Collections.sort(out);
        return out;
    }

    /** True when this address must not be blocked. Reason is returned by {@link #why}. */
    public boolean isProtected(String ip) { return why(ip) != null; }

    public String why(String ip) {
        if (ip == null || ip.isBlank()) return "no address";
        if (!IpClassifier.isValid(ip)) return "not a valid IP address";
        if (exact.contains(ip)) return "on the allowlist";
        long v = IpClassifier.toLong(ip);
        if (v >= 0) {
            synchronized (ranges) {
                for (Cidr c : ranges) if ((v & c.mask) == c.base) return "inside an allowlisted range";
            }
        }
        if (internalTrusted && IpClassifier.isInternal(ip)) return "internal/private address";
        return null;
    }

    private void addLocalInterfaces() {
        try {
            Enumeration<NetworkInterface> nics = NetworkInterface.getNetworkInterfaces();
            while (nics != null && nics.hasMoreElements()) {
                for (InetAddress a : Collections.list(nics.nextElement().getInetAddresses())) {
                    exact.add(a.getHostAddress().replaceAll("%.*$", ""));
                }
            }
        } catch (Exception ignored) {
            // best effort: the private-range rule still protects the usual cases
        }
    }
}
