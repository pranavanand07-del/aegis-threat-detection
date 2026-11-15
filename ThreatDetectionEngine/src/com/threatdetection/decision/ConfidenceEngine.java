package com.threatdetection.decision;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * How sure are we that this is really an attack? Separate from severity (how bad it would be).
 * A high score built from one weak rule repeated is less trustworthy than the same score from several independent
 * kinds of evidence. Returns a 0..1 value plus the reasons, so a decision can always be explained.
 */
public final class ConfidenceEngine {
    public record Confidence(double value, List<String> reasons) {}

    private static final Set<String> WEAK = Set.of("BOT_DETECTED", "SUSPICIOUS_TIME", "BEHAVIOR_ANOMALY", "ASN_REPUTATION");
    private static final Set<String> INTEL = Set.of("BLACKLISTED_IP", "THREAT_INTEL_MATCH");

    private ConfidenceEngine() {}

    /** @param ruleLines core-format lines ("NAME (+n): detail") or bare rule names */
    public static Confidence assess(List<String> ruleLines, int score, boolean externalAddress) {
        Set<String> strong = new LinkedHashSet<>();
        Set<String> weak = new LinkedHashSet<>();
        boolean intel = false;
        for (String line : ruleLines) {
            String name = name(line);
            if (name.isEmpty() || name.equals("BLOCK_SKIPPED") || name.equals("IP_ALREADY_BLOCKED") || name.equals("OS_FIREWALL")) continue;
            if (INTEL.contains(name)) intel = true;
            else if (WEAK.contains(name)) weak.add(name);
            else strong.add(name);
        }
        List<String> why = new ArrayList<>();
        double c = 0.25;
        why.add("base 0.25");
        int n = Math.min(strong.size(), 3);
        if (n > 0) { c += 0.2 * n; why.add("+" + String.format("%.1f", 0.2 * n) + " for " + strong.size() + " independent rule(s): " + String.join(", ", strong)); }
        if (!weak.isEmpty()) { c += 0.05; why.add("+0.05 weak supporting signal(s): " + String.join(", ", weak)); }
        if (intel) { c += 0.25; why.add("+0.25 address is on a configured blocklist / threat-intel feed"); }
        if (score >= 150) { c += 0.1; why.add("+0.1 score " + score + " is far above the critical line"); }
        if (!externalAddress) { c -= 0.3; why.add("-0.3 internal or unverifiable address"); }
        c = Math.max(0.0, Math.min(0.99, c));
        return new Confidence(c, why);
    }

    private static String name(String line) {
        if (line == null) return "";
        int end = 0;
        while (end < line.length() && !Character.isWhitespace(line.charAt(end)) && line.charAt(end) != ':') end++;
        return line.substring(0, end);
    }
}
