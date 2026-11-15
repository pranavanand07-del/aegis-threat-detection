package com.threatdetection.response;

import com.threatdetection.model.ThreatLevel;

/**
 * Chooses a graduated response: MONITOR, ALERT, INVESTIGATE, APPROVE (needs an analyst), or BLOCK.
 * Only BLOCK is automatic at the operating-system firewall, and only when confidence is high enough.
 * Protected addresses (internal, allowlisted) can never reach BLOCK or APPROVE.
 */
public final class ResponsePolicyEngine {
    public enum Action { MONITOR, ALERT, INVESTIGATE, APPROVE, BLOCK }

    public record Decision(Action action, String reason) {}

    private final double autoBlockConfidence;
    private final boolean alwaysApprove;
    private final Allowlist allowlist;

    public ResponsePolicyEngine(Allowlist allowlist, double autoBlockConfidence, boolean alwaysApprove) {
        this.allowlist = allowlist;
        this.autoBlockConfidence = autoBlockConfidence;
        this.alwaysApprove = alwaysApprove;
    }

    /** -Daegis.response.confidence (default 0.7), -Daegis.response.approval=true (analyst must approve every block). */
    public static ResponsePolicyEngine fromSystemProperties(Allowlist allowlist) {
        double c = 0.7;
        try { c = Double.parseDouble(System.getProperty("aegis.response.confidence", "0.7")); } catch (NumberFormatException ignored) { /* keep default */ }
        if (Double.isNaN(c) || c < 0.0 || c > 1.0) c = 0.7;   // a negative value would make every critical event auto-block
        return new ResponsePolicyEngine(allowlist, c, Boolean.getBoolean("aegis.response.approval"));
    }

    public Decision decide(String ip, ThreatLevel level, double confidence) {
        String protectedWhy = allowlist.why(ip);
        if (level.ordinal() <= ThreatLevel.LOW.ordinal()) return new Decision(Action.MONITOR, "low risk");
        if (level == ThreatLevel.MEDIUM) return new Decision(Action.ALERT, "medium risk: alert only");
        if (protectedWhy != null) {
            return new Decision(level == ThreatLevel.CRITICAL ? Action.INVESTIGATE : Action.ALERT,
                    "address is protected (" + protectedWhy + "): never blocked automatically");
        }
        if (level == ThreatLevel.HIGH) return new Decision(Action.INVESTIGATE, "high risk: analyst should look");
        if (alwaysApprove) return new Decision(Action.APPROVE, "policy: every block needs analyst approval");
        if (confidence >= autoBlockConfidence) {
            return new Decision(Action.BLOCK, String.format("critical with confidence %.2f >= %.2f", confidence, autoBlockConfidence));
        }
        return new Decision(Action.APPROVE, String.format("critical but confidence %.2f < %.2f: needs analyst approval", confidence, autoBlockConfidence));
    }
}
