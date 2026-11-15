package com.threatdetection.model;

import java.util.List;

public class ThreatResult {
    public final String ip;
    public final int riskScore;
    public final ThreatLevel level;
    public final List<String> triggeredRules;
    public final long timestamp;
    public final boolean blocked;
    /** True when this is just a request rejected because the IP was already blocked (not a new detection). */
    public final boolean repeatOfBlock;
    /**
     * What happened at the operating-system firewall, separate from {@link #blocked} (which is the application-level
     * block): NOT_ATTEMPTED, APPLIED, ALREADY_BLOCKED, DRY_RUN, AWAITING_APPROVAL, NO_ACTION, REFUSED, FAILED, DISABLED, NOT_ATTACHED.
     * Only APPLIED and ALREADY_BLOCKED mean a real firewall rule exists.
     */
    public String osFirewall = "NOT_ATTEMPTED";
    public String osFirewallDetail = "";

    /** Application-level block (this process rejects the address). Same value as {@link #blocked}. */
    public boolean appBlocked() { return blocked; }

    /** True only when a real operating-system firewall rule was created or already existed. */
    public boolean osEnforced() { return "APPLIED".equals(osFirewall) || "ALREADY_BLOCKED".equals(osFirewall); }

    public ThreatResult(String ip, int riskScore, ThreatLevel level,
                         List<String> triggeredRules, long timestamp, boolean blocked) {
        this(ip, riskScore, level, triggeredRules, timestamp, blocked, false);
    }

    public ThreatResult(String ip, int riskScore, ThreatLevel level,
                         List<String> triggeredRules, long timestamp, boolean blocked, boolean repeatOfBlock) {
        this.ip = ip;
        this.riskScore = riskScore;
        this.level = level;
        this.triggeredRules = triggeredRules;
        this.timestamp = timestamp;
        this.blocked = blocked;
        this.repeatOfBlock = repeatOfBlock;
    }
}
