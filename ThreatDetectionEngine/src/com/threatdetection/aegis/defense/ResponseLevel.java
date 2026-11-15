package com.threatdetection.aegis.defense;

import com.threatdetection.model.ThreatLevel;

/** What AEGIS is allowed to do about an alert, by severity. */
public enum ResponseLevel {
    /** SAFE / LOW / MEDIUM: record and watch, take no action. */
    MONITOR,
    /** HIGH: alert the administrator and propose actions; nothing runs until an analyst approves. */
    ANALYST_APPROVAL,
    /** CRITICAL: a reversible, time-limited, policy-approved response may run on its own. */
    AUTO_REVERSIBLE;

    public static ResponseLevel of(ThreatLevel level) {
        return switch (level) {
            case CRITICAL -> AUTO_REVERSIBLE;
            case HIGH -> ANALYST_APPROVAL;
            default -> MONITOR;
        };
    }
}
