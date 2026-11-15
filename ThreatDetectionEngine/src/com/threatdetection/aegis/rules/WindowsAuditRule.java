package com.threatdetection.aegis.rules;

import com.threatdetection.aegis.AegisRule;
import com.threatdetection.aegis.AegisSignal;
import com.threatdetection.aegis.intel.IpClassifier;
import com.threatdetection.model.DetectionOutcome;

/** Windows Security log events that matter on their own (core brute-force logic still counts 4625s). */
public class WindowsAuditRule implements AegisRule {
    @Override
    public DetectionOutcome evaluate(AegisSignal s) {
        switch (s.winEventId) {
            case 4740:
                return new DetectionOutcome("ACCOUNT_LOCKOUT", 40,
                        "Account '" + s.user + "' was locked out (Event 4740)");
            case 1102:
                return new DetectionOutcome("AUDIT_LOG_CLEARED", 60,
                        "Security audit log was cleared by '" + s.user + "' (Event 1102) - common attacker cleanup");
            case 4720:
                return new DetectionOutcome("ACCOUNT_CREATED", 30,
                        "New local/domain account '" + s.path + "' created (Event 4720)");
            case 4728, 4732, 4756: {
                String group = s.path.toLowerCase();
                boolean priv = group.contains("admin");
                return new DetectionOutcome("GROUP_MEMBERSHIP_CHANGE", priv ? 45 : 25,
                        "Member added to " + (priv ? "privileged " : "") + "group '" + s.path + "' (Event " + s.winEventId + ")");
            }
            case 4625:
                if (s.logonType == 10) {
                    return new DetectionOutcome("RDP_FAILED_LOGON", 10,
                            "Failed Remote Desktop logon for '" + s.user + "'");
                }
                return null;
            case 4624:
                if (s.logonType == 10 && !s.ip.isEmpty() && !IpClassifier.isInternal(s.ip)) {
                    return new DetectionOutcome("EXTERNAL_RDP_LOGON", 25,
                            "Successful Remote Desktop logon from external address " + s.ip);
                }
                return null;
            default:
                return null;
        }
    }
}
