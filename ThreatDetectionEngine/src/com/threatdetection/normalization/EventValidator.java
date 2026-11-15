package com.threatdetection.normalization;

import com.threatdetection.aegis.AegisSignal;
import com.threatdetection.aegis.intel.IpClassifier;

import java.util.ArrayList;
import java.util.List;

/** Reports what is wrong with a signal without changing it. {@link EventNormalizer} repairs what can be repaired. */
public final class EventValidator {
    public static final long MIN_TS = 946_684_800_000L;          // 2000-01-01
    public static final long FUTURE_SLACK_MS = 5 * 60 * 1000L;

    private EventValidator() {}

    public static List<String> issues(AegisSignal s, long now) {
        List<String> out = new ArrayList<>();
        if (s.ts > 0 && s.ts < MIN_TS) out.add("timestamp before year 2000");
        if (s.ts > now + FUTURE_SLACK_MS) out.add("timestamp more than 5 minutes in the future");
        if (s.port < 0 || s.port > 65535) out.add("port out of range");
        if (s.ip != null && !s.ip.isEmpty() && !IpClassifier.isValid(s.ip)) out.add("invalid source address");
        boolean needsIp = s.kind == AegisSignal.Kind.WEB || s.kind == AegisSignal.Kind.NETWORK || s.kind == AegisSignal.Kind.AUTH;
        if (needsIp && (s.ip == null || s.ip.isEmpty())) out.add("no source address");
        if (hasControl(s.user) || hasControl(s.host) || hasControl(s.path)) out.add("control characters in a text field");
        return out;
    }

    static boolean hasControl(String v) {
        if (v == null) return false;
        for (int i = 0; i < v.length(); i++) if (v.charAt(i) < 0x20 || v.charAt(i) == 0x7f) return true;
        return false;
    }
}
