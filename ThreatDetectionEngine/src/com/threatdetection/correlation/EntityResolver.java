package com.threatdetection.correlation;

import com.threatdetection.aegis.AegisSignal;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/** Decides which entities an event belongs to, so evidence from different sources lands on the same actor/asset. */
public final class EntityResolver {
    private static final Set<String> GENERIC_USERS = Set.of("", "unknown", "guest", "-", "anonymous", "system", "local service", "network service");

    private EntityResolver() {}

    /** Keys look like ip:203.0.113.5, host:SRV01, user:administrator. */
    public static List<String> keys(AegisSignal s) {
        List<String> k = new ArrayList<>(3);
        if (s.ip != null && !s.ip.isEmpty()) k.add("ip:" + s.ip);
        if (s.host != null && !s.host.isEmpty()) k.add("host:" + s.host.toLowerCase());
        if (s.user != null && !GENERIC_USERS.contains(s.user.toLowerCase())
                && (s.kind == AegisSignal.Kind.AUTH || s.kind == AegisSignal.Kind.AUDIT || s.kind == AegisSignal.Kind.PROCESS)) {
            k.add("user:" + s.user.toLowerCase());
        }
        return k;
    }

    public static boolean isAccount(String s) { return s != null && !GENERIC_USERS.contains(s.toLowerCase()); }
}
