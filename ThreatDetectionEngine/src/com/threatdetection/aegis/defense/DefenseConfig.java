package com.threatdetection.aegis.defense;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * All settings are JVM system properties and all are optional. Safe defaults: DRY_RUN, 15 minute
 * temporary actions (hard cap 24 h), only firewall/session/rate-limit may run automatically,
 * account locking and file quarantine always wait for an analyst unless you opt in.
 */
public final class DefenseConfig {
    public static final long MAX_TTL_MS = 24L * 3600 * 1000;

    public DefenseMode mode = DefenseMode.DRY_RUN;
    public long ttlMs = 15L * 60 * 1000;
    public long approvalWindowMs = 60L * 60 * 1000;
    /** Action types that may run without an analyst when the alert is CRITICAL and corroborated. */
    public Set<DefenseAction.Type> auto = EnumSet.of(DefenseAction.Type.FIREWALL_BLOCK,
            DefenseAction.Type.REVOKE_SESSION, DefenseAction.Type.RATE_LIMIT);
    /** A heuristic score alone is not enough: an automatic response needs this many distinct rules (or a threat-intel hit). */
    public int minRules = 2;
    public int maxActiveBlocks = 100;
    public int maxAutoPerMinute = 10;
    public int rateLimitMax = 30;
    public long rateLimitWindowMs = 60_000L;
    public Path dataDir = Path.of("aegis-data");
    public Path quarantineDir = Path.of("aegis-data", "quarantine");
    public List<Path> quarantineRoots = new ArrayList<>();
    public Set<String> protectedAccounts = new HashSet<>(Set.of("administrator", "system", "root", "guest",
            "local service", "network service", "defaultaccount"));
    public String webhook = "";
    public boolean firewallEnabled = true;

    public static DefenseConfig fromSystemProperties() {
        DefenseConfig c = new DefenseConfig();
        String mode = System.getProperty("aegis.defense.mode", "dryrun").toLowerCase(Locale.ROOT).replace("-", "").replace("_", "");
        c.mode = switch (mode) {
            case "off", "false", "disabled" -> DefenseMode.OFF;
            case "enforce", "on", "true" -> DefenseMode.ENFORCE;
            default -> DefenseMode.DRY_RUN;
        };
        c.ttlMs = Math.min(MAX_TTL_MS, Math.max(60_000L, Long.getLong("aegis.defense.ttl.minutes", 15L) * 60_000L));
        c.approvalWindowMs = Math.max(60_000L, Long.getLong("aegis.defense.approval.minutes", 60L) * 60_000L);
        c.minRules = Math.max(1, Integer.getInteger("aegis.defense.minRules", 2));
        c.maxActiveBlocks = Math.max(1, Integer.getInteger("aegis.defense.maxBlocks", 100));
        c.maxAutoPerMinute = Math.max(1, Integer.getInteger("aegis.defense.maxAutoPerMinute", 10));
        c.rateLimitMax = Math.max(1, Integer.getInteger("aegis.defense.ratelimit.max", 30));
        c.rateLimitWindowMs = Math.max(1000L, Long.getLong("aegis.defense.ratelimit.windowSeconds", 60L) * 1000L);
        c.dataDir = Path.of(System.getProperty("aegis.data.dir", "aegis-data"));
        c.quarantineDir = Path.of(System.getProperty("aegis.defense.quarantine.dir", c.dataDir.resolve("quarantine").toString()));
        for (String r : System.getProperty("aegis.defense.quarantine.roots", "").split(",")) {
            if (!r.isBlank()) c.quarantineRoots.add(Path.of(r.trim()));
        }
        for (String a : System.getProperty("aegis.defense.protected.accounts", "").split(",")) {
            if (!a.isBlank()) c.protectedAccounts.add(a.trim().toLowerCase(Locale.ROOT));
        }
        String me = System.getProperty("user.name", "");
        if (!me.isBlank()) c.protectedAccounts.add(me.toLowerCase(Locale.ROOT));
        c.webhook = System.getProperty("aegis.defense.webhook", "").trim();
        c.firewallEnabled = !"false".equalsIgnoreCase(System.getProperty("aegis.defense.firewall"));
        String auto = System.getProperty("aegis.defense.auto");
        if (auto != null) {
            c.auto = EnumSet.noneOf(DefenseAction.Type.class);
            for (String a : auto.split(",")) {
                switch (a.trim().toLowerCase(Locale.ROOT)) {
                    case "firewall" -> c.auto.add(DefenseAction.Type.FIREWALL_BLOCK);
                    case "session" -> c.auto.add(DefenseAction.Type.REVOKE_SESSION);
                    case "rate", "ratelimit" -> c.auto.add(DefenseAction.Type.RATE_LIMIT);
                    case "lock", "account" -> c.auto.add(DefenseAction.Type.LOCK_ACCOUNT);
                    case "quarantine" -> c.auto.add(DefenseAction.Type.QUARANTINE_FILE);
                    default -> { }
                }
            }
        }
        return c;
    }
}
