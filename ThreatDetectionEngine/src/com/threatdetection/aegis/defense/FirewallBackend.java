package com.threatdetection.aegis.defense;

import com.threatdetection.aegis.intel.IpClassifier;
import com.threatdetection.response.WindowsFirewallAdapter;

import java.util.List;
import java.util.Locale;
import java.util.function.Supplier;

/**
 * The Defense layer's door to the operating-system firewall. It no longer runs netsh itself: every block and unblock is
 * handed to the ONE shared {@link WindowsFirewallAdapter}, so there is a single rule registry, a single naming scheme
 * (AEGIS-BLOCK-&lt;ip&gt;-IN), one allowlist, one rule cap, one audit trail and one switch for real enforcement
 * (-Daegis.fw.response). Defense's own mode (-Daegis.defense.mode) still decides whether an action is attempted at all.
 *
 * Honest reporting: if the shared adapter is not actually enforcing (dry-run, off, not Windows, not elevated) a block is
 * reported as FAILED with the reason, never as applied.
 */
public class FirewallBackend {
    public static final String PREFIX = WindowsFirewallAdapter.RULE_PREFIX;

    private volatile Supplier<WindowsFirewallAdapter> adapter = () -> null;
    private volatile long defaultTtlMs = 10 * 60 * 1000L;

    /** Late binding: the adapter is created after the Defense layer, so it is looked up when first needed. */
    public void bind(Supplier<WindowsFirewallAdapter> supplier) { this.adapter = supplier == null ? () -> null : supplier; }

    /** Lifetime of rules created through this backend (the Defense layer's configured TTL). */
    public void setDefaultTtlMs(long ms) { this.defaultTtlMs = ms; }

    public static boolean windows() { return WindowsFirewallAdapter.isWindows(); }

    static String ruleName(String ip) { return WindowsFirewallAdapter.ruleName(ip, "in"); }

    private static boolean safeIp(String ip) {
        return ip != null && ip.length() <= 45 && IpClassifier.isValid(ip) && ip.matches("[0-9a-fA-F:.]+");
    }

    /** The command the shared adapter runs to add the inbound rule (informational; it is never run from here). */
    public List<String> addCommand(String ip) {
        return List.of("netsh", "advfirewall", "firewall", "add", "rule", "name=" + ruleName(ip), "dir=in",
                "action=block", "remoteip=" + ip, "description=AEGIS-temporary-block");
    }

    public List<String> removeCommand(String ip) {
        return List.of("netsh", "advfirewall", "firewall", "delete", "rule", "name=" + ruleName(ip));
    }

    public String describe() {
        WindowsFirewallAdapter a = adapter.get();
        if (a == null) return "unavailable (shared firewall adapter not attached)";
        return "Windows Firewall via the shared adapter (" + a.effectiveMode().name().toLowerCase(Locale.ROOT) + ")";
    }

    /** @return null on success, otherwise why it failed. */
    public String block(String ip) {
        if (!safeIp(ip)) return "refused: not a plain IP address";
        WindowsFirewallAdapter a = adapter.get();
        if (a == null) return "no firewall adapter attached: nothing was blocked";
        WindowsFirewallAdapter.Outcome o = a.block(ip, defaultTtlMs, "defense layer", "defense");
        return switch (o.status()) {
            case APPLIED, ALREADY_BLOCKED -> null;
            case DRY_RUN -> "not enforced: the shared firewall adapter is in dry-run (set -Daegis.fw.response=enforce on Windows as Administrator); no rule was created";
            case REFUSED -> "refused: " + o.message();
            case DISABLED, ERROR -> o.message();
        };
    }

    /** @return null on success (including "the rule was already gone"), otherwise why it failed. */
    public String unblock(String ip) {
        if (!safeIp(ip)) return "refused: not a plain IP address";
        WindowsFirewallAdapter a = adapter.get();
        if (a == null) return "no firewall adapter attached";
        WindowsFirewallAdapter.Outcome o = a.unblock(ip, "defense layer restore", "defense");
        return switch (o.status()) {
            case APPLIED, ALREADY_BLOCKED, DRY_RUN -> null;
            case REFUSED -> null;      // no AEGIS rule exists any more (expired or removed): the goal is already met
            case DISABLED, ERROR -> o.message();
        };
    }
}
