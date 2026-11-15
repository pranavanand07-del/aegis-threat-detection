package com.threatdetection.response;

import com.threatdetection.aegis.intel.IpClassifier;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Real network-level blocking through Windows Defender Firewall (netsh advfirewall). Separate from the
 * in-memory block list in {@link AutoResponseService}, which only makes THIS application reject an address.
 *
 * Safety properties:
 *  - Modes: OFF, DRY_RUN (default: decide and audit, change nothing), ENFORCE (-Daegis.fw.response=enforce).
 *  - ENFORCE needs Windows AND an elevated (Administrator) process; otherwise it falls back to DRY_RUN and says why.
 *  - Every rule is temporary: it has an expiry, a scheduler removes it, and the rule table is saved to disk so
 *    rules are re-armed (or removed if already expired) after a restart.
 *  - Allowlist is checked first (internal/private ranges, this host, -Daegis.allowlist) and the address is strictly
 *    validated; netsh is run with an argument list, never through a shell, so a hostile value cannot inject commands.
 *  - A cap on simultaneous rules (-Daegis.fw.max, default 500) stops a spoofed-source flood from filling the firewall.
 *  - unblock() / rollbackAll() remove rules; every action is written to the {@link AuditLogger}.
 */
public final class WindowsFirewallAdapter {
    public enum Mode { OFF, DRY_RUN, ENFORCE }
    public enum Status { APPLIED, DRY_RUN, ALREADY_BLOCKED, REFUSED, ERROR, DISABLED }

    public record Outcome(Status status, String message) {
        public boolean ok() { return status == Status.APPLIED || status == Status.DRY_RUN || status == Status.ALREADY_BLOCKED; }
    }

    public record CommandResult(int exitCode, String output) {}

    /** Seam for tests: the real implementation runs a process, the test one records the arguments. */
    public interface CommandRunner {
        CommandResult run(List<String> argv) throws IOException, InterruptedException;
    }

    private record Rule(String ip, long expiresAt, long createdAt, String reason) {}

    public static final String RULE_PREFIX = "AEGIS-BLOCK-";

    private final Mode requested;
    private final Mode effective;
    private final String effectiveReason;
    private final CommandRunner runner;
    private final Allowlist allowlist;
    private final AuditLogger audit;
    private final Path stateFile;
    private final int maxRules;
    private final boolean outbound;
    private final Map<String, Rule> rules = new LinkedHashMap<>();
    private final ScheduledExecutorService timer = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "aegis-fw-expiry");
        t.setDaemon(true);
        return t;
    });

    public WindowsFirewallAdapter(Mode requested, CommandRunner runner, boolean windows, boolean admin, Allowlist allowlist,
                                  AuditLogger audit, Path stateFile, int maxRules, boolean outbound) {
        this.requested = requested;
        this.runner = runner;
        this.allowlist = allowlist;
        this.audit = audit;
        this.stateFile = stateFile;
        this.maxRules = maxRules;
        this.outbound = outbound;
        if (requested == Mode.ENFORCE && !windows) {
            effective = Mode.DRY_RUN;
            effectiveReason = "enforce requested but this is not Windows: running as dry-run";
        } else if (requested == Mode.ENFORCE && !admin) {
            effective = Mode.DRY_RUN;
            effectiveReason = "enforce requested but the process is not elevated (run as Administrator): running as dry-run";
        } else {
            effective = requested;
            effectiveReason = requested == Mode.DRY_RUN ? "dry-run: decisions are audited, no firewall rule is created"
                    : requested == Mode.OFF ? "disabled" : "enforcing through netsh advfirewall";
        }
        audit.log("system", "FIREWALL_ADAPTER_START", "-", effective.name(), effectiveReason);
        if (effective == Mode.ENFORCE) recover();
        timer.scheduleWithFixedDelay(this::sweep, 30, 30, TimeUnit.SECONDS);
    }

    /** Reads -Daegis.fw.response (off | dry-run | enforce), -Daegis.fw.max, -Daegis.fw.outbound. */
    public static WindowsFirewallAdapter fromSystemProperties(Allowlist allowlist, AuditLogger audit) {
        String m = System.getProperty("aegis.fw.response", "dry-run").trim().toLowerCase(Locale.ROOT);
        Mode mode = m.equals("enforce") ? Mode.ENFORCE : m.equals("off") ? Mode.OFF : Mode.DRY_RUN;
        boolean windows = isWindows();
        CommandRunner runner = new ProcessRunner();
        boolean admin = windows && mode == Mode.ENFORCE && isElevated(runner);
        Path dir = Path.of(System.getProperty("aegis.data.dir", "aegis-data"));
        return new WindowsFirewallAdapter(mode, runner, windows, admin, allowlist, audit, dir.resolve("firewall-rules.tsv"),
                Integer.getInteger("aegis.fw.max", 500), Boolean.getBoolean("aegis.fw.outbound"));
    }

    public static boolean isWindows() {
        return System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("win");
    }

    /** `net session` succeeds only in an elevated prompt. */
    public static boolean isElevated(CommandRunner runner) {
        try {
            return runner.run(List.of("net", "session")).exitCode() == 0;
        } catch (IOException | InterruptedException e) {
            return false;
        }
    }

    public Mode requestedMode() { return requested; }
    public Mode effectiveMode() { return effective; }

    // ------------------------------------------------------------------ block / unblock

    public synchronized Outcome block(String ip, long ttlMs, String reason, String actor) {
        if (effective == Mode.OFF) return new Outcome(Status.DISABLED, "firewall response is off");
        String bad = validate(ip);
        if (bad != null) return refuse(ip, actor, bad);
        String why = allowlist.why(ip);
        if (why != null) return refuse(ip, actor, "never blocked: " + why);
        long now = System.currentTimeMillis();
        long ttl = Math.max(60_000L, Math.min(ttlMs, 24L * 3600_000L));   // 1 minute .. 24 hours
        Rule existing = rules.get(ip);
        if (existing != null) {
            rules.put(ip, new Rule(ip, Math.max(existing.expiresAt(), now + ttl), existing.createdAt(), existing.reason()));
            save();
            audit.log(actor, "FIREWALL_BLOCK_EXTENDED", ip, "ALREADY_BLOCKED", "expiry extended; " + reason);
            return new Outcome(Status.ALREADY_BLOCKED, "rule already present; expiry extended");
        }
        if (rules.size() >= maxRules) return refuse(ip, actor, "rule limit reached (" + maxRules + ")");

        if (effective == Mode.DRY_RUN) {
            audit.log(actor, "FIREWALL_BLOCK_DRY_RUN", ip, "DRY_RUN", "would block for " + ttl / 60000 + " min; " + reason);
            return new Outcome(Status.DRY_RUN, "dry-run: would block " + ip + " for " + ttl / 60000 + " min");
        }
        // Note: if an orphan rule with this name already exists in the OS (registry lost), netsh creates a second one;
        // that is harmless because "delete rule name=..." removes every rule with that name in one go.
        try {
            for (String dir : directions()) {
                CommandResult r = runner.run(List.of("netsh", "advfirewall", "firewall", "add", "rule",
                        "name=" + ruleName(ip, dir), "dir=" + dir, "action=block", "remoteip=" + ip,
                        "description=AEGIS-temporary-block"));
                if (r.exitCode() != 0) {
                    removeRules(ip);   // roll back a half-applied pair
                    audit.log(actor, "FIREWALL_BLOCK", ip, "ERROR", "netsh exit " + r.exitCode() + ": " + clip(r.output()));
                    return new Outcome(Status.ERROR, "netsh failed (exit " + r.exitCode() + ")");
                }
            }
        } catch (IOException | InterruptedException e) {
            if (e instanceof InterruptedException) Thread.currentThread().interrupt();
            removeRules(ip);
            audit.log(actor, "FIREWALL_BLOCK", ip, "ERROR", e.getMessage());
            return new Outcome(Status.ERROR, "could not run netsh: " + e.getMessage());
        }
        rules.put(ip, new Rule(ip, now + ttl, now, reason));
        boolean saved = save();
        scheduleExpiry(ip, ttl);
        audit.log(actor, "FIREWALL_BLOCK", ip, "APPLIED", "blocked for " + ttl / 60000 + " min; " + reason
                + (saved ? "" : "; WARNING rule table could not be saved, the rule will not survive a restart"));
        return new Outcome(Status.APPLIED, "firewall rule created for " + ip + ", expires in " + ttl / 60000 + " min");
    }

    /**
     * Removes the rule for one address (analyst override, or expiry).
     * The registry entry is deleted only after the operating system confirmed the rule is gone (or was never there),
     * so a failed removal can be retried: the entry stays, is marked due immediately, and the sweeper retries it.
     */
    public synchronized Outcome unblock(String ip, String reason, String actor) {
        Rule r = rules.get(ip);
        if (r == null) {
            // Not in the registry. In ENFORCE mode a rule may still exist in the OS (registry lost): clean it up.
            if (effective == Mode.ENFORCE && validate(ip) == null) {
                Removal o = removeRules(ip);
                if (o == Removal.REMOVED) {
                    audit.log(actor, "FIREWALL_UNBLOCK", ip, "REMOVED", "orphan OS rule removed (was not in the registry); " + reason);
                    return new Outcome(Status.APPLIED, "orphan rule removed");
                }
                if (o == Removal.FAILED) {
                    audit.log(actor, "FIREWALL_UNBLOCK", ip, "ERROR", "orphan check failed; " + reason);
                    return new Outcome(Status.ERROR, "could not verify or remove an OS rule for " + ip + "; check netsh");
                }
            }
            audit.log(actor, "FIREWALL_UNBLOCK", String.valueOf(ip), "NOT_FOUND", reason);
            return new Outcome(Status.REFUSED, "no AEGIS rule for " + ip);
        }
        if (effective == Mode.ENFORCE) {
            Removal o = removeRules(ip);
            if (o == Removal.FAILED) {
                // keep the entry (rule may still be active) and make it due so the sweeper retries
                rules.put(ip, new Rule(ip, Math.min(r.expiresAt(), System.currentTimeMillis()), r.createdAt(), r.reason()));
                save();
                audit.log(actor, "FIREWALL_UNBLOCK", ip, "ERROR", "rule removal failed, kept for retry; " + reason);
                return new Outcome(Status.ERROR, "rule removal failed; the rule is still tracked and will be retried");
            }
            rules.remove(ip);
            save();
            audit.log(actor, "FIREWALL_UNBLOCK", ip, "REMOVED", o == Removal.ABSENT ? "rule was already gone from the OS; " + reason : reason);
            return new Outcome(Status.APPLIED, o == Removal.ABSENT ? "rule already absent in the OS; registry entry cleared" : "rule removed");
        }
        rules.remove(ip);
        save();
        audit.log(actor, "FIREWALL_UNBLOCK", ip, "REMOVED", reason);
        return new Outcome(Status.APPLIED, "tracked entry removed");
    }

    /** Rollback of everything AEGIS created. */
    public synchronized int rollbackAll(String actor, String reason) {
        int n = 0, failed = 0;
        for (String ip : new ArrayList<>(rules.keySet())) {
            Status st = unblock(ip, reason, actor).status();
            if (st == Status.APPLIED) n++; else failed++;
        }
        audit.log(actor, "FIREWALL_ROLLBACK_ALL", "-", failed == 0 ? "DONE" : "PARTIAL", n + " rule(s) removed, " + failed + " failed (still tracked); " + reason);
        return n;
    }

    public synchronized boolean tracks(String ip) { return rules.containsKey(ip); }

    /** Stops the expiry timer (tests and shutdown). Rules already in the firewall are left in place, by design. */
    public void close() { timer.shutdownNow(); }

    public synchronized List<Map<String, Object>> activeRules() {
        List<Map<String, Object>> out = new ArrayList<>();
        for (Rule r : rules.values()) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("ip", r.ip());
            m.put("createdAt", r.createdAt());
            m.put("expiresAt", r.expiresAt());
            m.put("reason", r.reason());
            out.add(m);
        }
        return out;
    }

    public Map<String, Object> status() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("requestedMode", requested.name());
        m.put("effectiveMode", effective.name());
        m.put("detail", effectiveReason);
        m.put("windows", isWindows());
        m.put("activeRules", activeRules().size());
        m.put("maxRules", maxRules);
        return m;
    }

    // ------------------------------------------------------------------ internals

    private String validate(String ip) {
        if (ip == null || ip.isBlank()) return "no address";
        if (!ip.matches("[0-9a-fA-F:.]{2,45}") || !IpClassifier.isValid(ip)) return "not a valid IP address";
        if (ip.equals("0.0.0.0") || ip.equals("255.255.255.255") || ip.equals("::")) return "unspecified/broadcast address";
        long v = IpClassifier.toLong(ip);
        if (v >= 0 && (v >> 28) == 0xE) return "multicast address";
        return null;
    }

    private Outcome refuse(String ip, String actor, String why) {
        audit.log(actor, "FIREWALL_BLOCK", String.valueOf(ip), "REFUSED", why);
        return new Outcome(Status.REFUSED, why);
    }

    private List<String> directions() { return outbound ? List.of("in", "out") : List.of("in"); }

    /** The one naming scheme for every AEGIS firewall rule (also used by the Defense layer). */
    public static String ruleName(String ip, String dir) {
        return RULE_PREFIX + ip.replace(':', '_') + "-" + dir.toUpperCase(Locale.ROOT);
    }

    private enum Removal { REMOVED, ABSENT, FAILED }

    /**
     * Deletes the rule(s) for an address. netsh also fails when nothing matches, so a failed delete is followed by a
     * "show rule" check: if the rule is really gone the result is ABSENT (fine), otherwise FAILED (retry later).
     */
    private Removal removeRules(String ip) {
        boolean removed = false, failed = false;
        for (String dir : List.of("in", "out")) {
            if (dir.equals("out") && !outbound) continue;
            String name = ruleName(ip, dir);
            try {
                CommandResult r = runner.run(List.of("netsh", "advfirewall", "firewall", "delete", "rule", "name=" + name));
                if (r.exitCode() == 0) { removed = true; continue; }
                CommandResult chk = runner.run(List.of("netsh", "advfirewall", "firewall", "show", "rule", "name=" + name));
                if (chk.exitCode() == 0) failed = true;          // still listed: the delete really failed
            } catch (IOException | InterruptedException e) {
                if (e instanceof InterruptedException) Thread.currentThread().interrupt();
                failed = true;
            }
        }
        return failed ? Removal.FAILED : removed ? Removal.REMOVED : Removal.ABSENT;
    }

    private void scheduleExpiry(String ip, long delayMs) {
        timer.schedule(() -> expire(ip), delayMs + 500, TimeUnit.MILLISECONDS);
    }

    private synchronized void expire(String ip) {
        Rule r = rules.get(ip);
        if (r != null && System.currentTimeMillis() >= r.expiresAt()) {
            if (unblock(ip, "automatic expiry", "system").status() == Status.ERROR) scheduleExpiry(ip, 30_000);   // retry
        } else if (r != null) scheduleExpiry(ip, r.expiresAt() - System.currentTimeMillis());   // extended meanwhile
    }

    private synchronized void sweep() {
        long now = System.currentTimeMillis();
        for (Rule r : new ArrayList<>(rules.values())) if (now >= r.expiresAt()) unblock(r.ip(), "automatic expiry (sweep)", "system");
    }

    /** Writes the rule table through a temp file + atomic move so a crash never leaves a half-written table. */
    private boolean save() {
        if (stateFile == null) return true;
        try {
            Path abs = stateFile.toAbsolutePath();
            Files.createDirectories(abs.getParent());
            StringBuilder sb = new StringBuilder();
            for (Rule r : rules.values()) {
                sb.append(r.ip()).append('\t').append(r.createdAt()).append('\t').append(r.expiresAt()).append('\t')
                  .append(r.reason().replace('\t', ' ').replace('\n', ' ').replace('\r', ' ')).append('\n');
            }
            Path tmp = abs.resolveSibling(abs.getFileName() + ".tmp");
            Files.writeString(tmp, sb.toString(), StandardCharsets.UTF_8);
            try {
                Files.move(tmp, abs, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(tmp, abs, StandardCopyOption.REPLACE_EXISTING);   // best effort on filesystems without atomic move
            }
            return true;
        } catch (IOException e) {
            System.err.println("[AEGIS] firewall rule table not saved: " + e.getMessage());
            return false;
        }
    }

    /** After a restart: expired rules are removed from the firewall, live ones are re-armed. */
    private synchronized void recover() {
        if (stateFile == null || !Files.exists(stateFile)) return;
        try {
            long now = System.currentTimeMillis();
            for (String line : Files.readAllLines(stateFile, StandardCharsets.UTF_8)) {
                String[] f = line.split("\t", 4);
                if (f.length < 3 || validate(f[0]) != null) continue;
                long created, expires;
                try { created = Long.parseLong(f[1]); expires = Long.parseLong(f[2]); }
                catch (NumberFormatException bad) { System.err.println("[AEGIS] skipped a corrupt firewall state line"); continue; }
                String reason = f.length > 3 ? f[3] : "recovered";
                if (now >= expires) {
                    if (removeRules(f[0]) == Removal.FAILED) {
                        rules.put(f[0], new Rule(f[0], expires, created, reason));   // keep: the sweeper retries
                        audit.log("system", "FIREWALL_UNBLOCK", f[0], "ERROR", "expired while AEGIS was not running; removal failed, will retry");
                    } else {
                        audit.log("system", "FIREWALL_UNBLOCK", f[0], "REMOVED", "expired while AEGIS was not running");
                    }
                } else {
                    rules.put(f[0], new Rule(f[0], expires, created, reason));
                    scheduleExpiry(f[0], expires - now);
                    audit.log("system", "FIREWALL_RULE_RECOVERED", f[0], "ARMED", "expiry re-armed after restart");
                }
            }
            save();
        } catch (IOException e) {
            System.err.println("[AEGIS] firewall state not recovered: " + e.getMessage());
        }
    }

    private static String clip(String s) {
        String t = s == null ? "" : s.replace('\n', ' ').trim();
        return t.length() > 200 ? t.substring(0, 200) : t;
    }

    /** Runs a process with an argument list (no shell), 15 second timeout that also covers a process that hangs without output. */
    private static final class ProcessRunner implements CommandRunner {
        @Override
        public CommandResult run(List<String> argv) throws IOException, InterruptedException {
            Process p = new ProcessBuilder(argv).redirectErrorStream(true).start();
            java.util.concurrent.CompletableFuture<byte[]> out = java.util.concurrent.CompletableFuture.supplyAsync(() -> {
                try (java.io.InputStream in = p.getInputStream()) {
                    byte[] kept = in.readNBytes(8192);
                    in.transferTo(java.io.OutputStream.nullOutputStream());   // keep draining so the child never blocks on a full pipe
                    return kept;
                } catch (IOException e) {
                    return new byte[0];
                }
            });
            if (!p.waitFor(15, TimeUnit.SECONDS)) {
                p.destroyForcibly();
                out.cancel(true);
                return new CommandResult(-1, "timeout");
            }
            byte[] bytes;
            try { bytes = out.get(2, TimeUnit.SECONDS); } catch (Exception e) { bytes = new byte[0]; }
            return new CommandResult(p.exitValue(), new String(bytes, StandardCharsets.UTF_8));
        }
    }
}
