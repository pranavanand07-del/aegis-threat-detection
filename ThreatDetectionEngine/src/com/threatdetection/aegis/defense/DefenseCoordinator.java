package com.threatdetection.aegis.defense;

import com.threatdetection.aegis.AegisEvent;
import com.threatdetection.aegis.AegisSignal;
import com.threatdetection.aegis.DataSource;
import com.threatdetection.aegis.defense.DefenseAction.State;
import com.threatdetection.aegis.defense.DefenseAction.Type;
import com.threatdetection.aegis.intel.IpClassifier;
import com.threatdetection.model.ThreatLevel;
import com.threatdetection.response.Allowlist;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import static com.threatdetection.aegis.JsonUtil.str;

/**
 * Decides and carries out defensive responses.
 *
 *   LOW / MEDIUM -> monitor only
 *   HIGH         -> escalate to the administrator, propose actions, wait for an analyst
 *   CRITICAL     -> escalate, and run a reversible, time-limited action ONLY if policy allows it, the data is
 *                   OBSERVED (not API/simulated), the alert is corroborated, and the circuit breaker is closed
 *
 * Never: delete a file, block permanently, act on simulated data, act on allowlisted/internal addresses,
 * or lock a protected account. Everything is written to the {@link AuditTrail}.
 */
public final class DefenseCoordinator {
    private static final long HISTORICAL_MS = 5 * 60 * 1000L;
    private static final long ESCALATION_QUIET_MS = 10 * 60 * 1000L;

    private final DefenseConfig cfg;
    private final AuditTrail audit;
    private final FirewallBackend firewall;
    private final QuarantineService quarantine;
    private final Controls controls;
    private final Escalator escalator;
    private final Allowlist allowlist;
    private final Path stateFile;

    private final Map<String, DefenseAction> actions = new LinkedHashMap<>();
    private final Map<String, Long> lastEscalation = new HashMap<>();
    private final Set<String> restoreFailureLogged = new HashSet<>();
    private final ArrayDeque<Long> autoTimes = new ArrayDeque<>();
    private long seq;
    private boolean breakerReported;

    public DefenseCoordinator(DefenseConfig cfg, AuditTrail audit, FirewallBackend firewall, QuarantineService quarantine,
                              Controls controls, Escalator escalator, Allowlist allowlist) {
        this.cfg = cfg;
        this.audit = audit;
        this.firewall = firewall;
        this.firewall.setDefaultTtlMs(cfg.ttlMs);
        this.quarantine = quarantine;
        this.controls = controls;
        this.escalator = escalator;
        this.allowlist = allowlist;
        this.stateFile = cfg.dataDir.resolve("defense-active.tsv");
    }

    public static DefenseCoordinator create(DefenseConfig cfg, Allowlist allowlist) throws IOException {
        Files.createDirectories(cfg.dataDir);
        return new DefenseCoordinator(cfg, new AuditTrail(cfg.dataDir), new FirewallBackend(),
                new QuarantineService(cfg.quarantineDir, cfg.quarantineRoots),
                new Controls(cfg.rateLimitMax, cfg.rateLimitWindowMs), new Escalator(cfg.dataDir, cfg.webhook), allowlist);
    }

    public DefenseConfig config() { return cfg; }
    public AuditTrail audit() { return audit; }
    public Controls controls() { return controls; }
    public QuarantineService quarantine() { return quarantine; }
    public Escalator escalator() { return escalator; }
    public FirewallBackend firewall() { return firewall; }

    /** Restores persisted actions (expired ones are undone) and starts the recovery sweeper. */
    public void start() {
        if (cfg.mode == DefenseMode.OFF) return;
        restore();
        ScheduledExecutorService ex = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "aegis-defense-recovery");
            t.setDaemon(true);
            return t;
        });
        ex.scheduleWithFixedDelay(() -> {
            try { sweep(); } catch (RuntimeException e) { System.err.println("[AEGIS] defense sweep failed: " + e); }
        }, 15, 15, TimeUnit.SECONDS);
    }

    // ------------------------------------------------------------------ decisions

    public void onEvent(AegisEvent e, AegisSignal s) {
        if (cfg.mode == DefenseMode.OFF || e.source == DataSource.SIMULATED) return;
        ResponseLevel rl = ResponseLevel.of(e.level);
        if (rl == ResponseLevel.MONITOR) return;
        long now = System.currentTimeMillis();
        if (now - e.ts > HISTORICAL_MS) return;                       // replayed history is not an attack in progress
        synchronized (this) {
            escalate(e, rl, now);
            boolean corroborated = distinctRules(e) >= cfg.minRules || "MALICIOUS".equals(e.repVerdict);
            for (Proposal p : plan(e, s, rl)) {
                if (findLive(p.type.name() + "|" + p.target, now) != null) continue;
                DefenseAction a = newAction(p.type, p.target, reason(e), e);
                boolean auto = rl == ResponseLevel.AUTO_REVERSIBLE && e.source == DataSource.OBSERVED && corroborated
                        && cfg.auto.contains(p.type) && breakerClosed(p.type, now);
                if (auto) {
                    autoTimes.addLast(now);
                    keep(a);
                    execute(a, "system:policy");
                } else {
                    a.expiresAt = now + cfg.approvalWindowMs;
                    a.result = pendingWhy(rl, e, corroborated, p.type);
                    keep(a);
                    audit.record("system:policy", "PROPOSE_" + a.type.name(), a.target, e.level.name(), cfg.mode.name(),
                            "PENDING_APPROVAL", a.reason + " | " + a.result, Long.toString(e.id));
                    save();
                }
            }
        }
    }

    private record Proposal(Type type, String target) {}

    private List<Proposal> plan(AegisEvent e, AegisSignal s, ResponseLevel rl) {
        List<Proposal> out = new ArrayList<>();
        boolean external = !e.ip.isEmpty() && IpClassifier.isValid(e.ip) && !e.internal && allowlist.why(e.ip) == null;
        if (external) out.add(new Proposal(rl == ResponseLevel.AUTO_REVERSIBLE ? Type.FIREWALL_BLOCK : Type.RATE_LIMIT, e.ip));
        if (s != null) {
            String user = s.user == null ? "" : s.user.trim();
            if (s.kind == AegisSignal.Kind.AUTH && !user.isEmpty() && !"unknown".equalsIgnoreCase(user)
                    && !cfg.protectedAccounts.contains(user.toLowerCase(Locale.ROOT))) out.add(new Proposal(Type.LOCK_ACCOUNT, user));
            if (s.session != null && !s.session.isBlank()) out.add(new Proposal(Type.REVOKE_SESSION, s.session));
            if (s.kind == AegisSignal.Kind.PROCESS && quarantine.enabled() && s.path != null && !s.path.isBlank()
                    && quarantine.refusal(s.path) == null) out.add(new Proposal(Type.QUARANTINE_FILE, s.path));
        }
        return out;
    }

    private static int distinctRules(AegisEvent e) {
        Set<String> names = new HashSet<>();
        for (AegisEvent.Contribution c : e.rules) if (c.score > 0) names.add(c.rule);
        return names.size();
    }

    private String pendingWhy(ResponseLevel rl, AegisEvent e, boolean corroborated, Type type) {
        if (rl == ResponseLevel.ANALYST_APPROVAL) return "HIGH severity: analyst approval required";
        if (e.source != DataSource.OBSERVED) return e.source.label + " data is unverified: analyst approval required";
        if (!corroborated) return "single heuristic signal (needs " + cfg.minRules + " distinct rules or a threat-intel hit): analyst approval required";
        if (!cfg.auto.contains(type)) return "policy requires approval for " + type.label.toLowerCase(Locale.ROOT);
        return "automatic limit reached (circuit breaker or block cap): analyst approval required";
    }

    private boolean breakerClosed(Type type, long now) {
        while (!autoTimes.isEmpty() && now - autoTimes.peekFirst() > 60_000L) autoTimes.pollFirst();
        if (autoTimes.size() >= cfg.maxAutoPerMinute) {
            if (!breakerReported) {
                breakerReported = true;
                audit.record("system:policy", "CIRCUIT_BREAKER", "-", "CRITICAL", cfg.mode.name(), "TRIPPED",
                        "More than " + cfg.maxAutoPerMinute + " automatic actions in one minute (possible spoofed-source flood); further actions need an analyst", "");
            }
            return false;
        }
        breakerReported = false;
        if (type == Type.FIREWALL_BLOCK) {
            long blocks = actions.values().stream().filter(a -> a.type == Type.FIREWALL_BLOCK && a.state == State.ACTIVE).count();
            if (blocks >= cfg.maxActiveBlocks) return false;
        }
        return true;
    }

    private void escalate(AegisEvent e, ResponseLevel rl, long now) {
        String actor = !e.ip.isEmpty() ? e.ip : e.host + "/" + e.user;
        Long last = lastEscalation.get(actor);
        if (last != null && now - last < ESCALATION_QUIET_MS) return;
        if (lastEscalation.size() > 10_000) lastEscalation.clear();
        lastEscalation.put(actor, now);
        String title = e.level + " incident from " + actor;
        String body = reason(e) + (rl == ResponseLevel.ANALYST_APPROVAL ? " - review pending actions in /aegis/defense" : "");
        escalator.notifyAdmin(e.level.name(), title, body, (channel, result) ->
                audit.record("system:policy", "ESCALATE", actor, e.level.name(), cfg.mode.name(), channel + ": " + result, body, Long.toString(e.id)));
    }

    private static String reason(AegisEvent e) {
        StringBuilder sb = new StringBuilder(e.level + " score " + e.score + " [" + e.source.label + "]: ");
        int n = 0;
        for (AegisEvent.Contribution c : e.rules) {
            if (c.score <= 0) continue;
            if (n++ > 0) sb.append(", ");
            sb.append(c.rule).append('+').append(c.score);
            if (n >= 5) break;
        }
        return sb.toString();
    }

    // ------------------------------------------------------------------ analyst operations

    public synchronized String approve(String id, String operator) {
        DefenseAction a = actions.get(id);
        if (a == null) return "no such action";
        if (a.state != State.PENDING) return "action is " + a.state + ", not pending";
        if (System.currentTimeMillis() > a.expiresAt) { expirePending(a); return "approval window has elapsed; no action taken"; }
        execute(a, operator);
        return null;
    }

    public synchronized String reject(String id, String operator) {
        DefenseAction a = actions.get(id);
        if (a == null) return "no such action";
        if (a.state != State.PENDING) return "action is " + a.state + ", not pending";
        a.state = State.REJECTED;
        a.decidedBy = operator;
        audit.record(operator, "REJECT_" + a.type.name(), a.target, a.level.name(), cfg.mode.name(), "REJECTED", a.reason, Long.toString(a.eventId));
        save();
        return null;
    }

    public synchronized String revert(String id, String operator) {
        DefenseAction a = actions.get(id);
        if (a == null) return "no such action";
        if (a.state != State.ACTIVE && a.state != State.DRY_RUN) return "action is " + a.state + ", nothing to revert";
        String err = a.state == State.ACTIVE ? undo(a) : null;
        if (err != null) {
            audit.record(operator, "REVERT_" + a.type.name(), a.target, a.level.name(), cfg.mode.name(), "FAILED: " + err, a.reason, Long.toString(a.eventId));
            return err;
        }
        a.state = State.REVERTED;
        a.decidedBy = operator;
        audit.record(operator, "REVERT_" + a.type.name(), a.target, a.level.name(), cfg.mode.name(), "RESTORED", a.reason, Long.toString(a.eventId));
        save();
        return null;
    }

    /** An analyst starts an action directly (this is the approval). Same safety checks apply. */
    public synchronized DefenseAction manual(Type type, String target, String reason, String operator) {
        long now = System.currentTimeMillis();
        DefenseAction a = new DefenseAction(nextId(), type, target, reason.isBlank() ? "manual action by analyst" : reason, 0,
                "MANUAL", ThreatLevel.CRITICAL, now);
        keep(a);
        execute(a, operator);
        return a;
    }

    // ------------------------------------------------------------------ execution and recovery

    private DefenseAction newAction(Type t, String target, String reason, AegisEvent e) {
        DefenseAction a = new DefenseAction(nextId(), t, target, reason, e.id, e.source.name(), e.level, System.currentTimeMillis());
        return a;
    }

    private String nextId() { return "A-" + Long.toString(System.currentTimeMillis() / 1000, 36) + "-" + (++seq); }

    private void keep(DefenseAction a) {
        actions.put(a.id, a);
        if (actions.size() > 600) {
            var it = actions.values().iterator();
            while (it.hasNext() && actions.size() > 500) { if (!it.next().live()) it.remove(); }
        }
    }

    private DefenseAction findLive(String key, long now) {
        for (DefenseAction a : actions.values()) {
            if (!a.key().equals(key)) continue;
            if (a.live() || (a.state == State.DRY_RUN && (a.expiresAt == 0 || now < a.expiresAt))) return a;
        }
        return null;
    }

    private String guard(DefenseAction a) {
        switch (a.type) {
            case FIREWALL_BLOCK, RATE_LIMIT -> {
                String why = allowlist.why(a.target);
                return why == null ? null : "target is protected (" + why + ")";
            }
            case LOCK_ACCOUNT -> {
                return cfg.protectedAccounts.contains(a.target.toLowerCase(Locale.ROOT)) ? "protected account" : null;
            }
            case QUARANTINE_FILE -> { return quarantine.refusal(a.target); }
            default -> { return a.target.isBlank() ? "empty target" : null; }
        }
    }

    private void execute(DefenseAction a, String operator) {
        long now = System.currentTimeMillis();
        a.decidedBy = operator;
        a.expiresAt = a.type.expires ? now + cfg.ttlMs : 0;
        String why = guard(a);
        if (why != null) {
            fail(a, "refused: " + why);
            return;
        }
        if (cfg.mode == DefenseMode.DRY_RUN) {
            a.state = State.DRY_RUN;
            a.result = "DRY_RUN: would " + a.type.label.toLowerCase(Locale.ROOT) + " '" + a.target + "'"
                    + (a.type.expires ? " for " + (cfg.ttlMs / 60000) + " min" : "");
            audit.record(operator, a.type.name(), a.target, a.level.name(), cfg.mode.name(), a.result, a.reason, Long.toString(a.eventId));
            save();
            return;
        }
        String err = null;
        a.result = "";
        switch (a.type) {
            case FIREWALL_BLOCK -> {
                err = cfg.firewallEnabled ? firewall.block(a.target) : "firewall control disabled (-Daegis.defense.firewall=false)";
                a.detail = FirewallBackend.ruleName(a.target);
            }
            case QUARANTINE_FILE -> {
                try {
                    QuarantineService.Held h = quarantine.quarantine(a.target, a.reason);
                    a.detail = h.id();
                    a.result = "moved to quarantine as " + h.id() + " (sha256 " + h.sha256().substring(0, 16) + "...)";
                } catch (IOException ex) {
                    err = ex.getMessage();
                }
            }
            case REVOKE_SESSION -> controls.revokeSession(a.target, a.expiresAt);
            case LOCK_ACCOUNT -> controls.lockAccount(a.target, a.expiresAt);
            case RATE_LIMIT -> controls.restrict(a.target, a.expiresAt);
        }
        if (err != null) {
            fail(a, err);
            return;
        }
        a.state = State.ACTIVE;
        if (a.result.isEmpty()) {
            a.result = "applied" + (a.type.expires ? ", expires in " + (cfg.ttlMs / 60000) + " min" : ", held until an analyst restores it");
        }
        audit.record(operator, a.type.name(), a.target, a.level.name(), cfg.mode.name(), "APPLIED: " + a.result, a.reason, Long.toString(a.eventId));
        save();
    }

    private void fail(DefenseAction a, String err) {
        a.state = State.FAILED;
        a.result = err;
        audit.record(a.decidedBy, a.type.name(), a.target, a.level.name(), cfg.mode.name(), "FAILED: " + err, a.reason, Long.toString(a.eventId));
        save();
    }

    /** @return null on success, otherwise what went wrong. */
    private String undo(DefenseAction a) {
        return switch (a.type) {
            case FIREWALL_BLOCK -> cfg.firewallEnabled ? firewall.unblock(a.target) : null;
            case QUARANTINE_FILE -> quarantine.restore(a.detail);
            case REVOKE_SESSION -> { controls.releaseSession(a.target); yield null; }
            case LOCK_ACCOUNT -> { controls.unlockAccount(a.target); yield null; }
            case RATE_LIMIT -> { controls.unrestrict(a.target); yield null; }
        };
    }

    private void expirePending(DefenseAction a) {
        a.state = State.EXPIRED;
        a.result = "approval window elapsed; no action was taken";
        audit.record("system:policy", "EXPIRE_" + a.type.name(), a.target, a.level.name(), cfg.mode.name(), "NO_ACTION", a.result, Long.toString(a.eventId));
    }

    /** Automatic recovery: expired temporary actions are undone and recorded; stale proposals lapse. */
    public synchronized void sweep() {
        long now = System.currentTimeMillis();
        boolean changed = false;
        for (DefenseAction a : new ArrayList<>(actions.values())) {
            if (a.state == State.PENDING && now > a.expiresAt) { expirePending(a); changed = true; }
            else if (a.state == State.ACTIVE && a.expiresAt != 0 && now > a.expiresAt) {
                String err = undo(a);
                if (err == null) {
                    a.state = State.EXPIRED;
                    restoreFailureLogged.remove(a.id);
                    audit.record("system:recovery", "RESTORE_" + a.type.name(), a.target, a.level.name(), cfg.mode.name(),
                            "RESTORED: temporary " + a.type.label.toLowerCase(Locale.ROOT) + " expired", a.reason, Long.toString(a.eventId));
                    changed = true;
                } else if (restoreFailureLogged.add(a.id)) {
                    audit.record("system:recovery", "RESTORE_" + a.type.name(), a.target, a.level.name(), cfg.mode.name(),
                            "FAILED (will retry): " + err, a.reason, Long.toString(a.eventId));
                }
            }
        }
        if (changed) save();
    }

    // ------------------------------------------------------------------ persistence

    private static String c(String s) { return s == null ? "" : s.replace('\t', ' ').replace('\n', ' ').replace('\r', ' '); }

    private synchronized void save() {
        try {
            StringBuilder sb = new StringBuilder();
            for (DefenseAction a : actions.values()) {
                if (!a.live()) continue;
                sb.append(String.join("\t", c(a.id), a.type.name(), c(a.target), c(a.reason), Long.toString(a.eventId), c(a.eventSource),
                        a.level.name(), Long.toString(a.createdAt), a.state.name(), Long.toString(a.expiresAt), c(a.decidedBy), c(a.detail),
                        c(a.result))).append('\n');
            }
            Path tmp = stateFile.resolveSibling("defense-active.tmp");
            Files.writeString(tmp, sb.toString(), StandardCharsets.UTF_8);
            Files.move(tmp, stateFile, StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException e) {
            System.err.println("[AEGIS] could not save defense state: " + e.getMessage());
        }
    }

    private synchronized void restore() {
        if (!Files.exists(stateFile)) return;
        long now = System.currentTimeMillis();
        try {
            for (String l : Files.readAllLines(stateFile, StandardCharsets.UTF_8)) {
                String[] f = l.split("\t", -1);
                if (f.length < 13) continue;
                DefenseAction a = new DefenseAction(f[0], Type.valueOf(f[1]), f[2], f[3], Long.parseLong(f[4]), f[5],
                        ThreatLevel.valueOf(f[6]), Long.parseLong(f[7]));
                a.state = State.valueOf(f[8]);
                a.expiresAt = Long.parseLong(f[9]);
                a.decidedBy = f[10];
                a.detail = f[11];
                a.result = f[12];
                keep(a);
                if (a.state == State.ACTIVE) {
                    if (a.expiresAt != 0 && now > a.expiresAt) {
                        // The process was down while this temporary action expired: undo it now (never leave a block behind).
                        String err = undo(a);
                        a.state = err == null ? State.EXPIRED : State.ACTIVE;
                        audit.record("system:recovery", "RESTORE_" + a.type.name(), a.target, a.level.name(), cfg.mode.name(),
                                err == null ? "RESTORED after restart: expired while AEGIS was stopped" : "FAILED (will retry): " + err,
                                a.reason, Long.toString(a.eventId));
                    } else {
                        switch (a.type) {
                            case REVOKE_SESSION -> controls.revokeSession(a.target, a.expiresAt);
                            case LOCK_ACCOUNT -> controls.lockAccount(a.target, a.expiresAt);
                            case RATE_LIMIT -> controls.restrict(a.target, a.expiresAt);
                            default -> { }
                        }
                    }
                }
            }
            save();
        } catch (IOException | RuntimeException e) {
            System.err.println("[AEGIS] could not restore defense state: " + e.getMessage());
        }
    }

    // ------------------------------------------------------------------ views

    public synchronized List<DefenseAction> list() {
        List<DefenseAction> l = new ArrayList<>(actions.values());
        java.util.Collections.reverse(l);
        return l;
    }

    public String statusJson() {
        StringBuilder auto = new StringBuilder();
        for (Type t : cfg.auto) { if (auto.length() > 0) auto.append(','); auto.append(str(t.name())); }
        long pending, active;
        synchronized (this) {
            pending = actions.values().stream().filter(a -> a.state == State.PENDING).count();
            active = actions.values().stream().filter(a -> a.state == State.ACTIVE).count();
        }
        return "{\"mode\":" + str(cfg.mode.name()) + ",\"ttlMinutes\":" + (cfg.ttlMs / 60000) + ",\"approvalMinutes\":" + (cfg.approvalWindowMs / 60000)
                + ",\"autoTypes\":[" + auto + "],\"minRules\":" + cfg.minRules + ",\"firewall\":" + str(firewall.describe())
                + ",\"firewallEnabled\":" + cfg.firewallEnabled + ",\"quarantineEnabled\":" + quarantine.enabled()
                + ",\"quarantineDir\":" + str(quarantine.dir().toString()) + ",\"webhook\":" + escalator.webhookConfigured()
                + ",\"pending\":" + pending + ",\"active\":" + active + ",\"softControls\":" + controls.counts()
                + ",\"auditFile\":" + str(audit.file().toString())
                + ",\"levels\":{\"LOW\":\"monitor\",\"MEDIUM\":\"monitor\",\"HIGH\":\"alert + analyst approval\",\"CRITICAL\":\"reversible policy-approved response\"}}";
    }
}
