package com.threatdetection.aegis.defense;

import com.threatdetection.aegis.AegisEvent;
import com.threatdetection.aegis.AegisSignal;
import com.threatdetection.aegis.DataSource;
import com.threatdetection.aegis.defense.DefenseAction.State;
import com.threatdetection.aegis.defense.DefenseAction.Type;
import com.threatdetection.model.ThreatLevel;
import com.threatdetection.response.Allowlist;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Plain-Java checks of the defense policy (no JUnit needed):
 *   java -cp out com.threatdetection.aegis.defense.DefenseSelfTest
 * Uses a recording firewall stand-in and temp directories; it never touches the real firewall.
 */
public final class DefenseSelfTest {
    private static int passed, failed;

    private static void check(String name, boolean ok) {
        if (ok) passed++; else failed++;
        System.out.println((ok ? "  PASS  " : "  FAIL  ") + name);
    }

    static final class FakeFirewall extends FirewallBackend {
        final List<String> blocked = new ArrayList<>(), unblocked = new ArrayList<>();
        @Override public String block(String ip) { blocked.add(ip); return null; }
        @Override public String unblock(String ip) { unblocked.add(ip); return null; }
    }

    private static DefenseCoordinator coordinator(DefenseConfig cfg, FakeFirewall fw) throws Exception {
        Files.createDirectories(cfg.dataDir);
        return new DefenseCoordinator(cfg, new AuditTrail(cfg.dataDir), fw, new QuarantineService(cfg.quarantineDir, cfg.quarantineRoots),
                new Controls(cfg.rateLimitMax, cfg.rateLimitWindowMs), new Escalator(cfg.dataDir, ""), new Allowlist(true, ""));
    }

    private static DefenseConfig config(Path dir, DefenseMode mode) {
        DefenseConfig c = new DefenseConfig();
        c.mode = mode;
        c.dataDir = dir;
        c.quarantineDir = dir.resolve("quarantine");
        c.rateLimitMax = 3;
        return c;
    }

    private static AegisEvent event(String ip, ThreatLevel level, DataSource src, String... rules) {
        AegisEvent e = new AegisEvent();
        e.id = 1;
        e.ts = System.currentTimeMillis();
        e.ip = ip;
        e.internal = com.threatdetection.aegis.intel.IpClassifier.isInternal(ip);
        e.source = src;
        e.level = level;
        e.score = level == ThreatLevel.CRITICAL ? 120 : 90;
        for (String r : rules) e.rules.add(new AegisEvent.Contribution(r, 40, "core", "test"));
        return e;
    }

    private static AegisSignal signal(AegisSignal.Kind k, String user) {
        AegisSignal s = new AegisSignal(k);
        s.user = user;
        return s;
    }

    private static DefenseAction find(DefenseCoordinator d, Type t, String target) {
        for (DefenseAction a : d.list()) if (a.type == t && a.target.equals(target)) return a;
        return null;
    }

    public static void main(String[] args) throws Exception {
        Path tmp = Files.createTempDirectory("aegis-defense-test");
        System.out.println("Defense policy checks");

        check("HIGH maps to analyst approval, CRITICAL to reversible response, MEDIUM to monitor",
                ResponseLevel.of(ThreatLevel.HIGH) == ResponseLevel.ANALYST_APPROVAL
                        && ResponseLevel.of(ThreatLevel.CRITICAL) == ResponseLevel.AUTO_REVERSIBLE
                        && ResponseLevel.of(ThreatLevel.MEDIUM) == ResponseLevel.MONITOR);

        // ---- audit trail
        AuditTrail at = new AuditTrail(tmp.resolve("audit"));
        for (int i = 0; i < 5; i++) at.record("op", "ACT" + i, "t", "HIGH", "ENFORCE", "OK", "why", "1");
        check("audit chain verifies when untouched", at.verify().ok() && at.verify().records() == 5);
        Path af = at.file();
        List<String> lines = Files.readAllLines(af);
        lines.set(2, lines.get(2).replace("ACT2", "ACTX"));
        Files.write(af, lines);
        AuditTrail.Verification v = at.verify();
        check("editing one audit record is detected (at record 3)", !v.ok() && v.firstBadSeq() == 3);
        lines = Files.readAllLines(af);
        lines.set(2, lines.get(2).replace("ACTX", "ACT2"));
        lines.remove(1);
        Files.write(af, lines);
        check("deleting an audit record is detected", !at.verify().ok());

        // ---- CRITICAL, observed, corroborated -> automatic reversible block
        FakeFirewall fw = new FakeFirewall();
        DefenseConfig cfg = config(tmp.resolve("a"), DefenseMode.ENFORCE);
        DefenseCoordinator d = coordinator(cfg, fw);
        d.onEvent(event("203.0.113.5", ThreatLevel.CRITICAL, DataSource.OBSERVED, "BRUTE_FORCE", "BLACKLISTED_IP"), signal(AegisSignal.Kind.NETWORK, "x"));
        DefenseAction a = find(d, Type.FIREWALL_BLOCK, "203.0.113.5");
        check("CRITICAL + OBSERVED + 2 rules -> block applied automatically", a != null && a.state == State.ACTIVE && fw.blocked.contains("203.0.113.5"));
        check("automatic block has an expiry (never permanent)", a != null && a.expiresAt > System.currentTimeMillis() && a.expiresAt <= System.currentTimeMillis() + DefenseConfig.MAX_TTL_MS);
        check("audit records operator, action, target and result", d.audit().tail(10).stream().anyMatch(r ->
                r.operator().equals("system:policy") && r.action().equals("FIREWALL_BLOCK") && r.target().equals("203.0.113.5") && r.result().startsWith("APPLIED")));

        d.onEvent(event("203.0.113.5", ThreatLevel.CRITICAL, DataSource.OBSERVED, "BRUTE_FORCE", "BLACKLISTED_IP"), null);
        check("same target is not blocked twice", fw.blocked.size() == 1);

        d.onEvent(event("203.0.113.6", ThreatLevel.CRITICAL, DataSource.OBSERVED, "BRUTE_FORCE"), null);
        DefenseAction single = find(d, Type.FIREWALL_BLOCK, "203.0.113.6");
        check("single heuristic signal is NOT enough for an automatic block -> pending", single != null && single.state == State.PENDING && !fw.blocked.contains("203.0.113.6"));

        d.onEvent(event("203.0.113.7", ThreatLevel.CRITICAL, DataSource.API, "BRUTE_FORCE", "SQL_INJECTION"), null);
        DefenseAction api = find(d, Type.FIREWALL_BLOCK, "203.0.113.7");
        check("API (unverified) data never triggers an automatic action", api != null && api.state == State.PENDING);

        d.onEvent(event("203.0.113.8", ThreatLevel.CRITICAL, DataSource.SIMULATED, "BRUTE_FORCE", "SQL_INJECTION"), null);
        check("SIMULATED events are ignored completely", find(d, Type.FIREWALL_BLOCK, "203.0.113.8") == null);

        d.onEvent(event("10.1.2.3", ThreatLevel.CRITICAL, DataSource.OBSERVED, "BRUTE_FORCE", "SQL_INJECTION"), null);
        check("internal/private address is never blocked", find(d, Type.FIREWALL_BLOCK, "10.1.2.3") == null);

        AegisEvent old = event("203.0.113.9", ThreatLevel.CRITICAL, DataSource.OBSERVED, "BRUTE_FORCE", "SQL_INJECTION");
        old.ts = System.currentTimeMillis() - 3600_000L;
        d.onEvent(old, null);
        check("replayed history (old timestamp) never triggers a response", find(d, Type.FIREWALL_BLOCK, "203.0.113.9") == null);

        d.onEvent(event("203.0.113.10", ThreatLevel.MEDIUM, DataSource.OBSERVED, "BRUTE_FORCE", "SQL_INJECTION"), null);
        check("MEDIUM is monitor-only", find(d, Type.FIREWALL_BLOCK, "203.0.113.10") == null && find(d, Type.RATE_LIMIT, "203.0.113.10") == null);

        // ---- HIGH -> pending, approve, rate limiting
        d.onEvent(event("198.51.100.4", ThreatLevel.HIGH, DataSource.OBSERVED, "BRUTE_FORCE", "SQL_INJECTION"), null);
        DefenseAction rl = find(d, Type.RATE_LIMIT, "198.51.100.4");
        check("HIGH proposes an action but runs nothing", rl != null && rl.state == State.PENDING && d.controls().allowRequest("198.51.100.4"));
        check("analyst approval applies it", d.approve(rl.id, "alice") == null && rl.state == State.ACTIVE && "alice".equals(rl.decidedBy));
        boolean limited = false;
        for (int i = 0; i < 6; i++) if (!d.controls().allowRequest("198.51.100.4")) limited = true;
        check("rate limit restricts repeated requests from that source only", limited && d.controls().allowRequest("198.51.100.99"));
        check("analyst can undo an active action", d.revert(rl.id, "alice") == null && rl.state == State.REVERTED && d.controls().allowRequest("198.51.100.4"));
        check("approval decision is audited with the operator", d.audit().tail(50).stream().anyMatch(r -> r.operator().equals("alice") && r.action().equals("RATE_LIMIT")));
        check("rejecting leaves everything untouched", d.reject(single.id, "bob") == null && single.state == State.REJECTED && !fw.blocked.contains("203.0.113.6"));

        // ---- account protection
        AegisSignal auth = signal(AegisSignal.Kind.AUTH, "mallory");
        d.onEvent(event("198.51.100.20", ThreatLevel.HIGH, DataSource.OBSERVED, "BRUTE_FORCE", "SQL_INJECTION"), auth);
        DefenseAction lock = find(d, Type.LOCK_ACCOUNT, "mallory");
        check("account lock is only proposed (never automatic by default)", lock != null && lock.state == State.PENDING && !d.controls().accountLocked("mallory"));
        d.approve(lock.id, "alice");
        check("approved lock is enforced through the check list", d.controls().accountLocked("mallory"));
        d.onEvent(event("198.51.100.21", ThreatLevel.HIGH, DataSource.OBSERVED, "BRUTE_FORCE", "SQL_INJECTION"), signal(AegisSignal.Kind.AUTH, "Administrator"));
        check("protected accounts are never proposed for locking", find(d, Type.LOCK_ACCOUNT, "Administrator") == null);
        DefenseAction forced = d.manual(Type.LOCK_ACCOUNT, "administrator", "test", "alice");
        check("even an analyst cannot lock a protected account", forced.state == State.FAILED);
        DefenseAction ownIp = d.manual(Type.FIREWALL_BLOCK, "192.168.1.1", "test", "alice");
        check("even an analyst cannot block a private/allowlisted address", ownIp.state == State.FAILED && !fw.blocked.contains("192.168.1.1"));

        // ---- session revocation
        AegisSignal sess = signal(AegisSignal.Kind.WEB, "u");
        sess.session = "sess-abc";
        d.onEvent(event("203.0.113.30", ThreatLevel.CRITICAL, DataSource.OBSERVED, "SQL_INJECTION", "BLACKLISTED_IP"), sess);
        check("session is revoked automatically on a corroborated CRITICAL", d.controls().sessionRevoked("sess-abc"));

        // ---- automatic recovery
        FakeFirewall fw2 = new FakeFirewall();
        DefenseConfig c2 = config(tmp.resolve("b"), DefenseMode.ENFORCE);
        c2.ttlMs = 150;
        DefenseCoordinator d2 = coordinator(c2, fw2);
        d2.onEvent(event("203.0.113.40", ThreatLevel.CRITICAL, DataSource.OBSERVED, "A", "B"), null);
        Thread.sleep(250);
        d2.sweep();
        DefenseAction ex = find(d2, Type.FIREWALL_BLOCK, "203.0.113.40");
        check("expired block is removed automatically", ex != null && ex.state == State.EXPIRED && fw2.unblocked.contains("203.0.113.40"));
        check("restoration is recorded in the audit trail", d2.audit().tail(20).stream().anyMatch(r -> r.operator().equals("system:recovery") && r.result().startsWith("RESTORED")));

        // ---- restart recovery: a block that expired while AEGIS was down is removed on startup
        FakeFirewall fw3 = new FakeFirewall();
        DefenseConfig c3 = config(tmp.resolve("c"), DefenseMode.ENFORCE);
        c3.ttlMs = 100;
        DefenseCoordinator d3 = coordinator(c3, fw3);
        d3.onEvent(event("203.0.113.41", ThreatLevel.CRITICAL, DataSource.OBSERVED, "A", "B"), null);
        Thread.sleep(200);
        FakeFirewall fw3b = new FakeFirewall();
        DefenseCoordinator d3b = coordinator(c3, fw3b);
        d3b.start();
        check("block that expired while AEGIS was stopped is lifted on restart", fw3b.unblocked.contains("203.0.113.41"));
        DefenseCoordinator d3c = coordinator(c3, new FakeFirewall());
        check("audit chain stays valid across restarts", d3c.audit().verify().ok());

        // ---- circuit breaker
        FakeFirewall fw4 = new FakeFirewall();
        DefenseConfig c4 = config(tmp.resolve("d"), DefenseMode.ENFORCE);
        c4.maxAutoPerMinute = 2;
        DefenseCoordinator d4 = coordinator(c4, fw4);
        for (int i = 50; i < 55; i++) d4.onEvent(event("203.0.113." + i, ThreatLevel.CRITICAL, DataSource.OBSERVED, "A", "B"), null);
        check("circuit breaker caps automatic actions (flood of spoofed sources)", fw4.blocked.size() == 2
                && d4.list().stream().filter(x -> x.state == State.PENDING).count() == 3);

        // ---- dry run
        FakeFirewall fw5 = new FakeFirewall();
        DefenseCoordinator d5 = coordinator(config(tmp.resolve("e"), DefenseMode.DRY_RUN), fw5);
        d5.onEvent(event("203.0.113.60", ThreatLevel.CRITICAL, DataSource.OBSERVED, "A", "B"), null);
        DefenseAction dry = find(d5, Type.FIREWALL_BLOCK, "203.0.113.60");
        check("DRY_RUN decides and audits but changes nothing", dry != null && dry.state == State.DRY_RUN && fw5.blocked.isEmpty());
        d5.onEvent(event("203.0.113.60", ThreatLevel.CRITICAL, DataSource.OBSERVED, "A", "B"), null);
        check("DRY_RUN does not repeat itself for the same target", d5.list().stream().filter(x -> x.target.equals("203.0.113.60")).count() == 1);

        DefenseCoordinator d6 = coordinator(config(tmp.resolve("f"), DefenseMode.OFF), new FakeFirewall());
        d6.onEvent(event("203.0.113.61", ThreatLevel.CRITICAL, DataSource.OBSERVED, "A", "B"), null);
        check("OFF mode does nothing", d6.list().isEmpty());

        // ---- quarantine
        Path root = Files.createDirectories(tmp.resolve("watched"));
        Path bad = root.resolve("evil.exe");
        Files.writeString(bad, "payload-bytes");
        QuarantineService q = new QuarantineService(tmp.resolve("q"), List.of(root));
        QuarantineService.Held h = q.quarantine(bad.toString(), "test");
        check("quarantine moves the file and keeps its bytes (nothing deleted)", !Files.exists(bad)
                && Files.readString(tmp.resolve("q").resolve(h.id() + ".quarantined")).equals("payload-bytes") && h.sha256().length() == 64);
        check("restore puts the file back exactly", q.restore(h.id()) == null && Files.readString(bad).equals("payload-bytes"));
        Path outside = Files.writeString(tmp.resolve("outside.txt"), "x");
        check("files outside the configured roots are refused", q.refusal(outside.toString()) != null && Files.exists(outside));
        check("system locations are refused", q.refusal("/etc/passwd") != null);
        check("with no roots configured quarantine is off", new QuarantineService(tmp.resolve("q2"), List.of()).refusal(bad.toString()) != null);
        DefenseConfig c7 = config(tmp.resolve("g"), DefenseMode.ENFORCE);
        c7.quarantineRoots.add(root);
        DefenseCoordinator d7 = coordinator(c7, new FakeFirewall());
        AegisSignal proc = signal(AegisSignal.Kind.PROCESS, "u");
        proc.path = bad.toString();
        d7.onEvent(event("203.0.113.70", ThreatLevel.CRITICAL, DataSource.OBSERVED, "A", "B"), proc);
        DefenseAction qa = find(d7, Type.QUARANTINE_FILE, bad.toString());
        check("quarantine always waits for an analyst by default", qa != null && qa.state == State.PENDING && Files.exists(bad));
        d7.approve(qa.id, "alice");
        check("approved quarantine moves the file; undo restores it", qa.state == State.ACTIVE && !Files.exists(bad)
                && d7.revert(qa.id, "alice") == null && Files.exists(bad));

        // ---- netsh command safety
        FirewallBackend fb = new FirewallBackend();
        check("netsh command is an argument list with the shared rule name (no shell)", fb.addCommand("203.0.113.5").contains("name=AEGIS-BLOCK-203.0.113.5-IN")
                && fb.addCommand("203.0.113.5").get(0).equals("netsh"));
        check("injection-style target is refused", fb.block("1.2.3.4 & calc").startsWith("refused"));

        System.out.println("\n" + passed + " passed, " + failed + " failed");
        if (failed > 0) System.exit(1);
    }
}
