package com.threatdetection.testing;

import com.sun.net.httpserver.Headers;
import com.threatdetection.aegis.Aegis;
import com.threatdetection.aegis.AegisEvent;
import com.threatdetection.aegis.DataSource;
import com.threatdetection.aegis.defense.FirewallBackend;
import com.threatdetection.aegis.storage.AegisPersistence;
import com.threatdetection.engine.ThreatDetectionEngine;
import com.threatdetection.intelligence.ThreatIntelService;
import com.threatdetection.model.ThreatLevel;
import com.threatdetection.response.Allowlist;
import com.threatdetection.response.AuditLogger;
import com.threatdetection.response.AutoResponseService;
import com.threatdetection.response.OsResponseCoordinator;
import com.threatdetection.response.OsResponseCoordinator.ApprovalState;
import com.threatdetection.response.ResponsePolicyEngine;
import com.threatdetection.response.WindowsFirewallAdapter;
import com.threatdetection.response.WindowsFirewallAdapter.CommandResult;
import com.threatdetection.response.WindowsFirewallAdapter.Mode;
import com.threatdetection.response.WindowsFirewallAdapter.Status;
import com.threatdetection.server.ApiServer;
import com.threatdetection.server.WriteGuard;
import com.threatdetection.storage.InMemoryStore;

import java.net.InetAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;

/**
 * Regression tests for the audit fixes.  java -cp out com.threatdetection.testing.HardeningTestSuite
 * Nothing here touches the real firewall: every netsh call goes to a scripted fake runner, and the HTTP tests talk to a
 * loopback server on a random port. Exit code 0 = all passed.
 */
public final class HardeningTestSuite {
    private static int run, failed;
    private static void check(String name, boolean ok) {
        run++;
        if (!ok) { failed++; System.out.println("FAIL  " + name); }
    }

    /** Scripted netsh: records every call; the script decides each result (default exit 0). */
    static final class Fake implements WindowsFirewallAdapter.CommandRunner {
        final List<String> calls = Collections.synchronizedList(new ArrayList<>());
        volatile Function<String, CommandResult> script = c -> new CommandResult(0, "Ok.");
        volatile boolean throwIo;
        @Override public CommandResult run(List<String> argv) throws java.io.IOException {
            String c = String.join(" ", argv);
            calls.add(c);
            if (throwIo) throw new java.io.IOException("cannot start netsh");
            return script.apply(c);
        }
        long count(String part) { synchronized (calls) { return calls.stream().filter(x -> x.contains(part)).count(); } }
    }

    private static WindowsFirewallAdapter fw(Mode m, boolean windows, boolean admin, Fake f, Path state, int max) {
        return new WindowsFirewallAdapter(m, f, windows, admin, new Allowlist(true, "198.51.100.200"), AuditLogger.memoryOnly(), state, max, false);
    }

    public static void main(String[] args) throws Exception {
        System.setProperty("aegis.persist", "false");
        firewallFailures();
        approvals();
        blockCap();
        engineReporting();
        writeGuardUnit();
        httpIntegration();
        persistence();
        defenseUnification();
        chainAutoBlock();
        System.out.println(run + " checks, " + failed + " failed");
        System.exit(failed == 0 ? 0 : 1);
    }

    // ------------------------------------------------------------------ 1,2: firewall adapter

    private static void firewallFailures() throws Exception {
        Path state = Files.createTempFile("fwstate", ".tsv");
        Fake f = new Fake();
        WindowsFirewallAdapter a = fw(Mode.ENFORCE, true, true, f, state, 5);
        check("fw: block applies", a.block("203.0.113.9", 600_000, "t", "t").status() == Status.APPLIED && a.tracks("203.0.113.9"));

        // unblock fails (delete nonzero AND the rule is still listed) -> entry must survive for a retry
        f.script = c -> c.contains(" delete rule") ? new CommandResult(1, "Access is denied") : new CommandResult(0, "Rule Name: x");
        WindowsFirewallAdapter.Outcome bad = a.unblock("203.0.113.9", "t", "t");
        check("fw: failed unblock reports ERROR", bad.status() == Status.ERROR);
        check("fw: failed unblock keeps the registry entry (retry possible)", a.tracks("203.0.113.9"));
        check("fw: failed unblock keeps the persisted entry", Files.readString(state).contains("203.0.113.9"));
        f.script = c -> new CommandResult(0, "Ok.");
        check("fw: retry succeeds and clears the entry", a.unblock("203.0.113.9", "t", "t").status() == Status.APPLIED && !a.tracks("203.0.113.9"));
        check("fw: persisted table is emptied after the confirmed removal", !Files.readString(state).contains("203.0.113.9"));

        // stale registry entry: rule already gone from the OS (delete fails, show also fails) -> cleared, not stuck
        a.block("203.0.113.10", 600_000, "t", "t");
        f.script = c -> new CommandResult(1, "No rules match the specified criteria.");
        check("fw: stale entry (rule already gone) is cleared as success", a.unblock("203.0.113.10", "t", "t").status() == Status.APPLIED && !a.tracks("203.0.113.10"));

        // orphan: OS rule exists, registry has nothing
        f.script = c -> new CommandResult(0, "Deleted 1 rule(s).");
        check("fw: orphan OS rule is removed when asked", a.unblock("203.0.113.11", "t", "t").status() == Status.APPLIED);
        f.script = c -> new CommandResult(1, "No rules match");
        check("fw: unknown address with no OS rule is REFUSED (not found)", a.unblock("203.0.113.12", "t", "t").status() == Status.REFUSED);

        // block failures: nonzero exit, timeout (-1), process cannot start, missing permission
        Fake f2 = new Fake();
        f2.script = c -> new CommandResult(1, "The requested operation requires elevation");
        WindowsFirewallAdapter b = fw(Mode.ENFORCE, true, true, f2, null, 5);
        check("fw: netsh nonzero exit -> ERROR and nothing tracked", b.block("203.0.113.20", 600_000, "t", "t").status() == Status.ERROR && !b.tracks("203.0.113.20"));
        f2.script = c -> new CommandResult(-1, "timeout");
        check("fw: netsh timeout -> ERROR and nothing tracked", b.block("203.0.113.21", 600_000, "t", "t").status() == Status.ERROR && !b.tracks("203.0.113.21"));
        f2.throwIo = true;
        check("fw: netsh cannot start -> ERROR and nothing tracked", b.block("203.0.113.22", 600_000, "t", "t").status() == Status.ERROR && !b.tracks("203.0.113.22"));
        Fake f3 = new Fake();
        check("fw: not elevated -> dry-run, no netsh call", fw(Mode.ENFORCE, true, false, f3, null, 5).block("203.0.113.23", 600_000, "t", "t").status() == Status.DRY_RUN && f3.calls.isEmpty());

        // duplicates / allowlist / cap
        Fake f4 = new Fake();
        WindowsFirewallAdapter c = fw(Mode.ENFORCE, true, true, f4, null, 2);
        c.block("203.0.113.30", 600_000, "t", "t");
        long adds = f4.count(" add rule");
        check("fw: duplicate block does not add a second rule", c.block("203.0.113.30", 600_000, "t", "t").status() == Status.ALREADY_BLOCKED && f4.count(" add rule") == adds);
        check("fw: allowlisted address is refused even in ENFORCE, with no netsh call", c.block("198.51.100.200", 600_000, "t", "t").status() == Status.REFUSED && f4.count("198.51.100.200") == 0);
        check("fw: internal address is refused", c.block("10.0.0.5", 600_000, "t", "t").status() == Status.REFUSED);
        check("fw: injection-style address is refused", c.block("1.2.3.4 & calc", 600_000, "t", "t").status() == Status.REFUSED);
        c.block("203.0.113.31", 600_000, "t", "t");
        check("fw: rule cap enforced", c.block("203.0.113.32", 600_000, "t", "t").status() == Status.REFUSED);

        // rollbackAll with one failure keeps the failed one tracked
        Fake f5 = new Fake();
        WindowsFirewallAdapter d = fw(Mode.ENFORCE, true, true, f5, null, 5);
        d.block("203.0.113.40", 600_000, "t", "t"); d.block("203.0.113.41", 600_000, "t", "t");
        f5.script = x -> x.contains("203.0.113.41") ? (x.contains(" delete rule") ? new CommandResult(1, "denied") : new CommandResult(0, "listed")) : new CommandResult(0, "Ok.");
        int n = d.rollbackAll("t", "test");
        check("fw: rollbackAll counts only confirmed removals and keeps the failed rule", n == 1 && d.tracks("203.0.113.41") && !d.tracks("203.0.113.40"));

        // restart recovery: expired rule whose removal fails stays tracked for retry
        Path st2 = Files.createTempFile("fwstate2", ".tsv");
        Files.writeString(st2, "203.0.113.50\t1000\t2000\told\ngarbage line\n203.0.113.51\tx\ty\tbad numbers\n");
        Fake f6 = new Fake();
        f6.script = x -> x.contains(" delete rule") ? new CommandResult(1, "denied") : new CommandResult(0, "listed");
        WindowsFirewallAdapter e = fw(Mode.ENFORCE, true, true, f6, st2, 5);
        check("fw: expired rule with failed removal is kept after restart; corrupt lines are skipped", e.tracks("203.0.113.50") && !e.tracks("203.0.113.51"));
        check("fw: no .tmp file is left behind by the atomic save", !Files.exists(Path.of(st2.toString() + ".tmp")));
        for (WindowsFirewallAdapter w : List.of(a, b, c, d, e)) w.close();
    }

    // ------------------------------------------------------------------ 3: approvals

    private static OsResponseCoordinator coordinator(Fake f, Mode m, boolean alwaysApprove) {
        Allowlist al = new Allowlist(true, "198.51.100.200");
        AuditLogger audit = AuditLogger.memoryOnly();
        WindowsFirewallAdapter a = new WindowsFirewallAdapter(m, f, true, true, al, audit, null, 10, false);
        return new OsResponseCoordinator(a, new ResponsePolicyEngine(al, 0.7, alwaysApprove), audit);
    }

    private static void approvals() throws Exception {
        Fake f = new Fake();
        OsResponseCoordinator oc = coordinator(f, Mode.ENFORCE, true);
        oc.handleDetailed("203.0.113.60", 150, ThreatLevel.CRITICAL, List.of("SQL_INJECTION", "BRUTE_FORCE"), "t");
        long id = oc.pending().get(0).id();
        f.script = c -> c.contains(" add rule") ? new CommandResult(1, "denied") : new CommandResult(0, "ok");
        WindowsFirewallAdapter.Outcome o = oc.approve(id, "alice");
        check("approve: failed action is reported as ERROR", o.status() == Status.ERROR);
        check("approve: failed request is NOT lost, it stays open as FAILED",
                oc.pending().size() == 1 && oc.history().get(0).state() == ApprovalState.FAILED && oc.history().get(0).decidedBy().equals("alice"));
        f.script = c -> new CommandResult(0, "ok");
        check("approve: retry after failure applies the block", oc.approve(id, "bob").status() == Status.APPLIED && oc.pending().isEmpty());
        long adds = f.count(" add rule");
        oc.approve(id, "carol");
        check("approve: approving again never runs the action a second time", f.count(" add rule") == adds && oc.history().get(0).state() == ApprovalState.APPLIED);

        // concurrent approvals of one request -> exactly one firewall action
        Fake f2 = new Fake();
        OsResponseCoordinator oc2 = coordinator(f2, Mode.ENFORCE, true);
        oc2.handleDetailed("203.0.113.61", 150, ThreatLevel.CRITICAL, List.of("SQL_INJECTION"), "t");
        long id2 = oc2.pending().get(0).id();
        ExecutorService ex = Executors.newFixedThreadPool(16);
        CountDownLatch go = new CountDownLatch(1);
        for (int i = 0; i < 16; i++) { int k = i; ex.submit(() -> { go.await(); return oc2.approve(id2, "analyst" + k); }); }
        go.countDown(); ex.shutdown(); ex.awaitTermination(10, java.util.concurrent.TimeUnit.SECONDS);
        check("approve: 16 concurrent approvals create exactly one rule", f2.count(" add rule") == 1);

        // refusal (allowlisted address got queued by an older policy) is final and audited
        Fake f3 = new Fake();
        OsResponseCoordinator oc3 = coordinator(f3, Mode.ENFORCE, true);
        oc3.handleDetailed("203.0.113.62", 150, ThreatLevel.CRITICAL, List.of("SQL_INJECTION"), "t");
        long id3 = oc3.pending().get(0).id();
        oc3.firewall().rollbackAll("t", "t");
        Allowlist.class.getName();
        check("approve: dry-run outcome is recorded as DRY_RUN, not APPLIED", dryRunState());
        check("approve: unknown request id is refused", oc3.approve(9999, "x").status() == Status.REFUSED);
        check("reject: an open request can be rejected once", oc3.reject(id3, "dave") && !oc3.reject(id3, "dave") && oc3.pending().isEmpty());
        check("reject: history keeps who rejected it", oc3.history().get(0).state() == ApprovalState.REJECTED && oc3.history().get(0).decidedBy().equals("dave"));
        check("policy: out-of-range confidence property falls back to the default", clampedPolicy());
    }

    private static boolean dryRunState() {
        Fake f = new Fake();
        OsResponseCoordinator oc = coordinator(f, Mode.DRY_RUN, true);
        oc.handleDetailed("203.0.113.70", 150, ThreatLevel.CRITICAL, List.of("SQL_INJECTION"), "t");
        long id = oc.pending().get(0).id();
        WindowsFirewallAdapter.Outcome o = oc.approve(id, "erin");
        return o.status() == Status.DRY_RUN && oc.history().get(0).state() == ApprovalState.DRY_RUN && f.calls.isEmpty();
    }

    private static boolean clampedPolicy() {
        System.setProperty("aegis.response.confidence", "-5");
        try {
            ResponsePolicyEngine p = ResponsePolicyEngine.fromSystemProperties(new Allowlist(true, ""));
            return p.decide("203.0.113.5", ThreatLevel.CRITICAL, 0.1).action() != ResponsePolicyEngine.Action.BLOCK;
        } finally { System.clearProperty("aegis.response.confidence"); }
    }

    // ------------------------------------------------------------------ 9, 11: block cap and allowlist under concurrency

    private static void blockCap() throws Exception {
        System.setProperty("aegis.block.max", "20");
        try {
            int worst = 0;
            for (int round = 0; round < 40; round++) {           // repeated, barrier-released rounds make the old check-then-insert race show up reliably
                InMemoryStore store = new InMemoryStore();
                AutoResponseService svc = new AutoResponseService(store, new Allowlist(true, "198.51.100.200"));
                int threads = 64;
                ExecutorService ex = Executors.newFixedThreadPool(threads);
                java.util.concurrent.CyclicBarrier barrier = new java.util.concurrent.CyclicBarrier(threads);
                AtomicInteger accepted = new AtomicInteger();
                for (int i = 0; i < threads; i++) {
                    int k = i, rd = round;
                    ex.submit(() -> { barrier.await(); if (svc.block("203.0." + rd + "." + (k + 1)) == null) accepted.incrementAndGet(); return null; });
                }
                ex.shutdown(); ex.awaitTermination(20, java.util.concurrent.TimeUnit.SECONDS);
                worst = Math.max(worst, Math.max(accepted.get(), store.getBlockedIps().size()));
                if (round == 0) {
                    check("cap: an already-blocked address can still be extended when the table is full", svc.block(store.getBlockedIps().iterator().next()) == null);
                    check("cap: a new address is refused when full", svc.block("203.0.250.250") != null && svc.block("203.0.250.250").contains("full"));
                    check("cap: allowlisted address is never blocked", svc.block("198.51.100.200") != null && !svc.isBlocked("198.51.100.200"));
                    check("cap: null/blank address is refused", svc.block(null) != null && svc.block(" ") != null);
                }
            }
            check("cap: 40 rounds of 64 concurrent distinct blocks never exceed the configured limit (20), worst seen " + worst, worst == 20);
        } finally { System.clearProperty("aegis.block.max"); }
    }

    // ------------------------------------------------------------------ 5: reporting

    private static void engineReporting() {
        for (Mode mode : List.of(Mode.DRY_RUN, Mode.ENFORCE)) {
            InMemoryStore store = new InMemoryStore();
            ThreatDetectionEngine engine = new ThreatDetectionEngine(store, ThreatIntelService.demo());
            Fake f = new Fake();
            engine.responseService().attachOsResponse(coordinator(f, mode, false));
            com.threatdetection.model.ThreatResult r = null;
            for (int i = 0; i < 30 && (r == null || r.level != ThreatLevel.CRITICAL); i++) {
                r = engine.process(new com.threatdetection.model.LogEvent("203.0.113.8" + mode.ordinal(), "admin", "/login?id=1' OR 1=1--",
                        "sqlmap/1.7", "' UNION SELECT password FROM users--", "Russia", com.threatdetection.model.EventType.LOGIN_FAILED, 0, ""));
            }
            boolean critical = r != null && r.level == ThreatLevel.CRITICAL;
            check("report[" + mode + "]: scenario reached CRITICAL", critical);
            if (!critical) continue;
            if (mode == Mode.DRY_RUN) {
                check("report[DRY_RUN]: app-level block is reported, OS firewall is DRY_RUN and NOT enforced",
                        r.blocked && r.appBlocked() && r.osFirewall.equals("DRY_RUN") && !r.osEnforced() && f.calls.isEmpty());
            } else {
                check("report[ENFORCE]: OS firewall rule really created is reported as APPLIED",
                        r.blocked && r.osFirewall.equals("APPLIED") && r.osEnforced() && f.count(" add rule") == 1);
            }
        }
        // no OS response attached at all
        InMemoryStore store = new InMemoryStore();
        ThreatDetectionEngine engine = new ThreatDetectionEngine(store, ThreatIntelService.demo());
        com.threatdetection.model.ThreatResult r = null;
        for (int i = 0; i < 30 && (r == null || r.level != ThreatLevel.CRITICAL); i++) {
            r = engine.process(new com.threatdetection.model.LogEvent("203.0.113.88", "admin", "/login?id=1' OR 1=1--", "sqlmap/1.7",
                    "' UNION SELECT password FROM users--", "Russia", com.threatdetection.model.EventType.LOGIN_FAILED, 0, ""));
        }
        check("report: without an OS response the result says NOT_ATTACHED and not enforced", r != null && r.osFirewall.equals("NOT_ATTACHED") && !r.osEnforced());
    }

    // ------------------------------------------------------------------ 4: WriteGuard (pure decision function)

    private static Headers h(String... kv) {
        Headers x = new Headers();
        for (int i = 0; i < kv.length; i += 2) x.add(kv[i], kv[i + 1]);
        return x;
    }

    private static void writeGuardUnit() throws Exception {
        InetAddress lo = InetAddress.getByName("127.0.0.1"), remote = InetAddress.getByName("203.0.113.5");
        System.setProperty("aegis.api.key", "s3cret-key");
        try {
            WriteGuard.resetForTests();
            String H = "127.0.0.1:8080";
            check("guard: missing key -> 401", WriteGuard.check("POST", lo, h("Host", H)).status() == 401);
            check("guard: wrong key -> 401", WriteGuard.check("POST", lo, h("Host", H, "X-API-Key", "nope")).status() == 401);
            check("guard: right key -> allowed", WriteGuard.check("POST", lo, h("Host", H, "X-API-Key", "s3cret-key")).ok());
            check("guard: Bearer token accepted", WriteGuard.check("POST", lo, h("Host", H, "Authorization", "Bearer s3cret-key")).ok());
            check("guard: loopback WITHOUT a key is not enough", WriteGuard.check("POST", lo, h("Host", H)).status() == 401);
            check("guard: remote client with the configured key is allowed", WriteGuard.check("POST", remote, h("Host", H, "X-API-Key", "s3cret-key")).ok());
            check("guard: CSRF - foreign Origin refused even with a key", WriteGuard.check("POST", lo, h("Host", H, "Origin", "http://evil.example", "X-API-Key", "s3cret-key")).status() == 403);
            check("guard: Origin null refused", WriteGuard.check("POST", lo, h("Host", H, "Origin", "null", "X-API-Key", "s3cret-key")).status() == 403);
            check("guard: same-origin Origin accepted", WriteGuard.check("POST", lo, h("Host", H, "Origin", "http://" + H, "X-API-Key", "s3cret-key")).ok());
            check("guard: Sec-Fetch-Site cross-site refused", WriteGuard.check("POST", lo, h("Host", H, "Sec-Fetch-Site", "cross-site", "X-API-Key", "s3cret-key")).status() == 403);
            check("guard: Sec-Fetch-Site same-origin accepted", WriteGuard.check("POST", lo, h("Host", H, "Sec-Fetch-Site", "same-origin", "X-API-Key", "s3cret-key")).ok());
            check("guard: DNS-rebinding Host refused", WriteGuard.check("POST", lo, h("Host", "attacker.example:8080", "X-API-Key", "s3cret-key")).status() == 403);
            check("guard: missing Host refused", WriteGuard.check("POST", lo, h("X-API-Key", "s3cret-key")).status() == 403);
            check("guard: body with a browser-simple/unsupported type -> 415", WriteGuard.check("POST", lo, h("Host", H, "Content-Length", "5", "Content-Type", "text/html", "X-API-Key", "s3cret-key")).status() == 415);
            check("guard: body without Content-Type -> 415", WriteGuard.check("POST", lo, h("Host", H, "Content-Length", "5", "X-API-Key", "s3cret-key")).status() == 415);
            check("guard: form body accepted", WriteGuard.check("POST", lo, h("Host", H, "Content-Length", "5", "Content-Type", "application/x-www-form-urlencoded; charset=UTF-8", "X-API-Key", "s3cret-key")).ok());
            check("guard: empty body needs no Content-Type", WriteGuard.check("POST", lo, h("Host", H, "Content-Length", "0", "X-API-Key", "s3cret-key")).ok());
        } finally { System.clearProperty("aegis.api.key"); WriteGuard.resetForTests(); }

        // no configured key: a generated per-run key, local only
        WriteGuard.resetForTests();
        String gen = WriteGuard.effectiveKey();
        check("guard: generated key is long and random", gen.length() >= 40 && !gen.equals(WriteGuard.effectiveKey().toUpperCase()) || gen.length() >= 40);
        check("guard: generated key works from loopback", WriteGuard.check("POST", lo, h("Host", "localhost:8080", "X-API-Key", gen)).ok());
        check("guard: generated key refused from a remote address", WriteGuard.check("POST", remote, h("Host", "localhost:8080", "X-API-Key", gen)).status() == 403);

        // rate limit
        System.setProperty("aegis.api.rate", "5");
        try {
            WriteGuard.resetForTests();
            String k = WriteGuard.effectiveKey();
            int tooMany = 0;
            for (int i = 0; i < 60; i++) if (WriteGuard.check("POST", lo, h("Host", "localhost", "X-API-Key", k)).status() == 429) tooMany++;
            check("guard: burst above the rate limit gets 429", tooMany > 0);
        } finally { System.clearProperty("aegis.api.rate"); WriteGuard.resetForTests(); }
    }

    // ------------------------------------------------------------------ 6, 7, 10, 15: real HTTP on loopback

    private static HttpResponse<String> send(HttpClient c, String method, String url, String body, String ct, String... hdr) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(url)).timeout(java.time.Duration.ofSeconds(10));
        if (ct != null) b.header("Content-Type", ct);
        for (int i = 0; i < hdr.length; i += 2) b.header(hdr[i], hdr[i + 1]);
        b.method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body));
        return c.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    private static void httpIntegration() throws Exception {
        System.setProperty("aegis.max.body", "4096");
        System.setProperty("aegis.api.rate", "100000");
        WriteGuard.resetForTests();
        InMemoryStore store = new InMemoryStore();
        ThreatDetectionEngine engine = new ThreatDetectionEngine(store, ThreatIntelService.demo());
        Aegis aegis = Aegis.create(store, engine, s -> new ThreatDetectionEngine(s, ThreatIntelService.demo()));
        ApiServer server = new ApiServer(aegis.engineFor(DataSource.API), store, 0);
        aegis.register(server);
        server.start();
        String base = "http://127.0.0.1:" + server.boundPort();
        String key = WriteGuard.effectiveKey();
        HttpClient c = HttpClient.newHttpClient();
        String form = "application/x-www-form-urlencoded";
        try {
            check("http: write without key -> 401", send(c, "POST", base + "/api/event", "ip=203.0.113.9", form).statusCode() == 401);
            HttpResponse<String> ok = send(c, "POST", base + "/api/event", "ip=203.0.113.9&eventType=LOGIN_FAILED&username=bob&port=22", form, "X-API-Key", key);
            check("http: valid event -> 200 with appBlocked/osFirewall fields and legacy blocked field",
                    ok.statusCode() == 200 && ok.body().contains("\"blocked\":") && ok.body().contains("\"appBlocked\":") && ok.body().contains("\"osFirewall\":"));
            String[][] bad = {
                    {"ip=not-an-ip", "bad IP"}, {"ip=999.1.1.1", "out-of-range IP"}, {"ip=0.0.0.0", "unspecified IP"}, {"eventType=LOGIN_FAILED", "missing IP"},
                    {"ip=203.0.113.9&eventType=NOPE", "bad event type"}, {"ip=203.0.113.9&port=abc", "non-numeric port"},
                    {"ip=203.0.113.9&port=70000", "port too high"}, {"ip=203.0.113.9&port=-1", "negative port"},
                    {"ip=203.0.113.9&username=" + "a".repeat(200), "oversized field"}, {"ip=203.0.113.9&body=%zz", "malformed percent-encoding"},
                    {"ip=203.0.113.9&country=<script>", "bad country"}};
            for (String[] b : bad) {
                HttpResponse<String> r = send(c, "POST", base + "/api/event", b[0], form, "X-API-Key", key);
                check("http: " + b[1] + " -> 400 JSON error without stack trace", r.statusCode() == 400 && r.body().startsWith("{\"error\"") && !r.body().contains("Exception") && !r.body().contains(" at com."));
            }
            check("http: invalid input has no side effect (nothing was recorded)", store.getTotalEvents() == 1);
            check("http: 70 KB body -> 413", send(c, "POST", base + "/api/event", "ip=203.0.113.9&body=" + "x".repeat(70_000), form, "X-API-Key", key).statusCode() == 413);
            check("http: wrong content type -> 415", send(c, "POST", base + "/api/event", "ip=203.0.113.9", "text/html", "X-API-Key", key).statusCode() == 415);
            check("http: cross-site Origin -> 403 and nothing recorded", send(c, "POST", base + "/api/event", "ip=203.0.113.9", form, "X-API-Key", key, "Origin", "http://evil.example").statusCode() == 403 && store.getTotalEvents() == 1);
            check("http: GET on a write endpoint -> 405", send(c, "GET", base + "/api/event", null, null).statusCode() == 405);

            // AegisApi ingest: auth, 413 (limit 4096 here), 400 for client errors, 500 is not used for bad input
            check("ingest: no key -> 401", send(c, "POST", base + "/aegis/api/ingest?type=web", "x", "text/plain").statusCode() == 401);
            check("ingest: oversized body -> 413", send(c, "POST", base + "/aegis/api/ingest?type=web", "a".repeat(8000), "text/plain", "X-API-Key", key).statusCode() == 413);
            check("ingest: unknown type -> 400", send(c, "POST", base + "/aegis/api/ingest?type=nope", "x", "text/plain", "X-API-Key", key).statusCode() == 400);
            check("ingest: malformed XML -> 400 (not 500)", send(c, "POST", base + "/aegis/api/ingest?type=winxml", "<Event><oops>", "application/xml", "X-API-Key", key).statusCode() == 400);
            check("ingest: XML with a DOCTYPE (XXE attempt) is rejected, not processed", send(c, "POST", base + "/aegis/api/ingest?type=winxml",
                    "<!DOCTYPE x [<!ENTITY e SYSTEM \"file:///etc/passwd\">]><Event>&e;</Event>", "application/xml", "X-API-Key", key).statusCode() == 400);
            check("ingest: valid wazuh line -> 200", send(c, "POST", base + "/aegis/api/ingest?type=wazuh",
                    "{\"timestamp\":\"2026-11-10T05:31:00.000+0000\",\"rule\":{\"id\":\"5710\",\"level\":10,\"description\":\"sshd\"},\"data\":{\"srcip\":\"203.0.113.88\"}}", "text/plain", "X-API-Key", key).statusCode() == 200);

            // session bootstrap + dashboard compatibility
            check("session: key is NOT handed out without the dashboard header", send(c, "GET", base + "/api/session", null, null).statusCode() == 404);
            HttpResponse<String> s = send(c, "GET", base + "/api/session", null, null, "X-AEGIS-Dashboard", "1");
            check("session: same-origin dashboard request receives the key", s.statusCode() == 200 && s.body().contains(key));
            check("session: cross-site request does not receive the key", send(c, "GET", base + "/api/session", null, null, "X-AEGIS-Dashboard", "1", "Sec-Fetch-Site", "cross-site").statusCode() == 404);
            HttpResponse<String> page = send(c, "GET", base + "/aegis", null, null);
            check("dashboard: page still served, with key bootstrap, no-framing header", page.statusCode() == 200 && page.body().contains("/api/session")
                    && "DENY".equals(page.headers().firstValue("X-Frame-Options").orElse("")));
            for (String path : List.of("/", "/classic", "/api/stats", "/aegis/api/overview", "/aegis/api/alerts", "/aegis/api/events")) {
                check("compat: GET " + path + " -> 200", send(c, "GET", base + path, null, null).statusCode() == 200);
            }
            check("compat: stats keeps its fields", send(c, "GET", base + "/api/stats", null, null).body().contains("\"recentThreats\""));
        } finally {
            server.stop();
            System.clearProperty("aegis.max.body"); System.clearProperty("aegis.api.rate"); WriteGuard.resetForTests();
        }
    }

    // ------------------------------------------------------------------ 8: persistence

    private static AegisEvent ev(long ts, String ip) {
        AegisEvent e = new AegisEvent();
        e.ts = ts; e.ip = ip; e.source = DataSource.API; e.level = ThreatLevel.HIGH; e.score = 70;
        e.kind = "WEB"; e.summary = "s" + ts;
        return e;
    }

    private static void persistence() throws Exception {
        Path dir = Files.createTempDirectory("pers");
        AegisPersistence p = new AegisPersistence(dir, 600, 3);
        for (int i = 1; i <= 40; i++) p.append(ev(i, "203.0.113.1"));
        long gens = Files.list(dir).filter(x -> x.getFileName().toString().startsWith("alerts.tsv.")).count();
        check("persist: rotation keeps exactly the configured number of archives", gens == 3);
        List<AegisEvent> all = p.load(1000);
        check("persist: load reads across archives, newest data intact and in order", !all.isEmpty() && all.get(all.size() - 1).ts == 40
                && java.util.stream.IntStream.range(1, all.size()).allMatch(i -> all.get(i).ts > all.get(i - 1).ts));
        check("persist: only the oldest generation beyond retention is gone (not everything)", all.size() > 10);

        // torn last line + corrupt line + restart
        Path d2 = Files.createTempDirectory("pers2");
        AegisPersistence p2 = new AegisPersistence(d2);
        p2.append(ev(1, "203.0.113.2"));
        Files.writeString(d2.resolve("alerts.tsv"), Files.readString(d2.resolve("alerts.tsv")) + "garbage\n123\tpartial-line-no-newline", java.nio.file.StandardOpenOption.TRUNCATE_EXISTING);
        AegisPersistence p3 = new AegisPersistence(d2);   // "restart"
        p3.append(ev(2, "203.0.113.3"));
        List<AegisEvent> r = p3.load(100);
        check("persist: torn/corrupt lines are skipped and the next event is not glued to the torn one", r.size() == 2 && r.get(1).ts == 2 && r.get(1).ip.equals("203.0.113.3"));

        // interrupted rotation: live file missing, archive present
        Path d3 = Files.createTempDirectory("pers3");
        AegisPersistence p4 = new AegisPersistence(d3, 100_000, 3);
        p4.append(ev(7, "203.0.113.4"));
        Files.move(d3.resolve("alerts.tsv"), d3.resolve("alerts.tsv.1"));
        check("persist: crash between rotation steps loses nothing (archive is loaded)", new AegisPersistence(d3, 100_000, 3).load(10).size() == 1);

        // filesystem failure: the live file cannot be opened (it is a directory) -> no exception, failure counted
        Path d4 = Files.createTempDirectory("pers4");
        Files.createDirectory(d4.resolve("alerts.tsv"));
        AegisPersistence p5 = new AegisPersistence(d4);
        p5.append(ev(1, "203.0.113.5"));
        check("persist: write failure is counted and does not throw", p5.failures() == 1);
    }

    // ------------------------------------------------------------------ 2: Defense uses the shared adapter

    private static void defenseUnification() {
        Fake f = new Fake();
        WindowsFirewallAdapter shared = fw(Mode.ENFORCE, true, true, f, null, 10);
        FirewallBackend fb = new FirewallBackend();
        fb.bind(() -> shared);
        check("defense: block goes through the shared adapter with the single rule name", fb.block("203.0.113.80") == null
                && f.count("name=AEGIS-BLOCK-203.0.113.80-IN") == 1 && shared.tracks("203.0.113.80"));
        check("defense: the core engine's adapter sees (and can remove) the Defense rule", shared.unblock("203.0.113.80", "t", "t").status() == Status.APPLIED && !shared.tracks("203.0.113.80"));
        check("defense: unblocking a rule that already expired is success", fb.unblock("203.0.113.80") == null);
        check("defense: allowlisted address refused by the shared allowlist", fb.block("198.51.100.200") != null && f.count("198.51.100.200") == 0);
        check("defense: injection-style target refused", fb.block("1.2.3.4 & calc").startsWith("refused"));
        Fake f2 = new Fake();
        WindowsFirewallAdapter dry = fw(Mode.DRY_RUN, true, true, f2, null, 10);
        FirewallBackend fb2 = new FirewallBackend();
        fb2.bind(() -> dry);
        String msg = fb2.block("203.0.113.81");
        check("defense: dry-run adapter is reported as NOT enforced (never as success) and runs no netsh", msg != null && msg.startsWith("not enforced") && f2.calls.isEmpty());
        check("defense: with no adapter attached nothing is blocked and the reason is reported", new FirewallBackend().block("203.0.113.82") != null);
        Fake f3 = new Fake();
        f3.script = c -> new CommandResult(1, "denied");
        FirewallBackend fb3 = new FirewallBackend();
        fb3.bind(() -> fw(Mode.ENFORCE, true, true, f3, null, 10));
        check("defense: netsh failure is propagated as a failure", fb3.block("203.0.113.83") != null);
        shared.close(); dry.close();
    }

    // ------------------------------------------------------------------ 12: chain auto-block default

    private static void chainAutoBlock() throws Exception {
        java.lang.reflect.Constructor<com.threatdetection.correlation.AttackChainEngine.Finding> ctor =
                com.threatdetection.correlation.AttackChainEngine.Finding.class.getDeclaredConstructor(String.class, String.class, String.class, String.class);
        ctor.setAccessible(true);
        java.lang.reflect.Method m = Aegis.class.getDeclaredMethod("respondToChain", ThreatDetectionEngine.class, com.threatdetection.correlation.AttackChainEngine.Finding.class);
        m.setAccessible(true);
        for (boolean enable : new boolean[]{false, true}) {
            if (enable) System.setProperty("aegis.chain.autoblock", "true"); else System.clearProperty("aegis.chain.autoblock");
            InMemoryStore store = new InMemoryStore();
            ThreatDetectionEngine engine = new ThreatDetectionEngine(store, ThreatIntelService.demo());
            Fake f = new Fake();
            engine.responseService().attachOsResponse(coordinator(f, Mode.DRY_RUN, false));
            var fnd = ctor.newInstance("c1", "live", "ATTACK_CHAIN", "ip:203.0.113.90");
            fnd.ip = "203.0.113.90"; fnd.severity = "CRITICAL"; fnd.last = System.currentTimeMillis();
            fnd.ruleNames.add("SQL_INJECTION"); fnd.ruleNames.add("BRUTE_FORCE");
            m.invoke(null, engine, fnd);
            if (!enable) {
                check("chain: auto-block is OFF by default (no block, no response)", !engine.responseService().isBlocked("203.0.113.90") && fnd.response.isEmpty());
            } else {
                check("chain: auto-block only when deliberately enabled, and the response text separates app block from OS result",
                        engine.responseService().isBlocked("203.0.113.90") && fnd.response.startsWith("blocked in application") && fnd.response.contains("DRY_RUN") && f.calls.isEmpty());
            }
        }
        System.clearProperty("aegis.chain.autoblock");
    }
}
