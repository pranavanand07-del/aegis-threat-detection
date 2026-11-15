package com.threatdetection.testing;

import com.threatdetection.aegis.AegisEvent;
import com.threatdetection.aegis.AegisSignal;
import com.threatdetection.aegis.ingest.WindowsEventMapper;
import com.threatdetection.correlation.AttackChainEngine;
import com.threatdetection.intelligence.ThreatIntelService;
import com.threatdetection.model.ThreatLevel;
import com.threatdetection.normalization.EventNormalizer;
import com.threatdetection.platform.SelfTest;
import com.threatdetection.response.Allowlist;
import com.threatdetection.response.AuditLogger;
import com.threatdetection.response.ResponsePolicyEngine;
import com.threatdetection.response.WindowsFirewallAdapter;
import com.threatdetection.response.WindowsFirewallAdapter.Mode;
import com.threatdetection.response.WindowsFirewallAdapter.Status;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Runs everything without a framework:   java -cp out com.threatdetection.testing.DetectionTestSuite
 * Exit code 0 = all passed. Includes the 91-case rule self-test (attacks, near-misses and false-positive cases).
 */
public final class DetectionTestSuite {
    private static int run, failed;

    private static void check(String name, boolean ok) {
        run++;
        if (!ok) { failed++; System.out.println("FAIL  " + name); }
    }

    public static void main(String[] args) throws Exception {
        selfTest();
        windowsMapper();
        threatIntel();
        firewallAdapter();
        auditChain();
        correlation();
        normalizer();
        policy();
        System.out.println(run + " checks, " + failed + " failed");
        System.exit(failed == 0 ? 0 : 1);
    }

    private static void selfTest() {
        List<SelfTest.Case> cases = SelfTest.run();
        long bad = cases.stream().filter(c -> !c.pass()).count();
        check("rule self-test (" + cases.size() + " cases)", bad == 0);
    }

    // ---------------------------------------------------------------- Windows event mapping

    private static String sysmon3(boolean initiated) {
        return "<Event><System><EventID>3</EventID><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>SRV01</Computer>"
                + "<EventRecordID>9</EventRecordID><TimeCreated SystemTime=\"2026-11-10T10:00:00.000Z\"/></System><EventData>"
                + "<Data Name=\"Initiated\">" + initiated + "</Data>"
                + "<Data Name=\"SourceIp\">" + (initiated ? "10.0.0.5" : "203.0.113.9") + "</Data><Data Name=\"SourcePort\">" + (initiated ? "50123" : "61000") + "</Data>"
                + "<Data Name=\"DestinationIp\">" + (initiated ? "198.51.100.7" : "10.0.0.5") + "</Data><Data Name=\"DestinationPort\">" + (initiated ? "443" : "3389") + "</Data>"
                + "<Data Name=\"Image\">C:\\x.exe</Data><Data Name=\"User\">bob</Data></EventData></Event>";
    }

    private static String sec(int id, String ip) {
        return "<Event><System><EventID>" + id + "</EventID><Channel>Security</Channel><Computer>SRV01</Computer><EventRecordID>5</EventRecordID>"
                + "<TimeCreated SystemTime=\"2026-11-10T10:00:00.000Z\"/></System><EventData><Data Name=\"TargetUserName\">admin</Data>"
                + "<Data Name=\"LogonType\">3</Data><Data Name=\"IpAddress\">" + ip + "</Data></EventData></Event>";
    }

    private static void windowsMapper() throws Exception {
        AegisSignal out = WindowsEventMapper.parse(sysmon3(true)).get(0).signal;
        check("sysmon outbound: remote ip is the destination", out.ip.equals("198.51.100.7"));
        check("sysmon outbound: service port is the remote port, local port kept apart", out.port == 443 && out.remotePort == 443 && out.localPort == 50123);
        AegisSignal in = WindowsEventMapper.parse(sysmon3(false)).get(0).signal;
        check("sysmon inbound: remote ip is the source", in.ip.equals("203.0.113.9"));
        check("sysmon inbound: service port is the local listening port, peer port kept apart", in.port == 3389 && in.localPort == 3389 && in.remotePort == 61000);
        for (String bad : new String[]{"-", "", "garbage", "999.1.1.1"}) {
            AegisSignal s = WindowsEventMapper.parse(sec(4625, bad)).get(0).signal;
            check("4625 with address '" + bad + "' is not turned into localhost", s.ip.isEmpty() && s.ipMissing && s.toLogEvent() == null);
        }
        AegisSignal real = WindowsEventMapper.parse(sec(4625, "::ffff:203.0.113.4")).get(0).signal;
        check("IPv4-mapped IPv6 is unwrapped", real.ip.equals("203.0.113.4") && !real.ipMissing);
        AegisSignal loop = WindowsEventMapper.parse(sec(4625, "127.0.0.1")).get(0).signal;
        check("a genuine loopback address is kept as reported", loop.ip.equals("127.0.0.1") && !loop.ipMissing);
    }

    // ---------------------------------------------------------------- threat intel

    private static void threatIntel() throws Exception {
        ThreatIntelService empty = new ThreatIntelService();
        check("no blocklist configured: nothing is known-bad", empty.lookup("1.2.3.4") == null && empty.size() == 0);
        ThreatIntelService demo = ThreatIntelService.demo();
        check("demo entries are labelled as demo", demo.lookup("1.2.3.4") != null && demo.lookup("1.2.3.4").source().contains("DEMO"));
        Path f = Files.createTempFile("blocklist", ".txt");
        Files.writeString(f, "# my list\n203.0.113.0/24 scanner range\n198.51.100.9 botnet c2\nnot-an-ip\n");
        ThreatIntelService svc = new ThreatIntelService();
        svc.addFile(f);
        check("file: CIDR entry matches", svc.lookup("203.0.113.77") != null);
        check("file: exact entry carries its label", svc.lookup("198.51.100.9") != null && svc.lookup("198.51.100.9").label().equals("botnet c2"));
        check("file: junk line ignored, other addresses clean", svc.lookup("192.0.2.1") == null && svc.size() == 2);
        check("runtime add / remove", svc.add("192.0.2.50", "analyst", "manual", 0) && svc.lookup("192.0.2.50") != null
                && svc.remove("192.0.2.50") && svc.lookup("192.0.2.50") == null);
        svc.add("192.0.2.60", "analyst", "temporary", 1);
        Thread.sleep(20);
        check("expired entry no longer matches", svc.lookup("192.0.2.60") == null);
        check("invalid value rejected", !svc.add("hello", "x", "", 0));
        Files.deleteIfExists(f);
    }

    // ---------------------------------------------------------------- firewall adapter

    private static final class FakeNetsh implements WindowsFirewallAdapter.CommandRunner {
        final List<String> calls = new ArrayList<>();
        int exit = 0;
        @Override public WindowsFirewallAdapter.CommandResult run(List<String> argv) {
            calls.add(String.join(" ", argv));
            return new WindowsFirewallAdapter.CommandResult(exit, "");
        }
    }

    private static WindowsFirewallAdapter adapter(Mode m, boolean windows, boolean admin, FakeNetsh r, Path state, int max) {
        return new WindowsFirewallAdapter(m, r, windows, admin, new Allowlist(true, "198.51.100.200"),
                AuditLogger.memoryOnly(), state, max, false);
    }

    private static void firewallAdapter() throws Exception {
        FakeNetsh r = new FakeNetsh();
        WindowsFirewallAdapter dry = adapter(Mode.DRY_RUN, true, true, r, null, 10);
        check("dry-run: decision reported, nothing executed", dry.block("203.0.113.9", 600_000, "test", "t").status() == Status.DRY_RUN && r.calls.isEmpty());

        FakeNetsh r2 = new FakeNetsh();
        WindowsFirewallAdapter notAdmin = adapter(Mode.ENFORCE, true, false, r2, null, 10);
        check("enforce without Administrator falls back to dry-run", notAdmin.effectiveMode() == Mode.DRY_RUN
                && notAdmin.block("203.0.113.9", 600_000, "t", "t").status() == Status.DRY_RUN && r2.calls.isEmpty());
        check("enforce on a non-Windows machine falls back to dry-run", adapter(Mode.ENFORCE, false, true, new FakeNetsh(), null, 10).effectiveMode() == Mode.DRY_RUN);

        FakeNetsh r3 = new FakeNetsh();
        Path state = Files.createTempFile("fw", ".tsv");
        WindowsFirewallAdapter fw = adapter(Mode.ENFORCE, true, true, r3, state, 2);
        check("enforce: rule created with netsh and argument list", fw.block("203.0.113.9", 600_000, "t", "t").status() == Status.APPLIED
                && r3.calls.get(0).startsWith("netsh advfirewall firewall add rule name=AEGIS-BLOCK-203.0.113.9-IN dir=in action=block remoteip=203.0.113.9"));
        check("second block of the same address extends, does not duplicate", fw.block("203.0.113.9", 900_000, "t", "t").status() == Status.ALREADY_BLOCKED && r3.calls.size() == 1);
        check("internal address refused", fw.block("192.168.1.1", 600_000, "t", "t").status() == Status.REFUSED);
        check("allowlisted address refused", fw.block("198.51.100.200", 600_000, "t", "t").status() == Status.REFUSED);
        check("injection attempt refused", fw.block("1.2.3.4 & calc", 600_000, "t", "t").status() == Status.REFUSED
                && fw.block("1.2.3.4\" action=allow", 600_000, "t", "t").status() == Status.REFUSED);
        check("multicast / broadcast refused", fw.block("224.0.0.1", 600_000, "t", "t").status() == Status.REFUSED
                && fw.block("255.255.255.255", 600_000, "t", "t").status() == Status.REFUSED);
        fw.block("203.0.113.10", 600_000, "t", "t");
        check("rule cap enforced", fw.block("203.0.113.11", 600_000, "t", "t").status() == Status.REFUSED);
        check("rule table persisted", Files.readString(state).contains("203.0.113.9"));
        check("unblock removes the firewall rule", fw.unblock("203.0.113.9", "test", "t").status() == Status.APPLIED
                && r3.calls.stream().anyMatch(c -> c.contains("delete rule name=AEGIS-BLOCK-203.0.113.9-IN")));
        check("rollbackAll removes the rest", fw.rollbackAll("t", "test") == 1 && fw.activeRules().isEmpty());

        FakeNetsh bad = new FakeNetsh();
        bad.exit = 1;
        WindowsFirewallAdapter failing = adapter(Mode.ENFORCE, true, true, bad, null, 10);
        check("netsh failure is reported and nothing is tracked", failing.block("203.0.113.20", 600_000, "t", "t").status() == Status.ERROR && failing.activeRules().isEmpty());

        // restart recovery: an expired rule is removed from the firewall, a live one re-armed
        Path st2 = Files.createTempFile("fw2", ".tsv");
        long now = System.currentTimeMillis();
        Files.writeString(st2, "203.0.113.30\t" + (now - 7_200_000) + "\t" + (now - 3_600_000) + "\told\n"
                + "203.0.113.31\t" + (now - 1000) + "\t" + (now + 3_600_000) + "\tlive\n");
        FakeNetsh r4 = new FakeNetsh();
        WindowsFirewallAdapter rec = adapter(Mode.ENFORCE, true, true, r4, st2, 10);
        check("restart: expired rule deleted, live rule re-armed",
                r4.calls.stream().anyMatch(c -> c.contains("delete rule name=AEGIS-BLOCK-203.0.113.30-IN"))
                        && rec.activeRules().size() == 1 && rec.activeRules().get(0).get("ip").equals("203.0.113.31"));
        Files.deleteIfExists(state);
        Files.deleteIfExists(st2);
    }

    // ---------------------------------------------------------------- audit

    private static void auditChain() throws Exception {
        Path f = Files.createTempFile("audit", ".log");
        Files.delete(f);
        AuditLogger a = new AuditLogger(f);
        a.log("t", "A", "1.1.1.1", "OK", "first");
        a.log("t", "B", "2.2.2.2", "OK", "second\twith tab");
        a.log("t", "C", "3.3.3.3", "OK", "third");
        check("audit chain intact", a.verify() == null);
        check("audit survives reopen and continues the chain", new AuditLogger(f).log("t", "D", "-", "OK", "x").seq() == 4 && new AuditLogger(f).verify() == null);
        Files.writeString(f, Files.readString(f).replace("second", "edited"));
        check("tampering is detected", a.verify() != null);
        Files.deleteIfExists(f);
    }

    // ---------------------------------------------------------------- correlation

    private static AegisEvent ev(long ts, String ruleName, int score, String summary) {
        AegisEvent e = new AegisEvent();
        e.ts = ts;
        e.summary = summary;
        if (ruleName != null) e.rules.add(new AegisEvent.Contribution(ruleName, score, "aegis", summary));
        return e;
    }

    private static AegisSignal auth(String ip, String user, boolean fail) {
        AegisSignal s = new AegisSignal(AegisSignal.Kind.AUTH);
        s.ip = ip; s.user = user; s.authFailure = fail; s.ipMissing = ip.isEmpty();
        return s;
    }

    private static void correlation() {
        long t = System.currentTimeMillis();
        AtomicInteger fired = new AtomicInteger();
        AttackChainEngine ch = new AttackChainEngine("test", f -> fired.incrementAndGet());
        for (int i = 0; i < 24; i++) ch.observe(ev(t + i, null, 0, "Failed logon"), auth("203.0.113." + (i % 6 + 1), "admin", true));
        check("distributed brute force: 24 failures over 6 addresses is one finding on the account",
                ch.findings().stream().anyMatch(f -> f.type.equals("DISTRIBUTED_BRUTE_FORCE") && f.entity.equals("user:admin")));

        AttackChainEngine quiet = new AttackChainEngine("test", null);
        for (int i = 0; i < 24; i++) quiet.observe(ev(t + i, null, 0, "Failed logon"), auth("203.0.113.1", "admin", true));
        check("24 failures from ONE address is not 'distributed'", quiet.findings().stream().noneMatch(f -> f.type.equals("DISTRIBUTED_BRUTE_FORCE")));

        AttackChainEngine noIp = new AttackChainEngine("test", null);
        for (int i = 0; i < 30; i++) noIp.observe(ev(t + i, null, 0, "Failed logon"), auth("", "svc", true));
        check("failures with no source address never invent distinct addresses", noIp.findings().isEmpty());

        AttackChainEngine spray = new AttackChainEngine("test", null);
        for (int i = 0; i < 9; i++) spray.observe(ev(t + i, null, 0, "Failed logon"), auth("203.0.113.5", "user" + i, true));
        check("password spraying detected", spray.findings().stream().anyMatch(f -> f.type.equals("PASSWORD_SPRAYING") && f.severity.equals("CRITICAL")));

        AttackChainEngine typo = new AttackChainEngine("test", null);
        for (int i = 0; i < 5; i++) typo.observe(ev(t + i, null, 0, "Failed"), auth("192.168.1.20", "ravi", true));
        typo.observe(ev(t + 10, null, 0, "Successful logon"), auth("192.168.1.20", "ravi", false));
        check("a user's 5 typos then success from the LAN is HIGH, not CRITICAL",
                typo.findings().stream().anyMatch(f -> f.type.equals("BRUTE_FORCE_SUCCESS") && f.severity.equals("HIGH")));
        AttackChainEngine breach = new AttackChainEngine("test", null);
        for (int i = 0; i < 12; i++) breach.observe(ev(t + i, null, 0, "Failed"), auth("203.0.113.5", "ravi", true));
        breach.observe(ev(t + 20, null, 0, "Successful logon"), auth("203.0.113.5", "ravi", false));
        check("12 failures then success from outside is CRITICAL",
                breach.findings().stream().anyMatch(f -> f.type.equals("BRUTE_FORCE_SUCCESS") && f.severity.equals("CRITICAL")));

        AttackChainEngine scan = new AttackChainEngine("test", null);
        for (int p = 1; p <= 120; p++) {
            AegisSignal s = new AegisSignal(AegisSignal.Kind.NETWORK);
            s.ip = "203.0.113.50"; s.port = p; s.direction = "in";
            scan.observe(ev(t + p, null, 0, "scan"), s);
        }
        check("slow wide port scan found although no single event scored", scan.findings().stream().anyMatch(f -> f.type.equals("PORT_SCAN_SWEEP")));

        AtomicInteger blocks = new AtomicInteger();
        AttackChainEngine kill = new AttackChainEngine("test", f -> { if (f.severity.equals("CRITICAL")) blocks.incrementAndGet(); });
        String[][] steps = {{"SENSITIVE_PATH_PROBE", "GET /.env"}, {"SQL_INJECTION", "GET /s?id=1' or 1=1"}, {"MALWARE_DOWNLOAD", "x.exe"}, {"BACKUP_DESTRUCTION", "vssadmin delete shadows"}};
        for (int i = 0; i < steps.length; i++) {
            AegisSignal s = new AegisSignal(AegisSignal.Kind.WEB);
            s.ip = "203.0.113.60";
            kill.observe(ev(t + i, steps[i][0], 20, steps[i][1]), s);
        }
        AttackChainEngine.Finding f = kill.findings().stream().filter(x -> x.type.equals("MULTI_STAGE_ATTACK")).findFirst().orElse(null);
        check("4-stage chain found and mapped to ATT&CK tactics", f != null && f.severity.equals("CRITICAL")
                && f.tactics.contains("Reconnaissance") && f.tactics.contains("Impact") && f.techniques.stream().anyMatch(x -> x.startsWith("T1190")));
        check("callback fired once for the critical escalation", blocks.get() == 1);

        AttackChainEngine one = new AttackChainEngine("test", null);
        AegisSignal w = new AegisSignal(AegisSignal.Kind.WEB);
        w.ip = "203.0.113.61";
        one.observe(ev(t, "SQL_INJECTION", 40, "x"), w);
        one.observe(ev(t + 1, "XSS_ATTACK", 25, "y"), w);
        check("two web attacks are one tactic, not a chain", one.findings().isEmpty());
    }

    // ---------------------------------------------------------------- normalizer + policy

    private static void normalizer() {
        EventNormalizer n = new EventNormalizer();
        AegisSignal s = new AegisSignal(AegisSignal.Kind.WEB);
        s.ip = "not-an-ip"; s.user = "bad\nuser"; s.port = 70000; s.ts = System.currentTimeMillis() + 3_600_000L;
        check("normalizer accepts and repairs", n.process(s));
        check("garbage address dropped and flagged, newline removed, port and future time repaired",
                s.ip.isEmpty() && s.ipMissing && !s.user.contains("\n") && s.port == 0 && s.ts <= System.currentTimeMillis() + 1000);
        AegisSignal a = new AegisSignal(AegisSignal.Kind.AUTH);
        a.ip = "203.0.113.4"; a.user = "x"; a.channel = "windows-security"; a.winEventId = 4625; a.ts = 1_700_000_000_000L;
        AegisSignal b = new AegisSignal(AegisSignal.Kind.AUTH);
        b.ip = a.ip; b.user = a.user; b.channel = a.channel; b.winEventId = 4625; b.ts = a.ts;
        check("the same Windows record reported twice is dropped once", n.process(a) && !n.process(b));
        AegisSignal w1 = new AegisSignal(AegisSignal.Kind.WEB), w2 = new AegisSignal(AegisSignal.Kind.WEB);
        w1.ip = w2.ip = "203.0.113.4"; w1.path = w2.path = "/"; w1.ts = w2.ts = 1_700_000_000_000L; w1.channel = w2.channel = "web-access-log";
        check("identical web log lines are NOT de-duplicated (two real requests can look identical)", n.process(w1) && n.process(w2));
    }

    private static void policy() {
        Allowlist al = new Allowlist(true, "");
        ResponsePolicyEngine p = new ResponsePolicyEngine(al, 0.7, false);
        check("critical + high confidence on an outside address => BLOCK", p.decide("203.0.113.9", ThreatLevel.CRITICAL, 0.9).action() == ResponsePolicyEngine.Action.BLOCK);
        check("critical + low confidence => needs analyst approval", p.decide("203.0.113.9", ThreatLevel.CRITICAL, 0.4).action() == ResponsePolicyEngine.Action.APPROVE);
        check("internal address is never blocked or queued", p.decide("10.0.0.5", ThreatLevel.CRITICAL, 0.99).action() == ResponsePolicyEngine.Action.INVESTIGATE);
        check("high => investigate, medium => alert, low => monitor",
                p.decide("203.0.113.9", ThreatLevel.HIGH, 1).action() == ResponsePolicyEngine.Action.INVESTIGATE
                        && p.decide("203.0.113.9", ThreatLevel.MEDIUM, 1).action() == ResponsePolicyEngine.Action.ALERT
                        && p.decide("203.0.113.9", ThreatLevel.LOW, 1).action() == ResponsePolicyEngine.Action.MONITOR);
        check("approval-required mode never auto-blocks", new ResponsePolicyEngine(al, 0.7, true).decide("203.0.113.9", ThreatLevel.CRITICAL, 0.99).action() == ResponsePolicyEngine.Action.APPROVE);
        var strong = com.threatdetection.decision.ConfidenceEngine.assess(List.of("BRUTE_FORCE (+50): x", "SQL_INJECTION (+40): y", "BLACKLISTED_IP (+50): z"), 140, true);
        var weak = com.threatdetection.decision.ConfidenceEngine.assess(List.of("BOT_DETECTED (+15): x"), 120, true);
        check("confidence: several independent rules + blocklist beats one weak signal", strong.value() >= 0.7 && weak.value() < 0.5 && !strong.reasons().isEmpty());
    }
}
