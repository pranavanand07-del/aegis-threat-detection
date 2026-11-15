package com.threatdetection.testing;

import com.threatdetection.engine.ThreatDetectionEngine;
import com.threatdetection.model.EventType;
import com.threatdetection.model.LogEvent;
import com.threatdetection.model.ThreatResult;
import com.threatdetection.platform.SelfTest;
import com.threatdetection.storage.InMemoryStore;

import java.util.ArrayList;
import java.util.List;

/**
 * Negative tests: ordinary traffic that must NOT raise SQL injection, XSS, bot or malware alerts.
 * Cases are appended to the self-test, so they show on the platform page and fail the build when a rule regresses.
 */
public final class FalsePositiveTestSuite {
    private FalsePositiveTestSuite() {}

    private static final String BROWSER = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)";
    private record Benign(String rule, String title, String ua, String endpoint, String body) {}

    private static final List<Benign> BENIGN = List.of(
            new Benign("SQL_INJECTION", "Prose about inserting rows", BROWSER, "/comment", "text=you can insert into a table with a form"),
            new Benign("SQL_INJECTION", "Prose about select * from", BROWSER, "/comment", "text=tutorial: select * from beginners guide"),
            new Benign("SQL_INJECTION", "Blog slug with several double hyphens", BROWSER, "/blog/a--b--c-d", ""),
            new Benign("SQL_INJECTION", "Name with an apostrophe", BROWSER, "/profile", "name=O'Brien&city=Coimbatore"),
            new Benign("SQL_INJECTION", "Markdown horizontal rule", BROWSER, "/notes", "body=title\n---\ntext"),
            new Benign("SQL_INJECTION", "Words that contain 'union' and 'select'", BROWSER, "/search", "q=european union selection criteria"),
            new Benign("SQL_INJECTION", "Math expression 2=2 in prose", BROWSER, "/forum", "text=if x equals 2 then 2=2 holds"),
            new Benign("XSS_ATTACK", "Mentions the word script", BROWSER, "/comment", "text=I wrote a script to rename files"),
            new Benign("XSS_ATTACK", "Less-than and greater-than in maths", BROWSER, "/comment", "text=3 < 5 and 7 > 2"),
            new Benign("BOT_DETECTED", "Monitoring agent on /healthz", "kube-probe/1.28", "/healthz", ""),
            new Benign("BOT_DETECTED", "Load balancer probe on /ping", "ELB-HealthChecker/2.0", "/ping", ""),
            new Benign("BOT_DETECTED", "wget health check with trailing slash", "Wget/1.21", "/health/", ""),
            new Benign("BOT_DETECTED", "Empty User-Agent on /status", "", "/status", ""),
            new Benign("MALWARE_DOWNLOAD", "Request for a CSV export", BROWSER, "/export", "")
    );

    public static List<SelfTest.Case> cases() {
        List<SelfTest.Case> out = new ArrayList<>();
        int n = 0;
        for (Benign b : BENIGN) {
            // Each case gets its own address and its own engine so one case cannot influence another.
            ThreatDetectionEngine e = new ThreatDetectionEngine(new InMemoryStore());
            String ip = "198.51.100." + (++n);
            EventType type = b.rule().equals("MALWARE_DOWNLOAD") ? EventType.DOWNLOAD_REQUEST : EventType.HTTP_REQUEST;
            String file = type == EventType.DOWNLOAD_REQUEST ? "report.csv" : "";
            ThreatResult r = e.process(new LogEvent(ip, "guest", b.endpoint(), b.ua(), b.body(), "IN", type, 0, file));
            int points = -1;
            for (String s : r.triggeredRules) {
                if (s.startsWith(b.rule() + " (")) {
                    points = Integer.parseInt(s.substring(s.indexOf('(') + 1, s.indexOf(')')).replace("+", ""));
                }
            }
            out.add(new SelfTest.Case("false-positive", b.rule(), "benign", b.title(),
                    b.endpoint() + (b.body().isEmpty() ? "" : "  body: " + b.body().replace("\n", "\\n")),
                    false, -1, points));
        }
        return out;
    }
}
