package com.threatdetection.aegis.intel;

import com.sun.net.httpserver.HttpServer;
import com.threatdetection.aegis.AegisEvent;
import com.threatdetection.aegis.AegisSignal;
import com.threatdetection.aegis.DataSource;
import com.threatdetection.aegis.ingest.WazuhAlertParser;
import com.threatdetection.aegis.rules.WazuhRule;
import com.threatdetection.model.ThreatLevel;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Checks the optional-integration behaviour against a local fake server (no real keys, no internet):
 *   java -cp out com.threatdetection.aegis.intel.EnrichmentSelfTest
 */
public final class EnrichmentSelfTest {
    private static int passed, failed;
    private static final AtomicInteger hits = new AtomicInteger();
    private static volatile int abuseScore = 92, mode = 0;   // mode 1 = HTTP 500, 2 = slow

    private static void check(String name, boolean ok) {
        if (ok) passed++; else failed++;
        System.out.println((ok ? "  PASS  " : "  FAIL  ") + name);
    }

    private static AegisEvent event(String ip, ThreatLevel lvl, DataSource src) {
        AegisEvent e = new AegisEvent();
        e.ip = ip;
        e.internal = IpClassifier.isInternal(ip);
        e.level = lvl;
        e.source = src;
        return e;
    }

    public static void main(String[] args) throws Exception {
        HttpServer srv = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        srv.createContext("/abuse", ex -> {
            hits.incrementAndGet();
            if (mode == 2) try { Thread.sleep(7000); } catch (InterruptedException ignored) { }
            byte[] b = (mode == 1 ? "{}" : "{\"data\":{\"abuseConfidenceScore\":" + abuseScore + ",\"totalReports\":14,\"countryCode\":\"NL\",\"isp\":\"ExampleNet\"}}").getBytes(StandardCharsets.UTF_8);
            try { ex.sendResponseHeaders(mode == 1 ? 500 : 200, b.length); ex.getResponseBody().write(b); } catch (java.io.IOException ignored) { }
            ex.close();
        });
        srv.createContext("/vt", ex -> {
            hits.incrementAndGet();
            String p = ex.getRequestURI().getPath();
            boolean missing = p.endsWith("/deadbeefdeadbeefdeadbeefdeadbeef");
            byte[] b = "{\"data\":{\"attributes\":{\"last_analysis_stats\":{\"malicious\":5,\"suspicious\":1,\"harmless\":60,\"undetected\":20}}}}".getBytes(StandardCharsets.UTF_8);
            ex.sendResponseHeaders(missing ? 404 : 200, missing ? -1 : b.length);
            if (!missing) ex.getResponseBody().write(b);
            ex.close();
        });
        srv.start();
        String base = "http://127.0.0.1:" + srv.getAddress().getPort();

        System.out.println("Enrichment and integration checks");

        // ---- not configured: zero network traffic
        EnrichmentService none = EnrichmentService.fromSystemProperties();
        List<Enrichment> r0 = none.lookupIp("203.0.113.5");
        check("without API keys every provider reports NOT_CONFIGURED and nothing is sent", r0.stream().allMatch(x -> x.status.equals(Enrichment.NOT_CONFIGURED)) && hits.get() == 0);

        System.setProperty("aegis.abuseipdb.key", "test-key");
        System.setProperty("aegis.abuseipdb.url", base + "/abuse");
        System.setProperty("aegis.vt.key", "test-key");
        System.setProperty("aegis.vt.minIntervalMs", "0");
        System.setProperty("aegis.vt.url", base + "/vt");
        EnrichmentService svc = EnrichmentService.fromSystemProperties();

        check("internal addresses are never sent to external services", svc.lookupIp("192.168.1.10").get(0).status.equals(Enrichment.NOT_APPLICABLE) && hits.get() == 0);
        check("malformed input is rejected before any request", svc.lookupIp("1.2.3.4; rm").get(0).status.equals(Enrichment.NOT_APPLICABLE) && hits.get() == 0);

        List<Enrichment> r1 = svc.lookupIp("203.0.113.5");
        Enrichment abuse = r1.get(0);
        check("AbuseIPDB score 92 -> MALICIOUS with details", abuse.provider.equals("AbuseIPDB") && abuse.verdict.equals("MALICIOUS") && abuse.score == 92 && abuse.detail.contains("14 report"));
        int afterFirst = hits.get();
        Thread.sleep(600);
        List<Enrichment> r2 = svc.lookupIp("203.0.113.5");
        check("repeat lookup is served from cache (no second request)", r2.get(0).cached && hits.get() == afterFirst);

        Thread.sleep(600);
        abuseScore = 0;
        Enrichment zero = svc.lookupIp("203.0.113.77").get(0);
        check("score 0 is NO_DATA and says 'not reported does not mean safe' (never CLEAN/SAFE)", zero.verdict.equals("NO_DATA") && zero.detail.contains("does not mean safe")
                && !zero.verdict.equals("CLEAN") && !zero.verdict.equals("SAFE"));
        Enrichment quick = svc.lookupIp("203.0.113.78").get(0);
        check("free-tier throttle: a second immediate on-demand lookup is RATE_LIMITED, not queued forever", quick.status.equals(Enrichment.RATE_LIMITED));

        Enrichment vtMiss = svc.lookupHash("deadbeefdeadbeefdeadbeefdeadbeef");
        check("VirusTotal 'not found' is NO_DATA with 'unknown is not safe'", vtMiss.verdict.equals("NO_DATA") && vtMiss.detail.contains("not safe"));
        check("a non-hash is refused locally", svc.lookupHash("hello world").status.equals(Enrichment.NOT_APPLICABLE));

        // ---- failures degrade gracefully
        mode = 1;
        Thread.sleep(600);
        Enrichment err = svc.lookupIp("203.0.113.90").get(0);
        check("HTTP 500 from a provider -> ERROR status, no exception", err.status.equals(Enrichment.ERROR));
        mode = 0;

        // ---- offline provider + circuit breaker
        srv.stop(0);
        EnrichmentService off = EnrichmentService.fromSystemProperties();
        String[] ips = {"198.51.100.1", "198.51.100.2", "198.51.100.3", "198.51.100.4"};
        int offline = 0;
        for (String ip : ips) { Thread.sleep(600); Enrichment x = off.lookupIp(ip).get(0); if (x.status.equals(Enrichment.OFFLINE)) offline++; }
        check("unreachable service -> OFFLINE (the event is simply not enriched)", offline == 4);
        check("circuit breaker pauses a failing provider", off.statusJson().contains("\"paused\":true"));

        // ---- events: only live, public, MEDIUM+ events are enriched; the pipeline never waits
        HttpServer srv2 = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        AtomicInteger hits2 = new AtomicInteger();
        srv2.createContext("/abuse", ex -> {
            hits2.incrementAndGet();
            byte[] b = "{\"data\":{\"abuseConfidenceScore\":80,\"totalReports\":3,\"countryCode\":\"US\",\"isp\":\"X\"}}".getBytes(StandardCharsets.UTF_8);
            ex.sendResponseHeaders(200, b.length); ex.getResponseBody().write(b); ex.close();
        });
        srv2.start();
        System.setProperty("aegis.abuseipdb.url", "http://127.0.0.1:" + srv2.getAddress().getPort() + "/abuse");
        System.setProperty("aegis.vt.key", "");
        EnrichmentService live = EnrichmentService.fromSystemProperties();
        AegisEvent sim = event("203.0.113.5", ThreatLevel.CRITICAL, DataSource.SIMULATED);
        AegisEvent low = event("203.0.113.6", ThreatLevel.LOW, DataSource.OBSERVED);
        AegisEvent internal = event("10.0.0.9", ThreatLevel.CRITICAL, DataSource.OBSERVED);
        AegisEvent real = event("203.0.113.7", ThreatLevel.HIGH, DataSource.OBSERVED);
        long t0 = System.nanoTime();
        live.submit(sim); live.submit(low); live.submit(internal); live.submit(real);
        long ms = (System.nanoTime() - t0) / 1_000_000;
        check("submit() returns immediately (detection never waits for the network)", ms < 100);
        for (int i = 0; i < 30 && real.enrichments.isEmpty(); i++) Thread.sleep(100);
        check("an OBSERVED public HIGH event receives enrichment in the background", !real.enrichments.isEmpty() && real.enrichments.get(0).verdict.equals("MALICIOUS"));
        check("SIMULATED, LOW and internal events are never looked up", hits2.get() == 1 && sim.enrichments.isEmpty() && low.enrichments.isEmpty() && internal.enrichments.isEmpty());
        srv2.stop(0);

        // ---- MITRE mapping
        List<AegisEvent.Contribution> rules = List.of(new AegisEvent.Contribution("SQL_INJECTION", 40, "core", ""), new AegisEvent.Contribution("BRUTE_FORCE", 20, "core", ""));
        List<Enrichment> mitre = MitreMapper.forRules(rules, "T1078");
        check("MITRE ATT&CK techniques are mapped from fired rules (offline)", mitre.size() == 3 && mitre.get(0).detail.startsWith("T1190") && mitre.get(1).detail.startsWith("T1110"));

        // ---- Wazuh
        String line = "{\"timestamp\":\"2026-11-10T08:15:30.123+0000\",\"rule\":{\"level\":12,\"description\":\"sshd: brute force trying to get access\",\"id\":\"5763\",\"mitre\":{\"id\":[\"T1110\"]}},"
                + "\"agent\":{\"id\":\"001\",\"name\":\"web-01\"},\"data\":{\"srcip\":\"203.0.113.50\",\"dstuser\":\"root\"}}";
        AegisSignal w = WazuhAlertParser.parse(line);
        check("Wazuh alert is parsed (rule, level, agent, source IP, user, MITRE, timestamp)", w != null && w.extLevel == 12 && w.ip.equals("203.0.113.50")
                && w.host.equals("web-01") && w.user.equals("root") && w.extMitre.equals("T1110") && w.ts > 0);
        check("Wazuh level 12 scores 55 (MEDIUM range): one product's opinion cannot reach CRITICAL alone", new WazuhRule().evaluate(w).score == 55);
        check("garbage and non-alert lines are ignored", WazuhAlertParser.parse("not json") == null && WazuhAlertParser.parse("{\"a\":1}") == null && WazuhAlertParser.parse("{\"rule\":") == null);
        AegisSignal badIp = WazuhAlertParser.parse(line.replace("203.0.113.50", "not-an-ip"));
        check("an invalid srcip never becomes an address", badIp != null && badIp.ip.isEmpty());

        System.out.println("\n" + passed + " passed, " + failed + " failed");
        System.exit(failed > 0 ? 1 : 0);
    }
}
