package com.threatdetection.aegis;

import com.threatdetection.aegis.defense.DefenseApi;
import com.threatdetection.aegis.defense.DefenseConfig;
import com.threatdetection.aegis.defense.DefenseCoordinator;
import com.threatdetection.aegis.geo.AegisGeo;
import com.threatdetection.aegis.geo.CsvGeoIpProvider;
import com.threatdetection.aegis.ingest.FileTailer;
import com.threatdetection.aegis.ingest.FirewallLogParser;
import com.threatdetection.aegis.ingest.WazuhAlertParser;
import com.threatdetection.aegis.ingest.WebAccessLogParser;
import com.threatdetection.aegis.ingest.WindowsEventMapper;
import com.threatdetection.aegis.ingest.WindowsEventSource;
import com.threatdetection.aegis.intel.EnrichmentService;
import com.threatdetection.aegis.intel.ReputationService;
import com.threatdetection.aegis.rules.FirewallRule;
import com.threatdetection.aegis.rules.PathTraversalRule;
import com.threatdetection.aegis.rules.SysmonProcessRule;
import com.threatdetection.aegis.rules.WazuhRule;
import com.threatdetection.aegis.rules.WebProbeRule;
import com.threatdetection.aegis.rules.WindowsAuditRule;
import com.threatdetection.aegis.storage.AegisPersistence;
import com.threatdetection.aegis.storage.AegisStore;
import com.threatdetection.aegis.web.AegisApi;
import com.threatdetection.aegis.web.AegisResponseApi;
import com.threatdetection.aegis.web.EnrichApi;
import com.threatdetection.correlation.AttackChainEngine;
import com.threatdetection.response.OsResponseCoordinator;
import com.threatdetection.engine.ThreatDetectionEngine;
import com.threatdetection.geo.GeoLocation;
import com.threatdetection.geo.OfflineGeoIpProvider;
import com.threatdetection.map.ThreatMapService;
import com.threatdetection.server.ApiServer;
import com.threatdetection.storage.InMemoryStore;

import java.nio.file.Path;
import java.util.List;
import java.util.Locale;

/**
 * Entry point of the AEGIS module. Everything here is additive: the original engine, dashboard,
 * map and API keep working exactly as before; AEGIS observes their events and adds its own pages
 * (/aegis), endpoints (/aegis/api/*) and log-ingestion sources.
 *
 * System properties (all optional):
 *   -Daegis.web.log=/var/log/nginx/access.log[,more]   web server access logs (Apache/Nginx)
 *   -Daegis.fw.log=/var/log/ufw.log                    firewall log (Windows pfirewall.log / netfilter)
 *   -Daegis.win.security=true                          Windows Security log (Windows, run as Administrator)
 *   -Daegis.win.sysmon=true                            Sysmon operational log (Windows + Sysmon)
 *   -Daegis.ingest.fromStart=true                      replay existing log content instead of only new lines
 *   -Daegis.intel.feeds=malicious:/p/drop.txt,suspicious:/p/tor.txt   threat-intel feed files
 *   -Daegis.geo.csv=/path/geoip.csv                    real GeoIP database (CSV) for plotting observed IPs
 *   -Daegis.persist=false / -Daegis.data.dir=./aegis-data   alert persistence
 */
public final class Aegis {
    private final InMemoryStore legacyStore;
    private final ThreatDetectionEngine baseEngine;
    // Sandbox lane: simulators and the Attack Lab run on their OWN engine, trackers and block list,
    // so synthetic traffic can never block, escalate or pollute state used for real traffic.
    private final InMemoryStore sandboxStore;
    private final ThreatDetectionEngine sandboxEngine;
    private final AegisPipeline sandboxPipeline;
    private final AegisStore store;
    private final AegisPipeline pipeline;
    private final AegisGeo geo;
    private final ReputationService reputation;
    private final GeoLocation target;
    private final String persistFile;
    private DefenseCoordinator defense;
    private EnrichmentService enrichment;

    private Aegis(InMemoryStore legacyStore, ThreatDetectionEngine baseEngine, AegisStore store, AegisPipeline pipeline,
                  AegisGeo geo, ReputationService reputation, GeoLocation target, String persistFile,
                  InMemoryStore sandboxStore, ThreatDetectionEngine sandboxEngine, AegisPipeline sandboxPipeline) {
        this.legacyStore = legacyStore;
        this.baseEngine = baseEngine;
        this.sandboxStore = sandboxStore;
        this.sandboxEngine = sandboxEngine;
        this.sandboxPipeline = sandboxPipeline;
        this.store = store;
        this.pipeline = pipeline;
        this.geo = geo;
        this.reputation = reputation;
        this.target = target;
        this.persistFile = persistFile;
    }

    private static List<AegisRule> newRules() {
        return List.of(new PathTraversalRule(), new WebProbeRule(), new WindowsAuditRule(),
                new SysmonProcessRule(), new FirewallRule(), new WazuhRule());
    }

    /**
     * @param sandboxEngineFactory builds the isolated engine used for simulated traffic and the Attack Lab
     *                             (it receives the sandbox's own store).
     */
    public static Aegis create(InMemoryStore legacyStore, ThreatDetectionEngine baseEngine,
                               java.util.function.Function<InMemoryStore, ThreatDetectionEngine> sandboxEngineFactory) {
        GeoLocation target = ThreatMapService.targetFromSystemProperties();
        AegisStore store = new AegisStore(Integer.getInteger("aegis.max.recent", 10_000),
                Integer.getInteger("aegis.max.alerts", 50_000));

        CsvGeoIpProvider db = null;
        String csv = System.getProperty("aegis.geo.csv", "");
        if (!csv.isBlank()) {
            try {
                db = CsvGeoIpProvider.load(Path.of(csv));
                System.out.println("[AEGIS] GeoIP database loaded: " + db.size() + " IPv4 ranges");
            } catch (Exception e) {
                System.err.println("[AEGIS] GeoIP database not loaded: " + e.getMessage());
            }
        }
        AegisGeo geo = new AegisGeo(db, new OfflineGeoIpProvider(target), target);
        ReputationService reputation = ReputationService.fromSystemProperties();
        for (String err : reputation.loadErrors()) System.err.println("[AEGIS] threat-intel feed not loaded: " + err);

        AegisPipeline pipeline = new AegisPipeline(baseEngine, store, newRules(), reputation, geo);
        InMemoryStore sandboxStore = new InMemoryStore();
        ThreatDetectionEngine sandboxEngine = sandboxEngineFactory.apply(sandboxStore);
        AegisPipeline sandboxPipeline = new AegisPipeline(sandboxEngine, store, newRules(), reputation, geo);
        // Cross-event correlation. Only the live lane may trigger a response; the sandbox lane just records findings.
        pipeline.setChains(new AttackChainEngine("live", f -> respondToChain(baseEngine, f)));
        sandboxPipeline.setChains(new AttackChainEngine("sandbox", null));
        store.registerSource("attack-lab", "sandbox", "WAITING", "Attack Lab (isolated sandbox, never blocks real traffic)");

        String persistFile = "";
        if (!"false".equalsIgnoreCase(System.getProperty("aegis.persist"))) {
            try {
                AegisPersistence p = new AegisPersistence(Path.of(System.getProperty("aegis.data.dir", "aegis-data")));
                List<AegisEvent> old = p.load(Integer.getInteger("aegis.max.alerts", 50_000));
                for (AegisEvent e : old) store.restore(e);
                store.attach(p);
                persistFile = p.file().toString();
                System.out.println("[AEGIS] restored " + old.size() + " stored alert(s) from " + persistFile);
            } catch (Exception e) {
                System.err.println("[AEGIS] persistence disabled: " + e.getMessage());
            }
        }
        Aegis aegis = new Aegis(legacyStore, baseEngine, store, pipeline, geo, reputation, target, persistFile,
                sandboxStore, sandboxEngine, sandboxPipeline);
        EnrichmentService en = EnrichmentService.fromSystemProperties();
        pipeline.setEnrichment(en);   // live lane only: simulated/sandbox events are never sent to third parties
        aegis.enrichment = en;
        try {
            DefenseConfig dc = DefenseConfig.fromSystemProperties();
            DefenseCoordinator d = DefenseCoordinator.create(dc, baseEngine.responseService().allowlist());
            // One firewall for the whole product: Defense actions go through the same adapter as the core engine.
            d.firewall().bind(() -> {
                com.threatdetection.response.OsResponseCoordinator o = baseEngine.responseService().osResponse();
                return o == null ? null : o.firewall();
            });
            pipeline.setDefense(d);   // live lane only: simulated/sandbox traffic can never trigger a response
            d.start();
            aegis.defense = d;
            System.out.println("[AEGIS] defense mode: " + dc.mode + " (dashboard: /aegis/defense, audit: " + d.audit().file() + ")");
        } catch (Exception e) {
            System.err.println("[AEGIS] defense layer disabled: " + e.getMessage());
        }
        return aegis;
    }

    /** A drop-in engine that behaves exactly like the base engine but tags events with their source. */
    public ThreatDetectionEngine engineFor(DataSource source) {
        if (source == DataSource.SIMULATED) store.registerSource("simulator", "generator", "WAITING", "Built-in traffic simulator");
        if (source == DataSource.API) store.registerSource("http-api", "http", "WAITING", "POST /api/event");
        if (source == DataSource.SIMULATED) return new AegisEngine(sandboxStore, sandboxEngine, sandboxPipeline, source);
        return new AegisEngine(legacyStore, baseEngine, pipeline, source);
    }

    public void register(ApiServer server) {
        new AegisApi(this).register(server);
        new AegisResponseApi(this).register(server);
        if (defense != null) new DefenseApi(defense).register(server);
        if (enrichment != null) new EnrichApi(enrichment).register(server);
    }

    // ---------------------------------------------------------------- correlation / response access

    public AttackChainEngine chains() { return pipeline.chains(); }
    public AttackChainEngine sandboxChains() { return sandboxPipeline.chains(); }
    public OsResponseCoordinator osResponse() { return baseEngine.responseService().osResponse(); }
    public java.util.Map<String, Object> normalizerStats() { return pipeline.normalizer().stats(); }
    public java.util.Map<String, Object> intelStatus() { return baseEngine.intel().status(); }

    /** Analyst override: also lifts the in-memory block of the live lane. */
    public void unblock(String ip) { baseEngine.responseService().unblock(ip); }

    /**
     * A correlated finding on an EXTERNAL address (e.g. a slow 1000-port scan whose single events each score low)
     * goes through the same allowlist, confidence and policy checks as any other critical detection.
     * Account-level findings (distributed brute force, success after failures) are never auto-blocked:
     * blocking one address cannot stop them; the recommendation says what to do instead.
     */
    private static void respondToChain(ThreatDetectionEngine engine, AttackChainEngine.Finding f) {
        if (!f.severity.equals("CRITICAL") || f.ip.isEmpty() || !f.entity.startsWith("ip:")) return;
        // OFF by default: blocking on a correlated chain needs a deliberate -Daegis.chain.autoblock=true.
        if (!"true".equalsIgnoreCase(System.getProperty("aegis.chain.autoblock", "false"))) return;
        if (System.currentTimeMillis() - f.last > 5 * 60 * 1000L) { f.response = "not blocked: finding is historical (log replay)"; return; }
        String skipped = engine.responseService().block(f.ip);
        if (skipped != null) { f.response = "BLOCK_SKIPPED: " + skipped; return; }
        com.threatdetection.response.OsResponseCoordinator.Handled h = engine.responseService().osResponseDetailed(f.ip, 150,
                com.threatdetection.model.ThreatLevel.CRITICAL, new java.util.ArrayList<>(f.ruleNames), "attack-chain:" + f.type);
        String note = h == null ? null : h.note();
        // "blocked in application" = this process rejects the address; the OS note says what the firewall actually did
        // (APPLIED = real rule, DRY_RUN / REFUSED / FAILED / awaiting approval = no rule).
        f.response = "blocked in application" + (note == null ? "; no OS firewall response attached" : "; " + note);
    }

    // ---------------------------------------------------------------- ingestion

    /** Starts every ingestion source that is configured; the rest are listed as "not configured". */
    public void startIngestion() {
        boolean fromStart = Boolean.getBoolean("aegis.ingest.fromStart");
        startFiles("web-access-log", "aegis.web.log", fromStart, WebAccessLogParser::parse, "-Daegis.web.log=/path/access.log");
        startFiles("wazuh-alerts", "aegis.wazuh.alerts", fromStart, WazuhAlertParser::parse, "-Daegis.wazuh.alerts=/var/ossec/logs/alerts/alerts.json");
        startFiles("firewall-log", "aegis.fw.log", fromStart, FirewallLogParser::parse, "-Daegis.fw.log=/path/firewall.log");

        boolean windows = System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("win");
        startWindows("windows-security", "Security", new int[]{4625, 4624, 4740, 4720, 4728, 4732, 4756, 1102},
                "aegis.win.security", windows);
        startWindows("sysmon", "Microsoft-Windows-Sysmon/Operational", new int[]{1, 3}, "aegis.win.sysmon", windows);
    }

    private void startFiles(String name, String prop, boolean fromStart,
                            java.util.function.Function<String, AegisSignal> parser, String hint) {
        String spec = System.getProperty(prop, "").trim();
        if (spec.isEmpty()) {
            store.registerSource(name, "file", "DISABLED", "Not configured (" + hint + ")");
            return;
        }
        store.registerSource(name, "file", "WAITING", "Starting: " + spec);
        for (String p : spec.split(",")) {
            if (p.isBlank()) continue;
            FileTailer t = new FileTailer(name, Path.of(p.trim()), parser, s -> pipeline.ingest(s, DataSource.OBSERVED), store, fromStart);
            Thread th = new Thread(t, "aegis-" + name);
            th.setDaemon(true);
            th.start();
        }
    }

    private void startWindows(String name, String channel, int[] ids, String prop, boolean windows) {
        if (!Boolean.getBoolean(prop)) {
            store.registerSource(name, "windows-event-log", "DISABLED", "Not enabled (-D" + prop + "=true, Windows only)");
            return;
        }
        if (!windows) {
            store.registerSource(name, "windows-event-log", "ERROR", "Windows event logs are only available on Windows");
            return;
        }
        store.registerSource(name, "windows-event-log", "WAITING", "Starting");
        Thread th = new Thread(new WindowsEventSource(name, channel, ids, s -> pipeline.ingest(s, DataSource.OBSERVED), store),
                "aegis-" + name);
        th.setDaemon(true);
        th.start();
    }

    /** Analyses one normalized signal through the full pipeline of the live or sandbox lane. */
    public void ingestSignal(AegisSignal signal, DataSource source) {
        (source == DataSource.SIMULATED ? sandboxPipeline : pipeline).ingest(signal, source);
    }

    /** Attack Lab: same detection code, isolated state. Tagged API (unverified HTTP input), channel attack-lab. */
    public void ingestLab(AegisSignal signal) {
        signal.channel = "attack-lab";
        sandboxPipeline.ingest(signal, DataSource.API);
    }

    /** Lines (or Windows event XML) pushed over HTTP; counted as API data, not as observed. */
    public int[] ingestPushed(String type, String body) throws Exception {
        int accepted = 0, ignored = 0;
        switch (type) {
            case "web", "firewall" -> {
                for (String line : body.split("\n")) {
                    line = line.stripTrailing();
                    if (line.isEmpty()) continue;
                    AegisSignal s = type.equals("web") ? WebAccessLogParser.parse(line) : FirewallLogParser.parse(line);
                    if (s == null) { ignored++; continue; }
                    s.channel = "http-api";
                    pipeline.ingest(s, DataSource.API);
                    accepted++;
                }
            }
            case "wazuh" -> {
                for (String line : body.split("\n")) {
                    AegisSignal s = WazuhAlertParser.parse(line.strip());
                    if (s == null) { if (!line.isBlank()) ignored++; continue; }
                    s.channel = "http-api";
                    pipeline.ingest(s, DataSource.API);
                    accepted++;
                }
            }
            case "winxml" -> {
                for (WindowsEventMapper.Parsed p : WindowsEventMapper.parse(body)) {
                    p.signal.channel = "http-api";
                    pipeline.ingest(p.signal, DataSource.API);
                    accepted++;
                }
            }
            default -> throw new IllegalArgumentException("type must be web, firewall, wazuh or winxml");
        }
        return new int[]{accepted, ignored};
    }

    public DefenseCoordinator defense() { return defense; }
    public EnrichmentService enrichment() { return enrichment; }
    public AegisStore store() { return store; }
    public InMemoryStore legacyStore() { return legacyStore; }
    public AegisGeo geo() { return geo; }
    public ReputationService reputation() { return reputation; }
    public GeoLocation target() { return target; }
    public String persistFile() { return persistFile; }
}
