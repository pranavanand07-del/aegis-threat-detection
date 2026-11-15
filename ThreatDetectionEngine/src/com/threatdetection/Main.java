package com.threatdetection;

import com.threatdetection.aegis.Aegis;
import com.threatdetection.aegis.DataSource;
import com.threatdetection.engine.ThreatDetectionEngine;
import com.threatdetection.geo.GeoLocation;
import com.threatdetection.geo.OfflineGeoIpProvider;
import com.threatdetection.map.ThreatMapApi;
import com.threatdetection.map.ThreatMapEngine;
import com.threatdetection.map.ThreatMapService;
import com.threatdetection.server.ApiServer;
import com.threatdetection.simulator.GeoTrafficSimulator;
import com.threatdetection.simulator.TrafficSimulator;
import com.threatdetection.storage.InMemoryStore;

public class Main {
    public static void main(String[] args) throws Exception {
        InMemoryStore store = new InMemoryStore();

        // Threat Map: same detection engine, plus geolocation of every result (observe-only).
        GeoLocation target = ThreatMapService.targetFromSystemProperties();
        ThreatMapService mapService = new ThreatMapService(store, new OfflineGeoIpProvider(target), target);
        ThreatDetectionEngine engine = new ThreatMapEngine(store, mapService);

        // AEGIS: additive layer. Engines below behave exactly like `engine`; they only tag the data source.
        Aegis aegis = Aegis.create(store, engine, sandboxStore -> new ThreatMapEngine(sandboxStore, mapService,
                        // The isolated simulator/Attack Lab lane gets labelled DEMO entries so there is something to hit.
                        // The live lane above only uses what the operator configures (-Daegis.blacklist.file).
                        com.threatdetection.intelligence.ThreatIntelService.demo()));

        // Real firewall response for the LIVE lane only (default dry-run: decisions are audited, nothing is changed).
        engine.responseService().attachOsResponse(
                com.threatdetection.response.OsResponseCoordinator.fromSystemProperties(engine.responseService().allowlist()));

        
int port = Integer.parseInt(
        System.getenv().getOrDefault("PORT", "8080"));

ApiServer server = new ApiServer(
        aegis.engineFor(DataSource.API), store, port);

        ThreatMapApi.register(server, mapService);
        aegis.register(server);
        com.threatdetection.platform.PlatformApi.register(server, aegis);
        server.start();
        aegis.startIngestion();

        Thread simulatorThread = new Thread(new TrafficSimulator(aegis.engineFor(DataSource.SIMULATED)));
        simulatorThread.setDaemon(true);
        simulatorThread.start();

        // Extra worldwide demo attackers so the map has data. Turn off with -Dgeo.demo=false
        if (!"false".equalsIgnoreCase(System.getProperty("geo.demo"))) {
            Thread geoThread = new Thread(new GeoTrafficSimulator(aegis.engineFor(DataSource.SIMULATED)));
            geoThread.setDaemon(true);
            geoThread.start();
        }

        System.out.println("Firewall response: " + engine.responseService().osResponse().status().get("effectiveMode")
                + " (" + engine.responseService().osResponse().status().get("detail") + ")");
        System.out.println("Traffic simulator started.");
        System.out.println("Threat Map: http://localhost:8080/map");
        System.out.println("AEGIS:      http://localhost:8080/aegis");
        System.out.println("Platform:   http://localhost:8080/   (original dashboard: /classic)");
        System.out.println("Open http://localhost:8080 to view the live dashboard.");
        System.out.println("Send a custom event, e.g.:");
        System.out.println("curl -X POST http://localhost:8080/api/event -d \"ip=9.9.9.9&eventType=LOGIN_FAILED&username=admin\"");
    }
}
