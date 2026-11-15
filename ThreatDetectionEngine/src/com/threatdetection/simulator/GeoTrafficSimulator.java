package com.threatdetection.simulator;

import com.threatdetection.engine.ThreatDetectionEngine;
import com.threatdetection.model.EventType;
import com.threatdetection.model.LogEvent;

import java.util.Random;

/**
 * Extra demo traffic for the Threat Map: attacks from many countries (and several
 * Indian cities) so the map has something interesting to show.
 * The original TrafficSimulator is untouched and keeps running alongside this one.
 * Disable with:  java -Dgeo.demo=false -cp out com.threatdetection.Main
 *
 * The IPs below are made-up demo addresses; each is paired with a fixed country code.
 */
public class GeoTrafficSimulator implements Runnable {
    private static final String[][] SOURCES = {
        {"198.51.100.11","RU"},{"198.51.100.12","RU"},{"198.51.100.21","CN"},{"198.51.100.22","CN"},
        {"198.51.100.31","US"},{"198.51.100.32","US"},{"198.51.100.41","DE"},{"198.51.100.51","BR"},
        {"198.51.100.61","IR"},{"198.51.100.71","KP"},{"198.51.100.81","UA"},{"198.51.100.91","NG"},
        {"192.0.2.11","VN"},{"192.0.2.21","TR"},{"192.0.2.31","PK"},{"192.0.2.41","ID"},
        {"192.0.2.51","GB"},{"192.0.2.61","FR"},{"192.0.2.71","KR"},{"192.0.2.81","RO"},
        // India: shows up on the India threat map (state / city concentration)
        {"192.0.2.101","IN"},{"192.0.2.102","IN"},{"192.0.2.103","IN"},{"192.0.2.104","IN"},
        {"192.0.2.105","IN"},{"192.0.2.106","IN"},{"192.0.2.107","IN"},{"192.0.2.108","IN"},
    };
    private static final String[] BOT_AGENTS =
        {"python-requests/2.31", "sqlmap/1.7", "curl/8.4", "nmap scripting engine"};
    private static final String[] BROWSER_AGENTS = {"Mozilla/5.0", "Chrome/125.0"};

    private final ThreatDetectionEngine engine;
    private final Random random = new Random();

    public GeoTrafficSimulator(ThreatDetectionEngine engine) {
        this.engine = engine;
    }

    @Override
    public void run() {
        while (true) {
            try {
                attack(SOURCES[random.nextInt(SOURCES.length)]);
                Thread.sleep(1200 + random.nextInt(1200));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }

    private void attack(String[] src) {
        String ip = src[0], cc = src[1];
        switch (random.nextInt(8)) {
            case 0 -> {   // brute force
                for (int i = 0; i < 4 + random.nextInt(5); i++) {
                    engine.process(new LogEvent(ip, "admin", "/login", BOT_AGENTS[2], "", cc,
                            EventType.LOGIN_FAILED, 0, ""));
                }
            }
            case 1 -> engine.process(new LogEvent(ip, "guest", "/search",
                    BROWSER_AGENTS[random.nextInt(2)], "id=1' OR 1=1 --", cc, EventType.HTTP_REQUEST, 0, ""));
            case 2 -> engine.process(new LogEvent(ip, "guest", "/comment",
                    BROWSER_AGENTS[0], "<script>document.cookie</script>", cc, EventType.HTTP_REQUEST, 0, ""));
            case 3 -> {   // port scan
                for (int port : new int[]{21, 22, 23, 25, 53, 80, 443, 3306}) {
                    engine.process(new LogEvent(ip, "unknown", "/", BOT_AGENTS[3], "", cc,
                            EventType.PORT_ACCESS, port, ""));
                }
            }
            case 4 -> engine.process(new LogEvent(ip, "unknown", "/downloads", BOT_AGENTS[1], "", cc,
                    EventType.DOWNLOAD_REQUEST, 0, "payload.exe"));
            case 5 -> {   // request flood
                for (int i = 0; i < 40 + random.nextInt(25); i++) {
                    engine.process(new LogEvent(ip, "unknown", "/api/data", BOT_AGENTS[0], "", cc,
                            EventType.HTTP_REQUEST, 0, ""));
                }
            }
            case 6 -> {   // multi-vector: flood, then SQL injection from a scanner (signals stack up)
                for (int i = 0; i < 35; i++) {
                    engine.process(new LogEvent(ip, "unknown", "/api/data", BOT_AGENTS[0], "", cc,
                            EventType.HTTP_REQUEST, 0, ""));
                }
                engine.process(new LogEvent(ip, "guest", "/search", BOT_AGENTS[1],
                        "id=1' OR 1=1 --", cc, EventType.HTTP_REQUEST, 0, ""));
            }
            case 7 -> {   // multi-vector: brute force, then malware download
                for (int i = 0; i < 8; i++) {
                    engine.process(new LogEvent(ip, "root", "/login", BOT_AGENTS[2], "", cc,
                            EventType.LOGIN_FAILED, 0, ""));
                }
                engine.process(new LogEvent(ip, "root", "/downloads", BOT_AGENTS[1], "", cc,
                        EventType.DOWNLOAD_REQUEST, 0, "payload.exe"));
            }
        }
    }
}
