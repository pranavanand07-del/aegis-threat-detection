package com.threatdetection.simulator;

import com.threatdetection.engine.ThreatDetectionEngine;
import com.threatdetection.model.EventType;
import com.threatdetection.model.LogEvent;

import java.util.Random;

/**
 * Generates a continuous mix of normal traffic and attack scenarios so the
 * dashboard has live data to show without needing manual curl requests.
 */
public class TrafficSimulator implements Runnable {
    private final ThreatDetectionEngine engine;
    private final Random random = new Random();

    private final String[] normalIps = {"10.0.0.5", "10.0.0.6", "192.168.1.20"};
    private final String[] attackerIps = {"66.77.88.99", "203.0.113.5", "1.2.3.4"};
    private final String[] normalAgents = {"Mozilla/5.0", "Chrome/125.0", "Safari/17.0"};
    private final String[] botAgents = {"python-requests/2.31", "sqlmap/1.7", "curl/8.4", "nmap scripting engine"};

    public TrafficSimulator(ThreatDetectionEngine engine) {
        this.engine = engine;
    }

    @Override
    public void run() {
        while (true) {
            try {
                simulateNormalTraffic();
                if (random.nextInt(5) == 0) {
                    simulateAttackScenario();
                }
                Thread.sleep(800);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }

    private void simulateNormalTraffic() {
        String ip = normalIps[random.nextInt(normalIps.length)];
        LogEvent event = new LogEvent(ip, "user" + random.nextInt(100), "/home",
                normalAgents[random.nextInt(normalAgents.length)], "",
                "IN", EventType.HTTP_REQUEST, 0, "");
        engine.process(event);
    }

    private void simulateAttackScenario() {
        int scenario = random.nextInt(6);
        String attackerIp = attackerIps[random.nextInt(attackerIps.length)];

        switch (scenario) {
            case 0 -> {
                for (int i = 0; i < 7; i++) {
                    engine.process(new LogEvent(attackerIp, "admin", "/login", botAgents[2],
                            "", "RU", EventType.LOGIN_FAILED, 0, ""));
                }
            }
            case 1 -> engine.process(new LogEvent(attackerIp, "guest", "/search",
                    normalAgents[0], "id=1' OR 1=1 --", "CN", EventType.HTTP_REQUEST, 0, ""));
            case 2 -> engine.process(new LogEvent(attackerIp, "guest", "/comment",
                    normalAgents[0], "<script>document.cookie</script>", "CN", EventType.HTTP_REQUEST, 0, ""));
            case 3 -> {
                for (int port : new int[]{21, 22, 23, 25, 53, 80, 443, 3306}) {
                    engine.process(new LogEvent(attackerIp, "unknown", "/", botAgents[3],
                            "", "RU", EventType.PORT_ACCESS, port, ""));
                }
            }
            case 4 -> {
                for (int i = 0; i < 55; i++) {
                    engine.process(new LogEvent(attackerIp, "unknown", "/api/data",
                            botAgents[0], "", "US", EventType.HTTP_REQUEST, 0, ""));
                }
            }
            case 5 -> engine.process(new LogEvent(attackerIp, "unknown", "/downloads",
                    botAgents[1], "", "DE", EventType.DOWNLOAD_REQUEST, 0, "payload.exe"));
        }
    }
}
