package com.threatdetection.aegis.defense;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Duration;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.function.BiConsumer;

import static com.threatdetection.aegis.JsonUtil.str;

/**
 * Tells the administrator about HIGH and CRITICAL incidents: console line, an escalation log file,
 * and (optional) an HTTP webhook (-Daegis.defense.webhook=https://...). The webhook runs on a
 * background thread with short timeouts, so a dead endpoint can never slow detection down; its
 * outcome is reported through the callback (and therefore into the audit trail).
 */
public final class Escalator {
    private final Path log;
    private final String webhook;
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3)).build();
    private final ExecutorService pool = new ThreadPoolExecutor(1, 1, 0, TimeUnit.SECONDS, new ArrayBlockingQueue<>(100),
            r -> { Thread t = new Thread(r, "aegis-escalation"); t.setDaemon(true); return t; });

    public Escalator(Path dir, String webhook) {
        this.log = dir.resolve("defense-escalations.log");
        this.webhook = webhook == null ? "" : webhook;
    }

    public boolean webhookConfigured() { return !webhook.isEmpty(); }

    /** @param outcome called with a short result text for the audit trail */
    public void notifyAdmin(String severity, String title, String body, BiConsumer<String, String> outcome) {
        String line = java.time.Instant.now() + " [" + severity + "] " + title + " - " + body;
        System.out.println("[AEGIS ESCALATION] " + line);
        String fileResult = "logged";
        try {
            Files.createDirectories(log.getParent());
            Files.writeString(log, line.replace('\n', ' ') + System.lineSeparator(), StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (Exception e) {
            fileResult = "log write failed: " + e.getMessage();
        }
        if (webhook.isEmpty()) {
            outcome.accept("console+file", fileResult);
            return;
        }
        String payload = "{\"severity\":" + str(severity) + ",\"title\":" + str(title) + ",\"body\":" + str(body)
                + ",\"text\":" + str("[AEGIS " + severity + "] " + title + " - " + body) + "}";
        String fr = fileResult;
        try {
            pool.execute(() -> {
                try {
                    HttpResponse<Void> r = http.send(HttpRequest.newBuilder(URI.create(webhook)).timeout(Duration.ofSeconds(5))
                            .header("Content-Type", "application/json")
                            .POST(HttpRequest.BodyPublishers.ofString(payload)).build(), HttpResponse.BodyHandlers.discarding());
                    outcome.accept("webhook", fr + "; webhook HTTP " + r.statusCode());
                } catch (Exception e) {
                    outcome.accept("webhook", fr + "; webhook FAILED: " + e.getClass().getSimpleName());
                }
            });
        } catch (RejectedExecutionException e) {
            outcome.accept("webhook", fr + "; webhook queue full, dropped");
        }
    }
}
