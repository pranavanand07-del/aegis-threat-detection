package com.threatdetection.aegis.ingest;

import com.threatdetection.aegis.storage.AegisStore;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

/**
 * Polls a Windows event channel with the built-in wevtutil tool every 5 seconds (no agents, no
 * dependencies). Reading the Security log requires running the JVM as Administrator; the
 * Sysmon channel requires Sysmon to be installed. Problems are shown in the dashboard's source list.
 */
public final class WindowsEventSource implements Runnable {
    private static final long POLL_MS = 5000, LOOKBACK_MS = 15000;

    private final String name;
    private final String channel;
    private final int[] eventIds;
    private final Consumer<com.threatdetection.aegis.AegisSignal> sink;
    private final AegisStore store;
    private final Set<String> seen = new HashSet<>();
    private final Deque<String> seenOrder = new ArrayDeque<>();
    private volatile boolean running = true;

    public WindowsEventSource(String name, String channel, int[] eventIds,
                              Consumer<com.threatdetection.aegis.AegisSignal> sink, AegisStore store) {
        this.name = name;
        this.channel = channel;
        this.eventIds = eventIds;
        this.sink = sink;
        this.store = store;
    }

    public void stop() { running = false; }

    @Override
    public void run() {
        StringBuilder ids = new StringBuilder();
        for (int i = 0; i < eventIds.length; i++) ids.append(i > 0 ? " or " : "").append("EventID=").append(eventIds[i]);
        String query = "*[System[(" + ids + ") and TimeCreated[timediff(@SystemTime) <= " + LOOKBACK_MS + "]]]";
        while (running) {
            try {
                Process p = new ProcessBuilder("wevtutil", "qe", channel, "/q:" + query, "/f:xml")
                        .redirectErrorStream(true).start();
                StringBuilder out = new StringBuilder();
                try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
                    String l;
                    while ((l = r.readLine()) != null) out.append(l).append('\n');
                }
                p.waitFor(10, TimeUnit.SECONDS);
                String text = out.toString();
                if (p.exitValue() != 0 || text.toLowerCase().contains("access is denied")) {
                    store.setSourceState(name, "ERROR", text.isBlank() ? "wevtutil failed (exit " + p.exitValue() + ")"
                            : text.trim().split("\n")[0] + (text.toLowerCase().contains("denied") ? " - run the JVM as Administrator" : ""));
                } else {
                    store.setSourceState(name, "ACTIVE", "Polling '" + channel + "' every " + POLL_MS / 1000 + "s");
                    List<WindowsEventMapper.Parsed> parsed = WindowsEventMapper.parse(text);
                    for (WindowsEventMapper.Parsed e : parsed) {
                        String key = e.recordId;
                        if (!key.isEmpty() && !seen.add(key)) continue;
                        seenOrder.addLast(key);
                        if (seenOrder.size() > 5000) seen.remove(seenOrder.pollFirst());
                        sink.accept(e.signal);
                    }
                }
                Thread.sleep(POLL_MS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            } catch (Exception e) {
                store.setSourceState(name, "ERROR", String.valueOf(e.getMessage()));
                try { Thread.sleep(POLL_MS); } catch (InterruptedException ie) { Thread.currentThread().interrupt(); return; }
            }
        }
    }
}
