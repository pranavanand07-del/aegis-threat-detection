package com.threatdetection.aegis.ingest;

import com.threatdetection.aegis.AegisSignal;
import com.threatdetection.aegis.storage.AegisStore;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.function.Consumer;
import java.util.function.Function;

/**
 * Follows a growing log file (like `tail -F`): starts at the end unless -Daegis.ingest.fromStart=true,
 * survives truncation/rotation, and reports its health to the AEGIS source list.
 */
public final class FileTailer implements Runnable {
    private final String name;
    private final Path path;
    private final Function<String, AegisSignal> parser;
    private final Consumer<AegisSignal> sink;
    private final AegisStore store;
    private final boolean fromStart;
    private volatile boolean running = true;

    public FileTailer(String name, Path path, Function<String, AegisSignal> parser, Consumer<AegisSignal> sink,
                      AegisStore store, boolean fromStart) {
        this.name = name;
        this.path = path;
        this.parser = parser;
        this.sink = sink;
        this.store = store;
        this.fromStart = fromStart;
    }

    public void stop() { running = false; }

    @Override
    public void run() {
        long pos = -1;
        while (running) {
            try {
                if (!Files.isReadable(path)) {
                    store.setSourceState(name, "WAITING", "File not found or unreadable: " + path);
                    pos = -1;
                    Thread.sleep(2000);
                    continue;
                }
                long len = Files.size(path);
                if (pos < 0) pos = fromStart ? 0 : len;
                if (len < pos) pos = 0;                       // rotated or truncated
                if (len > pos) pos = readNew(pos, len);
                if (!"ACTIVE".equals(currentState())) store.setSourceState(name, "ACTIVE", "Following " + path);
                Thread.sleep(500);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            } catch (IOException | RuntimeException e) {
                store.setSourceState(name, "ERROR", e.getMessage() == null ? e.toString() : e.getMessage());
                try { Thread.sleep(3000); } catch (InterruptedException ie) { Thread.currentThread().interrupt(); return; }
            }
        }
    }

    private String currentState() {
        for (AegisStore.SourceStatus s : store.sources()) if (s.name.equals(name)) return s.state;
        return "";
    }

    private long readNew(long pos, long len) throws IOException {
        long toRead = Math.min(len - pos, 4L * 1024 * 1024);
        byte[] buf = new byte[(int) toRead];
        try (RandomAccessFile f = new RandomAccessFile(path.toFile(), "r")) {
            f.seek(pos);
            f.readFully(buf);
        }
        int lastNl = -1;
        for (int i = buf.length - 1; i >= 0; i--) if (buf[i] == '\n') { lastNl = i; break; }
        if (lastNl < 0) return buf.length >= 4 * 1024 * 1024 ? pos + buf.length : pos;   // wait for a full line
        String text = new String(buf, 0, lastNl, StandardCharsets.UTF_8);
        for (String line : text.split("\n")) {
            line = line.stripTrailing();
            if (line.isEmpty()) continue;
            AegisSignal s = parser.apply(line);
            if (s != null) sink.accept(s);
        }
        return pos + lastNl + 1;
    }
}
