package com.threatdetection.aegis.storage;

import com.threatdetection.aegis.AegisEvent;
import com.threatdetection.aegis.DataSource;
import com.threatdetection.model.ThreatLevel;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Locale;

/**
 * Dependency-free persistence: alerts (LOW and above) are appended to a tab-separated file so
 * time-range filtering and playback survive a restart. Disable with -Daegis.persist=false,
 * relocate with -Daegis.data.dir=... (default ./aegis-data). The live file rotates at 50 MB into
 * alerts.tsv.1 .. .N (-Daegis.rotate.keep, default 5); only the archive beyond that is deleted. Appends are flushed to
 * the OS but not fsynced, so a power failure can still lose the last few events; a torn last line is skipped on load.
 */
public final class AegisPersistence {
    private static final long ROTATE_BYTES = 50L * 1024 * 1024;
    private static final char SEP_RULE = '\u001e', SEP_FIELD = '\u001f';

    private final Path file;
    private final long rotateBytes;
    private final int keep;
    private BufferedWriter out;
    private long size = -1;
    private long failures;

    public AegisPersistence(Path dir) throws IOException {
        this(dir, ROTATE_BYTES, Math.max(1, Integer.getInteger("aegis.rotate.keep", 5)));
    }

    /** @param rotateBytes size at which the live file is rotated; @param keep rotated generations kept (alerts.tsv.1 ... .keep). */
    public AegisPersistence(Path dir, long rotateBytes, int keep) throws IOException {
        Files.createDirectories(dir);
        this.file = dir.resolve("alerts.tsv");
        this.rotateBytes = rotateBytes;
        this.keep = Math.max(1, keep);
    }

    public Path file() { return file; }

    /** Number of failed writes since start (surfaced so a full disk is not silent). */
    public synchronized long failures() { return failures; }

    private Path generation(int n) { return file.resolveSibling(file.getFileName() + "." + n); }

    public synchronized void append(AegisEvent e) {
        try {
            if (out == null) {
                boolean needNewline = endsMidLine();
                out = Files.newBufferedWriter(file, StandardCharsets.UTF_8, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
                size = Files.size(file);
                // A crash can leave a torn last line with no newline; start on a fresh line so the NEXT event is not glued to it.
                if (needNewline) { out.newLine(); size++; }
            }
            String line = toLine(e);
            out.write(line);
            out.newLine();
            out.flush();
            size += line.length() + 1;
            if (size > rotateBytes) rotate();
        } catch (IOException ex) {
            failures++;
            closeQuietly();          // reopen on the next append instead of writing to a broken stream
            System.err.println("[AEGIS] persistence write failed: " + ex.getMessage());
        }
    }

    private boolean endsMidLine() throws IOException {
        if (!Files.exists(file) || Files.size(file) == 0) return false;
        try (var ch = Files.newByteChannel(file)) {
            ch.position(ch.size() - 1);
            java.nio.ByteBuffer b = java.nio.ByteBuffer.allocate(1);
            ch.read(b);
            return b.get(0) != '\n';
        }
    }

    private void closeQuietly() {
        try { if (out != null) out.close(); } catch (IOException ignored) { /* already failing */ }
        out = null;
        size = -1;
    }

    /**
     * Shifts alerts.tsv.(n-1) -> .n from the oldest down, then alerts.tsv -> .1. Only the generation beyond the
     * configured retention ({@code keep}) is deleted, and that deletion is logged. Every step is a rename, so a crash in
     * the middle loses nothing: at worst a slot is empty or a file is still under its old name.
     */
    private void rotate() throws IOException {
        closeQuietly();
        Path oldest = generation(keep);
        if (Files.exists(oldest)) {
            System.err.println("[AEGIS] retention: dropping the oldest alert archive " + oldest.getFileName() + " (keeping " + keep + ")");
            Files.delete(oldest);
        }
        for (int n = keep - 1; n >= 1; n--) {
            Path from = generation(n);
            if (Files.exists(from)) moveAtomic(from, generation(n + 1));
        }
        moveAtomic(file, generation(1));
    }

    private static void moveAtomic(Path from, Path to) throws IOException {
        try {
            Files.move(from, to, StandardCopyOption.ATOMIC_MOVE);
        } catch (java.nio.file.AtomicMoveNotSupportedException e) {
            Files.move(from, to);
        }
    }

    /** Loads the newest {@code max} stored alerts (across rotated archives too), oldest first. */
    public synchronized List<AegisEvent> load(int max) {
        List<AegisEvent> list = new ArrayList<>();
        Deque<String> tail = new ArrayDeque<>();
        List<Path> files = new ArrayList<>();
        for (int n = keep; n >= 1; n--) if (Files.exists(generation(n))) files.add(generation(n));
        if (Files.exists(file)) files.add(file);
        for (Path f : files) {
            try (var lines = Files.lines(f, StandardCharsets.UTF_8)) {
                lines.forEach(l -> {
                    tail.addLast(l);
                    if (tail.size() > max) tail.removeFirst();
                });
            } catch (IOException | RuntimeException ex) {        // RuntimeException covers UncheckedIOException (bad encoding)
                System.err.println("[AEGIS] could not fully read " + f + ": " + ex.getMessage());
            }
        }
        int skipped = 0;
        for (String l : tail) {
            try {
                AegisEvent e = fromLine(l);
                if (e != null) list.add(e); else skipped++;
            } catch (RuntimeException ignored) {
                skipped++;           // a corrupt or torn line is skipped, the rest of the history is still loaded
            }
        }
        if (skipped > 0) System.err.println("[AEGIS] skipped " + skipped + " corrupt stored alert line(s)");
        return list;
    }

    static String clean(String s) {
        if (s == null) return "";
        return s.replace('\t', ' ').replace('\n', ' ').replace('\r', ' ')
                .replace(SEP_RULE, ' ').replace(SEP_FIELD, ' ');
    }

    static String toLine(AegisEvent e) {
        StringBuilder rules = new StringBuilder();
        for (AegisEvent.Contribution c : e.rules) {
            if (rules.length() > 0) rules.append(SEP_RULE);
            rules.append(clean(c.rule)).append(SEP_FIELD).append(c.score).append(SEP_FIELD)
                 .append(clean(c.origin)).append(SEP_FIELD).append(clean(c.detail));
        }
        String[] f = {
                Long.toString(e.ts), clean(e.ip), e.internal ? "1" : "0", clean(e.host), clean(e.user),
                clean(e.kind), clean(e.channel), clean(e.summary), clean(e.target), clean(e.targetType),
                e.source.name(), Integer.toString(e.score), e.level.name(), e.blocked ? "1" : "0",
                rules.toString(), clean(e.repVerdict), clean(e.repDetail), clean(e.geoClass), clean(e.geoSource),
                clean(e.cc), clean(e.country), clean(e.city),
                String.format(Locale.ROOT, "%.5f", e.lat), String.format(Locale.ROOT, "%.5f", e.lon)
        };
        return String.join("\t", f);
    }

    static AegisEvent fromLine(String line) {
        String[] f = line.split("\t", -1);
        if (f.length < 24) return null;
        AegisEvent e = new AegisEvent();
        e.ts = Long.parseLong(f[0]);
        e.ip = f[1];
        e.internal = "1".equals(f[2]);
        e.host = f[3];
        e.user = f[4];
        e.kind = f[5];
        e.channel = f[6];
        e.summary = f[7];
        e.target = f[8];
        e.targetType = f[9];
        e.source = DataSource.valueOf(f[10]);
        e.score = Integer.parseInt(f[11]);
        e.level = ThreatLevel.valueOf(f[12]);
        e.blocked = "1".equals(f[13]);
        if (!f[14].isEmpty()) {
            for (String r : f[14].split(String.valueOf(SEP_RULE))) {
                String[] p = r.split(String.valueOf(SEP_FIELD), -1);
                if (p.length >= 4) e.rules.add(new AegisEvent.Contribution(p[0], Integer.parseInt(p[1]), p[2], p[3]));
            }
        }
        e.repVerdict = f[15];
        e.repDetail = f[16];
        e.geoClass = f[17];
        e.geoSource = f[18];
        e.cc = f[19];
        e.country = f[20];
        e.city = f[21];
        e.lat = Double.parseDouble(f[22]);
        e.lon = Double.parseDouble(f[23]);
        return e;
    }
}
