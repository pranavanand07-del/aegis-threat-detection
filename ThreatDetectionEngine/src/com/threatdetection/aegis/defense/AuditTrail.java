package com.threatdetection.aegis.defense;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HexFormat;
import java.util.List;

import static com.threatdetection.aegis.JsonUtil.str;

/**
 * Append-only, hash-chained record of every defensive decision: sequence, time, operator, action,
 * target, level, mode, result, reason. Each line contains the SHA-256 of the previous line, so
 * editing, deleting or reordering any earlier line is detected by {@link #verify()}.
 *
 * Honest limit: this is TAMPER-EVIDENT, not tamper-proof. Someone with write access to the file
 * can rewrite the whole chain. For real immutability, also ship the lines to a remote log or WORM storage.
 */
public final class AuditTrail {
    public record Record(long seq, long ts, String operator, String action, String target, String level,
                         String mode, String result, String reason, String eventId) {
        public String toJson() {
            return "{\"seq\":" + seq + ",\"ts\":" + ts + ",\"operator\":" + str(operator) + ",\"action\":" + str(action)
                    + ",\"target\":" + str(target) + ",\"level\":" + str(level) + ",\"mode\":" + str(mode)
                    + ",\"result\":" + str(result) + ",\"reason\":" + str(reason) + ",\"eventId\":" + str(eventId) + "}";
        }
    }

    public record Verification(boolean ok, long records, long firstBadSeq, String message) {}

    private static final String GENESIS = "0".repeat(64);
    private final Path file;
    private final Deque<Record> recent = new ArrayDeque<>();
    private BufferedWriter out;
    private long seq;
    private String lastHash = GENESIS;

    public AuditTrail(Path dir) throws IOException {
        Files.createDirectories(dir);
        this.file = dir.resolve("defense-audit.tsv");
        if (Files.exists(file)) {
            try (var lines = Files.lines(file, StandardCharsets.UTF_8)) {
                for (String l : (Iterable<String>) lines::iterator) {
                    String[] f = l.split("\t", -1);
                    if (f.length != 12) continue;
                    seq = Long.parseLong(f[0]);
                    lastHash = f[11];
                    recent.addLast(parse(f));
                    if (recent.size() > 500) recent.removeFirst();
                }
            } catch (RuntimeException e) {
                System.err.println("[AEGIS] audit trail could not be fully read: " + e.getMessage());
            }
        }
    }

    public Path file() { return file; }

    public synchronized Record record(String operator, String action, String target, String level, String mode,
                                      String result, String reason, String eventId) {
        long ts = System.currentTimeMillis();
        String[] f = {Long.toString(++seq), Long.toString(ts), clean(operator), clean(action), clean(target), clean(level),
                clean(mode), clean(result), clean(reason), clean(eventId), lastHash};
        String hash = sha256(String.join("\t", f));
        try {
            if (out == null) {
                out = Files.newBufferedWriter(file, StandardCharsets.UTF_8, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            }
            out.write(String.join("\t", f) + "\t" + hash);
            out.newLine();
            out.flush();
        } catch (IOException e) {
            System.err.println("[AEGIS] AUDIT WRITE FAILED: " + e.getMessage());
        }
        lastHash = hash;
        Record r = new Record(seq, ts, f[2], f[3], f[4], f[5], f[6], f[7], f[8], f[9]);
        recent.addLast(r);
        if (recent.size() > 500) recent.removeFirst();
        return r;
    }

    public synchronized List<Record> tail(int n) {
        List<Record> all = new ArrayList<>(recent);
        return all.subList(Math.max(0, all.size() - n), all.size());
    }

    /** Re-computes the whole chain from the file on disk. */
    public synchronized Verification verify() {
        if (!Files.exists(file)) return new Verification(true, 0, 0, "No audit records yet");
        String prev = GENESIS;
        long n = 0;
        try (var lines = Files.lines(file, StandardCharsets.UTF_8)) {
            for (String l : (Iterable<String>) lines::iterator) {
                String[] f = l.split("\t", -1);
                if (f.length != 12) return new Verification(false, n, n + 1, "Malformed record after #" + n);
                String body = String.join("\t", java.util.Arrays.copyOfRange(f, 0, 11));
                if (!f[10].equals(prev) || !sha256(body).equals(f[11]) || Long.parseLong(f[0]) != n + 1) {
                    return new Verification(false, n, n + 1, "Chain broken at record #" + (n + 1));
                }
                prev = f[11];
                n++;
            }
        } catch (IOException | RuntimeException e) {
            return new Verification(false, n, n + 1, "Could not read audit file: " + e.getMessage());
        }
        return new Verification(true, n, 0, "Chain intact (" + n + " records)");
    }

    private static Record parse(String[] f) {
        return new Record(Long.parseLong(f[0]), Long.parseLong(f[1]), f[2], f[3], f[4], f[5], f[6], f[7], f[8], f[9]);
    }

    private static String clean(String s) {
        if (s == null) return "";
        String t = s.replace('\t', ' ').replace('\n', ' ').replace('\r', ' ');
        return t.length() > 400 ? t.substring(0, 400) + "..." : t;
    }

    private static String sha256(String s) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8)));
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
