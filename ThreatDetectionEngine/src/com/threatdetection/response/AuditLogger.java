package com.threatdetection.response;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;

/**
 * Append-only audit trail of every response decision and firewall change. Each line carries the SHA-256 of
 * the previous line, so editing or deleting an earlier line is detectable with {@link #verify()}.
 * (Tamper-EVIDENT, not tamper-proof: someone with file access can still rewrite the whole chain.)
 */
public final class AuditLogger {
    public record Entry(long seq, long ts, String actor, String action, String target, String result, String detail,
                        String prevHash, String hash) {}

    private static final String GENESIS = "0".repeat(64);
    private static final int KEEP = 500;

    private final Path file;           // null = memory only
    private final List<Entry> recent = new ArrayList<>();
    private long seq;
    private String lastHash = GENESIS;
    private boolean writeFailed;

    public AuditLogger(Path file) {
        this.file = file;
        if (file != null) {
            try {
                Files.createDirectories(file.toAbsolutePath().getParent());
                if (Files.exists(file)) {
                    for (String line : Files.readAllLines(file, StandardCharsets.UTF_8)) {
                        Entry e = parse(line);
                        if (e != null) { seq = e.seq(); lastHash = e.hash(); keep(e); }
                    }
                }
            } catch (IOException e) {
                writeFailed = true;
                System.err.println("[AEGIS] audit log not readable: " + e.getMessage());
            }
        }
    }

    public static AuditLogger memoryOnly() { return new AuditLogger(null); }

    public synchronized Entry log(String actor, String action, String target, String result, String detail) {
        long ts = System.currentTimeMillis();
        long n = ++seq;
        String hash = sha(lastHash + "|" + n + "|" + ts + "|" + actor + "|" + action + "|" + target + "|" + result + "|" + detail);
        Entry e = new Entry(n, ts, actor, action, target, result, detail, lastHash, hash);
        lastHash = hash;
        keep(e);
        if (file != null) {
            try {
                Files.writeString(file, format(e) + "\n", StandardCharsets.UTF_8,
                        StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            } catch (IOException ex) {
                if (!writeFailed) System.err.println("[AEGIS] audit log write failed: " + ex.getMessage());
                writeFailed = true;
            }
        }
        return e;
    }

    public synchronized List<Entry> recent(int max) {
        int from = Math.max(0, recent.size() - max);
        return new ArrayList<>(recent.subList(from, recent.size()));
    }

    /** @return null when the on-disk chain is intact, otherwise a description of the first problem. */
    public synchronized String verify() {
        if (file == null || !Files.exists(file)) return null;
        try {
            String prev = GENESIS;
            long expectSeq = 0;
            for (String line : Files.readAllLines(file, StandardCharsets.UTF_8)) {
                Entry e = parse(line);
                if (e == null) return "unreadable line after entry " + expectSeq;
                if (e.seq() != ++expectSeq) return "sequence gap at entry " + e.seq();
                if (!e.prevHash().equals(prev)) return "chain broken at entry " + e.seq();
                String h = sha(e.prevHash() + "|" + e.seq() + "|" + e.ts() + "|" + e.actor() + "|" + e.action() + "|"
                        + e.target() + "|" + e.result() + "|" + e.detail());
                if (!h.equals(e.hash())) return "entry " + e.seq() + " was modified";
                prev = e.hash();
            }
            return null;
        } catch (IOException e) {
            return "cannot read audit file: " + e.getMessage();
        }
    }

    public boolean writeFailed() { return writeFailed; }

    private void keep(Entry e) {
        recent.add(e);
        if (recent.size() > KEEP) recent.remove(0);
    }

    // one line: seq \t ts \t actor \t action \t target \t result \t detail \t prev \t hash  (fields are escaped)
    private static String format(Entry e) {
        return e.seq() + "\t" + e.ts() + "\t" + esc(e.actor()) + "\t" + esc(e.action()) + "\t" + esc(e.target()) + "\t"
                + esc(e.result()) + "\t" + esc(e.detail()) + "\t" + e.prevHash() + "\t" + e.hash();
    }

    private static Entry parse(String line) {
        String[] f = line.split("\t", -1);
        if (f.length != 9) return null;
        try {
            return new Entry(Long.parseLong(f[0]), Long.parseLong(f[1]), unesc(f[2]), unesc(f[3]), unesc(f[4]),
                    unesc(f[5]), unesc(f[6]), f[7], f[8]);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private static String esc(String s) {
        return (s == null ? "" : s).replace("\\", "\\\\").replace("\t", "\\t").replace("\n", "\\n").replace("\r", "\\r");
    }

    private static String unesc(String s) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\\' && i + 1 < s.length()) {
                char n = s.charAt(++i);
                sb.append(n == 't' ? '\t' : n == 'n' ? '\n' : n == 'r' ? '\r' : n);
            } else sb.append(c);
        }
        return sb.toString();
    }

    private static String sha(String s) {
        try {
            byte[] d = MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : d) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
