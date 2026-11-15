package com.threatdetection.aegis.defense;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.UUID;

/**
 * Moves a suspicious file into a controlled directory and records where it came from. It NEVER
 * deletes anything: the file keeps its bytes under a neutral name, and restore() puts it back.
 * Only files inside a configured root (-Daegis.defense.quarantine.roots) can be quarantined, and
 * operating-system directories are always refused, so a wrong or forged event cannot be used to
 * move system files.
 */
public final class QuarantineService {
    public record Held(String id, String original, String sha256, long size) {}

    private final Path dir;
    private final List<Path> roots;

    public QuarantineService(Path dir, List<Path> roots) {
        this.dir = dir.toAbsolutePath().normalize();
        this.roots = roots.stream().map(r -> r.toAbsolutePath().normalize()).toList();
    }

    public boolean enabled() { return !roots.isEmpty(); }
    public Path dir() { return dir; }
    public List<Path> roots() { return roots; }

    /** @return why the path may not be quarantined, or null when it is allowed. */
    public String refusal(String file) {
        if (roots.isEmpty()) return "no quarantine roots configured (-Daegis.defense.quarantine.roots)";
        Path p;
        try {
            p = Path.of(file).toRealPath();
        } catch (Exception e) {
            return "file not found or not accessible";
        }
        if (!Files.isRegularFile(p)) return "not a regular file";
        if (p.startsWith(dir)) return "already inside the quarantine directory";
        String s = p.toString().toLowerCase(Locale.ROOT).replace('\\', '/');
        for (String bad : new String[]{"c:/windows", "c:/program files", "/bin/", "/sbin/", "/usr/", "/etc/", "/boot/", "/system/"}) {
            if (s.startsWith(bad) || s.contains("/windows/system32")) return "operating-system location is never quarantined";
        }
        for (Path r : roots) {
            try {
                if (p.startsWith(r.toRealPath())) return null;
            } catch (IOException ignored) {
                // root missing: cannot match
            }
        }
        return "outside the configured quarantine roots";
    }

    public Held quarantine(String file, String reason) throws IOException {
        String why = refusal(file);
        if (why != null) throw new IOException(why);
        Path src = Path.of(file).toRealPath();
        Files.createDirectories(dir);
        String id = "Q-" + UUID.randomUUID().toString().substring(0, 8);
        long size = Files.size(src);
        String hash = sha256(src);
        Path dest = dir.resolve(id + ".quarantined");
        Files.move(src, dest);   // move, never delete: if the move fails the original stays where it was
        String meta = "id=" + id + "\noriginal=" + src + "\nsha256=" + hash + "\nsize=" + size + "\nreason="
                + reason.replace('\n', ' ') + "\nat=" + System.currentTimeMillis() + "\n";
        Files.writeString(dir.resolve(id + ".meta"), meta, StandardCharsets.UTF_8);
        return new Held(id, src.toString(), hash, size);
    }

    /** Puts the file back where it came from; refuses to overwrite anything that exists there now. */
    public String restore(String id) {
        if (!id.matches("Q-[0-9a-f]{8}")) return "invalid quarantine id";
        try {
            Path meta = dir.resolve(id + ".meta");
            Path held = dir.resolve(id + ".quarantined");
            if (!Files.exists(meta) || !Files.exists(held)) return "quarantined file not found";
            String original = null;
            for (String l : Files.readAllLines(meta, StandardCharsets.UTF_8)) if (l.startsWith("original=")) original = l.substring(9);
            if (original == null) return "metadata has no original path";
            Path target = Path.of(original);
            if (Files.exists(target)) return "a file already exists at " + original;
            Files.move(held, target, StandardCopyOption.ATOMIC_MOVE);
            Files.move(meta, dir.resolve(id + ".restored"), StandardCopyOption.REPLACE_EXISTING);
            return null;
        } catch (Exception e) {
            return "restore failed: " + e.getMessage();
        }
    }

    private static String sha256(Path p) throws IOException {
        try (InputStream in = Files.newInputStream(p)) {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] buf = new byte[65536];
            int n;
            while ((n = in.read(buf)) > 0) md.update(buf, 0, n);
            return HexFormat.of().formatHex(md.digest());
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IOException(e);
        }
    }
}
