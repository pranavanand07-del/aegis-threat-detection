package com.threatdetection.server;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Locale;
import java.util.Set;

/**
 * Protects every endpoint that changes state or feeds events into the detector.
 *
 * The engine blocks addresses based on the events it is given, and analysts approve firewall actions through the same
 * API, so a write must prove who it comes from. Being on the loopback interface is NOT enough: any web page the
 * operator visits can make their browser send requests to http://127.0.0.1 (CSRF / DNS rebinding).
 *
 * Checks, all performed before any side effect, in this order:
 *  1. per-client rate limit (429)
 *  2. Host header must be a known local name (anti DNS-rebinding)
 *  3. browser requests: Origin must match this server (or -Daegis.allowed.origins) and Sec-Fetch-Site must be
 *     same-origin / none
 *  4. a request with a body must carry a supported Content-Type (415)
 *  5. an API key in X-API-Key (or Authorization: Bearer), compared in constant time (401)
 *
 * Key: -Daegis.api.key=SECRET or env AEGIS_API_KEY. When neither is set a random key is generated for this run and
 * written to aegis-data/api-key.txt (owner-only where the file system supports it); the dashboard served by this same
 * server fetches it from /api/session (loopback + same-origin only). The key value is never logged.
 */
public final class WriteGuard {
    private WriteGuard() {}

    private static final SecureRandom RANDOM = new SecureRandom();
    private static volatile String generatedKey;
    private static volatile RateLimiter limiter;
    private static final Set<String> CONTENT_TYPES = Set.of("application/x-www-form-urlencoded", "application/json",
            "text/plain", "text/xml", "application/xml");

    /** Result of a check: status 0 = allowed, otherwise the HTTP status and message to send. */
    public record Verdict(int status, String message) {
        public boolean ok() { return status == 0; }
    }

    private static final Verdict OK = new Verdict(0, "");

    /** The explicitly configured key (empty when none). */
    public static String key() {
        String k = System.getProperty("aegis.api.key", "");
        if (k.isEmpty()) { String e = System.getenv("AEGIS_API_KEY"); if (e != null) k = e; }
        return k;
    }

    /** True when the operator configured a key; false when this run uses a generated one. */
    public static boolean keyConfigured() { return !key().isEmpty(); }

    /** The key writes must present: the configured one, else a per-run random one. */
    public static String effectiveKey() {
        String k = key();
        if (!k.isEmpty()) return k;
        String g = generatedKey;
        if (g == null) {
            synchronized (WriteGuard.class) {
                g = generatedKey;
                if (g == null) {
                    byte[] b = new byte[32];
                    RANDOM.nextBytes(b);
                    g = Base64.getUrlEncoder().withoutPadding().encodeToString(b);
                    generatedKey = g;
                    persistGeneratedKey(g);
                }
            }
        }
        return g;
    }

    private static void persistGeneratedKey(String k) {
        if ("false".equalsIgnoreCase(System.getProperty("aegis.persist"))) return;
        try {
            Path dir = Path.of(System.getProperty("aegis.data.dir", "aegis-data"));
            Files.createDirectories(dir);
            Path f = dir.resolve("api-key.txt");
            Files.writeString(f, k + "\n", StandardCharsets.UTF_8);
            try { Files.setPosixFilePermissions(f, PosixFilePermissions.fromString("rw-------")); }
            catch (UnsupportedOperationException ignored) { /* e.g. Windows: rely on the directory ACL */ }
            System.out.println("[AEGIS] no -Daegis.api.key set: a random key for this run is in " + f
                    + " (scripts send it as X-API-Key; the dashboard fetches it automatically)");
        } catch (IOException e) {
            System.err.println("[AEGIS] could not write the generated API key file: " + e.getMessage());
        }
    }

    /** Test hook: forget the generated key and rate-limit state. */
    public static void resetForTests() { generatedKey = null; limiter = null; }

    private static RateLimiter limiter() {
        RateLimiter l = limiter;
        if (l == null) {
            synchronized (WriteGuard.class) {
                if (limiter == null) {
                    double rate = parseDouble(System.getProperty("aegis.api.rate"), 50);
                    limiter = new RateLimiter(rate, Math.max(10, rate * 2), 10_000);
                }
                l = limiter;
            }
        }
        return l;
    }

    private static double parseDouble(String s, double dflt) {
        try { return s == null ? dflt : Double.parseDouble(s.trim()); } catch (NumberFormatException e) { return dflt; }
    }

    /** @return true when the request may proceed; otherwise an error response has already been sent. */
    public static boolean allow(HttpExchange ex) throws IOException {
        Verdict v = check(ex.getRequestMethod(), ex.getRemoteAddress() == null ? null : ex.getRemoteAddress().getAddress(),
                ex.getRequestHeaders());
        if (v.ok()) return true;
        deny(ex, v.status(), v.message());
        return false;
    }

    /** Pure decision function (no I/O), so every rule can be unit-tested. */
    public static Verdict check(String method, InetAddress remote, Headers h) {
        String client = remote == null ? "unknown" : remote.getHostAddress();
        if (!limiter().tryAcquire(client)) return new Verdict(429, "too many requests: slow down");

        String host = h.getFirst("Host");
        if (!knownHost(host)) return new Verdict(403, "unexpected Host header");

        String origin = h.getFirst("Origin");
        if (origin != null && !originAllowed(origin, host)) return new Verdict(403, "cross-origin request refused");
        String site = h.getFirst("Sec-Fetch-Site");
        if (site != null && !site.equalsIgnoreCase("same-origin") && !site.equalsIgnoreCase("none"))
            return new Verdict(403, "cross-site request refused");

        if (hasBody(h)) {
            String ct = h.getFirst("Content-Type");
            String base = ct == null ? "" : ct.split(";", 2)[0].trim().toLowerCase(Locale.ROOT);
            if (!CONTENT_TYPES.contains(base)) return new Verdict(415, "unsupported Content-Type");
        }

        // The generated (per-run) key is local-only: it is for the dashboard and scripts on this machine.
        if (!keyConfigured() && (remote == null || !remote.isLoopbackAddress()))
            return new Verdict(403, "no -Daegis.api.key configured: write endpoints accept only local requests");

        String given = h.getFirst("X-API-Key");
        if (given == null) {
            String auth = h.getFirst("Authorization");
            if (auth != null && auth.regionMatches(true, 0, "Bearer ", 0, 7)) given = auth.substring(7).trim();
        }
        if (given == null || given.isEmpty()) return new Verdict(401, "missing API key (X-API-Key header)");
        if (!constantTimeEquals(given, effectiveKey())) return new Verdict(401, "wrong API key");
        return OK;
    }

    /** True when the request proved knowledge of an operator-configured key. */
    public static boolean isTrustedWrite(HttpExchange ex) {
        if (!keyConfigured()) return false;
        String given = ex.getRequestHeaders().getFirst("X-API-Key");
        return given != null && constantTimeEquals(given, key());
    }

    /** Constant-time comparison of two secrets (digests are compared, so length is not leaked either). */
    static boolean constantTimeEquals(String a, String b) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] da = md.digest(a.getBytes(StandardCharsets.UTF_8));
            byte[] db = md.digest(b.getBytes(StandardCharsets.UTF_8));
            return MessageDigest.isEqual(da, db);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static boolean hasBody(Headers h) {
        String len = h.getFirst("Content-Length");
        if (len != null) { try { return Long.parseLong(len.trim()) > 0; } catch (NumberFormatException e) { return true; } }
        return h.getFirst("Transfer-Encoding") != null;
    }

    private static String hostOnly(String hostHeader) {
        String h = hostHeader.trim().toLowerCase(Locale.ROOT);
        if (h.startsWith("[")) { int e = h.indexOf(']'); return e > 0 ? h.substring(0, e + 1) : h; }
        int c = h.indexOf(':');
        return c >= 0 ? h.substring(0, c) : h;
    }

    static boolean knownHost(String hostHeader) {
        if (hostHeader == null || hostHeader.isBlank()) return false;
        String h = hostOnly(hostHeader);
        if (h.equals("localhost") || h.equals("127.0.0.1") || h.equals("[::1]")) return true;
        String bind = System.getProperty("bind", "127.0.0.1").toLowerCase(Locale.ROOT);
        if (!bind.equals("0.0.0.0") && h.equals(bind)) return true;
        for (String extra : System.getProperty("aegis.allowed.hosts", "").split(",")) {
            if (!extra.isBlank() && h.equals(extra.trim().toLowerCase(Locale.ROOT))) return true;
        }
        return false;
    }

    static boolean originAllowed(String origin, String hostHeader) {
        String o = origin.trim().toLowerCase(Locale.ROOT);
        if (o.equals("null") || hostHeader == null) return false;
        if (o.equals("http://" + hostHeader.trim().toLowerCase(Locale.ROOT))) return true;   // this server's own pages
        for (String extra : System.getProperty("aegis.allowed.origins", "").split(",")) {
            if (!extra.isBlank() && o.equals(extra.trim().toLowerCase(Locale.ROOT))) return true;
        }
        return false;
    }

    /**
     * Same-origin bootstrap for the dashboards: hands the key to a page served by this server. Not offered when the
     * operator configured their own key (the dashboard then asks for it once per browser session).
     */
    public static void session(HttpExchange ex) throws IOException {
        InetAddress remote = ex.getRemoteAddress() == null ? null : ex.getRemoteAddress().getAddress();
        Headers h = ex.getRequestHeaders();
        String site = h.getFirst("Sec-Fetch-Site");
        boolean ok = "GET".equalsIgnoreCase(ex.getRequestMethod()) && !keyConfigured()
                && remote != null && remote.isLoopbackAddress() && knownHost(h.getFirst("Host"))
                && "1".equals(h.getFirst("X-AEGIS-Dashboard"))
                && (h.getFirst("Origin") == null || originAllowed(h.getFirst("Origin"), h.getFirst("Host")))
                && (site == null || site.equalsIgnoreCase("same-origin"));
        if (!ok) { deny(ex, 404, "not available"); return; }
        byte[] b = ("{\"key\":\"" + effectiveKey() + "\"}").getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "application/json");
        ex.getResponseHeaders().set("Cache-Control", "no-store");
        ex.sendResponseHeaders(200, b.length);
        try (OutputStream os = ex.getResponseBody()) { os.write(b); }
    }

    /** Script injected into every dashboard page: adds the key to same-origin writes made by the page's own JavaScript. */
    private static final String SCRIPT = "<script>(function(){var of=window.fetch.bind(window),kp=null;"
            + "function key(){if(!kp)kp=of('/api/session',{headers:{'X-AEGIS-Dashboard':'1'},cache:'no-store'}).then(function(r){"
            + "if(r.ok)return r.json().then(function(j){return j.key;});var k=null;try{k=sessionStorage.getItem('aegisKey');}catch(e){}"
            + "if(!k){k=window.prompt('AEGIS API key (-Daegis.api.key):')||'';try{sessionStorage.setItem('aegisKey',k);}catch(e){}}return k;"
            + "}).catch(function(){return '';});return kp;}"
            + "window.fetch=function(input,init){init=init||{};var m=(init.method||(typeof input==='object'&&input.method)||'GET').toUpperCase();"
            + "var url=typeof input==='string'?input:(input.url||'');var same=url.charAt(0)==='/'||url.indexOf(location.origin)===0;"
            + "if(m==='GET'||m==='HEAD'||!same)return of(input,init);"
            + "return key().then(function(k){var h=new Headers(init.headers||(typeof input==='object'?input.headers:undefined));"
            + "if(k)h.set('X-API-Key',k);init.headers=h;return of(input,init);});};})();</script>";

    /** Adds the key bootstrap to a dashboard page. */
    public static String withBootstrap(String html) {
        int i = html.toLowerCase(Locale.ROOT).indexOf("<head>");
        return i < 0 ? SCRIPT + html : html.substring(0, i + 6) + SCRIPT + html.substring(i + 6);
    }

    /** Headers every HTML page gets: no framing (clickjacking of approve buttons), no sniffing, no referrer leakage. */
    public static void htmlHeaders(Headers h) {
        h.set("X-Frame-Options", "DENY");
        h.set("X-Content-Type-Options", "nosniff");
        h.set("Referrer-Policy", "no-referrer");
        h.set("Cache-Control", "no-store");
    }

    private static void deny(HttpExchange ex, int status, String msg) throws IOException {
        byte[] b = ("{\"error\":\"" + msg.replace("\"", "'") + "\"}").getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "application/json");
        if (status == 429) ex.getResponseHeaders().set("Retry-After", "1");
        // drain nothing: the body of a rejected request is never read
        ex.sendResponseHeaders(status, b.length);
        try (OutputStream os = ex.getResponseBody()) { os.write(b); }
    }
}
