package com.threatdetection.server;

import com.sun.net.httpserver.HttpExchange;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

/** Bounded request-body reader shared by every endpoint that accepts a body. */
public final class HttpBody {
    private HttpBody() {}

    /** Thrown when the body exceeds the limit; endpoints answer it with HTTP 413. */
    public static final class TooLarge extends IOException {
        private static final long serialVersionUID = 1L;
        public TooLarge(long limit) { super("request body larger than " + limit + " bytes"); }
    }

    /**
     * Reads at most {@code max} bytes. A Content-Length above the limit is refused BEFORE any byte is read, and a body
     * without (or with a lying) Content-Length is cut off as soon as it passes the limit, so memory use is bounded.
     */
    public static String read(HttpExchange ex, long max) throws IOException {
        String len = ex.getRequestHeaders().getFirst("Content-Length");
        if (len != null) {
            try {
                if (Long.parseLong(len.trim()) > max) throw new TooLarge(max);
            } catch (NumberFormatException e) {
                throw new IOException("invalid Content-Length");
            }
        }
        return read(ex.getRequestBody(), max);
    }

    public static String read(InputStream is, long max) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream((int) Math.min(max, 8192));
        byte[] data = new byte[8192];
        int n;
        while ((n = is.read(data)) != -1) {
            buf.write(data, 0, n);
            if (buf.size() > max) throw new TooLarge(max);
        }
        return buf.toString(StandardCharsets.UTF_8);
    }

    /** Maximum body for pushed log batches: -Daegis.max.body (bytes), default 2 MB, never above 32 MB. */
    public static long ingestLimit() {
        long v = 2L * 1024 * 1024;
        try { v = Long.parseLong(System.getProperty("aegis.max.body", Long.toString(v))); } catch (NumberFormatException ignored) { /* default */ }
        return Math.max(1024, Math.min(v, 32L * 1024 * 1024));
    }
}
