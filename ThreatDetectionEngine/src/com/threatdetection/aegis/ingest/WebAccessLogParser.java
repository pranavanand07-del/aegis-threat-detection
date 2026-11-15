package com.threatdetection.aegis.ingest;

import com.threatdetection.aegis.AegisSignal;

import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Apache / Nginx access logs (common and combined format). Requests that are rejected with
 * 401/403 on login-like paths are reported as failed logons so the core brute-force detector
 * can correlate them; everything else is an HTTP request.
 */
public final class WebAccessLogParser {
    private static final Pattern LINE = Pattern.compile(
            "^(\\S+) \\S+ (\\S+) \\[([^\\]]+)\\] \"([A-Z]+) (\\S+)(?: [^\"]*)?\" (\\d{3}) (\\S+)(?: \"([^\"]*)\" \"([^\"]*)\")?.*$");
    private static final DateTimeFormatter TIME = DateTimeFormatter.ofPattern("dd/MMM/yyyy:HH:mm:ss Z", Locale.ENGLISH);
    private static final Pattern LOGIN_PATH = Pattern.compile("(?i)(login|signin|sign-in|auth|admin|wp-login|xmlrpc)");
    private static final Set<String> RISKY_EXT = Set.of("exe", "dll", "msi", "bat", "ps1", "scr", "jar", "vbs", "apk", "sh");

    private WebAccessLogParser() {}

    /** @return the signal, or null when the line is not an access-log line. */
    public static AegisSignal parse(String line) {
        Matcher m = LINE.matcher(line);
        if (!m.matches()) return null;
        int status = Integer.parseInt(m.group(6));
        String path = m.group(5);
        String user = m.group(2).equals("-") ? "unknown" : m.group(2);
        boolean authFail = (status == 401 || status == 403) && LOGIN_PATH.matcher(path).find();

        AegisSignal s = new AegisSignal(authFail ? AegisSignal.Kind.AUTH : AegisSignal.Kind.WEB);
        s.authFailure = authFail;
        s.ip = m.group(1);
        s.user = user;
        s.path = path;
        s.status = status;
        s.userAgent = m.group(9) == null ? "" : m.group(9);
        s.channel = "web-access-log";
        try {
            s.ts = OffsetDateTime.parse(m.group(3), TIME).toInstant().toEpochMilli();
        } catch (RuntimeException e) {
            s.ts = 0;
        }
        String clean = path.contains("?") ? path.substring(0, path.indexOf('?')) : path;
        int dot = clean.lastIndexOf('.');
        if (!authFail && dot > 0 && RISKY_EXT.contains(clean.substring(dot + 1).toLowerCase(Locale.ROOT))
                && "GET".equals(m.group(4)) && status == 200) {
            s.fileName = clean.substring(clean.lastIndexOf('/') + 1);
        }
        return s;
    }
}
