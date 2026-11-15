package com.threatdetection.util;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.text.Normalizer;
import java.util.regex.Pattern;

/**
 * Canonical form of attacker-controlled text, so signature detectors see what the server would see.
 * Without this, "%27%20OR%201%3D1", "UNION/**&#47;SELECT" and full-width characters walk straight
 * past a plain substring check.
 */
public final class InputNormalizer {
    private static final Pattern SQL_BLOCK_COMMENT = Pattern.compile("/\\*.*?\\*/", Pattern.DOTALL);
    private static final Pattern WHITESPACE = Pattern.compile("[\\s\\u00a0]+");

    private InputNormalizer() {}

    /** URL-decodes (up to 3 layers, catches double encoding), lower-cases, NFKC-normalises. */
    public static String decode(String s) {
        if (s == null || s.isEmpty()) return "";
        String cur = s;
        for (int i = 0; i < 3; i++) {
            String next = decodeOnce(cur);
            if (next.equals(cur)) break;
            cur = next;
        }
        cur = Normalizer.normalize(cur, Normalizer.Form.NFKC);
        return cur.toLowerCase(java.util.Locale.ROOT);
    }

    /** decode() + comment stripping + whitespace collapsing: the form SQL signatures are matched on. */
    public static String forSql(String s) {
        String d = decode(s);
        d = SQL_BLOCK_COMMENT.matcher(d).replaceAll(" ");   // UNION/**/SELECT -> UNION SELECT
        d = d.replace("\u0000", "");
        return WHITESPACE.matcher(d).replaceAll(" ").trim();
    }

    private static String decodeOnce(String s) {
        if (s.indexOf('%') < 0 && s.indexOf('+') < 0) return s;
        try {
            return URLDecoder.decode(s, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return s;   // malformed escape: keep as is
        }
    }
}
