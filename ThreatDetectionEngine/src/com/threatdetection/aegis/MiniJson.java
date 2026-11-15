package com.threatdetection.aegis;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Minimal JSON reader (objects, arrays, strings, numbers, booleans, null) for API replies and Wazuh alerts. Throws IllegalArgumentException on bad input. */
public final class MiniJson {
    private final String s;
    private int i;

    private MiniJson(String s) { this.s = s; }

    public static Object parse(String text) {
        if (text == null || text.length() > 2_000_000) throw new IllegalArgumentException("json too large");
        MiniJson p = new MiniJson(text);
        p.ws();
        Object v = p.value(0);
        p.ws();
        if (p.i != p.s.length()) throw new IllegalArgumentException("trailing data");
        return v;
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> obj(Object o, String key) {
        Object v = o instanceof Map<?, ?> m ? m.get(key) : null;
        return v instanceof Map ? (Map<String, Object>) v : Map.of();
    }

    public static String text(Object o, String key) {
        Object v = o instanceof Map<?, ?> m ? m.get(key) : null;
        return v == null ? "" : (v instanceof Double d && d == Math.rint(d) ? Long.toString(d.longValue()) : v.toString());
    }

    public static int integer(Object o, String key, int dflt) {
        Object v = o instanceof Map<?, ?> m ? m.get(key) : null;
        if (v instanceof Double d) return d.intValue();
        if (v instanceof String t) { try { return Integer.parseInt(t.trim()); } catch (NumberFormatException e) { return dflt; } }
        return dflt;
    }

    public static List<?> list(Object o, String key) {
        Object v = o instanceof Map<?, ?> m ? m.get(key) : null;
        return v instanceof List<?> l ? l : List.of();
    }

    private Object value(int depth) {
        if (depth > 20) throw new IllegalArgumentException("nesting too deep");
        if (i >= s.length()) throw new IllegalArgumentException("unexpected end");
        char c = s.charAt(i);
        if (c == '{') {
            i++;
            Map<String, Object> m = new LinkedHashMap<>();
            ws();
            if (peek('}')) { i++; return m; }
            while (true) {
                ws();
                String k = string();
                ws(); expect(':'); ws();
                m.put(k, value(depth + 1));
                ws();
                if (peek(',')) { i++; continue; }
                expect('}');
                return m;
            }
        }
        if (c == '[') {
            i++;
            List<Object> l = new ArrayList<>();
            ws();
            if (peek(']')) { i++; return l; }
            while (true) {
                ws();
                l.add(value(depth + 1));
                ws();
                if (peek(',')) { i++; continue; }
                expect(']');
                return l;
            }
        }
        if (c == '"') return string();
        if (s.startsWith("true", i)) { i += 4; return Boolean.TRUE; }
        if (s.startsWith("false", i)) { i += 5; return Boolean.FALSE; }
        if (s.startsWith("null", i)) { i += 4; return null; }
        int st = i;
        while (i < s.length() && "+-0123456789.eE".indexOf(s.charAt(i)) >= 0) i++;
        if (st == i) throw new IllegalArgumentException("unexpected character at " + i);
        return Double.parseDouble(s.substring(st, i));
    }

    private String string() {
        expect('"');
        StringBuilder sb = new StringBuilder();
        while (i < s.length()) {
            char c = s.charAt(i++);
            if (c == '"') return sb.toString();
            if (c == '\\') {
                if (i >= s.length()) break;
                char e = s.charAt(i++);
                switch (e) {
                    case 'n' -> sb.append('\n');
                    case 't' -> sb.append('\t');
                    case 'r' -> sb.append('\r');
                    case 'b' -> sb.append('\b');
                    case 'f' -> sb.append('\f');
                    case 'u' -> {
                        if (i + 4 > s.length()) throw new IllegalArgumentException("bad escape");
                        sb.append((char) Integer.parseInt(s.substring(i, i + 4), 16));
                        i += 4;
                    }
                    default -> sb.append(e);
                }
            } else sb.append(c);
        }
        throw new IllegalArgumentException("unterminated string");
    }

    private void ws() { while (i < s.length() && Character.isWhitespace(s.charAt(i))) i++; }
    private boolean peek(char c) { return i < s.length() && s.charAt(i) == c; }
    private void expect(char c) {
        if (!peek(c)) throw new IllegalArgumentException("expected '" + c + "' at " + i);
        i++;
    }
}
