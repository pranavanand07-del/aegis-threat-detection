package com.threatdetection.map;

import java.util.Locale;

/** Minimal JSON helpers (the project is dependency-free, so no Jackson/Gson). */
final class Json {
    private Json() {}

    /** Escapes a string for use inside JSON quotes, including control characters. */
    static String esc(String s) {
        if (s == null) return "";
        StringBuilder sb = new StringBuilder(s.length() + 8);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                    else sb.append(c);
                }
            }
        }
        return sb.toString();
    }

    static String str(String s) {
        return "\"" + esc(s) + "\"";
    }

    /** Locale-independent number (always '.' as the decimal separator). */
    static String num(double d) {
        return String.format(Locale.ROOT, "%.4f", d);
    }
}
