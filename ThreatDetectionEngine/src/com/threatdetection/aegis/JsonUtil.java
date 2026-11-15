package com.threatdetection.aegis;

import java.util.Locale;

/** Tiny JSON helpers (the project is dependency-free, so no Jackson/Gson). */
public final class JsonUtil {
    private JsonUtil() {}

    public static String esc(String s) {
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

    public static String str(String s) {
        return "\"" + esc(s) + "\"";
    }

    public static String num(double d) {
        return String.format(Locale.ROOT, "%.4f", d);
    }
}
