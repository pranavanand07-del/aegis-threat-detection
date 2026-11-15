package com.threatdetection.aegis.rules;

import com.threatdetection.aegis.AegisRule;
import com.threatdetection.aegis.AegisSignal;
import com.threatdetection.model.DetectionOutcome;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

/** Flags directory-traversal attempts, including URL-encoded and double-encoded forms. */
public class PathTraversalRule implements AegisRule {
    private static final String[] MARKERS = {
            "../", "..\\", "....//", "..;/", "%c0%af", "/etc/passwd", "/etc/shadow", "/proc/self",
            "boot.ini", "win.ini", "windows\\system32", "web-inf/", "..%5c"
    };

    @Override
    public DetectionOutcome evaluate(AegisSignal s) {
        if (s.kind != AegisSignal.Kind.WEB && s.kind != AegisSignal.Kind.AUTH) return null;
        String raw = (s.path + " " + s.command).toLowerCase();
        String once = decode(raw);
        String twice = decode(once);
        for (String m : MARKERS) {
            if (raw.contains(m) || once.contains(m) || twice.contains(m)) {
                return new DetectionOutcome("PATH_TRAVERSAL", 40, "Directory traversal pattern in request: " + m);
            }
        }
        return null;
    }

    static String decode(String s) {
        try {
            return URLDecoder.decode(s.replace("+", "%2B"), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return s;
        }
    }
}
