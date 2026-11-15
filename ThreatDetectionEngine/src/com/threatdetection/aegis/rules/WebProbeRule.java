package com.threatdetection.aegis.rules;

import com.threatdetection.aegis.AegisRule;
import com.threatdetection.aegis.AegisSignal;
import com.threatdetection.model.DetectionOutcome;

import java.util.regex.Pattern;

/** Other suspicious web requests: Log4Shell-style lookups, command injection, recon of sensitive paths. */
public class WebProbeRule implements AegisRule {
    private static final Pattern CMD_INJECTION = Pattern.compile(
            "(;|\\||&&|`|\\$\\()\\s*(cat|whoami|id|uname|wget|curl|nc|bash|sh|cmd|powershell)\\b");
    private static final String[] RECON = {
            "/.env", "/.git/", "/.aws/", "/.ds_store", "/phpmyadmin", "/server-status", "/actuator/env",
            "/actuator/heapdump", "/xmlrpc.php", "/wp-config", "/id_rsa", "/cgi-bin/", "/.htpasswd", "/backup.sql"
    };

    @Override
    public DetectionOutcome evaluate(AegisSignal s) {
        if (s.kind != AegisSignal.Kind.WEB && s.kind != AegisSignal.Kind.AUTH) return null;
        String text = PathTraversalRule.decode(PathTraversalRule.decode((s.path + " " + s.command).toLowerCase()));
        if (text.contains("${jndi:") || text.contains("${${")) {
            return new DetectionOutcome("LOG4SHELL_PROBE", 50, "JNDI lookup string in request (Log4Shell-style)");
        }
        if (CMD_INJECTION.matcher(text).find()) {
            return new DetectionOutcome("COMMAND_INJECTION", 35, "Shell command appended to request parameters");
        }
        for (String r : RECON) {
            if (text.contains(r)) {
                return new DetectionOutcome("SENSITIVE_PATH_PROBE", 15, "Request for commonly probed path: " + r);
            }
        }
        return null;
    }
}
