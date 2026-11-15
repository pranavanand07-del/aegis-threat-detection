package com.threatdetection.detector;

import com.threatdetection.model.DetectionOutcome;
import com.threatdetection.model.LogEvent;
import com.threatdetection.tracking.IpActivityTracker;
import com.threatdetection.util.InputNormalizer;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Scans endpoint + request body for SQL injection payloads. Input is normalised first (URL decoding,
 * comment stripping, whitespace folding). A bare "--" is NOT a signature: ordinary text and URLs
 * contain it. It only counts as a comment terminator right after a quote or a SQL keyword.
 */
public class SqlInjectionDetector implements Detector {
    // Strong: hard to write by accident, always an alert.
    private static final String[] PHRASES = {
            "' or 1=1", "' or '1'='1", "\" or 1=1", "drop table",
            "xp_cmdshell", "information_schema", "waitfor delay", "; shutdown", "'; --", "';--"
    };
    // Weak: also appear in ordinary prose ("how to insert into a table", "sleep(5) in C"). They only count
    // when SQL syntax surrounds them (a quote, semicolon, comment marker or closing bracket).
    private static final String[] WEAK_PHRASES = {"insert into", "select * from", "exec(", "sleep(", "benchmark("};
    private static final Pattern SQL_SYNTAX = Pattern.compile("['\";)]|--|/\\*|#");
    // quote or ')' followed by optional spaces and a comment marker, e.g.  admin'--   or  1) -- -
    // word boundaries: "european union selection criteria" is prose, "1 union select pass" is not
    private static final Pattern UNION_SELECT = Pattern.compile("\\bunion\\s+(all\\s+)?select\\b");
    private static final Pattern TAUTOLOGY = Pattern.compile("\\b(or|and)\\s+\\d+\\s*=\\s*\\d+");
    private static final Pattern COMMENT_AFTER_QUOTE = Pattern.compile("['\")]\\s*(--|#|/\\*)");
    // keyword then '--'  e.g.  select 1 --
    private static final Pattern COMMENT_AFTER_SQL = Pattern.compile("\\b(select|union|or|and|where|from)\\b[^\\n]{0,60}\\s--(\\s|$)");

    @Override
    public DetectionOutcome evaluate(LogEvent event, IpActivityTracker tracker) {
        String hay = InputNormalizer.forSql(event.endpoint + " " + event.requestBody);
        for (String p : PHRASES) {
            if (hay.contains(p)) {
                return new DetectionOutcome("SQL_INJECTION", 40, "SQL injection pattern detected: " + p);
            }
        }
        if (UNION_SELECT.matcher(hay).find()) {
            return new DetectionOutcome("SQL_INJECTION", 40, "SQL injection pattern detected: union select");
        }
        for (String p : WEAK_PHRASES) {
            if (hay.contains(p) && SQL_SYNTAX.matcher(hay).find()) {
                return new DetectionOutcome("SQL_INJECTION", 40, "SQL injection pattern detected: " + p + " with SQL syntax around it");
            }
        }
        if (TAUTOLOGY.matcher(hay).find()) {
            return new DetectionOutcome("SQL_INJECTION", 40, "SQL injection pattern detected: numeric tautology (or 1=1)");
        }
        Matcher m = COMMENT_AFTER_QUOTE.matcher(hay);
        if (m.find()) {
            return new DetectionOutcome("SQL_INJECTION", 40, "SQL injection pattern detected: quote followed by comment marker");
        }
        if (COMMENT_AFTER_SQL.matcher(hay).find()) {
            return new DetectionOutcome("SQL_INJECTION", 40, "SQL injection pattern detected: SQL keyword followed by --");
        }
        return null;
    }
}
